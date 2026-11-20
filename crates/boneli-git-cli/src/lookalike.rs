//! Names that are `.git` on another file system (ADR-010, D1 and D6).
//!
//! `diff` writes the workspace onto the host before git sees it, and on a
//! case-insensitive or normalizing file system (ext4, f2fs or tmpfs
//! `casefold`, HFS+, vfat) such a name is `.git` when git looks it up while
//! it walks the tree, before `core.protectNTFS` and `core.protectHFS` check
//! the names it adds. So the adapter refuses these names itself, before
//! anything is written:
//!
//! - git's NTFS forms (`is_ntfs_dotgit`): `.git` or `git~1` in any case,
//!   followed by nothing but dots and spaces, or by `:` and anything;
//! - git's HFS form, widened: `.git` in any case once every Unicode
//!   default-ignorable code point is removed. git's HFS list is a subset;
//!   the full set also covers a case-insensitive file system that drops
//!   any ignorable code point from a name, where `.g<U+200B>it`, which
//!   git accepts, would be `.git`.
//!
//! Exactly `.git` is in both forms; `without_metadata` drops it first.
//!
//! Paths are bytes (ADR-018, D3):
//!
//! - components are split at `/` and at `\`, because git's own NTFS check
//!   treats `\` as a separator on every host: git 2.56.0 refuses
//!   `x\.git`, `.git\config` and `x\git~1` in `add` and `apply`, and
//!   accepts `x\.g<U+200B>it`, which this check refuses too;
//! - the NTFS form reads bytes, as git's does;
//! - the folded form reads a component that is not UTF-8 twice, once with
//!   every maximal run of bytes that are not UTF-8 removed and once with
//!   each such run replaced by `.`, and either reading that is `.git`
//!   refuses. Removal covers a file system that drops the bytes it cannot
//!   decode (`.g<0xFF>it`); `.` covers one that decodes an overlong
//!   sequence, where `<0xC0 0xAE>` is `.` and `<0xC0 0xAE>git` is `.git`.

/// Unicode `Default_Ignorable_Code_Point`, as inclusive ranges, merged
/// from DerivedCoreProperties.txt of Unicode 18.0.0.
const DEFAULT_IGNORABLE: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];

fn ignorable(c: char) -> bool {
    let c = u32::from(c);
    DEFAULT_IGNORABLE
        .iter()
        .any(|&(low, high)| (low..=high).contains(&c))
}

/// `.git` in any ASCII case once the ignorable code points are gone.
fn str_folds_to_git(component: &str) -> bool {
    let mut rest = component.chars().filter(|c| !ignorable(*c));
    ".git"
        .chars()
        .all(|want| rest.next().is_some_and(|c| c.to_ascii_lowercase() == want))
        && rest.next().is_none()
}

/// The folded form over bytes: as UTF-8 when the component is, otherwise
/// both readings of its invalid runs (removed, and each replaced by `.`).
fn folds_to_git(component: &[u8]) -> bool {
    if let Ok(text) = std::str::from_utf8(component) {
        return str_folds_to_git(text);
    }
    let mut removed = String::new();
    let mut replaced = String::new();
    // `utf8_chunks` ends a chunk at each invalid sequence, so a run of
    // invalid bytes spans chunks whose valid part between them is empty.
    let mut in_run = false;
    for chunk in component.utf8_chunks() {
        if !chunk.valid().is_empty() {
            in_run = false;
        }
        removed.push_str(chunk.valid());
        replaced.push_str(chunk.valid());
        if !chunk.invalid().is_empty() && !in_run {
            replaced.push('.');
            in_run = true;
        }
    }
    str_folds_to_git(&removed) || str_folds_to_git(&replaced)
}

/// git's `is_ntfs_dotgit` for one component.
fn ntfs_git(bytes: &[u8]) -> bool {
    let rest = if bytes.len() >= 4 && bytes[0] == b'.' && bytes[1..4].eq_ignore_ascii_case(b"git") {
        &bytes[4..]
    } else if bytes.len() >= 5 && bytes[..3].eq_ignore_ascii_case(b"git") && &bytes[3..5] == b"~1" {
        &bytes[5..]
    } else {
        return false;
    };
    for &b in rest {
        if b == b':' {
            return true;
        }
        if b != b'.' && b != b' ' {
            return false;
        }
    }
    true
}

/// Whether some component of a tree path, split at `/` and at `\`, may
/// name `.git` on some file system.
pub(crate) fn names_git_elsewhere(path: &[u8]) -> bool {
    path.split(|b| *b == b'/' || *b == b'\\')
        .any(|component| folds_to_git(component) || ntfs_git(component))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookalikes() {
        for name in [
            ".git",
            ".GIT",
            ".Git",
            ".gIT",
            "git~1",
            "GIT~1",
            ".git.",
            ".git ",
            ".git. .",
            ".git:x",
            ".git::$INDEX_ALLOCATION",
            "git~1:",
            ".g\u{200C}it",
            ".g\u{200B}it",
            "\u{FEFF}.GiT",
            ".git\u{00AD}",
            ".gi\u{E0001}t",
        ] {
            assert!(names_git_elsewhere(name.as_bytes()), "{name:?}");
        }
        for name in [
            "git",
            ".gitignore",
            ".github",
            ".gitx",
            "x.git",
            "git~2",
            ".git~1",
            "git~1x",
            ".gi",
            "",
            ".g\u{0130}t",
            ".git\u{0301}",
            "\u{FF0E}git",
        ] {
            assert!(!names_git_elsewhere(name.as_bytes()), "{name:?}");
        }
        // Components split at `\` too, as git's NTFS check splits them: the
        // first three git refuses itself, the last it accepts (ADR-018, D3).
        // `.git\x` is one name, not metadata, so it is refused here.
        // Bytes that are not UTF-8 are read removed and as `.`.
        let refused: [&[u8]; 11] = [
            b"x\\.git",
            b".git\\config",
            b"x\\GIT~1",
            "x\\.g\u{200B}it".as_bytes(),
            b".git\\x",
            b"a/b\\.GIT/c",
            b".g\xffit",
            b"\xc0\xaegit",
            b".git\xff",
            b"\xff.git",
            b"a/.g\xfe\xffit/b",
        ];
        for path in refused {
            assert!(names_git_elsewhere(path), "{path:?}");
        }
        let passed: [&[u8]; 8] = [
            b"a\\b",
            b"x\xff",
            b"\xff",
            b"\xc0\xae\xc0\xae",
            b"..\\x",
            b"x.git\\y",
            b".gi\xff",
            b"src/lib.rs",
        ];
        for path in passed {
            assert!(!names_git_elsewhere(path), "{path:?}");
        }
    }

    #[test]
    fn ignorable_ranges_are_sorted_and_disjoint() {
        for pair in DEFAULT_IGNORABLE.windows(2) {
            assert!(pair[0].0 <= pair[0].1 && pair[0].1 < pair[1].0, "{pair:?}");
        }
    }
}
