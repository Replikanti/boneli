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
fn folds_to_git(component: &str) -> bool {
    let mut rest = component.chars().filter(|c| !ignorable(*c));
    ".git"
        .chars()
        .all(|want| rest.next().is_some_and(|c| c.to_ascii_lowercase() == want))
        && rest.next().is_none()
}

/// git's `is_ntfs_dotgit` for one component.
fn ntfs_git(component: &str) -> bool {
    let bytes = component.as_bytes();
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

/// Whether a path component may name `.git` on some file system.
pub(crate) fn names_git_elsewhere(component: &str) -> bool {
    folds_to_git(component) || ntfs_git(component)
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
            assert!(names_git_elsewhere(name), "{name:?}");
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
            assert!(!names_git_elsewhere(name), "{name:?}");
        }
    }

    #[test]
    fn ignorable_ranges_are_sorted_and_disjoint() {
        for pair in DEFAULT_IGNORABLE.windows(2) {
            assert!(pair[0].0 <= pair[0].1 && pair[0].1 < pair[1].0, "{pair:?}");
        }
    }
}
