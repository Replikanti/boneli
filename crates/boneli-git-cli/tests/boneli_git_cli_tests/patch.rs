//! `patch_between` (ADR-023, D4 and D6): the patch policy's input from two
//! checkouts, built from the trees' listings so gitlinks are seen.

use std::collections::BTreeMap;

use boneli_app::{CheckoutId, Git, GitError, TreePath};
use boneli_domain::{
    BaseLink, Change, Entry, EntryKind, Patch, PatchLimits, PatchVerdict, PatchViolation,
    UnreadablePath, patch_policy,
};
use boneli_git_cli::{Kind, Workspace, patch_between};

use crate::support::{
    Source, TempDir, bpath, cli, decode, edit, edit_kind, encode, failed, host_git, open, sha,
    tpath,
};

/// The patch from `base` to `after`, which must be readable.
fn patch(git: &impl Git, base: &CheckoutId, after: &CheckoutId) -> Patch {
    git.patch_between(base, after)
        .expect("patch_between")
        .expect("UTF-8 paths")
}

/// The checkout that `change` makes of `base`'s snapshot, through `diff`
/// and `apply`.
fn changed(git: &impl Git, base: &CheckoutId, change: impl Fn(Vec<u8>) -> Vec<u8>) -> CheckoutId {
    let snapshot = git.snapshot(base).expect("snapshot");
    let diff = git.diff(base, &change(snapshot)).expect("diff");
    git.apply(base, &diff).expect("apply")
}

fn file(kind: EntryKind, data: &[u8]) -> Option<Entry> {
    Some(Entry {
        kind,
        data: data.to_vec(),
    })
}

fn change(path: &str, before: Option<Entry>, after: Option<Entry>) -> Change {
    Change {
        path: path.to_owned(),
        before,
        after,
    }
}

fn link(path: &str, target: &[u8]) -> BaseLink {
    BaseLink {
        path: path.to_owned(),
        target: target.to_vec(),
    }
}

/// A file whose mode alone changes is one change from `File` to
/// `Executable` with the same data.
#[test]
fn patch_between_mode_only_change() {
    let tmp = TempDir::new("patch-mode");
    let source = Source::new(&tmp, "src", false);
    source.write("run.sh", b"echo\n", false);
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let after = changed(&git, &c, |w| {
        edit_kind(&w, &tpath("run.sh"), Some((Kind::Executable, b"echo\n")))
    });
    assert_eq!(
        patch(&git, &c, &after).changes,
        [change(
            "run.sh",
            file(EntryKind::File, b"echo\n"),
            file(EntryKind::Executable, b"echo\n")
        )]
    );
}

/// A file that becomes a directory is two changes in byte order: the file
/// removed, then the file beneath it added.
#[test]
fn patch_between_file_to_directory() {
    let tmp = TempDir::new("patch-file-to-dir");
    let source = Source::new(&tmp, "src", false);
    source.write("p", b"file\n", false);
    source.write("q", b"q\n", false);
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let after = changed(&git, &c, |w| {
        let w = edit(&w, &tpath("p"), None);
        edit(&w, &tpath("p/x"), Some(b"x\n"))
    });
    assert_eq!(
        patch(&git, &c, &after).changes,
        [
            change("p", file(EntryKind::File, b"file\n"), None),
            change("p/x", None, file(EntryKind::File, b"x\n")),
        ]
    );
}

/// A source with a symlink, an executable, a file to edit, one to remove
/// and one that stays, and the checkout of an edit of each kind.
fn kinds(tmp: &TempDir) -> (impl Git, CheckoutId, CheckoutId) {
    let source = Source::new(tmp, "src", false);
    source.write("a.ts", b"a\n", false);
    source.write("bin/run", b"echo\n", true);
    source.link("docs/link", "../a.ts");
    source.write("gone.txt", b"gone\n", false);
    source.write("same.txt", b"same\n", false);
    source.link("to-file", "a.ts");
    source.write("to-link", b"target\n", false);
    let base = source.commit("base");
    let git = cli(tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let after = changed(&git, &c, |w| {
        let w = edit(&w, &tpath("a.ts"), Some(b"b\n"));
        let w = edit_kind(&w, &tpath("bin/run"), Some((Kind::File, b"echo\n")));
        let w = edit(&w, &tpath("docs/link"), Some(b"../same.txt"));
        let w = edit(&w, &tpath("gone.txt"), None);
        let w = edit(&w, &tpath("new.ts"), Some(b"new\n"));
        let w = edit_kind(&w, &tpath("new-link"), Some((Kind::Symlink, b"a.ts")));
        let w = edit_kind(&w, &tpath("to-file"), Some((Kind::File, b"now a file\n")));
        edit_kind(&w, &tpath("to-link"), Some((Kind::Symlink, b"a.ts")))
    });
    (git, c, after)
}

/// The patch of `after` to `base` is the inverse of the patch of `base` to
/// `after`, and its base links are `after`'s.
#[test]
fn patch_between_reversed_is_inverse() {
    let tmp = TempDir::new("patch-reversed");
    let (git, c, after) = kinds(&tmp);
    let forward = patch(&git, &c, &after);
    let backward = patch(&git, &after, &c);
    assert!(!forward.changes.is_empty());
    let inverted: Vec<Change> = forward
        .changes
        .into_iter()
        .map(|c| change(&c.path, c.after, c.before))
        .collect();
    assert_eq!(backward.changes, inverted);
    assert_eq!(
        backward.base_links,
        [
            link("docs/link", b"../same.txt"),
            link("new-link", b"a.ts"),
            link("to-link", b"a.ts"),
        ]
    );
}

/// Every symlink of the base is a base link, unchanged ones included, and
/// no symlink of the tree after the fix is.
#[test]
fn patch_between_lists_base_links() {
    let tmp = TempDir::new("patch-base-links");
    let source = Source::new(&tmp, "src", false);
    source.write("a.ts", b"a\n", false);
    source.link("kept", "a.ts");
    source.link("lib/moved", "../a.ts");
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let after = changed(&git, &c, |w| {
        let w = edit(&w, &tpath("a.ts"), Some(b"b\n"));
        let w = edit(&w, &tpath("lib/moved"), Some(b"../kept"));
        edit_kind(&w, &tpath("new-link"), Some((Kind::Symlink, b"a.ts")))
    });
    let p = patch(&git, &c, &after);
    assert_eq!(
        p.base_links,
        [link("kept", b"a.ts"), link("lib/moved", b"../a.ts")]
    );
    assert_eq!(patch(&git, &c, &c).base_links, p.base_links);
}

/// The merge join reports an added path before the first base entry and
/// removed paths after the last one.
#[test]
fn patch_between_head_and_tail() {
    let tmp = TempDir::new("patch-head-tail");
    let source = Source::new(&tmp, "src", false);
    source.write("m", b"m\n", false);
    source.write("y", b"y\n", false);
    source.write("z", b"z\n", false);
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let after = changed(&git, &c, |w| {
        let w = edit(&w, &tpath("a"), Some(b"a\n"));
        let w = edit(&w, &tpath("y"), None);
        edit(&w, &tpath("z"), None)
    });
    assert_eq!(
        patch(&git, &c, &after).changes,
        [
            change("a", None, file(EntryKind::File, b"a\n")),
            change("y", file(EntryKind::File, b"y\n"), None),
            change("z", file(EntryKind::File, b"z\n"), None),
        ]
    );
}

const ONE: &str = "1111111111111111111111111111111111111111";
const TWO: &str = "2222222222222222222222222222222222222222";
const THREE: &str = "3333333333333333333333333333333333333333";

/// A gitlink added, removed or retargeted by a diff is a change with a
/// `Gitlink` side whose data is the commit id, so the policy refuses it.
/// A workspace has no gitlinks (ADR-010, D3), so a patch built from
/// snapshots would see none of these and pass the fix.
#[test]
fn patch_between_reports_gitlinks() {
    let tmp = TempDir::new("patch-gitlinks");
    let source = Source::new(&tmp, "src", false);
    source.write("a.ts", b"a\n", false);
    source.gitlink("lib/mod", ONE);
    source.gitlink("sub", ONE);
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let gitlink = |id: &str| file(EntryKind::Gitlink, id.as_bytes());
    let cases: [(&str, String, Change); 3] = [
        (
            "added",
            format!(
                "diff --git a/new b/new\nnew file mode 160000\nindex {z}..{TWO}\n--- /dev/null\n\
                 +++ b/new\n@@ -0,0 +1 @@\n+Subproject commit {TWO}\n",
                z = "0".repeat(40)
            ),
            change("new", None, gitlink(TWO)),
        ),
        (
            "removed",
            format!(
                "diff --git a/sub b/sub\ndeleted file mode 160000\nindex {ONE}..{z}\n--- a/sub\n\
                 +++ /dev/null\n@@ -1 +0,0 @@\n-Subproject commit {ONE}\n",
                z = "0".repeat(40)
            ),
            change("sub", gitlink(ONE), None),
        ),
        (
            "retargeted",
            format!(
                "diff --git a/lib/mod b/lib/mod\nindex {ONE}..{THREE} 160000\n--- a/lib/mod\n\
                 +++ b/lib/mod\n@@ -1 +1 @@\n-Subproject commit {ONE}\n\
                 +Subproject commit {THREE}\n"
            ),
            change("lib/mod", gitlink(ONE), gitlink(THREE)),
        ),
    ];
    for (which, diff, want) in cases {
        let after = git.apply(&c, diff.as_bytes()).expect(which);
        let p = patch(&git, &c, &after);
        assert_eq!(p.changes, [want], "{which}");
        let verdict = patch_policy(&p, &PatchLimits::DEFAULT);
        assert!(
            matches!(
                &verdict,
                PatchVerdict::Reject(v)
                    if v.iter().any(|v| matches!(v, PatchViolation::Gitlink { index: 0 }))
            ),
            "{which}: {verdict:?}"
        );
    }
}

/// For trees without gitlinks the adapter's patch equals the workspace
/// patch of the two snapshots (the differential oracle, ADR-013 D1), and
/// the after sides applied to the base snapshot give the after snapshot.
#[test]
fn patch_between_matches_workspace_patch() {
    let tmp = TempDir::new("patch-differential");
    let (git, c, after) = kinds(&tmp);
    let base_ws = decode(&git.snapshot(&c).expect("snapshot"));
    let after_ws = decode(&git.snapshot(&after).expect("snapshot"));
    for (from, to, a, b) in [
        (&c, &after, &base_ws, &after_ws),
        (&after, &c, &after_ws, &base_ws),
        (&c, &c, &base_ws, &base_ws),
    ] {
        let got = patch(&git, from, to);
        let want = patch_between(a, b).expect("UTF-8 paths");
        assert_eq!(got, want);
        assert_eq!(applied(a, &got), b.clone().without_metadata());
    }
}

fn kind_of(kind: EntryKind) -> Kind {
    match kind {
        EntryKind::File => Kind::File,
        EntryKind::Executable => Kind::Executable,
        EntryKind::Symlink => Kind::Symlink,
        EntryKind::Gitlink => panic!("no gitlinks in this test"),
    }
}

/// `base` without metadata with every change's after side applied,
/// removals first, so a file can become a directory.
fn applied(base: &Workspace, patch: &Patch) -> Workspace {
    let mut out: BTreeMap<TreePath, (Kind, Vec<u8>)> = base
        .clone()
        .without_metadata()
        .iter()
        .map(|(p, kind, data)| (p.clone(), (kind, data.to_vec())))
        .collect();
    for c in &patch.changes {
        out.remove(&tpath(&c.path));
    }
    for c in &patch.changes {
        if let Some(after) = &c.after {
            out.insert(tpath(&c.path), (kind_of(after.kind), after.data.clone()));
        }
    }
    decode(&encode(
        out.into_iter()
            .map(|(p, (kind, data))| (p, kind, data))
            .collect(),
    ))
}

/// A changed path or a base link path that is not UTF-8 is an
/// `UnreadablePath` naming its index; changes are checked first. An
/// unchanged file at such a path is no part of the patch.
#[test]
fn patch_between_reports_the_first_unreadable_path() {
    let tmp = TempDir::new("patch-unreadable");
    let source = Source::new(&tmp, "src", false);
    source.write("a.ts", b"a\n", false);
    source.write_bytes(b"x\xff", b"x\n", false);
    let base = source.commit("base");
    source.link_bytes(b"l\xfe", b"a.ts");
    let linked = source.commit("linked");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let edits = |w: Vec<u8>, paths: &[&TreePath]| {
        paths.iter().fold(w, |w, p| edit(&w, p, Some(b"changed\n")))
    };
    let (a, x) = (tpath("a.ts"), bpath(b"x\xff"));
    // Unchanged: an edit elsewhere reads.
    let after = changed(&git, &c, |w| edits(w, &[&a]));
    assert_eq!(patch(&git, &c, &after).changes.len(), 1);
    // `a.ts` is change 0, the non-UTF-8 path sorts after it.
    let after = changed(&git, &c, |w| edits(w, &[&a, &x]));
    assert_eq!(
        git.patch_between(&c, &after),
        Ok(Err(UnreadablePath::Change { index: 1 }))
    );
    let removed = changed(&git, &c, |w| edit(&w, &x, None));
    assert_eq!(
        git.patch_between(&c, &removed),
        Ok(Err(UnreadablePath::Change { index: 0 }))
    );
    // A base link at a non-UTF-8 path, and both kinds at once.
    let l = git.fetch_base(&source.url(), &sha(&linked)).expect("fetch");
    let after = changed(&git, &l, |w| edits(w, &[&a]));
    assert_eq!(
        git.patch_between(&l, &after),
        Ok(Err(UnreadablePath::BaseLink { index: 0 }))
    );
    let after = changed(&git, &l, |w| edits(w, &[&x]));
    assert_eq!(
        git.patch_between(&l, &after),
        Ok(Err(UnreadablePath::Change { index: 0 }))
    );
}

/// A listing of exactly the node cap is read, one more entry is `Failed`,
/// on either side. Two fetches make two stores, so this also reads each
/// side from its own.
#[test]
fn patch_between_entry_cap() {
    const CAP: usize = 4;
    let tmp = TempDir::new("patch-cap");
    let source = Source::new(&tmp, "src", false);
    for n in 0..CAP {
        source.write(&format!("f{n}"), b"x\n", false);
    }
    let at = source.commit("at the cap");
    source.write("over", b"x\n", false);
    let over = source.commit("over the cap");
    let git = open(&tmp, &host_git(), CAP);
    let c_at = git.fetch_base(&source.url(), &sha(&at)).expect("fetch");
    let c_over = git.fetch_base(&source.url(), &sha(&over)).expect("fetch");
    assert_eq!(patch(&git, &c_at, &c_at).changes, []);
    for (from, to) in [(&c_at, &c_over), (&c_over, &c_at)] {
        let detail = failed(git.patch_between(from, to));
        assert!(detail.contains("entries"), "{detail}");
    }
    // The same pair under the default cap: one added file.
    let wide = cli(&tmp);
    let c_at = wide.fetch_base(&source.url(), &sha(&at)).expect("fetch");
    let c_over = wide.fetch_base(&source.url(), &sha(&over)).expect("fetch");
    assert_eq!(
        patch(&wide, &c_at, &c_over).changes,
        [change("over", None, file(EntryKind::File, b"x\n"))]
    );
}

/// An unknown handle on either side is `UnknownCheckout`, before any
/// process starts.
#[test]
fn patch_between_unknown_checkout() {
    let tmp = TempDir::new("patch-unknown");
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a\n", false);
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let unknown = CheckoutId::new("checkout-unknown".to_owned());
    assert_eq!(
        git.patch_between(&unknown, &c),
        Err(GitError::UnknownCheckout)
    );
    assert_eq!(
        git.patch_between(&c, &unknown),
        Err(GitError::UnknownCheckout)
    );
}

/// SHA-256 repositories: gitlink data is the 64-digit id.
#[test]
fn patch_between_sha256() {
    let tmp = TempDir::new("patch-sha256");
    let source = Source::new(&tmp, "src", true);
    source.write("a.ts", b"a\n", false);
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let id = "4".repeat(64);
    let diff = format!(
        "diff --git a/m b/m\nnew file mode 160000\nindex {z}..{id}\n--- /dev/null\n+++ b/m\n\
         @@ -0,0 +1 @@\n+Subproject commit {id}\n",
        z = "0".repeat(64)
    );
    let after = git.apply(&c, diff.as_bytes()).expect("apply");
    assert_eq!(
        patch(&git, &c, &after).changes,
        [change("m", None, file(EntryKind::Gitlink, id.as_bytes()))]
    );
}
