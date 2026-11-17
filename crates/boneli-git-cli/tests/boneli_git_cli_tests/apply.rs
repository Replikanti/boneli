//! `apply`: fail closed, all or nothing, and checkout ids (ADR-010, D6).

use boneli_app::{CheckoutId, Git};

use crate::support::{Source, TempDir, cli, edit, failed, listing, path, sha};

fn source(tmp: &TempDir) -> (Source, String) {
    let source = Source::new(tmp, "src", false);
    source.write("a", b"one\ntwo\nthree\n", false);
    source.write("b", b"alpha\nbeta\n", false);
    source.link("link", "dir");
    source.write("dir/x", b"x\n", false);
    let base = source.commit("base");
    (source, base)
}

#[test]
fn apply_empty_diff() {
    let tmp = TempDir::new("apply-empty");
    let (source, base) = source(&tmp);
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let after = git.apply(&c, b"").expect("apply");
    assert_ne!(after, c);
    assert_eq!(git.snapshot(&after), git.snapshot(&c));
}

/// A new file at `p`, in git's format.
fn adds(p: &str) -> Vec<u8> {
    format!(
        "diff --git a/{p} b/{p}\nnew file mode 100644\n--- /dev/null\n+++ b/{p}\n@@ -0,0 +1 @@\n+x\n"
    )
    .into_bytes()
}

#[test]
fn apply_refuses_hostile_diffs() {
    let tmp = TempDir::new("apply-hostile");
    let (source, base) = source(&tmp);
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let before = git.snapshot(&c).expect("snapshot");
    // The control: the same shape applies at a plain path.
    git.apply(&c, &adds("new/x"))
        .expect("a plain new file applies");
    for diff in [
        b"garbage\n".to_vec(),
        adds(".git/hooks/x"),
        adds("sub/.git/config"),
        adds(".GIT/config"),
        adds("../x"),
        adds("/etc/x"),
        adds("link/x"),
    ] {
        failed(git.apply(&c, &diff));
    }
    assert_eq!(git.snapshot(&c), Ok(before));
    assert_eq!(listing(&git.root().join("tmp")), Vec::<String>::new());
}

/// A diff that adds a path with a component that is `.git` on another file
/// system is refused, as `diff` and `snapshot` refuse one, also where git
/// itself accepts the name and also through a rename; no checkout is issued
/// (ADR-010, D6).
#[test]
fn apply_refuses_lookalikes() {
    let tmp = TempDir::new("apply-lookalike");
    let (source, base) = source(&tmp);
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let before = git.snapshot(&c).expect("snapshot");
    let renamed = |to: &str| {
        format!("diff --git a/b b/{to}\nsimilarity index 100%\nrename from b\nrename to {to}\n")
            .into_bytes()
    };
    for (p, diff) in [
        ("sub/.g\u{200B}it/x", adds("sub/.g\u{200B}it/x")),
        (".g\u{2060}it/config", adds(".g\u{2060}it/config")),
        ("sub/\u{00AD}.GIT", adds("sub/\u{00AD}.GIT")),
        ("dir/.g\u{200B}it", renamed("dir/.g\u{200B}it")),
    ] {
        let detail = failed(git.apply(&c, &diff));
        assert!(detail.contains(&format!("{p:?}")), "{p:?}: {detail}");
    }
    assert_eq!(git.snapshot(&c), Ok(before));
    assert_eq!(listing(&git.root().join("tmp")), Vec::<String>::new());
    // No id was spent on a refused diff.
    assert_eq!(
        git.apply(&c, &adds("new/x")),
        Ok(CheckoutId::new("checkout-2".to_owned()))
    );
}

/// A two-file diff whose second hunk does not apply changes nothing.
#[test]
fn apply_is_all_or_nothing() {
    let tmp = TempDir::new("apply-atomic");
    let (source, base) = source(&tmp);
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let before = git.snapshot(&c).expect("snapshot");
    let w = edit(&before, &path("a"), Some(b"one\nTWO\nthree\n"));
    let w = edit(&w, &path("b"), Some(b"alpha\nBETA\n"));
    let good = String::from_utf8(git.diff(&c, &w).expect("diff")).expect("utf8");
    // Break the second file's hunk: its context no longer matches.
    let broken = good.replacen(" alpha\n", " gamma\n", 1);
    assert_ne!(broken, good);
    failed(git.apply(&c, broken.as_bytes()));
    assert_eq!(git.snapshot(&c), Ok(before));
    let after = git
        .apply(&c, good.as_bytes())
        .expect("the good diff applies");
    assert_eq!(
        git.read(&after, &path("b")),
        Ok(Some(b"alpha\nBETA\n".to_vec()))
    );
}

#[test]
fn failed_apply_creates_no_checkout() {
    let tmp = TempDir::new("apply-ids");
    let (source, base) = source(&tmp);
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    assert_eq!(c, CheckoutId::new("checkout-1".to_owned()));
    let good = adds("new/x");
    assert_eq!(
        git.apply(&c, &good),
        Ok(CheckoutId::new("checkout-2".to_owned()))
    );
    failed(git.apply(&c, b"garbage\n"));
    assert_eq!(
        git.apply(&c, &good),
        Ok(CheckoutId::new("checkout-3".to_owned()))
    );
}

/// More than 1 MiB of diff, well over a 64 KiB pipe buffer, both ways.
#[test]
fn large_diff_applies() {
    let tmp = TempDir::new("apply-large");
    let (source, base) = source(&tmp);
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let snapshot = git.snapshot(&c).expect("snapshot");
    let big: Vec<u8> = (0..40_000)
        .flat_map(|k| format!("line {k} of a large generated file\n").into_bytes())
        .collect();
    assert!(big.len() > 1 << 20);
    let w = edit(&snapshot, &path("big.txt"), Some(&big));
    let diff = git.diff(&c, &w).expect("diff");
    assert!(diff.len() > 1 << 20, "{}", diff.len());
    let after = git.apply(&c, &diff).expect("apply");
    assert_eq!(git.read(&after, &path("big.txt")), Ok(Some(big)));
}
