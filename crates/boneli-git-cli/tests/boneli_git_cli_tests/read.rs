//! `read` and unknown handles (ADR-010, D6).

use boneli_app::{CheckoutId, Git, GitError};

use crate::support::{Source, TempDir, cli, path, sha};

#[test]
fn read_entries() {
    let tmp = TempDir::new("read");
    let source = Source::new(&tmp, "src", false);
    source.write("README", b"readme", false);
    source.write("run.sh", b"#!/bin/sh\n", true);
    source.write("dir/inner", b"inner", false);
    source.write("*", b"star", false);
    source.write("a\nb", b"newline", false);
    source.link("link", "dir");
    source.gitlink("mod", "1234567890123456789012345678901234567890");
    let base = source.commit("base");
    let listed = crate::support::fgit(&source.dir, &["ls-tree", "HEAD", "mod"]);
    assert!(listed.starts_with("160000 commit "), "{listed}");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let read = |p: &str| git.read(&c, &path(p)).expect("read");
    assert_eq!(read("README"), Some(b"readme".to_vec()));
    assert_eq!(read("run.sh"), Some(b"#!/bin/sh\n".to_vec()));
    assert_eq!(read("dir/inner"), Some(b"inner".to_vec()));
    assert_eq!(read("a\nb"), Some(b"newline".to_vec()));
    // Literal, not a pathspec: `*` is the file named `*`.
    assert_eq!(read("*"), Some(b"star".to_vec()));
    for missing in [
        "missing",
        "dir",
        "link",
        "link/inner",
        "mod",
        ".git/config",
        ":(top)README",
        "READ*",
        "dir/",
        "di",
    ] {
        if let Ok(p) = boneli_app::RelativePath::parse(missing) {
            assert_eq!(git.read(&c, &p), Ok(None), "{missing:?}");
        }
    }
}

#[test]
fn unknown_checkout() {
    let tmp = TempDir::new("unknown");
    let git = cli(&tmp);
    let id = CheckoutId::new("checkout-999".to_owned());
    assert_eq!(git.read(&id, &path("a")), Err(GitError::UnknownCheckout));
    assert_eq!(git.snapshot(&id), Err(GitError::UnknownCheckout));
    assert_eq!(git.diff(&id, b""), Err(GitError::UnknownCheckout));
    assert_eq!(git.apply(&id, b""), Err(GitError::UnknownCheckout));
}
