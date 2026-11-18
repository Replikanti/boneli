//! The evidence store (ADR-012, D2, D4 and D6).

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boneli_app::{Evidence, EvidenceError};
use boneli_domain::EvidenceRef;
use boneli_store_fs::FsStore;

use crate::support::{Fresh, TempDir, blob_path, names_in, sha256_hex};

/// A reference is `sha256:` and the SHA-256 of the content in lowercase
/// hex: the FIPS 180-4 known answers for `""` and `"abc"`, and the blob
/// sits under that name with mode `0o600`.
#[test]
fn reference_is_sha256_of_content() {
    let fresh = Fresh::new("ref-sha256");
    let empty = fresh.put(b"").expect("put");
    assert_eq!(
        empty.as_str(),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    let abc = fresh.put(b"abc").expect("put");
    assert_eq!(
        abc.as_str(),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let every_byte: Vec<u8> = (0..=u8::MAX).collect();
    let all = fresh.put(&every_byte).expect("put");
    assert_eq!(all.as_str(), format!("sha256:{}", sha256_hex(&every_byte)));
    let path = blob_path(fresh.store.root(), &abc);
    assert_eq!(std::fs::read(&path).expect("blob"), b"abc");
    let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600);
}

/// Content changed after `put`, to the same length, shorter, longer or
/// empty, is `Corrupted`.
#[test]
fn tampered_blob_is_corrupted() {
    let fresh = Fresh::new("tampered");
    let reference = fresh.put(b"genuine bytes").expect("put");
    let path = blob_path(fresh.store.root(), &reference);
    for replacement in [&b"GENUINE BYTES"[..], b"genuine", b"genuine bytes!", b""] {
        std::fs::write(&path, replacement).expect("tamper");
        assert_eq!(
            fresh.get(&reference),
            Err(EvidenceError::Corrupted),
            "{replacement:?}"
        );
    }
}

/// The next `put` of the genuine bytes rewrites a tampered blob, because
/// the bytes it writes hash to the name.
#[test]
fn put_repairs_a_tampered_blob() {
    let fresh = Fresh::new("repair");
    let reference = fresh.put(b"genuine bytes").expect("put");
    let path = blob_path(fresh.store.root(), &reference);
    std::fs::write(&path, b"GENUINE BYTES").expect("tamper");
    assert_eq!(fresh.get(&reference), Err(EvidenceError::Corrupted));
    assert_eq!(fresh.put(b"genuine bytes"), Ok(reference.clone()));
    assert_eq!(fresh.get(&reference).as_deref(), Ok(&b"genuine bytes"[..]));
    let leftovers: Vec<String> = names_in(path.parent().expect("dir"))
        .into_iter()
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// A `put` of bytes already stored syncs the blob and `evidence/sha256/`
/// before it returns the reference, so an earlier writer that died between
/// its rename and its directory sync cannot leave an acknowledged reference
/// to a blob that is not durable (ADR-012, D4). The directory is made
/// unreadable (`0o300`): the blob still opens and verifies through it, but
/// the directory cannot be opened for its `fsync`, so the dedup `put` must
/// fail. Root reads any directory, so the check does not apply there.
#[test]
fn dedup_put_syncs_the_existing_blob() {
    let fresh = Fresh::new("dedup-sync");
    let reference = fresh.put(b"stored once").expect("put");
    if std::fs::metadata("/proc/self").expect("self").uid() == 0 {
        println!("skipped: root reads an unreadable directory");
        return;
    }
    let dir = fresh.store.root().join("evidence").join("sha256");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o300)).expect("chmod");
    let dedup = fresh.put(b"stored once");
    let get = fresh.get(&reference);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    match dedup {
        Err(EvidenceError::Unavailable { detail }) => {
            assert!(detail.contains("sync the directory"), "{detail}")
        }
        other => panic!("a dedup put without a directory sync gave {other:?}"),
    }
    assert_eq!(get.as_deref(), Ok(&b"stored once"[..]), "the blob verifies");
    assert_eq!(fresh.put(b"stored once"), Ok(reference));
}

/// A blob replaced by a symlink (to the genuine bytes or to `/dev/zero`),
/// a directory or a FIFO is `Corrupted` and never opened: the FIFO would
/// block an open for reading, `/dev/zero` would never end. The whole check
/// must finish well inside 10 s.
#[test]
fn non_regular_blob_is_corrupted() {
    let fresh = Fresh::new("non-regular");
    let reference = fresh.put(b"genuine bytes").expect("put");
    let path = blob_path(fresh.store.root(), &reference);
    let elsewhere = fresh.store.root().join("genuine-copy");
    std::fs::write(&elsewhere, b"genuine bytes").expect("copy");
    let started = Instant::now();

    let replace = |make: &dyn Fn(&Path)| {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&path);
        make(&path);
        assert_eq!(fresh.get(&reference), Err(EvidenceError::Corrupted));
    };
    replace(&|p| std::os::unix::fs::symlink(&elsewhere, p).expect("symlink"));
    replace(&|p| std::os::unix::fs::symlink("/dev/zero", p).expect("symlink"));
    replace(&|p| std::fs::create_dir(p).expect("dir"));
    replace(&|p| {
        let status = Command::new("mkfifo").arg(p).status().expect("mkfifo");
        assert!(status.success(), "mkfifo failed");
    });
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
    // A put of the genuine bytes replaces the FIFO.
    assert_eq!(fresh.put(b"genuine bytes"), Ok(reference.clone()));
    assert_eq!(fresh.get(&reference).as_deref(), Ok(&b"genuine bytes"[..]));
}

/// Every reference the store does not issue is `InvalidReference`, decided
/// on the text alone: a file planted under an uppercase name is never
/// returned.
#[test]
fn malformed_references_are_invalid() {
    let fresh = Fresh::new("malformed-refs");
    let reference = fresh.put(b"victim").expect("put");
    let hex = reference
        .as_str()
        .strip_prefix("sha256:")
        .expect("prefix")
        .to_owned();
    let dir = fresh.store.root().join("evidence").join("sha256");
    std::fs::write(dir.join(hex.to_uppercase()), b"victim").expect("plant");
    let fullwidth: String = hex
        .chars()
        .map(|c| match c.to_digit(10) {
            Some(d) => char::from_u32(0xFF10 + d).expect("fullwidth digit"),
            None => c,
        })
        .collect();
    let candidates = [
        format!("sha256:{}", hex.to_uppercase()),
        format!("sha256:{}", &hex[..63]),
        format!("sha256:{hex}0"),
        format!("sha256-{hex}"),
        format!("SHA256:{hex}"),
        format!(" sha256:{hex}"),
        format!("sha256:{hex}\n"),
        format!("sha256:{}\u{200B}{}", &hex[..32], &hex[32..]),
        format!("sha256:{fullwidth}"),
        format!("fnv1a64-{}", &hex[..16]),
        format!("sha256:../{hex}"),
        format!("sha256:{}", &hex[..62]),
        hex.clone(),
        String::from("sha256:"),
    ];
    for text in candidates {
        let parsed = EvidenceRef::parse(&text).expect("not blank");
        assert_eq!(
            fresh.get(&parsed),
            Err(EvidenceError::InvalidReference),
            "{text:?}"
        );
    }
    assert_eq!(fresh.get(&reference).as_deref(), Ok(&b"victim"[..]));
}

/// Eight threads put the same 1 MiB: one reference, one blob, no temporary
/// file left.
#[test]
fn concurrent_puts_of_the_same_bytes() {
    let fresh = Arc::new(Fresh::new("concurrent-puts"));
    let content: Arc<Vec<u8>> = Arc::new((0..1 << 20).map(|k| (k % 251) as u8).collect());
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let fresh = Arc::clone(&fresh);
            let content = Arc::clone(&content);
            std::thread::spawn(move || fresh.put(&content))
        })
        .collect();
    let references: Vec<EvidenceRef> = threads
        .into_iter()
        .map(|t| t.join().expect("thread").expect("put"))
        .collect();
    assert!(
        references.windows(2).all(|w| w[0] == w[1]),
        "{references:?}"
    );
    let dir = fresh.store.root().join("evidence").join("sha256");
    assert_eq!(names_in(&dir), vec![sha256_hex(&content)]);
    assert_eq!(fresh.get(&references[0]).as_deref(), Ok(content.as_slice()));
}

/// A blob put before the store is dropped reads back after a reopen.
#[test]
fn blob_survives_reopen() {
    let tmp = TempDir::new("blob-reopen");
    let root = tmp.path().join("store");
    let reference = {
        let store = FsStore::open(&root).expect("open");
        store.put(b"kept across a restart").expect("put")
    };
    let store = FsStore::open(&root).expect("reopen");
    assert_eq!(
        store.get(&reference).as_deref(),
        Ok(&b"kept across a restart"[..])
    );
    let other = FsStore::open(&tmp.path().join("other")).expect("open");
    assert_eq!(other.get(&reference), Err(EvidenceError::NotFound));
}
