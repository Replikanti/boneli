//! `TrustedRoot::from_json`: the public-good root reads as measured, and
//! every rule of the strict reader refuses a file that breaks it.

mod support;

use boneli_json::Value;
use boneli_sigstore::{ConfigError, MAX_TRUSTED_ROOT_BYTES, TrustedRoot, base64};
use support::pki::{self, EPOCH_2020, Pki, log_instance, remove, root_value, s, set, to_bytes};
use support::real;

fn read(value: &Value) -> Result<TrustedRoot, ConfigError> {
    TrustedRoot::from_json(&to_bytes(value))
}

#[test]
fn public_good_root_reads() {
    let root = TrustedRoot::from_json(real::TRUSTED_ROOT).expect("public-good root");
    // Rekor v1 only (log2025-1 is v2 and left out), both Fulcio CAs,
    // both CT logs.
    assert_eq!(
        (
            root.tlog_count(),
            root.authority_count(),
            root.ctlog_count()
        ),
        (1, 2, 2)
    );
}

#[test]
fn synthetic_root_reads() {
    let pki = Pki::new();
    let root = read(&root_value(&pki)).expect("root");
    assert_eq!(
        (
            root.tlog_count(),
            root.authority_count(),
            root.ctlog_count()
        ),
        (1, 1, 1)
    );
    // Empty lists may be omitted, as protobuf JSON does.
    let mut v = root_value(&pki);
    remove(&mut v, &["tlogs"]);
    remove(&mut v, &["ctlogs"]);
    remove(&mut v, &["certificateAuthorities"]);
    let root = read(&v).expect("empty root");
    assert_eq!(
        (
            root.tlog_count(),
            root.authority_count(),
            root.ctlog_count()
        ),
        (0, 0, 0)
    );
}

#[test]
fn duplicate_log_id_refused() {
    let pki = Pki::new();
    let twice = Value::Array(vec![
        log_instance(&pki.rekor_key, EPOCH_2020, None),
        log_instance(&pki.rekor_key, "2024-01-01T00:00:00Z", None),
    ]);
    let mut v = root_value(&pki);
    set(&mut v, &["tlogs"], twice);
    assert_eq!(read(&v).err(), Some(ConfigError::RootDuplicateLogId));
    // The same key as a Rekor and a CT log.
    let mut v = root_value(&pki);
    set(
        &mut v,
        &["ctlogs"],
        Value::Array(vec![log_instance(&pki.rekor_key, EPOCH_2020, None)]),
    );
    assert_eq!(read(&v).err(), Some(ConfigError::RootDuplicateLogId));
    // The same key once kept and once left out (a keyId that is not its
    // SHA-256), in either order.
    let mut left_out = log_instance(&pki.rekor_key, EPOCH_2020, None);
    set(
        &mut left_out,
        &["logId", "keyId"],
        s(&base64::encode(&pki.other_key.id())),
    );
    let kept = log_instance(&pki.rekor_key, EPOCH_2020, None);
    for pair in [
        vec![kept.clone(), left_out.clone()],
        vec![left_out.clone(), kept.clone()],
    ] {
        let mut v = root_value(&pki);
        set(&mut v, &["tlogs"], Value::Array(pair));
        assert_eq!(read(&v).err(), Some(ConfigError::RootDuplicateLogId));
    }
    // A left-out Rekor key that is also a CT log's.
    let mut v = root_value(&pki);
    let mut ct_as_v2 = log_instance(&pki.ct_key, EPOCH_2020, None);
    set(
        &mut ct_as_v2,
        &["logId", "keyId"],
        s(&base64::encode(&pki.other_key.id())),
    );
    set(&mut v, &["tlogs"], Value::Array(vec![kept, ct_as_v2]));
    assert_eq!(read(&v).err(), Some(ConfigError::RootDuplicateLogId));
    // The public-good root has no such duplicate and still reads.
    assert!(TrustedRoot::from_json(real::TRUSTED_ROOT).is_ok());
}

#[test]
fn reversed_window_refused() {
    let pki = Pki::new();
    for path in [&["tlogs"][..], &["ctlogs"][..]] {
        let mut v = root_value(&pki);
        let key = if path[0] == "tlogs" {
            &pki.rekor_key
        } else {
            &pki.ct_key
        };
        set(
            &mut v,
            path,
            Value::Array(vec![log_instance(
                key,
                "2024-01-01T00:00:01Z",
                Some("2024-01-01T00:00:00Z"),
            )]),
        );
        assert_eq!(
            read(&v).err(),
            Some(ConfigError::RootReversedWindow),
            "{path:?}"
        );
    }
    let mut v = root_value(&pki);
    set(
        &mut v,
        &["certificateAuthorities"],
        Value::Array(vec![pki::authority(
            &[&pki.intermediate, &pki.root],
            "2024-01-01T00:00:01Z",
            Some("2024-01-01T00:00:00Z"),
        )]),
    );
    assert_eq!(read(&v).err(), Some(ConfigError::RootReversedWindow));
    // A window of one instant is not reversed.
    let mut v = root_value(&pki);
    set(
        &mut v,
        &["tlogs"],
        Value::Array(vec![log_instance(
            &pki.rekor_key,
            "2024-01-01T00:00:00Z",
            Some("2024-01-01T00:00:00Z"),
        )]),
    );
    assert!(read(&v).is_ok());
}

#[test]
fn media_type_exact() {
    let pki = Pki::new();
    for media_type in [
        "application/vnd.dev.sigstore.trustedroot+json;version=0.2",
        "application/vnd.dev.sigstore.trustedroot+json; version=0.1",
        "application/vnd.dev.sigstore.trustedroot.v0.1+json",
        "APPLICATION/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "application/vnd.dev.sigstore.trustedroot+json;version=0.1 ",
    ] {
        let mut v = root_value(&pki);
        set(&mut v, &["mediaType"], s(media_type));
        assert_eq!(
            read(&v).err(),
            Some(ConfigError::RootMediaType),
            "{media_type}"
        );
    }
    let mut v = root_value(&pki);
    remove(&mut v, &["mediaType"]);
    assert_eq!(read(&v).err(), Some(ConfigError::RootMediaType));
}

#[test]
fn key_details_must_name_the_key() {
    let pki = Pki::new();
    for details in [
        "PKIX_ECDSA_P256_SHA_256",
        "PKIX_RSA_PKCS1V15_3072_SHA256",
        "PKIX_RSA_PSS_2048_SHA256",
        "pkix_rsa_pkcs1v15_2048_sha256",
        "",
    ] {
        let mut v = root_value(&pki);
        let mut log = log_instance(&pki.rekor_key, EPOCH_2020, None);
        set(&mut log, &["publicKey", "keyDetails"], s(details));
        set(&mut v, &["tlogs"], Value::Array(vec![log]));
        assert_eq!(
            read(&v).err(),
            Some(ConfigError::RootKeyDetails),
            "{details}"
        );
    }
    // The real P-256 logs pass with PKIX_ECDSA_P256_SHA_256.
    assert!(TrustedRoot::from_json(real::TRUSTED_ROOT).is_ok());
}

#[test]
fn hash_algorithm_and_keys() {
    let pki = Pki::new();
    let mut v = root_value(&pki);
    let mut log = log_instance(&pki.ct_key, EPOCH_2020, None);
    set(&mut log, &["hashAlgorithm"], s("SHA2_384"));
    set(&mut v, &["ctlogs"], Value::Array(vec![log]));
    assert_eq!(read(&v).err(), Some(ConfigError::RootHashAlgorithm));

    for raw in [s("AAAA"), s("not base64"), Value::Null] {
        let mut v = root_value(&pki);
        let mut log = log_instance(&pki.rekor_key, EPOCH_2020, None);
        set(&mut log, &["publicKey", "rawBytes"], raw);
        set(&mut v, &["tlogs"], Value::Array(vec![log]));
        assert_eq!(read(&v).err(), Some(ConfigError::RootKey));
    }
}

#[test]
fn log_ids_are_recomputed() {
    let pki = Pki::new();
    let other = base64::encode(&pki.other_key.id());
    // A CT log whose keyId is not its key's SHA-256 refuses the file.
    let mut v = root_value(&pki);
    let mut log = log_instance(&pki.ct_key, EPOCH_2020, None);
    set(&mut log, &["logId", "keyId"], s(&other));
    set(&mut v, &["ctlogs"], Value::Array(vec![log]));
    assert_eq!(read(&v).err(), Some(ConfigError::RootLogId));
    // A Rekor log with such a keyId (a v2 log) is left out.
    let mut v = root_value(&pki);
    let mut log = log_instance(&pki.rekor_key, EPOCH_2020, None);
    set(&mut log, &["logId", "keyId"], s(&other));
    set(&mut v, &["tlogs"], Value::Array(vec![log]));
    assert_eq!(read(&v).expect("root").tlog_count(), 0);
    // A keyId that is not 32 bytes refuses the file either way.
    for list in ["tlogs", "ctlogs"] {
        let mut v = root_value(&pki);
        let key = if list == "tlogs" {
            &pki.rekor_key
        } else {
            &pki.ct_key
        };
        let mut log = log_instance(key, EPOCH_2020, None);
        set(&mut log, &["logId", "keyId"], s("AAAA"));
        set(&mut v, &[list], Value::Array(vec![log]));
        assert_eq!(read(&v).err(), Some(ConfigError::RootLogId), "{list}");
    }
}

#[test]
fn authorities_and_times() {
    let pki = Pki::new();
    let mut v = root_value(&pki);
    set(
        &mut v,
        &["certificateAuthorities"],
        Value::Array(vec![pki::authority(&[], EPOCH_2020, None)]),
    );
    assert_eq!(read(&v).err(), Some(ConfigError::RootCertificate));
    let mut v = root_value(&pki);
    let mut ca = pki::authority(&[&pki.root], EPOCH_2020, None);
    set(
        &mut ca,
        &["certChain", "certificates"],
        Value::Array(vec![pki::obj(vec![("rawBytes", s(""))])]),
    );
    set(&mut v, &["certificateAuthorities"], Value::Array(vec![ca]));
    assert_eq!(read(&v).err(), Some(ConfigError::RootCertificate));

    for start in [
        "2020-01-01",
        "2020-01-01T00:00:00+00:00",
        "2020-02-30T00:00:00Z",
    ] {
        let mut v = root_value(&pki);
        set(
            &mut v,
            &["tlogs"],
            Value::Array(vec![log_instance(&pki.rekor_key, start, None)]),
        );
        assert_eq!(read(&v).err(), Some(ConfigError::RootTime), "{start}");
    }
    let mut v = root_value(&pki);
    let mut log = log_instance(&pki.rekor_key, EPOCH_2020, None);
    remove(&mut log, &["publicKey", "validFor", "start"]);
    set(&mut v, &["tlogs"], Value::Array(vec![log]));
    assert_eq!(read(&v).err(), Some(ConfigError::RootTime));
}

#[test]
fn size_and_shape() {
    let pki = Pki::new();
    let mut big = to_bytes(&root_value(&pki));
    big.resize(MAX_TRUSTED_ROOT_BYTES + 1, b' ');
    assert_eq!(
        TrustedRoot::from_json(&big).err(),
        Some(ConfigError::RootTooLarge)
    );
    // At the cap, trailing whitespace is still JSON.
    big.truncate(MAX_TRUSTED_ROOT_BYTES);
    assert!(TrustedRoot::from_json(&big).is_ok());
    assert_eq!(
        TrustedRoot::from_json(b"[]").err(),
        Some(ConfigError::RootMalformed)
    );
    assert_eq!(
        TrustedRoot::from_json(b"{").err(),
        Some(ConfigError::RootMalformed)
    );
    let mut v = root_value(&pki);
    set(&mut v, &["tlogs"], s("x"));
    assert_eq!(read(&v).err(), Some(ConfigError::RootMalformed));
}

#[test]
fn config_error_texts() {
    assert_eq!(
        ConfigError::RootLogId.to_string(),
        "a log ID is not the SHA-256 of its key"
    );
    assert_eq!(
        ConfigError::PrefixWithoutBoundary.to_string(),
        "a SAN prefix does not end in /"
    );
}

/// Timestamp authorities (ADR-038, D4): the public-good root lists one; a
/// chain needs a leaf and an anchor; the window reads as every other.
#[test]
fn root_tsa_and_note_logs() {
    let root = TrustedRoot::from_json(real::TRUSTED_ROOT).expect("public-good root");
    assert_eq!(root.tsa_count(), 1);
    assert_eq!(
        format!("{root:?}"),
        "TrustedRoot { tlogs: 1, authorities: 2, ctlogs: 2, tsas: 1 }"
    );
    let pki = Pki::new();
    let tsa = pki::Tsa::new(&pki);
    let with = |entry: Value| pki::with_tsas(root_value(&pki), vec![entry]);
    assert_eq!(read(&root_value(&pki)).map(|r| r.tsa_count()), Ok(0));
    assert_eq!(
        read(&with(tsa.authority(EPOCH_2020, None))).map(|r| r.tsa_count()),
        Ok(1)
    );
    // A three-certificate chain, as GitHub's TSAs have, reads too.
    let three = pki::authority(&[&tsa.leaf, &pki.intermediate, &pki.root], EPOCH_2020, None);
    assert_eq!(read(&with(three)).map(|r| r.tsa_count()), Ok(1));
    // None, an empty one.
    for chain in [vec![], vec![&[][..], &pki.root[..]]] {
        let entry = pki::authority(&chain, EPOCH_2020, None);
        assert_eq!(read(&with(entry)).err(), Some(ConfigError::RootCertificate));
    }
    // One certificate (a leaf alone, a CA alone) anchors no token: the
    // entry is skipped, not the file (review of PR #132, run 1). Its
    // window is still read strictly.
    for one in [&tsa.leaf, &pki.root] {
        let entry = pki::authority(&[one], EPOCH_2020, None);
        assert_eq!(read(&with(entry)).map(|r| r.tsa_count()), Ok(0));
        let mut no_start = pki::authority(&[one], EPOCH_2020, None);
        remove(&mut no_start, &["validFor", "start"]);
        assert_eq!(read(&with(no_start)).err(), Some(ConfigError::RootTime));
        let skipped_and_kept = pki::with_tsas(
            root_value(&pki),
            vec![
                pki::authority(&[one], EPOCH_2020, None),
                tsa.authority(EPOCH_2020, None),
            ],
        );
        assert_eq!(read(&skipped_and_kept).map(|r| r.tsa_count()), Ok(1));
    }
    // CAs only (an intermediate and the root) stay listed; no token
    // verifies through them (`tests/timestamp.rs`).
    let cas_only = pki::authority(&[&pki.intermediate, &pki.root], EPOCH_2020, None);
    assert_eq!(read(&with(cas_only)).map(|r| r.tsa_count()), Ok(1));
    let mut no_chain = tsa.authority(EPOCH_2020, None);
    remove(&mut no_chain, &["certChain"]);
    assert_eq!(
        read(&with(no_chain)).err(),
        Some(ConfigError::RootCertificate)
    );
    // The window.
    assert_eq!(
        read(&with(
            tsa.authority("2026-01-01T00:00:00Z", Some(EPOCH_2020))
        ))
        .err(),
        Some(ConfigError::RootReversedWindow)
    );
    let mut no_start = tsa.authority(EPOCH_2020, None);
    remove(&mut no_start, &["validFor", "start"]);
    assert_eq!(read(&with(no_start)).err(), Some(ConfigError::RootTime));
    let mut no_window = tsa.authority(EPOCH_2020, None);
    remove(&mut no_window, &["validFor"]);
    assert_eq!(read(&with(no_window)).err(), Some(ConfigError::RootTime));
    // Not a list.
    let mut v = root_value(&pki);
    set(&mut v, &["timestampAuthorities"], s("x"));
    assert_eq!(read(&v).err(), Some(ConfigError::RootMalformed));
}
