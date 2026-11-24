//! The trusted root and its chain (TUF 5.2 and 5.3, ADR-033 items 2 to
//! 5): the envelope, thresholds over distinct keys, key entries, the
//! version rule, expiry and the fast-forward signal, on fixture roots
//! signed at test time and on Sigstore's real roots v3 to v16.

mod support;

use boneli_json::{ErrorKind, Value};
use boneli_tuf::{Error, MAX_ROOT_BYTES, TrustedSet};
use support::real;
use support::repo::{
    ED25519_PEM, FAR_SECS, P384_PEM, RSA_PEM, RootBuilder, START, at, envelope, key_entry, keyid,
    obj, p256_entry, pem, remove, s, set, signature, signature_as, signed_by,
};

const ROOT: Error = Error::BelowThreshold { role: "root" };

fn trusted(builder: &RootBuilder) -> TrustedSet {
    TrustedSet::new(&builder.bytes(), START).expect("trusted root")
}

/// A set at v1 with the default keys.
fn v1() -> TrustedSet {
    trusted(&RootBuilder::new(1))
}

// ---- Envelope ----

/// A second `signed` member, or a second `keyid` in one signature, is
/// refused by the parser; neither can smuggle a second reading.
#[test]
fn duplicate_member_refused() {
    let signed = RootBuilder::new(1).signed();
    let good = boneli_json::to_string(&signed).expect("serialize");
    let sig = boneli_json::to_string(&signature(1, &signed)).expect("serialize");
    let doubled = format!("{{\"signed\":{good},\"signed\":{good},\"signatures\":[{sig}]}}");
    assert_eq!(
        TrustedSet::new(doubled.as_bytes(), START).err(),
        Some(Error::Json(ErrorKind::DuplicateKey))
    );
    let twice = format!(
        "{{\"signed\":{good},\"signatures\":[{{\"keyid\":\"{}\",\"keyid\":\"{}\",\"sig\":\"00\"}}]}}",
        keyid(1),
        keyid(2)
    );
    assert_eq!(
        TrustedSet::new(twice.as_bytes(), START).err(),
        Some(Error::Json(ErrorKind::DuplicateKey))
    );
}

/// Members next to `signed` and `signatures` are not signed and not read:
/// adding or changing one changes nothing.
#[test]
fn unsigned_extra_member_ignored() {
    let builder = RootBuilder::new(1);
    let signed = builder.signed();
    let sigs: Vec<Value> = [1, 2, 3].iter().map(|n| signature(*n, &signed)).collect();
    for extra in [s("note"), Value::from(1i64), obj([("signed", obj([]))])] {
        let doc = obj([
            ("signatures", Value::Array(sigs.clone())),
            ("x-unsigned", extra),
            ("signed", signed.clone()),
        ]);
        let bytes = boneli_json::to_vec(&doc).expect("serialize");
        let set = TrustedSet::new(&bytes, START).expect("extra member ignored");
        assert_eq!(set.root().version(), 1);
    }
}

/// The envelope's shape: an object with a `signed` object and a
/// `signatures` array of `{keyid, sig}` strings.
#[test]
fn envelope_shape_refused() {
    let signed = RootBuilder::new(1).signed();
    let sig = signature(1, &signed);
    let cases = [
        Value::Array(vec![]),
        obj([("signatures", Value::Array(vec![sig.clone()]))]),
        obj([("signed", signed.clone())]),
        obj([("signed", s("x")), ("signatures", Value::Array(vec![]))]),
        obj([("signed", signed.clone()), ("signatures", obj([]))]),
        obj([
            ("signed", signed.clone()),
            ("signatures", Value::Array(vec![s("x")])),
        ]),
        obj([
            ("signed", signed.clone()),
            ("signatures", Value::Array(vec![obj([("keyid", s("a"))])])),
        ]),
        obj([
            ("signed", signed.clone()),
            (
                "signatures",
                Value::Array(vec![obj([("keyid", Value::from(1i64)), ("sig", s("00"))])]),
            ),
        ]),
    ];
    for (i, doc) in cases.iter().enumerate() {
        let bytes = boneli_json::to_vec(doc).expect("serialize");
        assert_eq!(
            TrustedSet::new(&bytes, START).err(),
            Some(Error::Envelope),
            "{i}"
        );
    }
}

/// The root cap is inclusive: a valid root padded with trailing
/// whitespace to exactly `MAX_ROOT_BYTES` loads, one byte more is refused
/// before parsing.
#[test]
fn metadata_cap_inclusive() {
    assert_eq!(MAX_ROOT_BYTES, 65_536);
    let mut bytes = RootBuilder::new(1).bytes();
    bytes.resize(MAX_ROOT_BYTES, b' ');
    assert!(TrustedSet::new(&bytes, START).is_ok(), "at the cap");
    bytes.push(b' ');
    assert_eq!(
        TrustedSet::new(&bytes, START).err(),
        Some(Error::TooLarge {
            cap: MAX_ROOT_BYTES
        })
    );
}

// ---- Thresholds ----

/// t = 3 of 5: two valid signatures refuse, three pass, for the trusted
/// root's own threshold and for a rotation.
#[test]
fn threshold_two_of_three_refused() {
    let b = RootBuilder::new(1);
    assert_eq!(
        TrustedSet::new(&b.signed_by(&[1, 2]), START).err(),
        Some(Error::BelowOwnThreshold)
    );
    let mut set = v1();
    assert_eq!(
        set.update_root(&RootBuilder::new(2).signed_by(&[4, 5])),
        Err(ROOT)
    );
    assert_eq!(set.root().version(), 1);
}

#[test]
fn threshold_three_passes() {
    for signers in [[1, 2, 3], [3, 4, 5], [5, 1, 3]] {
        assert!(TrustedSet::new(&RootBuilder::new(1).signed_by(&signers), START).is_ok());
        let mut set = v1();
        set.update_root(&RootBuilder::new(2).signed_by(&signers))
            .expect("three of five");
        assert_eq!(set.root().version(), 2);
    }
}

/// Three role entries where two key IDs carry one key count 2, so t = 3
/// refuses: the threshold counts distinct keys, not key IDs.
#[test]
fn same_key_two_keyids_counts_once() {
    let mut signed = RootBuilder::new(1).signed();
    let alias = "alias-of-key-1";
    set(at(&mut signed, &["keys"]), alias, p256_entry(1));
    set(
        at(&mut signed, &["roles", "root"]),
        "keyids",
        Value::Array(vec![s(&keyid(1)), s(alias), s(&keyid(2))]),
    );
    let sigs = vec![
        signature(1, &signed),
        signature_as(alias, 1, &signed),
        signature(2, &signed),
    ];
    let bytes = envelope(&signed, sigs.clone());
    assert_eq!(
        TrustedSet::new(&bytes, START).err(),
        Some(Error::BelowOwnThreshold)
    );
    // With t = 2 the two distinct keys pass.
    set(
        at(&mut signed, &["roles", "root"]),
        "threshold",
        Value::from(2i64),
    );
    let sigs: Vec<Value> = [1, 2].iter().map(|n| signature(*n, &signed)).collect();
    assert!(TrustedSet::new(&envelope(&signed, sigs), START).is_ok());
}

/// One key ID listed three times counts once; and only its first entry
/// is checked, so a valid signature after a bad one for the same key ID
/// does not count.
#[test]
fn repeated_signature_counts_once() {
    let signed = RootBuilder::new(1).signed();
    let one = signature(1, &signed);
    let sigs = vec![one.clone(), one.clone(), one, signature(2, &signed)];
    assert_eq!(
        TrustedSet::new(&envelope(&signed, sigs), START).err(),
        Some(Error::BelowOwnThreshold)
    );
    let bad = obj([("keyid", s(&keyid(3))), ("sig", s(""))]);
    let sigs = vec![
        signature(1, &signed),
        signature(2, &signed),
        bad,
        signature(3, &signed),
    ];
    assert_eq!(
        TrustedSet::new(&envelope(&signed, sigs), START).err(),
        Some(Error::BelowOwnThreshold)
    );
}

/// Signatures that do not decode or verify count zero without refusing
/// the document: empty (as in Sigstore's v12 to v14), odd-length or
/// non-hex text, another document's signature, a truncated one.
#[test]
fn bad_signatures_count_zero() {
    let signed = RootBuilder::new(1).signed();
    let other = RootBuilder::new(2).signed();
    let good = |n: usize| signature(n, &signed);
    let truncated = {
        let sig = good(3);
        let hex = sig.get("sig").and_then(Value::as_str).expect("sig");
        obj([("keyid", s(&keyid(3))), ("sig", s(&hex[..hex.len() - 2]))])
    };
    for third in [
        obj([("keyid", s(&keyid(3))), ("sig", s(""))]),
        obj([("keyid", s(&keyid(3))), ("sig", s("abc"))]),
        obj([("keyid", s(&keyid(3))), ("sig", s("zz"))]),
        signature(3, &other),
        truncated,
    ] {
        let sigs = vec![good(1), good(2), third.clone()];
        assert_eq!(
            TrustedSet::new(&envelope(&signed, sigs), START).err(),
            Some(Error::BelowOwnThreshold),
            "{third:?}"
        );
        let sigs = vec![third, good(1), good(4), good(2)];
        assert!(TrustedSet::new(&envelope(&signed, sigs), START).is_ok());
    }
    // Upper-case hex decodes too.
    let upper = {
        let sig = good(3);
        let hex = sig.get("sig").and_then(Value::as_str).expect("sig");
        obj([("keyid", s(&keyid(3))), ("sig", s(&hex.to_uppercase()))])
    };
    assert!(TrustedSet::new(&envelope(&signed, vec![good(1), good(2), upper]), START).is_ok());
}

/// Threshold 0 or below refuses the root as malformed.
#[test]
fn threshold_zero_refused() {
    for (role, field) in [
        ("root", "root"),
        ("timestamp", "timestamp"),
        ("snapshot", "snapshot"),
        ("targets", "targets"),
    ] {
        for threshold in [0i64, -1] {
            let mut signed = RootBuilder::new(1).signed();
            set(
                at(&mut signed, &["roles", field]),
                "threshold",
                Value::from(threshold),
            );
            assert_eq!(
                TrustedSet::new(&signed_by(&signed, &[1, 2, 3, 4, 5]), START).err(),
                Some(Error::InvalidThreshold { role }),
                "{role} {threshold}"
            );
        }
    }
}

/// Threshold 6 with 5 keys is well-formed and unreachable: it refuses as
/// unverified, not as malformed.
#[test]
fn threshold_above_keys_unreachable() {
    let mut b = RootBuilder::new(1);
    b.root.threshold = 6;
    assert_eq!(
        TrustedSet::new(&b.signed_by(&[1, 2, 3, 4, 5]), START).err(),
        Some(Error::BelowOwnThreshold)
    );
}

/// Role key IDs must be distinct and present in `keys`.
#[test]
fn role_keyids_checked() {
    let mut signed = RootBuilder::new(1).signed();
    set(
        at(&mut signed, &["roles", "targets"]),
        "keyids",
        Value::Array(vec![s(&keyid(1)), s(&keyid(2)), s(&keyid(1))]),
    );
    assert_eq!(
        TrustedSet::new(&signed_by(&signed, &[1, 2, 3]), START).err(),
        Some(Error::DuplicateKeyId { role: "targets" })
    );
    let mut signed = RootBuilder::new(1).signed();
    remove(at(&mut signed, &["keys"]), &keyid(6));
    assert_eq!(
        TrustedSet::new(&signed_by(&signed, &[1, 2, 3]), START).err(),
        Some(Error::UnknownKeyId { role: "timestamp" })
    );
}

// ---- Key entries ----

/// Ed25519, RSA and P-384 keys in the root role count zero and the
/// threshold of the others decides; so does a P-256 key under a key type
/// other than `ecdsa` or `ecdsa-sha2-nistp256`, even though its signature
/// is valid.
#[test]
fn unsupported_key_counts_zero() {
    let entries = [
        ("ed", key_entry("ed25519", "ed25519", ED25519_PEM)),
        ("rsa", key_entry("rsa", "rsassa-pss-sha256", RSA_PEM)),
        ("p384", key_entry("ecdsa", "ecdsa-sha2-nistp384", P384_PEM)),
        (
            "p384-as-256",
            key_entry("ecdsa", "ecdsa-sha2-nistp256", P384_PEM),
        ),
        (
            "relabelled",
            key_entry("rsa", "ecdsa-sha2-nistp256", &pem(3)),
        ),
        (
            "hex",
            key_entry("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256", "04ab"),
        ),
        ("not-an-object", s("key")),
    ];
    for (id, entry) in entries {
        let mut signed = RootBuilder::new(1).signed();
        set(at(&mut signed, &["keys"]), id, entry);
        set(
            at(&mut signed, &["roles", "root"]),
            "keyids",
            Value::Array(vec![s(&keyid(1)), s(&keyid(2)), s(id)]),
        );
        let sigs = vec![
            signature(1, &signed),
            signature(2, &signed),
            signature_as(id, 3, &signed),
        ];
        assert_eq!(
            TrustedSet::new(&envelope(&signed, sigs.clone()), START).err(),
            Some(Error::BelowOwnThreshold),
            "{id}"
        );
        set(
            at(&mut signed, &["roles", "root"]),
            "threshold",
            Value::from(2i64),
        );
        let sigs = vec![
            signature(1, &signed),
            signature(2, &signed),
            signature_as(id, 3, &signed),
        ];
        assert!(
            TrustedSet::new(&envelope(&signed, sigs), START).is_ok(),
            "{id}"
        );
    }
    // Both accepted key types count.
    for keytype in ["ecdsa", "ecdsa-sha2-nistp256"] {
        let mut signed = RootBuilder::new(1).signed();
        set(
            at(&mut signed, &["keys"]),
            &keyid(3),
            key_entry(keytype, "ecdsa-sha2-nistp256", &pem(3)),
        );
        assert!(
            TrustedSet::new(&signed_by(&signed, &[1, 2, 3]), START).is_ok(),
            "{keytype}"
        );
    }
}

/// A P-256 key under scheme `ecdsa-sha2-nistp384` counts zero.
#[test]
fn scheme_mismatch_counts_zero() {
    let mut signed = RootBuilder::new(1).signed();
    set(
        at(&mut signed, &["keys"]),
        &keyid(3),
        key_entry("ecdsa", "ecdsa-sha2-nistp384", &pem(3)),
    );
    assert_eq!(
        TrustedSet::new(&signed_by(&signed, &[1, 2, 3]), START).err(),
        Some(Error::BelowOwnThreshold)
    );
    assert!(TrustedSet::new(&signed_by(&signed, &[1, 2, 4]), START).is_ok());
}

/// A signature under a look-alike of a role key ID (Cyrillic `а`, a
/// zero-width space, upper case) is not counted, even when `keys` maps
/// the look-alike to the right key.
#[test]
fn lookalike_keyid_not_counted() {
    let real = keyid(3);
    let lookalikes = [
        format!("{}\u{430}", &real[..real.len() - 1]),
        format!("{real}\u{200B}"),
        real.to_uppercase(),
        format!(" {real}"),
    ];
    for fake in lookalikes {
        assert_ne!(fake, real);
        let mut signed = RootBuilder::new(1).signed();
        set(at(&mut signed, &["keys"]), &fake, p256_entry(3));
        let sigs = vec![
            signature(1, &signed),
            signature(2, &signed),
            signature_as(&fake, 3, &signed),
        ];
        assert_eq!(
            TrustedSet::new(&envelope(&signed, sigs), START).err(),
            Some(Error::BelowOwnThreshold),
            "{fake:?}"
        );
    }
}

// ---- Fields ----

/// `_type` compares byte-exact: a document of another role, or a near
/// spelling, is refused before any signature is checked.
#[test]
fn type_confusion_refused() {
    for type_ in ["timestamp", "Root", "root ", "snapshot", "targets", ""] {
        let mut b = RootBuilder::new(2);
        b.type_ = type_.to_string();
        let mut set = v1();
        assert_eq!(
            set.update_root(&b.bytes()),
            Err(Error::Type { expected: "root" }),
            "{type_:?}"
        );
        assert_eq!(set.root().version(), 1);
    }
}

/// `spec_version` is `1.<n>` or `1.<n>.<m>`.
#[test]
fn spec_version_rules() {
    for good in ["1.0", "1.0.31", "1.12", "1.0.0"] {
        let mut b = RootBuilder::new(1);
        b.spec_version = good.to_string();
        assert!(TrustedSet::new(&b.bytes(), START).is_ok(), "{good}");
    }
    for bad in [
        "2.0", "1", "1.", "1.0.", "1.0.0.0", "1.a", "01.0", "1.00", "v1.0", "1.0-rc1", "",
    ] {
        let mut b = RootBuilder::new(1);
        b.spec_version = bad.to_string();
        assert_eq!(
            TrustedSet::new(&b.bytes(), START).err(),
            Some(Error::SpecVersion),
            "{bad}"
        );
    }
}

/// `version` is an integer of at least 1; `consistent_snapshot` a
/// boolean; `keys` and `roles` objects; all four roles present.
#[test]
fn field_rules() {
    let cases: Vec<(&str, Value, &str)> = vec![
        ("version", Value::from(0i64), "version"),
        ("version", Value::from(-1i64), "version"),
        ("version", s("1"), "version"),
        ("consistent_snapshot", s("true"), "consistent_snapshot"),
        ("keys", Value::Array(vec![]), "keys"),
        ("roles", Value::Array(vec![]), "roles"),
        ("expires", Value::from(1i64), "expires"),
    ];
    for (member, value, field) in cases {
        let mut signed = RootBuilder::new(1).signed();
        set(&mut signed, member, value);
        assert_eq!(
            TrustedSet::new(&signed_by(&signed, &[1, 2, 3]), START).err(),
            Some(Error::Field(field)),
            "{member}"
        );
    }
    for member in [
        "version",
        "consistent_snapshot",
        "keys",
        "roles",
        "expires",
        "spec_version",
    ] {
        let mut signed = RootBuilder::new(1).signed();
        remove(&mut signed, member);
        assert!(
            TrustedSet::new(&signed_by(&signed, &[1, 2, 3]), START).is_err(),
            "{member}"
        );
    }
    for role in ["root", "timestamp", "snapshot", "targets"] {
        let mut signed = RootBuilder::new(1).signed();
        remove(at(&mut signed, &["roles"]), role);
        assert_eq!(
            TrustedSet::new(&signed_by(&signed, &[1, 2, 3]), START).err(),
            Some(Error::Field("roles")),
            "{role}"
        );
    }
}

/// `expires` is exactly `YYYY-MM-DDTHH:MM:SSZ`: no fraction, no offset,
/// upper-case `T` and `Z`, a real date, no leap second.
#[test]
fn expires_strict_format() {
    for bad in [
        "2030-01-01T00:00:00.5Z",
        "2030-01-01T00:00:00+00:00",
        "2030-01-01T00:00:00z",
        "2030-01-01t00:00:00Z",
        "2026-02-29T00:00:00Z",
        "2030-01-01T00:00:60Z",
        "2030-01-01 00:00:00Z",
        "2030-1-01T00:00:00Z",
        "1969-12-31T23:59:59Z",
        "",
    ] {
        let mut b = RootBuilder::new(1);
        b.expires = bad.to_string();
        assert_eq!(
            TrustedSet::new(&b.bytes(), START).err(),
            Some(Error::Expires),
            "{bad}"
        );
    }
    let mut b = RootBuilder::new(1);
    b.expires = "2028-02-29T23:59:59Z".to_string();
    assert_eq!(trusted(&b).root().expires(), 1_835_481_599);
}

// ---- The chain ----

/// The next root must be exactly N+1: a skip and a repeat are refused.
#[test]
fn root_version_skip_refused() {
    let mut set = v1();
    for version in [3, 1, 0] {
        let b = RootBuilder::new(version);
        let want = if version == 0 {
            Error::Field("version")
        } else {
            Error::NotNextVersion {
                expected: 2,
                found: version,
            }
        };
        assert_eq!(set.update_root(&b.bytes()), Err(want), "{version}");
        assert_eq!(set.root().version(), 1);
    }
    set.update_root(&RootBuilder::new(2).bytes()).expect("v2");
    assert_eq!(set.next_root_version(), Ok(3));
}

/// A rotation signed by only 2 of the old root's 3 needed is refused, and
/// the trusted root stays N, even when the new keys reach their own
/// threshold.
#[test]
fn rotation_below_threshold_refused() {
    let mut b = RootBuilder::new(2);
    b.root.keys = vec![3, 4, 5, 6, 7];
    let mut set = v1();
    // Old keys 1 to 5: 4 and 5 sign (2 of 3). New keys 3 to 7: 4, 5, 6, 7.
    assert_eq!(set.update_root(&b.signed_by(&[4, 5, 6, 7])), Err(ROOT));
    assert_eq!(set.root().version(), 1);
    // With 3 of the old keys it rotates.
    set.update_root(&b.signed_by(&[3, 4, 5])).expect("rotation");
    assert_eq!(set.root().version(), 2);
    // From now on the old keys 1 and 2 no longer count.
    let mut v3 = RootBuilder::new(3);
    v3.root.keys = vec![3, 4, 5, 6, 7];
    assert_eq!(set.update_root(&v3.signed_by(&[1, 2, 3])), Err(ROOT));
    set.update_root(&v3.signed_by(&[3, 6, 7]))
        .expect("new keys");
}

/// A root that the old keys sign but that does not reach its own
/// threshold is refused.
#[test]
fn rotation_without_self_threshold_refused() {
    let mut b = RootBuilder::new(2);
    b.root.keys = vec![1, 6, 7];
    b.root.threshold = 2;
    let mut set = v1();
    assert_eq!(
        set.update_root(&b.signed_by(&[1, 2, 3])),
        Err(Error::BelowOwnThreshold)
    );
    assert_eq!(set.root().version(), 1);
    set.update_root(&b.signed_by(&[1, 2, 3, 6]))
        .expect("both thresholds");
}

/// The expiry of intermediate roots is not checked (5.3.10 checks the
/// newest only).
#[test]
fn expired_intermediate_root_passes() {
    let mut set = v1();
    let mut v2 = RootBuilder::new(2);
    v2.expires = "2020-01-01T00:00:00Z".to_string();
    set.update_root(&v2.bytes()).expect("expired v2");
    set.update_root(&RootBuilder::new(3).bytes()).expect("v3");
    assert_eq!(set.check_root_expiry(), Ok(()));
}

/// The newest root must not be expired: expired when start >= expires.
#[test]
fn expired_final_root_refused() {
    let mut b = RootBuilder::new(1);
    b.expires = "2020-01-01T00:00:00Z".to_string();
    let set = trusted(&b);
    assert_eq!(
        set.check_root_expiry(),
        Err(Error::Expired { role: "root" })
    );
}

/// The bound is inclusive: one second before `expires` passes, `expires`
/// itself is expired.
#[test]
fn root_expiry_boundary_inclusive() {
    let bytes = RootBuilder::new(1).bytes();
    let before = TrustedSet::new(&bytes, FAR_SECS - 1).expect("root");
    assert_eq!(before.check_root_expiry(), Ok(()));
    let at = TrustedSet::new(&bytes, FAR_SECS).expect("root");
    assert_eq!(at.check_root_expiry(), Err(Error::Expired { role: "root" }));
    assert_eq!(at.start_secs(), FAR_SECS);
}

/// Version `i64::MAX` has no successor: the next version and every
/// update fail without reading the new bytes.
#[test]
fn root_version_overflow_refused() {
    let set = trusted(&RootBuilder::new(i64::MAX));
    assert_eq!(set.next_root_version(), Err(Error::NoNextVersion));
    let mut set = set;
    assert_eq!(set.update_root(b"not even JSON"), Err(Error::NoNextVersion));
    // One above i64::MAX is not a canonical integer.
    let mut signed = RootBuilder::new(1).signed();
    set_version_lexeme(&mut signed, "9223372036854775808");
    assert_eq!(
        TrustedSet::new(&envelope(&signed, vec![]), START).err(),
        Some(Error::NotCanonical)
    );
}

fn set_version_lexeme(signed: &mut Value, lexeme: &str) {
    let number = boneli_json::Number::from_lexeme(lexeme).expect("lexeme");
    set(signed, "version", Value::Number(number));
}

/// A forgery at v5 after valid v2 to v4 keeps v4, and the genuine v5
/// still passes afterwards.
#[test]
fn chain_failure_keeps_verified_prefix() {
    let mut set = v1();
    for version in 2..=4 {
        set.update_root(&RootBuilder::new(version).bytes())
            .expect("chain");
    }
    let mut forged = RootBuilder::new(5);
    forged.root.keys = vec![6, 7, 1];
    forged.root.threshold = 2;
    assert_eq!(set.update_root(&forged.signed_by(&[6, 7, 1])), Err(ROOT));
    assert_eq!(set.root().version(), 4);
    set.update_root(&RootBuilder::new(5).bytes())
        .expect("genuine v5");
    assert_eq!(set.root().version(), 5);
}

// ---- Fast-forward signal (5.3.11) ----

/// A new root that changes the key material or the threshold of
/// timestamp or snapshot sets the signal, and it stays set; root and
/// targets rotations do not set it.
#[test]
fn online_keys_changed_signal() {
    type Change = fn(&mut RootBuilder);
    let two_online: Change = |b| {
        b.timestamp.keys = vec![6, 7];
        b.snapshot.keys = vec![6, 7];
    };
    let cases: [(&str, Change, Change); 4] = [
        ("timestamp key", |_| {}, |b| b.timestamp.keys = vec![7]),
        ("snapshot key", |_| {}, |b| b.snapshot.keys = vec![7]),
        ("timestamp threshold", two_online, |b| {
            b.timestamp.keys = vec![6, 7];
            b.snapshot.keys = vec![6, 7];
            b.timestamp.threshold = 2;
        }),
        ("snapshot threshold", two_online, |b| {
            b.timestamp.keys = vec![6, 7];
            b.snapshot.keys = vec![6, 7];
            b.snapshot.threshold = 2;
        }),
    ];
    for (name, base, change) in cases {
        let mut v1 = RootBuilder::new(1);
        base(&mut v1);
        let mut trust = trusted(&v1);
        // A root that changes nothing online leaves the signal off.
        let mut v2 = RootBuilder::new(2);
        base(&mut v2);
        trust.update_root(&v2.bytes()).expect(name);
        assert!(!trust.online_keys_changed(), "{name}, unchanged");
        let mut v3 = RootBuilder::new(3);
        change(&mut v3);
        trust.update_root(&v3.bytes()).expect(name);
        assert!(trust.online_keys_changed(), "{name}");
        // Sticky: a later root that changes nothing keeps it.
        let mut v4 = RootBuilder::new(4);
        change(&mut v4);
        trust.update_root(&v4.bytes()).expect(name);
        assert!(trust.online_keys_changed(), "{name}, sticky");
    }
    // Same key ID, another key behind it.
    let mut trust = v1();
    let mut signed = RootBuilder::new(2).signed();
    set(at(&mut signed, &["keys"]), &keyid(6), p256_entry(7));
    trust
        .update_root(&signed_by(&signed, &[1, 2, 3]))
        .expect("v2");
    assert!(trust.online_keys_changed(), "key behind the same key ID");
    // Root and targets rotations do not touch it.
    let mut trust = v1();
    let mut v2 = RootBuilder::new(2);
    v2.root.keys = vec![3, 4, 5, 6, 7];
    v2.targets.keys = vec![1, 2, 7];
    v2.targets.threshold = 2;
    trust
        .update_root(&v2.signed_by(&[3, 4, 5]))
        .expect("rotation");
    assert!(!trust.online_keys_changed(), "root and targets only");
}

// ---- Sigstore's real roots ----

/// The real chain from v5 to v16 verifies: 11 rotations, each signed by
/// a threshold of its predecessor's keys and its own, and v16 is current
/// at the capture date. The timestamp key changed on the way.
#[test]
fn sigstore_chain_v5_to_v16_verifies() {
    let mut set = TrustedSet::new(real::root(5), real::START).expect("v5 pin");
    for version in 6..=16 {
        set.update_root(real::root(version))
            .unwrap_or_else(|e| panic!("v{version}: {e}"));
    }
    assert_eq!(set.root().version(), 16);
    assert!(set.root().consistent_snapshot());
    assert_eq!(set.check_root_expiry(), Ok(()));
    assert!(set.online_keys_changed());
    // Each of v5 to v16 is also a valid pin on its own.
    for version in 5..=16 {
        let set = TrustedSet::new(real::root(version), real::START)
            .unwrap_or_else(|e| panic!("v{version}: {e}"));
        assert_eq!(set.root().version(), version as i64);
    }
    // v15 expired on 2026-11-20, before the capture.
    let v15 = TrustedSet::new(real::root(15), real::START).expect("v15");
    assert_eq!(
        v15.check_root_expiry(),
        Err(Error::Expired { role: "root" })
    );
    // Skipping a version is refused on real data too.
    let mut set = TrustedSet::new(real::root(5), real::START).expect("v5 pin");
    assert_eq!(
        set.update_root(real::root(7)),
        Err(Error::NotNextVersion {
            expected: 6,
            found: 7
        })
    );
}

/// v4 carries hex keys, which count zero, so it cannot reach its own
/// threshold.
#[test]
fn sigstore_v4_pin_refused() {
    assert_eq!(
        TrustedSet::new(real::root(4), real::START).err(),
        Some(Error::BelowOwnThreshold)
    );
}

/// v3 has a fractional `expires`, which the strict reader refuses.
#[test]
fn sigstore_v3_pin_refused() {
    assert_eq!(
        TrustedSet::new(real::root(3), real::START).err(),
        Some(Error::Expires)
    );
}

/// One changed signed byte in a real root breaks its signatures.
#[test]
fn sigstore_root_tampered_refused() {
    let text = std::str::from_utf8(real::root(16)).expect("UTF-8");
    let tampered = text.replacen("2027-04-22T19:27:31Z", "2027-04-22T19:27:32Z", 1);
    assert_ne!(tampered, text);
    assert_eq!(
        TrustedSet::new(tampered.as_bytes(), real::START).err(),
        Some(Error::BelowOwnThreshold)
    );
    let mut set = TrustedSet::new(real::root(15), real::START).expect("v15");
    assert_eq!(set.update_root(tampered.as_bytes()), Err(ROOT));
}
