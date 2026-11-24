//! The signed envelope and the header every role shares (ADR-033, item
//! 4): parsed under the role's limits, with the canonical bytes of
//! `signed` computed once. Those bytes are what the signatures are
//! checked over, and every field read comes from the same parsed value,
//! so no second reading of the input can decide anything.

use boneli_json::{Limits, Object, Value};

use crate::canonical::{canonical, is_canonical_integer};
use crate::{
    Error, MAX_JSON_DEPTH, MAX_JSON_VALUES, MAX_ROOT_BYTES, MAX_SNAPSHOT_BYTES, MAX_TARGETS_BYTES,
    MAX_TIMESTAMP_BYTES, expires,
};

/// A top-level role: its name as `_type` and in `roles`, and its cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoleName {
    Root,
    Timestamp,
    Snapshot,
    Targets,
}

impl RoleName {
    /// The four, in the order a root lists them.
    pub(crate) const ALL: [RoleName; 4] = [
        RoleName::Root,
        RoleName::Timestamp,
        RoleName::Snapshot,
        RoleName::Targets,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            RoleName::Root => "root",
            RoleName::Timestamp => "timestamp",
            RoleName::Snapshot => "snapshot",
            RoleName::Targets => "targets",
        }
    }

    pub(crate) fn max_bytes(self) -> usize {
        match self {
            RoleName::Root => MAX_ROOT_BYTES,
            RoleName::Timestamp => MAX_TIMESTAMP_BYTES,
            RoleName::Snapshot => MAX_SNAPSHOT_BYTES,
            RoleName::Targets => MAX_TARGETS_BYTES,
        }
    }
}

/// One entry of `signatures`. `sig` is `None` when its text is not hex
/// (an empty one included): such a signature counts zero.
pub(crate) struct Signature {
    pub(crate) keyid: String,
    pub(crate) sig: Option<Vec<u8>>,
}

/// A parsed document of one role.
pub(crate) struct Envelope {
    /// The `signed` object.
    pub(crate) signed: Object,
    /// Its canonical bytes, which the signatures sign.
    pub(crate) canonical: Vec<u8>,
    pub(crate) signatures: Vec<Signature>,
    /// `version`, at least 1.
    pub(crate) version: i64,
    /// `expires`, in seconds since the Unix epoch.
    pub(crate) expires: u64,
}

/// Parses `bytes` as a document of `role`: the size cap first, then JSON
/// under `MAX_JSON_DEPTH` and `MAX_JSON_VALUES` (duplicate keys refused by
/// the parser), the envelope, the canonical form of `signed`, `_type`,
/// `spec_version`, `version` and `expires`. Other top-level members are
/// unsigned and not read; so are members of a signature object other than
/// `keyid` and `sig`.
pub(crate) fn parse(bytes: &[u8], role: RoleName) -> Result<Envelope, Error> {
    let cap = role.max_bytes();
    if bytes.len() > cap {
        return Err(Error::TooLarge { cap });
    }
    let limits =
        Limits::new(cap, MAX_JSON_DEPTH, MAX_JSON_VALUES).map_err(|e| Error::Json(e.kind()))?;
    let doc = boneli_json::parse(bytes, &limits).map_err(|e| Error::Json(e.kind()))?;
    let Value::Object(mut doc) = doc else {
        return Err(Error::Envelope);
    };
    let Some(Value::Object(signed)) = doc.remove("signed") else {
        return Err(Error::Envelope);
    };
    let Some(Value::Array(entries)) = doc.remove("signatures") else {
        return Err(Error::Envelope);
    };
    let mut signatures = Vec::with_capacity(entries.len());
    for entry in &entries {
        let keyid = entry.get("keyid").and_then(Value::as_str);
        let sig = entry.get("sig").and_then(Value::as_str);
        let (Some(keyid), Some(sig)) = (keyid, sig) else {
            return Err(Error::Envelope);
        };
        signatures.push(Signature {
            keyid: keyid.to_string(),
            sig: decode_hex(sig),
        });
    }
    let signed = Value::Object(signed);
    let canonical = canonical(&signed)?;
    let Value::Object(signed) = signed else {
        return Err(Error::Envelope);
    };
    if signed.get("_type").and_then(Value::as_str) != Some(role.name()) {
        return Err(Error::Type {
            expected: role.name(),
        });
    }
    let spec = signed
        .get("spec_version")
        .and_then(Value::as_str)
        .ok_or(Error::Field("spec_version"))?;
    if !spec_version_ok(spec) {
        return Err(Error::SpecVersion);
    }
    let version = integer(&signed, "version")?;
    if version < 1 {
        return Err(Error::Field("version"));
    }
    let expires = signed
        .get("expires")
        .and_then(Value::as_str)
        .ok_or(Error::Field("expires"))?;
    let expires = expires::parse(expires).ok_or(Error::Expires)?;
    Ok(Envelope {
        signed,
        canonical,
        signatures,
        version,
        expires,
    })
}

/// The integer member `name` of `o`. `signed` passed the canonical form,
/// so every number in it is a canonical integer within `i64`; the check
/// is repeated so that this holds for any caller.
pub(crate) fn integer(o: &Object, name: &'static str) -> Result<i64, Error> {
    match o.get(name) {
        Some(Value::Number(n)) if is_canonical_integer(n) => n.as_i64().ok_or(Error::Field(name)),
        _ => Err(Error::Field(name)),
    }
}

/// `1.<n>` or `1.<n>.<m>`, each number `0` or without a leading zero.
fn spec_version_ok(text: &str) -> bool {
    let mut parts = text.split('.');
    if parts.next() != Some("1") {
        return false;
    }
    let rest: Vec<&str> = parts.collect();
    (1..=2).contains(&rest.len())
        && rest.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

/// Hex of either case, or `None` (odd length, another character, empty).
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |b: u8| (b as char).to_digit(16);
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[hi, lo]| Some((nibble(*hi)? * 16 + nibble(*lo)?) as u8))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use boneli_json::ErrorKind;

    /// The error a document of `bytes` gets as `role`; `Envelope` means
    /// the JSON limits passed.
    fn error(bytes: &[u8], role: RoleName) -> Error {
        match parse(bytes, role) {
            Ok(_) => panic!("accepted"),
            Err(e) => e,
        }
    }

    /// Every role's byte cap is inclusive: `[]` padded to the cap passes
    /// the size and JSON checks (and fails as an envelope), one byte more
    /// is `TooLarge` before parsing.
    #[test]
    fn byte_caps_inclusive() {
        for role in RoleName::ALL {
            let cap = role.max_bytes();
            let mut bytes = b"[]".to_vec();
            bytes.resize(cap, b' ');
            assert_eq!(error(&bytes, role), Error::Envelope, "{role:?}");
            bytes.push(b' ');
            assert_eq!(error(&bytes, role), Error::TooLarge { cap }, "{role:?}");
        }
        assert_eq!(MAX_ROOT_BYTES, 65_536);
        assert_eq!(MAX_TIMESTAMP_BYTES, 16_384);
        assert_eq!(MAX_SNAPSHOT_BYTES, 1_048_576);
        assert_eq!(MAX_TARGETS_BYTES, 1_048_576);
    }

    /// Depth 16 parses, 17 does not.
    #[test]
    fn depth_limit_inclusive() {
        assert_eq!(MAX_JSON_DEPTH, 16);
        let nested = |depth: usize| {
            let mut s = "[".repeat(depth);
            s.push_str(&"]".repeat(depth));
            s.into_bytes()
        };
        assert_eq!(error(&nested(16), RoleName::Root), Error::Envelope);
        assert_eq!(
            error(&nested(17), RoleName::Root),
            Error::Json(ErrorKind::TooDeep)
        );
    }

    /// 65,536 values parse, 65,537 do not (an array counts itself).
    #[test]
    fn value_limit_inclusive() {
        assert_eq!(MAX_JSON_VALUES, 65_536);
        let zeros = |n: usize| {
            let mut s = String::from("[");
            s.push_str(&vec!["0"; n].join(","));
            s.push(']');
            s.into_bytes()
        };
        assert_eq!(error(&zeros(65_535), RoleName::Snapshot), Error::Envelope);
        assert_eq!(
            error(&zeros(65_536), RoleName::Snapshot),
            Error::Json(ErrorKind::TooManyValues)
        );
    }

    #[test]
    fn hex_forms() {
        assert_eq!(decode_hex("00ff"), Some(vec![0, 255]));
        assert_eq!(decode_hex("00FF"), Some(vec![0, 255]));
        assert_eq!(decode_hex(""), None);
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("0g"), None);
        assert_eq!(decode_hex("+1"), None);
        assert_eq!(decode_hex("é0"), None);
    }
}
