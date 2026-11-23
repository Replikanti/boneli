//! The CRL of an intermediate's issuer (ADR-027, item 4): a strict parser
//! of the `CertificateList` and the decision whose result decides.
//!
//! webpki does not take these lists: it refuses an issuingDistributionPoint
//! without a `distributionPoint`, the form every Let's Encrypt and GoDaddy
//! CA list has (D1). So nothing behind this module re-checks what it
//! accepts, and it is strict as `ocsp::response` is: definite minimal
//! lengths and no trailing bytes at any level (`der::Reader`), version 2,
//! a required `nextUpdate`, entry serials in minimal DER, and every
//! critical extension it does not understand refused. The signature is
//! checked over the raw `tbsCertList` bytes as they arrived, with the
//! handshake's algorithms and webpki's matching rule
//! (`signature::verified`). The list decides only for a certificate whose
//! issuer name it carries byte for byte, inside the scope of its
//! issuingDistributionPoint, read whether or not it is marked critical.

use rustls::pki_types::SignatureVerificationAlgorithm;

use super::der::{
    self, BIT_STRING, BOOLEAN, CONTEXT_0, CONTEXT_1, DerError, ENUMERATED, GENERALIZED_TIME,
    INTEGER, KeyUsage, OCTET_STRING, OID, Reader, SEQUENCE, UTC_TIME,
};
use super::signature;

#[cfg(test)]
pub(crate) mod testing;

/// id-ce-cRLNumber, 2.5.29.20.
const CRL_NUMBER: &[u8] = &[0x55, 0x1D, 0x14];
/// id-ce-cRLReasons, 2.5.29.21.
const REASON_CODE: &[u8] = &[0x55, 0x1D, 0x15];
/// id-ce-deltaCRLIndicator, 2.5.29.27.
const DELTA_CRL_INDICATOR: &[u8] = &[0x55, 0x1D, 0x1B];
/// id-ce-issuingDistributionPoint, 2.5.29.28.
const ISSUING_DISTRIBUTION_POINT: &[u8] = &[0x55, 0x1D, 0x1C];
/// id-ce-authorityKeyIdentifier, 2.5.29.35.
const AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1D, 0x23];

/// `uniformResourceIdentifier [6] IA5String`, implicitly tagged.
const URI: u8 = 0x86;
/// The implicitly tagged BOOLEANs and the BIT STRING of an
/// issuingDistributionPoint, `[1]` to `[5]`.
const ONLY_USER: u8 = 0x81;
const ONLY_CA: u8 = 0x82;
const ONLY_SOME_REASONS: u8 = 0x83;
const INDIRECT_CRL: u8 = 0x84;
const ONLY_ATTRIBUTE: u8 = 0x85;

/// The certificate a list is asked about: an intermediate on the
/// verified path.
pub(crate) struct Subject<'a> {
    /// Its issuer Name, the content of the SEQUENCE (webpki's
    /// `Cert::issuer()`).
    pub(crate) issuer: &'a [u8],
    /// Its serial, the content of the INTEGER (webpki's `Cert::serial()`).
    pub(crate) serial: &'a [u8],
    /// The URIs of its CRL distribution points as the certificate carries
    /// them (`der::distribution_point_uris`).
    pub(crate) points: &'a [&'a [u8]],
}

/// The key a list must be signed with: the subject's issuer on the path.
pub(crate) struct IssuerKey<'a> {
    /// Its whole `SubjectPublicKeyInfo`.
    pub(crate) spki: &'a [u8],
    /// Its keyUsage when the issuer is an intermediate that has one; `None`
    /// for an anchor, whose key usage is not checked, as webpki does not.
    pub(crate) key_usage: Option<KeyUsage>,
}

/// What one list says about one certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Good,
    Revoked,
    /// At or past its `nextUpdate`.
    Expired(String),
    /// A valid list that does not cover the certificate: another issuer, a
    /// scope or shard that leaves it out, an issuer that may not sign
    /// lists, a bad signature or an algorithm the handshake does not take.
    NotSettled(String),
    /// Not a list this parser accepts, or its dates are reversed.
    Malformed(String),
}

/// The issuingDistributionPoint of a list, in the forms accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Scope<'a> {
    /// The URIs of a `fullName`, when the extension names a point.
    names: Option<Vec<&'a [u8]>>,
    /// `onlyContainsUserCerts`: never authoritative for a CA.
    only_user: bool,
}

/// A list that parsed: what the decision reads.
pub(crate) struct Parsed<'a> {
    /// `tbsCertList`, whole: what the signature covers.
    tbs: &'a [u8],
    /// The content of the outer `signatureAlgorithm`.
    signature_algorithm: &'a [u8],
    signature: &'a [u8],
    /// The issuer Name, the content of the SEQUENCE.
    issuer: &'a [u8],
    pub(crate) this_update: u64,
    pub(crate) next_update: u64,
    /// The serial of every entry, the content of the INTEGER.
    serials: Vec<&'a [u8]>,
    scope: Option<Scope<'a>>,
}

/// The verdict of the list `der` on `subject`, signed by `issuer`'s key,
/// at `now` (Unix seconds), with `algorithms` (the handshake's).
pub(crate) fn decide(
    der: &[u8],
    subject: &Subject<'_>,
    issuer: &IssuerKey<'_>,
    algorithms: &[&dyn SignatureVerificationAlgorithm],
    now: u64,
) -> Verdict {
    match parse(der) {
        Ok(list) => list.decide(subject, issuer, algorithms, now),
        Err(e) => Verdict::Malformed(e.0.to_owned()),
    }
}

impl Parsed<'_> {
    /// The decision, in this order: the dates, the authority (issuer name,
    /// scope, point name), the issuer's right to sign lists, the
    /// signature, the entries.
    pub(crate) fn decide(
        &self,
        subject: &Subject<'_>,
        issuer: &IssuerKey<'_>,
        algorithms: &[&dyn SignatureVerificationAlgorithm],
        now: u64,
    ) -> Verdict {
        if self.next_update < self.this_update {
            return Verdict::Malformed("nextUpdate is before thisUpdate".into());
        }
        // Exclusive, as webpki's bound and ADR-017's. A `thisUpdate` in
        // the future is accepted, as webpki and ADR-020 accept one.
        if now >= self.next_update {
            return Verdict::Expired("the list is at or past its nextUpdate".into());
        }
        if self.issuer != subject.issuer {
            return Verdict::NotSettled("the list's issuer is not the certificate's".into());
        }
        if let Some(scope) = &self.scope {
            if scope.only_user {
                return Verdict::NotSettled("the list covers end-entity certificates only".into());
            }
            // webpki's rule: a named point must be one of the
            // certificate's, byte for byte. A list whose extension names
            // no point is authoritative within its scope (RFC 5280,
            // 5.2.5); this is the one difference from webpki.
            if let Some(names) = &scope.names
                && !names.iter().any(|name| subject.points.contains(name))
            {
                return Verdict::NotSettled(
                    "the list's distribution point is not one of the certificate's".into(),
                );
            }
        }
        if issuer.key_usage.is_some_and(|usage| !usage.crl_sign()) {
            return Verdict::NotSettled("the issuer's keyUsage lacks cRLSign".into());
        }
        if !signature::verified(
            issuer.spki,
            self.signature_algorithm,
            self.tbs,
            self.signature,
            algorithms,
        ) {
            return Verdict::NotSettled("the list's signature does not verify".into());
        }
        // Whatever the reasonCode: `removeFromCRL` belongs to delta lists,
        // which are refused, and a hold is a revocation while it is listed.
        if self.serials.contains(&subject.serial) {
            Verdict::Revoked
        } else {
            Verdict::Good
        }
    }
}

/// `CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm,
/// signatureValue BIT STRING }` (RFC 5280, 5.1).
pub(crate) fn parse(der: &[u8]) -> Result<Parsed<'_>, DerError> {
    let mut outer = Reader::new(der);
    let mut list = Reader::new(outer.expect(SEQUENCE)?);
    outer.finish()?;
    let tbs = list.expect_tlv(SEQUENCE)?;
    let signature_algorithm = list.expect(SEQUENCE)?;
    let signature = match list.expect(BIT_STRING)?.split_first() {
        Some((0, signature)) => signature,
        _ => return Err(DerError("a signature with unused bits")),
    };
    list.finish()?;

    // TBSCertList ::= SEQUENCE { version, signature, issuer, thisUpdate,
    // nextUpdate, revokedCertificates OPTIONAL, crlExtensions [0]
    // OPTIONAL }.
    let mut whole = Reader::new(tbs);
    let mut fields = Reader::new(whole.expect(SEQUENCE)?);
    whole.finish()?;
    // v2 (1) only: a v1 list cannot carry the extensions that scope it.
    if fields.optional(INTEGER)? != Some(&[1]) {
        return Err(DerError("not a version 2 list"));
    }
    // RFC 5280, 5.1.1.2: the same algorithm inside and outside.
    if fields.expect(SEQUENCE)? != signature_algorithm {
        return Err(DerError("the inner and outer signature algorithms differ"));
    }
    let issuer = fields.expect(SEQUENCE)?;
    let this_update = read_time(&mut fields)?;
    // RFC 5280, 5.1.2.5: conforming CAs include it; without it a list
    // would be valid forever.
    if !matches!(fields.peek(), Some(UTC_TIME | GENERALIZED_TIME)) {
        return Err(DerError("no nextUpdate"));
    }
    let next_update = read_time(&mut fields)?;
    let mut serials = Vec::new();
    if let Some(entries) = fields.optional(SEQUENCE)? {
        let mut entries = Reader::new(entries);
        while !entries.is_empty() {
            serials.push(entry(entries.expect(SEQUENCE)?)?);
        }
    }
    let mut scope = None;
    if let Some(extensions) = fields.optional(CONTEXT_0)? {
        let mut wrapper = Reader::new(extensions);
        let list = wrapper.expect(SEQUENCE)?;
        wrapper.finish()?;
        if list.is_empty() {
            return Err(DerError("an empty crlExtensions"));
        }
        each_extension(list, |oid, critical, value| match oid {
            DELTA_CRL_INDICATOR => Err(DerError("a delta list")),
            ISSUING_DISTRIBUTION_POINT => {
                scope = Some(issuing_distribution_point(value)?);
                Ok(())
            }
            AUTHORITY_KEY_IDENTIFIER | CRL_NUMBER => Ok(()),
            _ if critical => Err(DerError("an unknown critical list extension")),
            _ => Ok(()),
        })?;
    }
    fields.finish()?;
    Ok(Parsed {
        tbs,
        signature_algorithm,
        signature,
        issuer,
        this_update,
        next_update,
        serials,
        scope,
    })
}

fn read_time(reader: &mut Reader<'_>) -> Result<u64, DerError> {
    let (tag, value) = reader.read()?;
    der::time(tag, value)
}

/// One entry: `SEQUENCE { userCertificate, revocationDate,
/// crlEntryExtensions OPTIONAL }`; its serial. BR 7.2 compares serials
/// byte for byte, so a serial that is not minimal DER is refused rather
/// than matched loosely.
fn entry(entry: &[u8]) -> Result<&[u8], DerError> {
    let mut entry = Reader::new(entry);
    let serial = entry.expect(INTEGER)?;
    let minimal = match serial {
        [] => false,
        [0x00, next, ..] => next & 0x80 != 0,
        [0xFF, next, ..] => next & 0x80 == 0,
        _ => true,
    };
    if !minimal {
        return Err(DerError("an entry serial not in minimal DER"));
    }
    read_time(&mut entry)?; // revocationDate
    if let Some(extensions) = entry.optional(SEQUENCE)? {
        // CAs encode "no extensions" as an empty SEQUENCE too; webpki
        // accepts that, and so does this parser.
        each_extension(extensions, |oid, critical, value| match oid {
            REASON_CODE => {
                let mut reason = Reader::new(value);
                reason.expect(ENUMERATED)?;
                reason.finish()
            }
            _ if critical => Err(DerError("an unknown critical entry extension")),
            _ => Ok(()),
        })?;
    }
    entry.finish()?;
    Ok(serial)
}

/// Each `Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE,
/// extnValue OCTET STRING }` of `list` (the content of a SEQUENCE), in
/// order: its OID, whether it is critical and its value. An OID seen twice
/// is an error (RFC 5280, 4.2).
fn each_extension<'a>(
    list: &'a [u8],
    mut each: impl FnMut(&'a [u8], bool, &'a [u8]) -> Result<(), DerError>,
) -> Result<(), DerError> {
    let mut list = Reader::new(list);
    let mut seen: Vec<&[u8]> = Vec::new();
    while !list.is_empty() {
        let mut extension = Reader::new(list.expect(SEQUENCE)?);
        let oid = extension.expect(OID)?;
        let critical = match extension.optional(BOOLEAN)? {
            None | Some([0x00]) => false,
            Some([0xFF]) => true,
            Some(_) => return Err(DerError("a malformed critical flag")),
        };
        let value = extension.expect(OCTET_STRING)?;
        extension.finish()?;
        if seen.contains(&oid) {
            return Err(DerError("an extension seen twice"));
        }
        seen.push(oid);
        each(oid, critical, value)?;
    }
    Ok(())
}

/// `IssuingDistributionPoint ::= SEQUENCE { distributionPoint [0]
/// OPTIONAL, onlyContainsUserCerts [1], onlyContainsCACerts [2],
/// onlySomeReasons [3] OPTIONAL, indirectCRL [4],
/// onlyContainsAttributeCerts [5] }` (RFC 5280, 5.2.5). Forms that would
/// need a rule this client does not have are refused, so that no scope
/// is ever ignored: a name relative to the issuer, a reasons partition,
/// an indirect list, attribute certificates, and both `onlyContains*`
/// flags at once (BR 7.2.2.1 forbids it).
fn issuing_distribution_point(value: &[u8]) -> Result<Scope<'_>, DerError> {
    let mut outer = Reader::new(value);
    let mut point = Reader::new(outer.expect(SEQUENCE)?);
    outer.finish()?;
    let names = match point.optional(CONTEXT_0)? {
        Some(name) => {
            let mut name = Reader::new(name);
            let (tag, general_names) = name.read()?;
            name.finish()?;
            match tag {
                CONTEXT_0 => {}
                CONTEXT_1 => return Err(DerError("a name relative to the list's issuer")),
                _ => return Err(DerError("an unknown distribution point name")),
            }
            let mut general_names = Reader::new(general_names);
            let mut uris = Vec::new();
            if general_names.is_empty() {
                return Err(DerError("an empty fullName"));
            }
            while !general_names.is_empty() {
                let (tag, value) = general_names.read()?;
                if tag == URI {
                    uris.push(value);
                }
            }
            Some(uris)
        }
        None => None,
    };
    let only_user = flag(&mut point, ONLY_USER)?;
    let only_ca = flag(&mut point, ONLY_CA)?;
    if point.optional(ONLY_SOME_REASONS)?.is_some() {
        return Err(DerError("a reasons partition"));
    }
    if flag(&mut point, INDIRECT_CRL)? {
        return Err(DerError("an indirect list"));
    }
    if flag(&mut point, ONLY_ATTRIBUTE)? {
        return Err(DerError("a list of attribute certificates"));
    }
    point.finish()?;
    if only_user && only_ca {
        return Err(DerError("both onlyContains flags"));
    }
    Ok(Scope { names, only_user })
}

/// An implicitly tagged `BOOLEAN DEFAULT FALSE`.
fn flag(reader: &mut Reader<'_>, tag: u8) -> Result<bool, DerError> {
    match reader.optional(tag)? {
        None | Some([0x00]) => Ok(false),
        Some([0xFF]) => Ok(true),
        Some(_) => Err(DerError("a malformed flag")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;
    use std::time::Duration;

    use rustls::RootCertStore;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, UnixTime};

    use super::super::chain::{self, Path};
    use super::testing::{
        self, CA_KEY, CA1, CA1_NO_CRL_SIGN, CA2, DELTA_CRL_INDICATOR, ECDSA_SHA1, ECDSA_SHA256,
        FORGER_KEY, FRESHEST_CRL, IDP, INVALIDITY_DATE, ListSpec, REASON_CODE, ROOT, ROOT_KEY, T0,
        WEEK1_END, entry, ext, idp_value, reason, subject_name, uri,
    };

    const ROOT_EMPTY: &[u8] = include_bytes!("../../tests/data/chain-root-empty.crl");
    const ROOT_LISTS_CA1: &[u8] = include_bytes!("../../tests/data/chain-root-lists-ca1.crl");

    /// An hour into the default window.
    const NOW: u64 = T0 + 3_600;
    const CA1_SERIAL: &[u8] = &[0x11];

    fn algorithms() -> &'static [&'static dyn SignatureVerificationAlgorithm] {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .all
    }

    /// A fixture certificate as a list's subject and as an issuer.
    struct Fixture {
        der: Vec<u8>,
        issuer: Vec<u8>,
        serial: Vec<u8>,
        spki: Vec<u8>,
    }

    fn fixture(pem: &[u8]) -> Fixture {
        let der = testing::pem_der(pem);
        let cert = CertificateDer::from(der.clone());
        let parsed = webpki::EndEntityCert::try_from(&cert).expect("certificate");
        Fixture {
            issuer: parsed.issuer().to_vec(),
            serial: parsed.serial().to_vec(),
            spki: parsed.subject_public_key_info().as_ref().to_vec(),
            der,
        }
    }

    /// The verdict of `list` on `subject`, whose issuer is `issuer`: an
    /// anchor (`as_anchor`, no key usage read) or an intermediate.
    fn verdict_on(
        list: &[u8],
        subject: &[u8],
        issuer: &[u8],
        as_anchor: bool,
        now: u64,
    ) -> Verdict {
        let subject = fixture(subject);
        let issuer_fixture = fixture(issuer);
        let points = der::distribution_point_uris(&subject.der).expect("points");
        let key_usage = if as_anchor {
            None
        } else {
            der::key_usage(&issuer_fixture.der).expect("keyUsage")
        };
        decide(
            list,
            &Subject {
                issuer: &subject.issuer,
                serial: &subject.serial,
                points: &points,
            },
            &IssuerKey {
                spki: &issuer_fixture.spki,
                key_usage,
            },
            algorithms(),
            now,
        )
    }

    /// The root's list on CA 1.
    fn on_ca1(list: &[u8]) -> Verdict {
        verdict_on(list, CA1, ROOT, true, NOW)
    }

    fn on_ca1_at(list: &[u8], now: u64) -> Verdict {
        verdict_on(list, CA1, ROOT, true, now)
    }

    /// CA 1's list on CA 2.
    fn on_ca2(list: &[u8]) -> Verdict {
        verdict_on(list, CA2, CA1, false, NOW)
    }

    fn malformed(v: &Verdict) -> bool {
        matches!(v, Verdict::Malformed(_))
    }

    fn not_settled(v: &Verdict) -> bool {
        matches!(v, Verdict::NotSettled(_))
    }

    fn with_idp(critical: Option<u8>, value: Vec<u8>) -> ListSpec {
        ListSpec::root().with_extension(ext(IDP, critical, &value))
    }

    // -------------------------------------------------- the decision

    #[test]
    fn listed_and_unlisted() {
        assert_eq!(on_ca1(&ListSpec::root().build()), Verdict::Good);
        assert_eq!(
            on_ca1(&ListSpec::root().listing(&[CA1_SERIAL]).build()),
            Verdict::Revoked
        );
        assert_eq!(
            on_ca2(&ListSpec::ca1().listing(&[&[0x12]]).build()),
            Verdict::Revoked
        );
        assert_eq!(on_ca2(&ListSpec::ca1().build()), Verdict::Good);
    }

    #[test]
    fn list_of_another_issuer_does_not_settle() {
        // CA 1's list, valid and signed, asked about CA 1 itself.
        let v = on_ca1(&ListSpec::ca1().listing(&[CA1_SERIAL]).build());
        assert!(not_settled(&v), "{v:?}");
        // The root's list asked about CA 2.
        let v = on_ca2(&ListSpec::root().listing(&[&[0x12]]).build());
        assert!(not_settled(&v), "{v:?}");
        // Signed by the right key under another name: only the name
        // tells them apart.
        let renamed = ListSpec::new(subject_name(CA1), ROOT_KEY).listing(&[CA1_SERIAL]);
        let v = on_ca1(&renamed.build());
        assert!(not_settled(&v), "{v:?}");
        let renamed = ListSpec::new(subject_name(ROOT), CA_KEY).listing(&[&[0x12]]);
        let v = on_ca2(&renamed.build());
        assert!(not_settled(&v), "{v:?}");
    }

    #[test]
    fn forged_list_does_not_settle() {
        let forged = ListSpec {
            key: FORGER_KEY,
            ..ListSpec::root()
        };
        for list in [forged.clone(), forged.listing(&[CA1_SERIAL])] {
            let v = on_ca1(&list.build());
            assert!(not_settled(&v), "{v:?}");
        }
    }

    #[test]
    fn issuer_without_crl_sign_does_not_settle() {
        // The same key and name; only the issuer's keyUsage differs.
        let list = ListSpec::ca1().build();
        assert_eq!(verdict_on(&list, CA2, CA1, false, NOW), Verdict::Good);
        let v = verdict_on(&list, CA2, CA1_NO_CRL_SIGN, false, NOW);
        assert!(not_settled(&v), "{v:?}");
        // An anchor's key usage is not read.
        assert_eq!(
            verdict_on(&list, CA2, CA1_NO_CRL_SIGN, true, NOW),
            Verdict::Good
        );
    }

    #[test]
    fn nameless_ca_only_idp_settles() {
        // openssl's encoding (Let's Encrypt's and GoDaddy's form).
        assert_eq!(on_ca1(ROOT_LISTS_CA1), Verdict::Revoked);
        assert_eq!(on_ca1(ROOT_EMPTY), Verdict::Good);
        let only_ca = idp_value(None, &[(ONLY_CA, &[0xFF])]);
        assert_eq!(
            on_ca1(&with_idp(Some(0xFF), only_ca.clone()).build()),
            Verdict::Good
        );
        assert_eq!(
            on_ca1(&with_idp(Some(0xFF), only_ca).listing(&[CA1_SERIAL]).build()),
            Verdict::Revoked
        );
    }

    #[test]
    fn user_only_list_does_not_settle_a_ca() {
        let only_user = idp_value(None, &[(ONLY_USER, &[0xFF])]);
        let v = on_ca1(
            &with_idp(Some(0xFF), only_user)
                .listing(&[CA1_SERIAL])
                .build(),
        );
        assert!(not_settled(&v), "{v:?}");
    }

    #[test]
    fn noncritical_idp_scope_still_applies() {
        let only_user = idp_value(None, &[(ONLY_USER, &[0xFF])]);
        let v = on_ca1(&with_idp(None, only_user).build());
        assert!(not_settled(&v), "{v:?}");
        let other = idp_value(Some(&[uri("http://crl1.boneli.test/other.crl")]), &[]);
        let v = on_ca1(&with_idp(Some(0x00), other).build());
        assert!(not_settled(&v), "{v:?}");
    }

    #[test]
    fn idp_name_must_match_a_point_byte_for_byte() {
        let named =
            |names: &[Vec<u8>]| on_ca1(&with_idp(Some(0xFF), idp_value(Some(names), &[])).build());
        assert_eq!(
            named(&[uri("http://crl1.boneli.test/root.crl")]),
            Verdict::Good
        );
        // The second point, after a name that matches nothing.
        assert_eq!(
            named(&[
                uri("http://crl9.boneli.test/root.crl"),
                uri("http://crl2.boneli.test/root.crl")
            ]),
            Verdict::Good
        );
        for name in [
            "http://CRL1.boneli.test/root.crl",
            "http://crl1.boneli.test/root.crl/",
            "http://crl1.boneli.test:80/root.crl",
            "https://crl1.boneli.test/root.crl",
        ] {
            let v = named(&[uri(name)]);
            assert!(not_settled(&v), "{name}: {v:?}");
        }
        // A directoryName is not a URI.
        let directory = der::encode(0xA4, &der::encode(SEQUENCE, &[]));
        assert!(not_settled(&named(&[directory])));
    }

    #[test]
    fn unsupported_idp_forms_are_malformed() {
        let relative_value = der::encode(
            SEQUENCE,
            &der::encode(CONTEXT_0, &der::encode(CONTEXT_1, &der::encode(0x31, &[]))),
        );
        let empty_full_name = der::encode(
            SEQUENCE,
            &der::encode(CONTEXT_0, &der::encode(CONTEXT_0, &[])),
        );
        let forms: Vec<(&str, Vec<u8>)> = vec![
            ("nameRelativeToCRLIssuer", relative_value),
            ("empty fullName", empty_full_name),
            (
                "onlySomeReasons",
                idp_value(None, &[(ONLY_SOME_REASONS, &[0x07, 0x80])]),
            ),
            ("indirectCRL", idp_value(None, &[(INDIRECT_CRL, &[0xFF])])),
            (
                "onlyContainsAttributeCerts",
                idp_value(None, &[(ONLY_ATTRIBUTE, &[0xFF])]),
            ),
            (
                "both onlyContains flags",
                idp_value(None, &[(ONLY_USER, &[0xFF]), (ONLY_CA, &[0xFF])]),
            ),
            ("malformed flag", idp_value(None, &[(ONLY_CA, &[0x01])])),
            (
                "flags out of order",
                idp_value(None, &[(ONLY_CA, &[0xFF]), (ONLY_USER, &[0x00])]),
            ),
        ];
        for (what, value) in forms {
            for critical in [Some(0xFF), None] {
                let v = on_ca1(&with_idp(critical, value.clone()).build());
                assert!(malformed(&v), "{what}, {critical:?}: {v:?}");
            }
        }
    }

    #[test]
    fn entry_serials_must_be_minimal_der() {
        for serial in [&[0x00, 0x11][..], &[0xFF, 0x80], &[]] {
            let v = on_ca1(&ListSpec::root().listing(&[serial]).build());
            assert!(malformed(&v), "{serial:02X?}: {v:?}");
        }
        // Minimal forms of other serials settle CA 1 as good.
        for serial in [&[0x12][..], &[0x00, 0x80], &[0xFF, 0x7F], &[0x11, 0x00]] {
            assert_eq!(
                on_ca1(&ListSpec::root().listing(&[serial]).build()),
                Verdict::Good,
                "{serial:02X?}"
            );
        }
    }

    #[test]
    fn every_listing_revokes_regardless_of_reason() {
        // None, keyCompromise, superseded, certificateHold, removeFromCRL;
        // and an empty extension SEQUENCE.
        let mut lists = vec![ListSpec::root().listing(&[CA1_SERIAL])];
        for code in [1, 4, 6, 8] {
            let mut list = ListSpec::root();
            list.entries = Some(vec![entry(CA1_SERIAL, Some(vec![reason(code)]))]);
            lists.push(list);
        }
        let mut empty = ListSpec::root();
        empty.entries = Some(vec![entry(CA1_SERIAL, Some(vec![]))]);
        lists.push(empty);
        // Among other entries, last.
        lists.push(ListSpec::root().listing(&[&[0x01], &[0x02], CA1_SERIAL]));
        for (i, list) in lists.iter().enumerate() {
            assert_eq!(on_ca1(&list.build()), Verdict::Revoked, "{i}");
        }
    }

    #[test]
    fn critical_unknown_extensions_are_refused() {
        let flag_one = ext(FRESHEST_CRL, Some(0x01), &[0x30, 0x00]);
        let cases: Vec<(&str, ListSpec)> = vec![
            (
                "critical freshestCRL",
                ListSpec::root().with_extension(ext(FRESHEST_CRL, Some(0xFF), &[0x30, 0x00])),
            ),
            (
                "deltaCRLIndicator",
                ListSpec::root().with_extension(ext(
                    DELTA_CRL_INDICATOR,
                    None,
                    &der::encode(INTEGER, &[1]),
                )),
            ),
            (
                "duplicate cRLNumber",
                ListSpec::root().with_extension(ext(
                    testing::CRL_NUMBER,
                    None,
                    &der::encode(INTEGER, &[2]),
                )),
            ),
            (
                "malformed critical flag",
                ListSpec::root().with_extension(flag_one),
            ),
            (
                "empty crlExtensions",
                ListSpec {
                    extensions: Some(vec![]),
                    ..ListSpec::root()
                },
            ),
        ];
        for (what, list) in cases {
            let v = on_ca1(&list.build());
            assert!(malformed(&v), "{what}: {v:?}");
        }
        let entry_cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
            (
                "critical invalidityDate",
                vec![ext(INVALIDITY_DATE, Some(0xFF), &testing_time())],
            ),
            ("duplicate reasonCode", vec![reason(1), reason(4)]),
            (
                "malformed reasonCode",
                vec![ext(REASON_CODE, None, &der::encode(INTEGER, &[1]))],
            ),
        ];
        for (what, extensions) in entry_cases {
            let mut list = ListSpec::root();
            list.entries = Some(vec![entry(CA1_SERIAL, Some(extensions))]);
            let v = on_ca1(&list.build());
            assert!(malformed(&v), "{what}: {v:?}");
        }
        // Unknown non-critical ones are ignored; a critical reasonCode is
        // understood.
        let list = ListSpec::root().with_extension(ext(FRESHEST_CRL, None, &[0x30, 0x00]));
        assert_eq!(on_ca1(&list.build()), Verdict::Good);
        let mut list = ListSpec::root();
        list.entries = Some(vec![entry(
            CA1_SERIAL,
            Some(vec![
                ext(INVALIDITY_DATE, None, &testing_time()),
                ext(REASON_CODE, Some(0xFF), &der::encode(ENUMERATED, &[1])),
            ]),
        )]);
        assert_eq!(on_ca1(&list.build()), Verdict::Revoked);
    }

    fn testing_time() -> Vec<u8> {
        super::super::ocsp::testing::gtime(T0)
    }

    #[test]
    fn structural_violations_are_malformed() {
        let good = ListSpec::root();
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "version 1",
                ListSpec {
                    version: None,
                    ..good.clone()
                }
                .build(),
            ),
            (
                "version 0",
                ListSpec {
                    version: Some(der::encode(INTEGER, &[0])),
                    ..good.clone()
                }
                .build(),
            ),
            (
                "version 3",
                ListSpec {
                    version: Some(der::encode(INTEGER, &[2])),
                    ..good.clone()
                }
                .build(),
            ),
            (
                "inner algorithm differs",
                ListSpec {
                    inner_algorithm: ECDSA_SHA1.to_vec(),
                    ..good.clone()
                }
                .build(),
            ),
            (
                "unused signature bits",
                ListSpec {
                    unused_bits: 1,
                    ..good.clone()
                }
                .build(),
            ),
            (
                "no nextUpdate",
                ListSpec {
                    next_update: None,
                    ..good.clone()
                }
                .build(),
            ),
            (
                "no nextUpdate, entries next",
                ListSpec {
                    next_update: None,
                    ..good.clone().listing(&[&[0x01]])
                }
                .build(),
            ),
            ("empty body", Vec::new()),
        ];
        let der = good.build();
        let mut trailing = der.clone();
        trailing.push(0);
        cases.push(("trailing byte", trailing));
        let pem = format!(
            "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----\n",
            der.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        cases.push(("PEM", pem.into_bytes()));
        // A byte inside tbsCertList, after its last field.
        let tbs = super::super::ocsp::testing::append_inside(&good.tbs(), &[0x05, 0x00]);
        cases.push((
            "trailing field in tbsCertList",
            good.assemble(&tbs, &testing::sign(ROOT_KEY, &tbs)),
        ));
        for (what, bytes) in cases {
            let v = on_ca1(&bytes);
            assert!(malformed(&v), "{what}: {v:?}");
        }
    }

    #[test]
    fn sha1_signed_list_never_settles() {
        // Claimed SHA-1 inside and out: no handshake algorithm has the id,
        // so whatever the signature bytes are, it never verifies.
        let list = ListSpec {
            inner_algorithm: ECDSA_SHA1.to_vec(),
            outer_algorithm: ECDSA_SHA1.to_vec(),
            ..ListSpec::root()
        };
        for list in [list.clone(), list.listing(&[CA1_SERIAL])] {
            let v = on_ca1(&list.build());
            assert!(not_settled(&v), "{v:?}");
        }
        // The control: the same list under SHA-256 settles.
        assert_eq!(ECDSA_SHA256, ListSpec::root().outer_algorithm.as_slice());
    }

    #[test]
    fn empty_revoked_list_forms() {
        let absent = ListSpec::root();
        let empty = ListSpec {
            entries: Some(vec![]),
            ..ListSpec::root()
        };
        for list in [absent, empty] {
            let der = list.build();
            assert!(parse(&der).expect("parses").serials.is_empty());
            assert_eq!(on_ca1(&der), Verdict::Good);
        }
    }

    #[test]
    fn ca_list_next_update_is_exclusive() {
        let list = ListSpec::root().build();
        assert_eq!(on_ca1_at(&list, WEEK1_END - 1), Verdict::Good);
        assert!(matches!(on_ca1_at(&list, WEEK1_END), Verdict::Expired(_)));
        assert!(matches!(
            on_ca1_at(&list, WEEK1_END + 1),
            Verdict::Expired(_)
        ));
        // Expired comes first, even before a revocation.
        let revoking = ListSpec::root().listing(&[CA1_SERIAL]).build();
        assert!(matches!(
            on_ca1_at(&revoking, WEEK1_END),
            Verdict::Expired(_)
        ));
    }

    #[test]
    fn ca_list_dates() {
        // Reversed: Malformed, whatever the time.
        let reversed = ListSpec::window(subject_name(ROOT), ROOT_KEY, T0 + 10, T0).build();
        for now in [T0 - 1, T0 + 5, T0 + 20] {
            assert!(malformed(&on_ca1_at(&reversed, now)), "{now}");
        }
        // A thisUpdate in the future is accepted.
        let list = ListSpec::root().build();
        assert_eq!(on_ca1_at(&list, T0 - 86_400), Verdict::Good);
        // Equal dates: expired from that second on.
        let zero = ListSpec::window(subject_name(ROOT), ROOT_KEY, T0, T0).build();
        assert!(matches!(on_ca1_at(&zero, T0), Verdict::Expired(_)));
        // openssl's UTCTime and GeneralizedTime.
        let parsed = parse(ROOT_EMPTY).expect("openssl list");
        assert_eq!(
            (parsed.this_update, parsed.next_update),
            (T0, 4_922_899_200)
        );
    }

    /// The fixture lists and real captures every sweep below runs over.
    fn sweep_lists() -> Vec<Vec<u8>> {
        let mut lists = vec![
            ListSpec::root().build(),
            ListSpec::root()
                .listing(&[CA1_SERIAL, &[0x00, 0x80]])
                .build(),
            with_idp(Some(0xFF), idp_value(None, &[(ONLY_CA, &[0xFF])]))
                .listing(&[CA1_SERIAL])
                .build(),
            ROOT_EMPTY.to_vec(),
            ROOT_LISTS_CA1.to_vec(),
        ];
        lists.extend(CAPTURES.iter().map(|(_, der, _)| der.to_vec()));
        lists
    }

    #[test]
    fn every_truncation_and_flip_is_refused_or_unchanged() {
        for (i, list) in sweep_lists().iter().enumerate() {
            let whole = on_ca1(list);
            for len in 0..list.len() {
                let v = on_ca1(&list[..len]);
                assert!(malformed(&v), "list {i}, prefix of {len}: {v:?}");
            }
            let tbs_end = parse(list).expect("parses").tbs.len() + {
                // The outer SEQUENCE's tag and length.
                let mut r = Reader::new(list);
                let (_, content) = r.read().expect("outer");
                list.len() - content.len()
            };
            for at in 0..list.len() {
                for mask in [0x01u8, 0x80, 0xFF] {
                    let mut flipped = list.clone();
                    flipped[at] ^= mask;
                    let v = on_ca1(&flipped);
                    let refused = matches!(
                        v,
                        Verdict::Malformed(_) | Verdict::NotSettled(_) | Verdict::Expired(_)
                    );
                    assert!(
                        refused || v == whole,
                        "list {i}, byte {at} ^ {mask:#x}: {v:?}"
                    );
                    if at < tbs_end && whole != Verdict::Revoked {
                        assert_ne!(v, Verdict::Good, "list {i}, byte {at} ^ {mask:#x}");
                    }
                }
            }
        }
    }

    // --------------------------------------------------- real captures

    /// Captured on 2026-11-20 at 23:18 UTC (`tests/data/README.md`).
    const CAPTURED: u64 = 1_795_216_692;

    /// Every distinct measured CA list and its entry count by `openssl crl
    /// -text`.
    const CAPTURES: [(&str, &[u8], usize); 16] = [
        (
            "amazon-root-ca1",
            include_bytes!("../../tests/data/capture-crl-amazon-root-ca1.crl"),
            10,
        ),
        (
            "amazon-root-ca3",
            include_bytes!("../../tests/data/capture-crl-amazon-root-ca3.crl"),
            9,
        ),
        (
            "digicert-global-root-g2",
            include_bytes!("../../tests/data/capture-crl-digicert-global-root-g2.crl"),
            33,
        ),
        (
            "globalsign-root-r3",
            include_bytes!("../../tests/data/capture-crl-globalsign-root-r3.crl"),
            36,
        ),
        (
            "globalsign-root-r46",
            include_bytes!("../../tests/data/capture-crl-globalsign-root-r46.crl"),
            6,
        ),
        (
            "godaddy-root-g2",
            include_bytes!("../../tests/data/capture-crl-godaddy-root-g2.crl"),
            1,
        ),
        (
            "godaddy-tls-root-r1",
            include_bytes!("../../tests/data/capture-crl-godaddy-tls-root-r1.crl"),
            0,
        ),
        (
            "gts-r4",
            include_bytes!("../../tests/data/capture-crl-gts-r4.crl"),
            5,
        ),
        (
            "lencr-x1",
            include_bytes!("../../tests/data/capture-crl-lencr-x1.crl"),
            2,
        ),
        (
            "lencr-x2",
            include_bytes!("../../tests/data/capture-crl-lencr-x2.crl"),
            1,
        ),
        (
            "lencr-ye",
            include_bytes!("../../tests/data/capture-crl-lencr-ye.crl"),
            0,
        ),
        (
            "lencr-yr",
            include_bytes!("../../tests/data/capture-crl-lencr-yr.crl"),
            0,
        ),
        (
            "microsoft-rsa-root-g2",
            include_bytes!("../../tests/data/capture-crl-microsoft-rsa-root-g2.crl"),
            5,
        ),
        (
            "sectigo-root-e46",
            include_bytes!("../../tests/data/capture-crl-sectigo-root-e46.crl"),
            1,
        ),
        (
            "sectigo-root-r46",
            include_bytes!("../../tests/data/capture-crl-sectigo-root-r46.crl"),
            1,
        ),
        (
            "sslcom-tls-rsa-root-2022",
            include_bytes!("../../tests/data/capture-crl-sslcom-tls-rsa-root-2022.crl"),
            0,
        ),
    ];

    /// The captures whose issuingDistributionPoint names no point:
    /// webpki refuses them (D1).
    const NAMELESS_IDP: [&str; 6] = [
        "godaddy-root-g2",
        "godaddy-tls-root-r1",
        "lencr-x1",
        "lencr-x2",
        "lencr-ye",
        "lencr-yr",
    ];

    fn capture(name: &str) -> &'static [u8] {
        CAPTURES
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, der, _)| *der)
            .expect("capture")
    }

    fn time(secs: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(secs))
    }

    fn mozilla() -> RootCertStore {
        RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        }
    }

    /// The verified path of a captured chain (leaf first) at `CAPTURED`.
    fn path_of(pems: &[&[u8]]) -> Path {
        let certs: Vec<CertificateDer<'static>> = pems
            .iter()
            .flat_map(|pem| CertificateDer::pem_slice_iter(pem))
            .collect::<Result<_, _>>()
            .expect("PEM");
        chain::verified_path(
            &mozilla(),
            algorithms(),
            &certs[0],
            &certs[1..],
            time(CAPTURED),
        )
        .expect("path")
    }

    const ISRG_CHAIN: &[u8] = include_bytes!("../../tests/data/capture-isrgrootx1-chain.pem");
    const MICROSOFT_CHAIN: &[u8] = include_bytes!("../../tests/data/capture-microsoft-chain.pem");
    const E36_CHAIN: &[u8] = include_bytes!("../../tests/data/capture-e36-chain.pem");
    const R36_CHAIN: &[u8] = include_bytes!("../../tests/data/capture-r36-chain.pem");
    const ROOT_YR_SUPERSEDED: &[u8] =
        include_bytes!("../../tests/data/capture-root-yr-superseded.pem");

    #[test]
    fn captures_parse_with_their_entry_counts() {
        for (name, der, entries) in CAPTURES {
            let parsed = parse(der).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(parsed.serials.len(), entries, "{name}");
            assert!(
                parsed.this_update < CAPTURED && CAPTURED < parsed.next_update,
                "{name}"
            );
        }
    }

    #[test]
    fn real_chains_settle_at_capture_time() {
        // Path, then each intermediate's list, the leaf's issuer first.
        let cases: [(&str, &[u8], &[&str]); 4] = [
            ("valid-isrgrootx1", ISRG_CHAIN, &["lencr-yr", "lencr-x1"]),
            (
                "www.microsoft.com",
                MICROSOFT_CHAIN,
                &["microsoft-rsa-root-g2", "digicert-global-root-g2"],
            ),
            ("github.com", E36_CHAIN, &["sectigo-root-e46"]),
            ("gitlab.com", R36_CHAIN, &["sectigo-root-r46"]),
        ];
        for (host, chain, lists) in cases {
            let path = path_of(&[chain]);
            assert_eq!(path.links.len(), lists.len(), "{host}");
            for (link, list) in path.links.iter().zip(lists) {
                let der = capture(list);
                assert_eq!(
                    link.verdict(der, algorithms(), CAPTURED),
                    Verdict::Good,
                    "{host}: {list}"
                );
                let next = parse(der).expect("list").next_update;
                assert_eq!(
                    link.verdict(der, algorithms(), next - 1),
                    Verdict::Good,
                    "{host}: {list}"
                );
                assert!(
                    matches!(link.verdict(der, algorithms(), next), Verdict::Expired(_)),
                    "{host}: {list}"
                );
            }
            // A list of the other links' issuers does not settle them.
            if let [first, second] = path.links.as_slice() {
                assert!(not_settled(&first.verdict(
                    capture(lists[1]),
                    algorithms(),
                    CAPTURED
                )));
                assert!(not_settled(&second.verdict(
                    capture(lists[0]),
                    algorithms(),
                    CAPTURED
                )));
            }
        }
    }

    #[test]
    fn real_revoked_root_yr_cross_sign_is_revoked() {
        // Valid-isrgrootx1's leaf and YR issuer, with the superseded
        // Root YR cross-sign in place of the current one.
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(ISRG_CHAIN)
            .collect::<Result<_, _>>()
            .expect("PEM");
        let superseded = CertificateDer::from_pem_slice(ROOT_YR_SUPERSEDED).expect("PEM");
        let path = chain::verified_path(
            &mozilla(),
            algorithms(),
            &certs[0],
            &[certs[1].clone(), superseded],
            time(CAPTURED),
        )
        .expect("path");
        let cross = &path.links[1];
        assert_eq!(
            cross.serial(),
            [
                0x00, 0xFA, 0xA6, 0x27, 0x5D, 0xC2, 0x58, 0x43, 0x1D, 0x97, 0x66, 0xEC, 0x30, 0x45,
                0xEF, 0x24, 0xAC
            ]
        );
        assert_eq!(
            cross.verdict(capture("lencr-x1"), algorithms(), CAPTURED),
            Verdict::Revoked
        );
    }

    #[test]
    fn webpki_still_refuses_nameless_idp() {
        // If this fails after a webpki update, revisit ADR-027 D1.
        for name in NAMELESS_IDP {
            match webpki::BorrowedCertRevocationList::from_der(capture(name)) {
                Err(webpki::Error::UnsupportedCrlIssuingDistributionPoint) => {}
                other => panic!("{name}: {:?}", other.map(|_| "parsed")),
            }
        }
    }

    // ------------------------------------------ the webpki differential

    #[test]
    fn issuer_and_serials_agree_with_webpki() {
        let mut lists: Vec<(String, Vec<u8>)> = CAPTURES
            .iter()
            .filter(|(name, _, _)| !NAMELESS_IDP.contains(name))
            .map(|(name, der, _)| ((*name).to_owned(), der.to_vec()))
            .collect();
        assert_eq!(lists.len(), 10, "the captures of the 12 URLs webpki parses");
        lists.push(("root-empty".into(), ROOT_EMPTY.to_vec()));
        lists.push((
            "built".into(),
            ListSpec::root()
                .listing(&[CA1_SERIAL, &[0x00, 0x80], &[0x7F]])
                .build(),
        ));
        for (name, der) in lists {
            let ours = parse(&der).expect("ours");
            let theirs = webpki::BorrowedCertRevocationList::from_der(&der).expect("webpki");
            let theirs_list = webpki::CertRevocationList::from(
                webpki::BorrowedCertRevocationList::from_der(&der).expect("webpki"),
            );
            assert_eq!(ours.issuer, theirs_list.issuer(), "{name}");
            let ours_serials: BTreeSet<&[u8]> = ours.serials.iter().copied().collect();
            let theirs_serials: BTreeSet<Vec<u8>> = (&theirs)
                .into_iter()
                .map(|entry| entry.expect("entry").serial_number.to_vec())
                .collect();
            assert_eq!(
                ours_serials,
                theirs_serials.iter().map(Vec::as_slice).collect(),
                "{name}"
            );
        }
    }

    #[test]
    fn chain_verdicts_agree_with_webpki() {
        let leaf = CertificateDer::from(testing::pem_der(include_bytes!(
            "../../tests/data/chain-leaf-ca2.pem"
        )));
        let sent = vec![
            CertificateDer::from(testing::pem_der(CA2)),
            CertificateDer::from(testing::pem_der(CA1)),
        ];
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(testing::pem_der(ROOT)))
            .expect("root");
        let path =
            chain::verified_path(&roots, algorithms(), &leaf, &sent, time(NOW)).expect("path");
        let root_lists = [
            ListSpec::root().build(),
            ListSpec::root().listing(&[CA1_SERIAL]).build(),
            ListSpec::root().listing(&[&[0x12]]).build(),
        ];
        let ca1_lists = [
            ListSpec::ca1().build(),
            ListSpec::ca1().listing(&[&[0x12]]).build(),
            ListSpec::ca1().listing(&[CA1_SERIAL]).build(),
        ];
        for (r, root_list) in root_lists.iter().enumerate() {
            for (c, ca1_list) in ca1_lists.iter().enumerate() {
                // Ours: CA 2 against CA 1's list, CA 1 against the root's.
                let ours_revoked = path.links[0].verdict(ca1_list, algorithms(), NOW)
                    == Verdict::Revoked
                    || path.links[1].verdict(root_list, algorithms(), NOW) == Verdict::Revoked;
                let parsed: Vec<webpki::CertRevocationList<'_>> = [root_list, ca1_list]
                    .iter()
                    .map(|der| {
                        webpki::BorrowedCertRevocationList::from_der(der)
                            .expect("webpki")
                            .into()
                    })
                    .collect();
                let refs: Vec<&webpki::CertRevocationList<'_>> = parsed.iter().collect();
                let options = webpki::RevocationOptionsBuilder::new(&refs)
                    .expect("lists")
                    .with_depth(webpki::RevocationCheckDepth::Chain)
                    .with_status_policy(webpki::UnknownStatusPolicy::Allow)
                    .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
                    .build();
                let ee = webpki::EndEntityCert::try_from(&leaf).expect("leaf");
                let theirs = ee.verify_for_usage(
                    algorithms(),
                    &roots.roots,
                    &sent,
                    time(NOW),
                    webpki::KeyUsage::server_auth(),
                    Some(options),
                    None,
                );
                let theirs_revoked = matches!(theirs, Err(webpki::Error::CertRevoked));
                assert!(
                    theirs.is_ok() || theirs_revoked,
                    "{r} {c}: {:?}",
                    theirs.err()
                );
                assert_eq!(ours_revoked, theirs_revoked, "root list {r}, CA 1 list {c}");
            }
        }
    }

    #[test]
    fn the_keys_of_the_fixtures() {
        // The kept keys belong to the fixtures: lists they sign settle.
        assert_eq!(on_ca1(&ListSpec::root().build()), Verdict::Good);
        assert_eq!(
            on_ca2(&ListSpec::new(subject_name(CA1), CA_KEY).build()),
            Verdict::Good
        );
    }
}
