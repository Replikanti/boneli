//! A DER reader for the two things webpki parses but keeps to itself
//! (ADR-017, item 9): the CRL distribution points of a certificate and the
//! `thisUpdate` and `nextUpdate` of a CRL.
//!
//! Both functions read only bytes webpki has accepted already: the leaf
//! after the handshake verified it, the CRL after `build()` parsed it. A
//! misparse here can therefore refuse a valid certificate or miss a point,
//! but never accept a certificate a CRL lists: webpki decides that.
//!
//! Definite lengths only, in their minimal encoding, at most four length
//! bytes; low tag numbers only. No index can panic: every slice comes from
//! `split_first` or `split_at_checked`.

use std::fmt;

/// Why the reader refused its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DerError(pub(crate) &'static str);

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BOOLEAN: u8 = 0x01;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0]` constructed: the certificate version, a distribution point's
/// name, and `fullName` inside it.
const CONTEXT_0: u8 = 0xA0;
/// `[1]` constructed: `nameRelativeToCRLIssuer`.
const CONTEXT_1: u8 = 0xA1;
/// `[1]` and `[2]` primitive: the unique IDs of a certificate, and
/// `reasons` of a distribution point (`[1]`, a BIT STRING).
const CONTEXT_1_PRIMITIVE: u8 = 0x81;
const CONTEXT_2_PRIMITIVE: u8 = 0x82;
/// `[2]` constructed: a distribution point's `cRLIssuer`.
const CONTEXT_2: u8 = 0xA2;
/// `[3]` constructed: the extensions of a certificate.
const CONTEXT_3: u8 = 0xA3;
/// `uniformResourceIdentifier [6] IA5String`, implicitly tagged.
const URI: u8 = 0x86;
/// id-ce-cRLDistributionPoints, 2.5.29.31.
const CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1D, 0x1F];

/// A cursor over DER bytes.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// The next tag and value.
    fn read(&mut self) -> Result<(u8, &'a [u8]), DerError> {
        let (&tag, rest) = self.data.split_first().ok_or(DerError("truncated"))?;
        if tag & 0x1F == 0x1F {
            return Err(DerError("high tag number"));
        }
        let (&first, mut rest) = rest.split_first().ok_or(DerError("truncated"))?;
        let len = match first {
            0..=0x7F => usize::from(first),
            0x80 => return Err(DerError("indefinite length")),
            0x81..=0x84 => {
                let count = usize::from(first & 0x7F);
                let (bytes, after) = rest.split_at_checked(count).ok_or(DerError("truncated"))?;
                rest = after;
                let mut len: usize = 0;
                for &b in bytes {
                    len = (len << 8) | usize::from(b);
                }
                // Minimal: no leading zero byte, and the long form only
                // where the short form cannot hold the length.
                if bytes.first() == Some(&0) || len < 0x80 {
                    return Err(DerError("non-minimal length"));
                }
                len
            }
            _ => return Err(DerError("length longer than four bytes")),
        };
        let (value, after) = rest
            .split_at_checked(len)
            .ok_or(DerError("length past the end"))?;
        self.data = after;
        Ok((tag, value))
    }

    /// The value of the next element, which must have `tag`.
    fn expect(&mut self, tag: u8) -> Result<&'a [u8], DerError> {
        match self.read()? {
            (t, value) if t == tag => Ok(value),
            _ => Err(DerError("unexpected tag")),
        }
    }

    /// The value of the next element if it has `tag`.
    fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>, DerError> {
        if self.peek() == Some(tag) {
            return self.expect(tag).map(Some);
        }
        Ok(None)
    }

    /// Nothing may follow.
    fn finish(&self) -> Result<(), DerError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(DerError("trailing bytes"))
        }
    }
}

/// The `uniformResourceIdentifier` names of the certificate's CRL
/// distribution points, in certificate order, from every point whose
/// `distributionPoint` is a `fullName` and that has neither `reasons` nor
/// `cRLIssuer` (ADR-017, item 3). Other name types and
/// `nameRelativeToCRLIssuer` are skipped, as webpki's `authoritative_for`
/// skips them. No extension gives an empty list; a second
/// cRLDistributionPoints extension is an error.
pub(crate) fn distribution_point_uris(cert: &[u8]) -> Result<Vec<&[u8]>, DerError> {
    let mut outer = Reader::new(cert);
    let certificate = outer.expect(SEQUENCE)?;
    outer.finish()?;
    let mut certificate = Reader::new(certificate);
    let tbs = certificate.expect(SEQUENCE)?;
    certificate.expect(SEQUENCE)?; // signatureAlgorithm
    certificate.expect(BIT_STRING)?; // signature
    certificate.finish()?;

    let mut tbs = Reader::new(tbs);
    tbs.optional(CONTEXT_0)?; // version
    tbs.expect(INTEGER)?; // serialNumber
    for _ in 0..5 {
        // signature, issuer, validity, subject, subjectPublicKeyInfo
        tbs.expect(SEQUENCE)?;
    }
    tbs.optional(CONTEXT_1_PRIMITIVE)?; // issuerUniqueID
    tbs.optional(CONTEXT_2_PRIMITIVE)?; // subjectUniqueID
    let Some(extensions) = tbs.optional(CONTEXT_3)? else {
        tbs.finish()?;
        return Ok(Vec::new());
    };
    tbs.finish()?;

    let mut wrapper = Reader::new(extensions);
    let extensions = wrapper.expect(SEQUENCE)?;
    wrapper.finish()?;
    let mut extensions = Reader::new(extensions);
    let mut found: Option<&[u8]> = None;
    while !extensions.is_empty() {
        let mut extension = Reader::new(extensions.expect(SEQUENCE)?);
        let id = extension.expect(OID)?;
        extension.optional(BOOLEAN)?; // critical
        let value = extension.expect(OCTET_STRING)?;
        extension.finish()?;
        if id == CRL_DISTRIBUTION_POINTS {
            if found.is_some() {
                return Err(DerError("two cRLDistributionPoints extensions"));
            }
            found = Some(value);
        }
    }
    match found {
        Some(value) => points(value),
        None => Ok(Vec::new()),
    }
}

/// `CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint`.
fn points(value: &[u8]) -> Result<Vec<&[u8]>, DerError> {
    let mut wrapper = Reader::new(value);
    let points = wrapper.expect(SEQUENCE)?;
    wrapper.finish()?;
    let mut points = Reader::new(points);
    let mut uris = Vec::new();
    while !points.is_empty() {
        let mut point = Reader::new(points.expect(SEQUENCE)?);
        let name = point.optional(CONTEXT_0)?;
        let reasons = point.optional(CONTEXT_1_PRIMITIVE)?;
        let issuer = point.optional(CONTEXT_2)?;
        point.finish()?;
        let Some(name) = name else { continue };
        // Read the name even when the point is skipped, so that a
        // malformed one is an error wherever it sits.
        let mut name = Reader::new(name);
        let (tag, names) = name.read()?;
        name.finish()?;
        let full = match tag {
            CONTEXT_0 => true,
            CONTEXT_1 => false,
            _ => return Err(DerError("unknown distribution point name")),
        };
        let mut names = Reader::new(names);
        while !names.is_empty() {
            let (tag, value) = names.read()?;
            if full && tag == URI && reasons.is_none() && issuer.is_none() {
                uris.push(value);
            }
        }
    }
    Ok(uris)
}

/// The `thisUpdate` and `nextUpdate` of a CRL as Unix seconds. A CRL
/// without `nextUpdate` is an error, as webpki refuses it.
pub(crate) fn crl_validity(crl: &[u8]) -> Result<(u64, u64), DerError> {
    let mut outer = Reader::new(crl);
    let list = outer.expect(SEQUENCE)?;
    outer.finish()?;
    let mut list = Reader::new(list);
    let mut tbs = Reader::new(list.expect(SEQUENCE)?);
    tbs.optional(INTEGER)?; // version
    tbs.expect(SEQUENCE)?; // signature
    tbs.expect(SEQUENCE)?; // issuer
    let this_update = read_time(&mut tbs)?;
    let next_update = read_time(&mut tbs)?;
    Ok((this_update, next_update))
}

fn read_time(reader: &mut Reader<'_>) -> Result<u64, DerError> {
    let (tag, value) = reader.read()?;
    time(tag, value)
}

/// A UTCTime or GeneralizedTime as Unix seconds, with exactly webpki's
/// rules (`rustls-webpki`, `src/time.rs`): a UTCTime year of 50 or more is
/// 19YY, else 20YY; years before 1970 are refused; seconds 00 to 59; `Z`
/// required; no fraction; days per month with the 4/100/400 leap rule.
pub(crate) fn time(tag: u8, value: &[u8]) -> Result<u64, DerError> {
    let bad = DerError("invalid time");
    let mut digits = Digits(value);
    let year = match tag {
        UTC_TIME => {
            let yy = digits.two(0, 99)?;
            if yy >= 50 { 1900 + yy } else { 2000 + yy }
        }
        GENERALIZED_TIME => digits.two(0, 99)? * 100 + digits.two(0, 99)?,
        _ => return Err(DerError("not a time")),
    };
    let month = digits.two(1, 12)?;
    let day = digits.two(1, days_in_month(year, month))?;
    let hour = digits.two(0, 23)?;
    let minute = digits.two(0, 59)?;
    let second = digits.two(0, 59)?;
    if digits.0 != b"Z" {
        return Err(bad);
    }
    if year < 1970 {
        return Err(bad);
    }
    let days =
        days_before_year(year) - days_before_year(1970) + days_before_month(year, month) + day - 1;
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Two-digit fields of a time, consumed from the front.
struct Digits<'a>(&'a [u8]);

impl Digits<'_> {
    fn two(&mut self, min: u64, max: u64) -> Result<u64, DerError> {
        let bad = DerError("invalid time");
        let (pair, rest) = self.0.split_at_checked(2).ok_or(bad)?;
        let mut value = 0;
        for &b in pair {
            if !b.is_ascii_digit() {
                return Err(bad);
            }
            value = value * 10 + u64::from(b - b'0');
        }
        if value < min || value > max {
            return Err(bad);
        }
        self.0 = rest;
        Ok(value)
    }
}

fn is_leap(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 0001-01-01 to January 1 of `year` (`year` at least 1).
fn days_before_year(year: u64) -> u64 {
    let y = year - 1;
    y * 365 + y / 4 - y / 100 + y / 400
}

fn days_before_month(year: u64, month: u64) -> u64 {
    (1..month).map(|m| days_in_month(year, m)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    fn der(pem: &[u8]) -> Vec<u8> {
        CertificateDer::from_pem_slice(pem)
            .expect("PEM")
            .as_ref()
            .to_vec()
    }

    const CERTS: [&[u8]; 11] = [
        include_bytes!("../../tests/data/crl-good.pem"),
        include_bytes!("../../tests/data/crl-revoked.pem"),
        include_bytes!("../../tests/data/crl-revoked-first.pem"),
        include_bytes!("../../tests/data/crl-two-dp.pem"),
        include_bytes!("../../tests/data/crl-five-urls.pem"),
        include_bytes!("../../tests/data/crl-ldap-only.pem"),
        include_bytes!("../../tests/data/crl-reasons-only.pem"),
        include_bytes!("../../tests/data/crl-dps.pem"),
        include_bytes!("../../tests/data/crl-stray.pem"),
        include_bytes!("../../tests/data/crl-ca.pem"),
        include_bytes!("../../tests/data/leaf.pem"),
    ];

    const CRLS: [&[u8]; 10] = [
        include_bytes!("../../tests/data/crl-ca-fresh.crl"),
        include_bytes!("../../tests/data/crl-ca-empty.crl"),
        include_bytes!("../../tests/data/crl-ca-week1.crl"),
        include_bytes!("../../tests/data/crl-ca-day2.crl"),
        include_bytes!("../../tests/data/crl-ca-idp.crl"),
        include_bytes!("../../tests/data/crl-ca-other-shard.crl"),
        include_bytes!("../../tests/data/crl-ca-v1.crl"),
        include_bytes!("../../tests/data/crl-ca-reversed.crl"),
        include_bytes!("../../tests/data/crl-ca-forged.crl"),
        include_bytes!("../../tests/data/crl-ca-empty.crl"),
    ];

    fn uris(pem: &[u8]) -> Vec<String> {
        let cert = der(pem);
        distribution_point_uris(&cert)
            .expect("points")
            .into_iter()
            .map(|uri| String::from_utf8(uri.to_vec()).expect("ASCII"))
            .collect()
    }

    #[test]
    fn cdp_order_and_skips() {
        assert_eq!(
            uris(include_bytes!("../../tests/data/crl-dps.pem")),
            [
                "http://crl.boneli.test/a.crl",
                "ldap://ldap.boneli.test/cn=a",
                "http://crl.boneli.test/e.crl",
            ]
        );
        assert_eq!(
            uris(include_bytes!("../../tests/data/crl-good.pem")),
            ["http://crl.boneli.test/ca.crl"]
        );
        assert_eq!(
            uris(include_bytes!("../../tests/data/crl-two-dp.pem")),
            [
                "http://crl1.boneli.test/ca.crl",
                "http://crl2.boneli.test/ca.crl"
            ]
        );
        assert_eq!(
            uris(include_bytes!("../../tests/data/crl-five-urls.pem")).len(),
            5
        );
        assert!(uris(include_bytes!("../../tests/data/crl-reasons-only.pem")).is_empty());
        assert!(uris(include_bytes!("../../tests/data/leaf.pem")).is_empty());
        assert!(uris(include_bytes!("../../tests/data/crl-ca.pem")).is_empty());
    }

    #[test]
    fn crl_validity_of_fixtures() {
        let t0 = 1_767_225_600;
        let end = 4_922_899_200;
        assert_eq!(crl_validity(CRLS[0]), Ok((t0, end)));
        assert_eq!(crl_validity(CRLS[2]), Ok((t0, 1_767_830_400)));
        assert_eq!(crl_validity(CRLS[3]), Ok((t0 + 86_400, 1_767_916_800)));
        assert_eq!(crl_validity(CRLS[6]), Ok((t0, end)), "version 1");
        let (this, next) = crl_validity(CRLS[7]).expect("reversed");
        assert!(next < this);
    }

    #[test]
    fn every_truncation_is_an_error() {
        for pem in CERTS {
            let cert = der(pem);
            distribution_point_uris(&cert).expect("whole certificate");
            for len in 0..cert.len() {
                assert!(
                    distribution_point_uris(&cert[..len]).is_err(),
                    "prefix of {len} bytes"
                );
            }
        }
        for crl in CRLS {
            crl_validity(crl).expect("whole CRL");
            for len in 0..crl.len() {
                assert!(crl_validity(&crl[..len]).is_err(), "prefix of {len} bytes");
            }
        }
    }

    #[test]
    fn every_byte_flip_returns() {
        let cert = der(include_bytes!("../../tests/data/crl-dps.pem"));
        for i in 0..cert.len() {
            for bit in 0..8 {
                let mut flipped = cert.clone();
                flipped[i] ^= 1 << bit;
                let _ = distribution_point_uris(&flipped);
            }
        }
        let crl = CRLS[0];
        for i in 0..crl.len() {
            let mut flipped = crl.to_vec();
            flipped[i] ^= 0xFF;
            let _ = crl_validity(&flipped);
        }
    }

    #[test]
    fn indefinite_length_is_refused() {
        assert!(Reader::new(&[0x30, 0x80, 0x00, 0x00]).read().is_err());
    }

    #[test]
    fn non_minimal_length_is_refused() {
        let mut long = vec![0x04, 0x81, 0x05];
        long.extend_from_slice(&[0; 5]);
        assert_eq!(
            Reader::new(&long).read(),
            Err(DerError("non-minimal length"))
        );
        let mut zero = vec![0x04, 0x82, 0x00, 0x80];
        zero.extend_from_slice(&[0; 0x80]);
        assert_eq!(
            Reader::new(&zero).read(),
            Err(DerError("non-minimal length"))
        );
        // The minimal forms of the same lengths read.
        let mut short = vec![0x04, 0x05];
        short.extend_from_slice(&[0; 5]);
        assert!(Reader::new(&short).read().is_ok());
        let mut one = vec![0x04, 0x81, 0x80];
        one.extend_from_slice(&[0; 0x80]);
        assert!(Reader::new(&one).read().is_ok());
    }

    #[test]
    fn five_length_bytes_are_refused() {
        assert_eq!(
            Reader::new(&[0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00]).read(),
            Err(DerError("length longer than four bytes"))
        );
    }

    #[test]
    fn length_past_end_is_refused() {
        assert_eq!(
            Reader::new(&[0x04, 0x03, 0x00, 0x00]).read(),
            Err(DerError("length past the end"))
        );
        assert_eq!(
            Reader::new(&[0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]).read(),
            Err(DerError("length past the end"))
        );
    }

    #[test]
    fn high_tag_number_is_refused() {
        assert_eq!(
            Reader::new(&[0x1F, 0x22, 0x00]).read(),
            Err(DerError("high tag number"))
        );
        assert_eq!(
            Reader::new(&[0xBF, 0x22, 0x00]).read(),
            Err(DerError("high tag number"))
        );
    }

    /// A TLV with a short or one-byte long length.
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 0x80 {
            out.push(value.len() as u8);
        } else {
            assert!(value.len() <= 0xFF);
            out.extend_from_slice(&[0x81, value.len() as u8]);
        }
        out.extend_from_slice(value);
        out
    }

    /// A certificate with the given extensions and dummy fields, enough
    /// for the reader (it never checks a signature).
    fn cert_with(extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut tbs = tlv(0xA0, &tlv(INTEGER, &[2]));
        tbs.extend(tlv(INTEGER, &[1]));
        for _ in 0..5 {
            tbs.extend(tlv(SEQUENCE, &[]));
        }
        tbs.extend(tlv(CONTEXT_3, &tlv(SEQUENCE, &extensions.concat())));
        let mut cert = tlv(SEQUENCE, &tbs);
        cert.extend(tlv(SEQUENCE, &[]));
        cert.extend(tlv(BIT_STRING, &[0]));
        tlv(SEQUENCE, &cert)
    }

    fn cdp_extension(uri: &[u8]) -> Vec<u8> {
        let names = tlv(CONTEXT_0, &tlv(URI, uri));
        let point = tlv(SEQUENCE, &tlv(CONTEXT_0, &names));
        let mut ext = tlv(OID, CRL_DISTRIBUTION_POINTS);
        ext.extend(tlv(OCTET_STRING, &tlv(SEQUENCE, &point)));
        tlv(SEQUENCE, &ext)
    }

    #[test]
    fn duplicate_cdp_extension_is_error() {
        let one = cert_with(&[cdp_extension(b"http://a/")]);
        assert_eq!(
            distribution_point_uris(&one),
            Ok(vec![b"http://a/".as_slice()])
        );
        let two = cert_with(&[cdp_extension(b"http://a/"), cdp_extension(b"http://b/")]);
        assert_eq!(
            distribution_point_uris(&two),
            Err(DerError("two cRLDistributionPoints extensions"))
        );
        // Trailing bytes after the certificate are refused too.
        let mut trailing = one.clone();
        trailing.push(0);
        assert!(distribution_point_uris(&trailing).is_err());
    }

    fn utc(text: &str) -> Result<u64, DerError> {
        time(UTC_TIME, text.as_bytes())
    }

    fn generalized(text: &str) -> Result<u64, DerError> {
        time(GENERALIZED_TIME, text.as_bytes())
    }

    #[test]
    fn utc_time_pivot() {
        assert_eq!(utc("491231235959Z"), Ok(2_524_607_999));
        assert!(utc("500101000000Z").is_err(), "1950 is before 1970");
        assert_eq!(utc("700101000000Z"), Ok(0));
        assert_eq!(utc("260101000000Z"), Ok(1_767_225_600));
    }

    #[test]
    fn generalized_time() {
        assert_eq!(generalized("21260101000000Z"), Ok(4_922_899_200));
        assert_eq!(generalized("19700101000000Z"), Ok(0));
        assert!(generalized("19691231235959Z").is_err());
    }

    #[test]
    fn leap_days() {
        assert_eq!(generalized("20240229000000Z"), Ok(1_709_164_800));
        assert_eq!(generalized("20000229120000Z"), Ok(951_825_600));
        assert!(generalized("20230229000000Z").is_err());
        assert!(generalized("21000229000000Z").is_err());
    }

    #[test]
    fn time_format_refusals() {
        assert!(utc("260101000060Z").is_err(), "second 60");
        assert!(generalized("20260101000000.5Z").is_err(), "fraction");
        assert!(utc("260101000000").is_err(), "no Z");
        assert!(utc("2601010000Z").is_err(), "no seconds");
        assert!(utc("260101000000+0100").is_err(), "offset");
        assert!(utc("260101000000Z ").is_err(), "trailing byte");
        assert!(utc("26-101000000Z").is_err(), "not a digit");
        assert!(time(OCTET_STRING, b"260101000000Z").is_err(), "wrong tag");
    }
}
