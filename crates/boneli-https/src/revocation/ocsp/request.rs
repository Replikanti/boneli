//! The OCSP request (RFC 6960, 4.1; ADR-019, item 3): one CertID with
//! SHA-1 hashes, no version, no requestor name, no extensions (so no
//! nonce, which no measured responder echoes), no signature; sent as a GET
//! with the request in the path (RFC 6960, A.1).

use super::super::der::{self, INTEGER, OCTET_STRING, SEQUENCE};
use super::super::url::CrlUrl;

/// `AlgorithmIdentifier { id-sha1, NULL }`, whole: what openssl sends and
/// every measured responder answers with.
const SHA1_ALGORITHM: &[u8] = &[
    0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00,
];

/// The certificate an OCSP request asks about, with the hashes a response
/// may name it by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertId {
    /// The SHA-1 `CertID`, whole: what the request carries and the cache
    /// is keyed by.
    pub(crate) der: Vec<u8>,
    pub(crate) sha1_name: [u8; 20],
    pub(crate) sha1_key: [u8; 20],
    pub(crate) sha256_name: [u8; 32],
    pub(crate) sha256_key: [u8; 32],
    /// The content of the leaf's serial number INTEGER, as encoded.
    pub(crate) serial: Vec<u8>,
}

impl CertId {
    /// The CertID of the certificate with `serial` (INTEGER content) from
    /// the issuer named `issuer_name` (the Name's content, without its
    /// SEQUENCE, as webpki's `Cert::issuer` gives it) whose key is
    /// `issuer_key` (the subjectPublicKey BIT STRING without its
    /// unused-bits byte). RFC 6960, 4.1.1: the name hash covers the whole
    /// DER Name, the key hash only the key bits.
    pub(crate) fn new(issuer_name: &[u8], issuer_key: &[u8], serial: &[u8]) -> CertId {
        let name = der::encode(SEQUENCE, issuer_name);
        let sha1_name = sha1(&name);
        let sha1_key = sha1(issuer_key);
        let mut body = SHA1_ALGORITHM.to_vec();
        body.extend(der::encode(OCTET_STRING, &sha1_name));
        body.extend(der::encode(OCTET_STRING, &sha1_key));
        body.extend(der::encode(INTEGER, serial));
        CertId {
            der: der::encode(SEQUENCE, &body),
            sha1_name,
            sha1_key,
            sha256_name: crate::Sha256::digest(&name),
            sha256_key: crate::Sha256::digest(issuer_key),
            serial: serial.to_vec(),
        }
    }
}

/// SHA-1, for CertIDs only: ring's `SHA1_FOR_LEGACY_USE_ONLY` (ADR-019,
/// item 10). A CertID names a certificate the chain already verified; it
/// is not a signature, so SHA-1's collisions buy an attacker nothing here.
fn sha1(data: &[u8]) -> [u8; 20] {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    let mut out = [0u8; 20];
    out.copy_from_slice(digest.as_ref());
    out
}

/// `OCSPRequest { TBSRequest { requestList { Request { CertID } } } }`,
/// byte for byte what `openssl ocsp -no_nonce -reqout` writes.
pub(crate) fn encode_request(id: &CertId) -> Vec<u8> {
    let request = der::encode(SEQUENCE, &id.der);
    let list = der::encode(SEQUENCE, &request);
    let tbs = der::encode(SEQUENCE, &list);
    der::encode(SEQUENCE, &tbs)
}

/// The GET path of `request` at `responder` (RFC 6960, A.1): the
/// responder's path without one trailing `/`, then `/`, then the request
/// in standard base64 with `+`, `/` and `=` percent-encoded.
pub(crate) fn get_path(responder: &CrlUrl, request: &[u8]) -> String {
    let base = responder.path();
    let base = base.strip_suffix('/').unwrap_or(base);
    let mut path = String::with_capacity(base.len() + 1 + request.len() * 2);
    path.push_str(base);
    path.push('/');
    for c in base64(request).chars() {
        match c {
            '+' => path.push_str("%2B"),
            '/' => path.push_str("%2F"),
            '=' => path.push_str("%3D"),
            c => path.push(c),
        }
    }
    path
}

/// Standard base64 with padding (RFC 4648, 4).
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 0x3F]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    const E36_CHAIN: &[u8] = include_bytes!("../../../tests/data/capture-e36-chain.pem");
    const E36_REQ: &[u8] = include_bytes!("../../../tests/data/capture-e36.req");
    const R36_CHAIN: &[u8] = include_bytes!("../../../tests/data/capture-r36-chain.pem");
    const R36_REQ: &[u8] = include_bytes!("../../../tests/data/capture-r36.req");
    const GOOD: &[u8] = include_bytes!("../../../tests/data/ocsp-good.pem");
    const CA: &[u8] = include_bytes!("../../../tests/data/ocsp-ca.pem");
    const GOOD_REQ: &[u8] = include_bytes!("../../../tests/data/ocsp-good.req");

    fn certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .expect("PEM")
    }

    /// The CertID of `leaf` issued by `issuer`, from the two certificates.
    fn id_of(leaf: &CertificateDer<'_>, issuer: &CertificateDer<'_>) -> CertId {
        let leaf = webpki::EndEntityCert::try_from(leaf).expect("leaf");
        let issuer = webpki::EndEntityCert::try_from(issuer).expect("issuer");
        let spki = issuer.subject_public_key_info();
        let (_, key) = der::spki_parts(spki.as_ref()).expect("SPKI");
        CertId::new(leaf.issuer(), key, leaf.serial())
    }

    fn chain_id(pem: &[u8]) -> CertId {
        let chain = certs(pem);
        id_of(&chain[0], &chain[1])
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    #[test]
    fn request_matches_openssl() {
        // 16-byte serial: 83 B; 17 bytes with a leading 00: 84 B.
        let e36 = encode_request(&chain_id(E36_CHAIN));
        assert_eq!((e36.len(), e36.as_slice()), (83, E36_REQ));
        let r36 = encode_request(&chain_id(R36_CHAIN));
        assert_eq!((r36.len(), r36.as_slice()), (84, R36_REQ));
        let good = encode_request(&id_of(&certs(GOOD)[0], &certs(CA)[0]));
        assert_eq!(good, GOOD_REQ);
    }

    #[test]
    fn cert_id_hashes_match_openssl() {
        // `openssl x509 -ocspid` of the issuers, and the CertIDs of the
        // captured Sectigo answers.
        let e36 = chain_id(E36_CHAIN);
        assert_eq!(
            hex(&e36.sha1_name),
            "B70E1256A2619B389154FE9CB9F0168E07A68C0B"
        );
        assert_eq!(
            hex(&e36.sha1_key),
            "1799A804C16FE42D70A80A103D03D3E91AB82663"
        );
        assert_eq!(hex(&e36.serial), "3E1D6026B4B0AEA279DCA2EFBBCED82B");
        let r36 = chain_id(R36_CHAIN);
        assert_eq!(
            hex(&r36.sha1_name),
            "D53ECCE5BF147292792E79266B72474A535AB4FD"
        );
        assert_eq!(
            hex(&r36.sha1_key),
            "68C01216180EAFCEF687A63257A346515DCB0727"
        );
        assert_eq!(hex(&r36.serial), "00D22060F1FFDA295326DFCC023C338ABF");
    }

    fn url(text: &str) -> CrlUrl {
        CrlUrl::parse(text).expect("URL")
    }

    #[test]
    fn get_path_appends_encoded_request() {
        let path = get_path(&url("http://ocsp.sectigo.com"), E36_REQ);
        // `base64 -w0 capture-e36.req`, with `+`, `/` and `=` encoded.
        assert_eq!(
            path,
            "/MFEwTzBNMEswSTAJBgUrDgMCGgUABBS3DhJWomGbOJFU%2Fpy58BaOB6aMCwQUF5moBMFv5C1wqAoQPQPT6Rq4JmMCED4dYCa0sK6iedyi77vO2Cs%3D"
        );
        assert_eq!(path.len(), 117);
        assert_eq!(
            get_path(&url("http://ocsp.sectigo.com"), R36_REQ).len(),
            119
        );
    }

    #[test]
    fn get_path_trailing_slash() {
        let request = [0xFB, 0xFF, 0xBF];
        assert_eq!(
            get_path(&url("http://h/ocsp/"), &request),
            "/ocsp/%2B%2F%2B%2F"
        );
        assert_eq!(
            get_path(&url("http://h/ocsp"), &request),
            "/ocsp/%2B%2F%2B%2F"
        );
        assert_eq!(get_path(&url("http://h/"), &request), "/%2B%2F%2B%2F");
        assert_eq!(get_path(&url("http://h"), &[0]), "/AA%3D%3D");
        // Only one trailing slash goes.
        assert_eq!(get_path(&url("http://h/a//"), &[0, 0, 0]), "/a//AAAA");
    }

    /// Standard base64 decoding of a path's last segment, for the test.
    fn decode(path: &str) -> Vec<u8> {
        let segment = path.rsplit('/').next().expect("segment");
        let text = segment
            .replace("%2B", "+")
            .replace("%2F", "/")
            .replace("%3D", "=");
        let value = |c: u8| -> u32 {
            match c {
                b'A'..=b'Z' => u32::from(c - b'A'),
                b'a'..=b'z' => u32::from(c - b'a') + 26,
                b'0'..=b'9' => u32::from(c - b'0') + 52,
                b'+' => 62,
                b'/' => 63,
                other => panic!("{other}"),
            }
        };
        let mut out = Vec::new();
        for quad in text.as_bytes().chunks(4) {
            let pad = quad.iter().filter(|c| **c == b'=').count();
            let n = quad
                .iter()
                .filter(|c| **c != b'=')
                .fold(0u32, |n, c| (n << 6) | value(*c))
                << (6 * pad);
            let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
            out.extend_from_slice(&bytes[..3 - pad]);
        }
        out
    }

    #[test]
    fn get_path_round_trips() {
        for request in [E36_REQ, R36_REQ, GOOD_REQ, &[], &[1], &[1, 2], &[0xFF; 7]] {
            let path = get_path(&url("http://ocsp.example/x"), request);
            assert_eq!(decode(&path), request, "{path}");
        }
    }

    #[test]
    fn base64_vectors() {
        // RFC 4648, 10.
        for (input, output) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), output);
        }
    }
}
