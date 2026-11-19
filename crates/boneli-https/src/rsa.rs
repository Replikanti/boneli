//! RS256 signatures (RSASSA-PKCS1-v1_5 with SHA-256) for GitHub App JWTs:
//! ring's RSA through rustls' public key-provider API (ADR-014, D4).
//!
//! ring is linked here for TLS already, and rustls' ring provider loads
//! and signs with RSA keys for servers and client certificates; using that
//! API adds no crate and no dependency edge, and keeps ring confined to
//! this crate (ADR-005).

use std::fmt;

use rustls::pki_types::pem::{self, SectionKind};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
use rustls::sign::Signer;
use rustls::{SignatureAlgorithm, SignatureScheme};

/// Why a key was refused or a signature failed. Every variant is a fixed
/// rule, so no message carries key bytes or a parser's quote of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The input is longer than [`RsaSha256Key::MAX_PEM_LEN`].
    TooLarge,
    /// The input does not hold exactly one PEM section.
    NotOneSection,
    /// The one section is not an unencrypted `RSA PRIVATE KEY` or
    /// `PRIVATE KEY`: a certificate, a public key, a SEC1 or OpenSSH key,
    /// or an encrypted key, under its PKCS#8 label or in OpenSSL's
    /// traditional form (`Proc-Type` and `DEK-Info` headers).
    UnsupportedSection,
    /// The PEM framing or its base64 is corrupt.
    CorruptPem,
    /// ring did not accept the DER as an RSA key: corrupt, inconsistent, or
    /// a modulus other than 2048, 3072 or 4096 bits.
    Rejected,
    /// A key ring accepts, but not an RSA key (ECDSA, Ed25519).
    NotRsa,
    /// Signing failed.
    SignFailed,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::TooLarge => "the key file is larger than 16384 bytes",
            KeyError::NotOneSection => "the key file must hold exactly one PEM section",
            KeyError::UnsupportedSection => {
                "the PEM section must be an unencrypted RSA PRIVATE KEY or PRIVATE KEY"
            }
            KeyError::CorruptPem => "the PEM section is corrupt",
            KeyError::Rejected => "not an RSA private key of 2048, 3072 or 4096 bits",
            KeyError::NotRsa => "the private key is not an RSA key",
            KeyError::SignFailed => "the RSA signature failed",
        })
    }
}

impl std::error::Error for KeyError {}

/// An RSA private key that signs with RS256.
///
/// `Debug` shows the modulus size only. ring keeps the key in memory for
/// the key's lifetime and does not wipe it on drop; the DER rustls decodes
/// is wiped (rustls' `Zeroizing`), and so is the caller's PEM buffer
/// ([`RsaSha256Key::from_pem`]).
pub struct RsaSha256Key {
    signer: Box<dyn Signer>,
    modulus_len: usize,
}

impl RsaSha256Key {
    /// The longest PEM input accepted. A 4096-bit key, the largest ring
    /// signs with, is about 3,270 bytes of PEM and about 11,130 bytes with
    /// OpenSSL's text dump in front (`openssl pkey -text`, measured with
    /// OpenSSL 3.5); 16 KiB holds both, and a cap below about 3,300 bytes
    /// would refuse a valid key. A larger cap only admits more text around
    /// the one section (ADR-014, D4).
    pub const MAX_PEM_LEN: usize = 16_384;

    /// Reads the one PEM section in `pem`: `RSA PRIVATE KEY` (PKCS#1) or
    /// `PRIVATE KEY` (PKCS#8) holding an unencrypted RSA key that ring
    /// accepts: 2048, 3072 or 4096 bits, because ring 0.17 signs with
    /// moduli of 2048 to 4096 bits whose primes are a multiple of 512 bits
    /// long. Text outside the section is ignored; a second section of any
    /// kind, a certificate included, is refused.
    ///
    /// `pem` is wiped (filled with zeros) before this returns, on success
    /// and on every refusal, so the caller's copy of the key file does not
    /// outlive the parse. Best effort: copies the PEM parser makes while it
    /// decodes are not wiped, and the optimizer is held back only by
    /// `black_box`.
    pub fn from_pem(pem: &mut [u8]) -> Result<RsaSha256Key, KeyError> {
        let key = parse(pem);
        wipe(pem);
        key
    }

    /// The RS256 signature of `message`: as many bytes as the modulus.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let signature = self
            .signer
            .sign(message)
            .map_err(|_| KeyError::SignFailed)?;
        if signature.len() != self.modulus_len {
            return Err(KeyError::SignFailed);
        }
        Ok(signature)
    }

    /// The modulus size in bits, rounded up to whole bytes.
    pub fn modulus_bits(&self) -> usize {
        self.modulus_len * 8
    }
}

impl fmt::Debug for RsaSha256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSha256Key")
            .field("modulus_bits", &self.modulus_bits())
            .finish()
    }
}

/// Fills `buf` with zeros in a way the optimizer keeps (best effort,
/// without `unsafe`).
fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    std::hint::black_box(buf);
}

/// The lines of `pem`, ending at LF or CR as in the rustls PEM parser, so
/// both see the same lines.
fn lines(pem: &[u8]) -> impl Iterator<Item = &[u8]> {
    pem.split(|b| *b == b'\n' || *b == b'\r')
}

/// Whether `line` opens a PEM section.
fn begins_section(line: &[u8]) -> bool {
    line.starts_with(b"-----BEGIN ")
}

/// Whether the section carries the RFC 1421 headers of OpenSSL's
/// traditional encryption, which keeps the `RSA PRIVATE KEY` label. The
/// rustls parser would feed them to base64 and report corrupt PEM; the
/// file is not corrupt, it is encrypted.
fn has_encryption_headers(pem: &[u8]) -> bool {
    lines(pem)
        .skip_while(|line| !begins_section(line))
        .skip(1)
        .take_while(|line| !line.starts_with(b"-----END "))
        .any(|line| line.starts_with(b"Proc-Type:") || line.starts_with(b"DEK-Info:"))
}

fn parse(pem: &[u8]) -> Result<RsaSha256Key, KeyError> {
    if pem.len() > RsaSha256Key::MAX_PEM_LEN {
        return Err(KeyError::TooLarge);
    }
    // The rustls parser skips sections it does not know (an encrypted or
    // OpenSSH key), so the count comes from the markers themselves.
    let sections = lines(pem).filter(|line| begins_section(line)).count();
    if sections != 1 {
        return Err(KeyError::NotOneSection);
    }
    if has_encryption_headers(pem) {
        return Err(KeyError::UnsupportedSection);
    }
    let mut iter = pem::SliceIter::<(SectionKind, Vec<u8>)>::new(pem);
    let (kind, mut der) = match iter.next() {
        Some(Ok(section)) => section,
        Some(Err(_)) => return Err(KeyError::CorruptPem),
        None => return Err(KeyError::UnsupportedSection),
    };
    let der = match kind {
        SectionKind::RsaPrivateKey => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
        SectionKind::PrivateKey => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
        _ => {
            wipe(&mut der);
            return Err(KeyError::UnsupportedSection);
        }
    };
    // rustls wraps the DER in `Zeroizing`, so it is wiped on every path.
    let key = rustls::crypto::ring::default_provider()
        .key_provider
        .load_private_key(der)
        .map_err(|_| KeyError::Rejected)?;
    // `choose_scheme` below refuses a non-RSA key too; the algorithm check
    // names the rule without relying on that.
    if key.algorithm() != SignatureAlgorithm::RSA {
        return Err(KeyError::NotRsa);
    }
    let signer = key
        .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
        .ok_or(KeyError::NotRsa)?;
    // One signature at load: it proves the signer works before the key is
    // handed out, and its length is the modulus size, which rustls does not
    // expose. ring signs with 2048, 3072 and 4096 bits only; the check
    // keeps the bounds true if ring's limits change.
    let probe = signer.sign(b"").map_err(|_| KeyError::Rejected)?;
    if !(256..=512).contains(&probe.len()) {
        return Err(KeyError::Rejected);
    }
    Ok(RsaSha256Key {
        signer,
        modulus_len: probe.len(),
    })
}
