//! Public keys that verify signatures for image signatures (ADR-029, S2):
//! ECDSA P-256 and P-384, Ed25519 and RSA of 2048 to 8192 bits, through
//! the webpki signature algorithms of rustls' ring provider, as the OCSP
//! check does (ADR-020).
//!
//! The algorithm follows from the key alone: a P-256 key verifies ECDSA
//! with SHA-256, a P-384 key ECDSA with SHA-384, an Ed25519 key Ed25519,
//! an RSA key RSASSA-PKCS1-v1_5 with SHA-256. Nothing the signature or
//! its envelope says chooses it, so an attacker cannot move a key to a
//! weaker or another algorithm.

use std::fmt;

use rustls::pki_types::pem::{self, SectionKind};
use rustls::pki_types::{AlgorithmIdentifier, SignatureVerificationAlgorithm, alg_id};

use crate::Sha256;
use crate::der::{self, INTEGER, Reader, SEQUENCE};

/// The longest PEM input [`PublicKey::from_pem`] accepts. The largest
/// accepted key, RSA with 8192 bits, is 1,491 bytes of PEM and 4,968 bytes
/// with OpenSSL's text dump in front (`openssl pkey -pubin -text`,
/// measured with OpenSSL 3.5); 8 KiB is 1.65 times that. A smaller cap
/// would refuse such a key file; a larger one only admits more text
/// around the one section (ADR-029).
pub const MAX_PUBLIC_KEY_PEM_LEN: usize = 8_192;

/// The smallest and largest RSA modulus ring verifies with
/// (`RSA_PKCS1_2048_8192_SHA256`): ring's range, not a number of ours.
const RSA_MIN_BITS: u32 = 2_048;
const RSA_MAX_BITS: u32 = 8_192;

/// What a key is, and so the one algorithm it verifies with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// ECDSA on P-256, with SHA-256.
    EcdsaP256,
    /// ECDSA on P-384, with SHA-384.
    EcdsaP384,
    /// Ed25519.
    Ed25519,
    /// RSA, RSASSA-PKCS1-v1_5 with SHA-256; `bits` is the modulus length.
    Rsa {
        /// The modulus length in bits, 2048 to 8192.
        bits: u32,
    },
}

/// Why a public key was refused. Every variant is a fixed rule, so no
/// message carries key bytes or a parser's quote of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicKeyError {
    /// The input is longer than [`MAX_PUBLIC_KEY_PEM_LEN`].
    TooLarge,
    /// The input does not hold exactly one PEM section.
    NotOneSection,
    /// The one section is not a `PUBLIC KEY` (SubjectPublicKeyInfo): a
    /// certificate, a private key, or PKCS#1's `RSA PUBLIC KEY`.
    NotPublicKey,
    /// The PEM framing or its base64 is corrupt.
    CorruptPem,
    /// The SubjectPublicKeyInfo is not strict DER, or its key bits do not
    /// have the form of its algorithm (a compressed point, for example).
    Malformed,
    /// Neither ECDSA P-256 or P-384, Ed25519 nor RSA: P-521, DSA, or an
    /// RSA key whose parameters are not NULL.
    UnsupportedAlgorithm,
    /// An RSA modulus shorter than 2048 or longer than 8192 bits.
    RsaSize,
}

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PublicKeyError::TooLarge => "the public key file is larger than 8192 bytes",
            PublicKeyError::NotOneSection => {
                "the public key file must hold exactly one PEM section"
            }
            PublicKeyError::NotPublicKey => "the PEM section must be a PUBLIC KEY",
            PublicKeyError::CorruptPem => "the PEM section is corrupt",
            PublicKeyError::Malformed => "the public key is malformed",
            PublicKeyError::UnsupportedAlgorithm => {
                "the public key is not ECDSA P-256 or P-384, Ed25519 or RSA"
            }
            PublicKeyError::RsaSize => "the RSA key is not between 2048 and 8192 bits",
        })
    }
}

impl std::error::Error for PublicKeyError {}

/// A signature did not verify. One fixed reason: which check inside the
/// algorithm failed is not the caller's business and could only help an
/// attacker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureError;

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the signature does not verify")
    }
}

impl std::error::Error for SignatureError {}

/// A public key of a supported kind, kept as its SubjectPublicKeyInfo.
///
/// `Debug` shows the kind only.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    spki: Vec<u8>,
    kind: KeyKind,
}

impl PublicKey {
    /// Reads the one `PUBLIC KEY` PEM section in `pem`. Text outside the
    /// section is ignored; a second section of any kind is refused.
    pub fn from_pem(pem: &[u8]) -> Result<PublicKey, PublicKeyError> {
        if pem.len() > MAX_PUBLIC_KEY_PEM_LEN {
            return Err(PublicKeyError::TooLarge);
        }
        // The rustls parser skips sections it does not know, so the count
        // comes from the markers themselves, as `RsaSha256Key` counts them.
        let sections = pem
            .split(|b| *b == b'\n' || *b == b'\r')
            .filter(|line| line.starts_with(b"-----BEGIN "))
            .count();
        if sections != 1 {
            return Err(PublicKeyError::NotOneSection);
        }
        let mut iter = pem::SliceIter::<(SectionKind, Vec<u8>)>::new(pem);
        match iter.next() {
            Some(Ok((SectionKind::PublicKey, der))) => PublicKey::from_spki_der(&der),
            Some(Ok(_)) | None => Err(PublicKeyError::NotPublicKey),
            Some(Err(_)) => Err(PublicKeyError::CorruptPem),
        }
    }

    /// Reads a DER SubjectPublicKeyInfo, whole and strict: nothing may
    /// follow it, and the key bits must have their algorithm's form (an
    /// uncompressed point of the curve's size, 32 bytes of Ed25519, an
    /// RSAPublicKey with a positive minimal modulus).
    pub fn from_spki_der(spki: &[u8]) -> Result<PublicKey, PublicKeyError> {
        let malformed = |_| PublicKeyError::Malformed;
        let (algorithm, key) = der::spki_parts(spki).map_err(malformed)?;
        let kind = if algorithm == alg_id::ECDSA_P256.as_ref() {
            point(key, 65)?;
            KeyKind::EcdsaP256
        } else if algorithm == alg_id::ECDSA_P384.as_ref() {
            point(key, 97)?;
            KeyKind::EcdsaP384
        } else if algorithm == alg_id::ED25519.as_ref() {
            if key.len() != 32 {
                return Err(PublicKeyError::Malformed);
            }
            KeyKind::Ed25519
        } else if algorithm == alg_id::RSA_ENCRYPTION.as_ref() {
            let bits = rsa_modulus_bits(key)?;
            if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&bits) {
                return Err(PublicKeyError::RsaSize);
            }
            KeyKind::Rsa { bits }
        } else {
            return Err(PublicKeyError::UnsupportedAlgorithm);
        };
        Ok(PublicKey {
            spki: spki.to_vec(),
            kind,
        })
    }

    /// The key's kind, which fixes its algorithm.
    pub fn kind(&self) -> KeyKind {
        self.kind
    }

    /// The whole DER SubjectPublicKeyInfo.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }

    /// The SHA-256 of the SubjectPublicKeyInfo DER: the log ID of RFC
    /// 6962, section 3.2, which Rekor uses for its logs too.
    pub fn key_id(&self) -> [u8; 32] {
        Sha256::digest(&self.spki)
    }

    /// Whether `signature` is this key's signature of `message`, under
    /// the one algorithm of the key's kind (module doc). ECDSA signatures
    /// are DER `Ecdsa-Sig-Value`s, as X.509, CT and Sigstore carry them.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        let (key_algorithm, signature_algorithm) = match self.kind {
            KeyKind::EcdsaP256 => (alg_id::ECDSA_P256, alg_id::ECDSA_SHA256),
            KeyKind::EcdsaP384 => (alg_id::ECDSA_P384, alg_id::ECDSA_SHA384),
            KeyKind::Ed25519 => (alg_id::ED25519, alg_id::ED25519),
            KeyKind::Rsa { .. } => (alg_id::RSA_ENCRYPTION, alg_id::RSA_PKCS1_SHA256),
        };
        let algorithm = algorithm(key_algorithm, signature_algorithm).ok_or(SignatureError)?;
        let (_, key) = der::spki_parts(&self.spki).map_err(|_| SignatureError)?;
        algorithm
            .verify_signature(key, message, signature)
            .map_err(|_| SignatureError)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("kind", &self.kind)
            .finish()
    }
}

/// The one webpki algorithm of rustls' ring provider for this key and
/// signature algorithm. Exactly one matches each pair `verify` asks for;
/// none would fail the signature, never widen it.
fn algorithm(
    key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
) -> Option<&'static dyn SignatureVerificationAlgorithm> {
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .all
        .iter()
        .copied()
        .find(|a| a.public_key_alg_id() == key && a.signature_alg_id() == signature)
}

/// An uncompressed elliptic curve point of `len` bytes (SEC 1, 2.3.3):
/// `04`, then X and Y. ring checks that it is on the curve when it
/// verifies.
fn point(key: &[u8], len: usize) -> Result<(), PublicKeyError> {
    match key.first() {
        Some(0x04) if key.len() == len => Ok(()),
        _ => Err(PublicKeyError::Malformed),
    }
}

/// The modulus length in bits of an `RSAPublicKey ::= SEQUENCE { modulus
/// INTEGER, publicExponent INTEGER }` (RFC 8017, A.1.1). The modulus must
/// be positive and minimally encoded; ring checks the exponent.
fn rsa_modulus_bits(key: &[u8]) -> Result<u32, PublicKeyError> {
    let malformed = |_| PublicKeyError::Malformed;
    let mut outer = Reader::new(key);
    let mut fields = Reader::new(outer.expect(SEQUENCE).map_err(malformed)?);
    outer.finish().map_err(malformed)?;
    let modulus = fields.expect(INTEGER).map_err(malformed)?;
    fields.expect(INTEGER).map_err(malformed)?;
    fields.finish().map_err(malformed)?;
    let digits = match modulus {
        [] => return Err(PublicKeyError::Malformed),
        [first, ..] if *first >= 0x80 => return Err(PublicKeyError::Malformed),
        [0, rest @ ..] => match rest.first() {
            Some(next) if *next >= 0x80 => rest,
            _ => return Err(PublicKeyError::Malformed),
        },
        all => all,
    };
    let Some(&top) = digits.first() else {
        return Err(PublicKeyError::Malformed);
    };
    // A count past `u32` is far past 8192 bits, so it is refused as such.
    let bits = (digits.len() as u64 - 1) * 8 + u64::from(8 - top.leading_zeros());
    u32::try_from(bits).map_err(|_| PublicKeyError::RsaSize)
}
