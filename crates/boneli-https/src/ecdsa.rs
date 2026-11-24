//! ECDSA P-256 signatures with SHA-256, DER-encoded: the one scheme
//! Sigstore's TUF repository signs with (`ecdsa-sha2-nistp256`), so the
//! tests of `boneli-tuf` sign fixture repositories at test time with the
//! scheme production accepts (ADR-033, S4).
//!
//! As for [`RsaSha256Key`](crate::RsaSha256Key), the key is loaded and used
//! through rustls' public key-provider API: the ring provider signs with
//! ring's `ECDSA_P256_SHA256_ASN1_SIGNING` and draws the nonce from ring's
//! system random source, the source [`fill_random`](crate::fill_random)
//! uses. No crate and no dependency edge is added, and ring stays in this
//! crate (ADR-005).

use std::fmt;

use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;
use rustls::pki_types::pem::{self, SectionKind};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::Signer;

use crate::rsa::{begins_section, has_encryption_headers, lines, wipe};
use crate::{KeyError, KeyKind, PublicKey};

/// An ECDSA P-256 private key that signs with SHA-256 and writes the
/// signature as a DER `Ecdsa-Sig-Value`, as TUF and X.509 carry it.
///
/// `Debug` shows nothing of the key. ring keeps the key in memory for the
/// key's lifetime and does not wipe it on drop; the DER rustls decodes is
/// wiped (rustls' `Zeroizing`), and so is the caller's PEM buffer
/// ([`EcdsaP256Key::from_pem`]).
pub struct EcdsaP256Key {
    signer: Box<dyn Signer>,
    public_key: PublicKey,
}

impl EcdsaP256Key {
    /// The longest PEM input accepted: 16,384 bytes. A P-256 key is 241
    /// bytes of PKCS#8 PEM and 643 bytes with OpenSSL's text dump in front
    /// (`openssl pkey -text`, measured with OpenSSL 3.5), so the cap is 25
    /// times that. It equals
    /// [`RsaSha256Key::MAX_PEM_LEN`](crate::RsaSha256Key::MAX_PEM_LEN), so
    /// the one fixed sentence of [`KeyError::TooLarge`] stays true for both
    /// key types; a larger cap only admits more text around the one
    /// section.
    pub const MAX_PEM_LEN: usize = 16_384;

    /// Reads the one PEM section in `pem`: an unencrypted PKCS#8 `PRIVATE
    /// KEY` holding an ECDSA P-256 key. A SEC1 `EC PRIVATE KEY`, a key of
    /// another curve or type and an encrypted key are refused with
    /// [`KeyError::NotEcdsaP256`]. Text outside the section is ignored; a
    /// second section of any kind is refused.
    ///
    /// `pem` is wiped (filled with zeros) before this returns, on success
    /// and on every refusal, as
    /// [`RsaSha256Key::from_pem`](crate::RsaSha256Key::from_pem) does, with
    /// the same limits: copies the PEM parser makes are not wiped.
    pub fn from_pem(pem: &mut [u8]) -> Result<EcdsaP256Key, KeyError> {
        let key = parse(pem);
        wipe(pem);
        key
    }

    /// The signature of `message`: ECDSA P-256 over its SHA-256, as a DER
    /// `Ecdsa-Sig-Value` (at most 72 bytes). The nonce is random, so two
    /// signatures of one message differ; both verify.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.signer.sign(message).map_err(|_| KeyError::SignFailed)
    }

    /// The public key, which verifies this key's signatures with
    /// [`PublicKey::verify`].
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl fmt::Debug for EcdsaP256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaP256Key").finish_non_exhaustive()
    }
}

fn parse(pem: &[u8]) -> Result<EcdsaP256Key, KeyError> {
    if pem.len() > EcdsaP256Key::MAX_PEM_LEN {
        return Err(KeyError::TooLarge);
    }
    // The rustls parser skips sections it does not know, so the count
    // comes from the markers themselves, as `RsaSha256Key` counts them.
    let sections = lines(pem).filter(|line| begins_section(line)).count();
    if sections != 1 {
        return Err(KeyError::NotOneSection);
    }
    if has_encryption_headers(pem) {
        return Err(KeyError::NotEcdsaP256);
    }
    let mut iter = pem::SliceIter::<(SectionKind, Vec<u8>)>::new(pem);
    let (kind, mut der) = match iter.next() {
        Some(Ok(section)) => section,
        Some(Err(_)) => return Err(KeyError::CorruptPem),
        None => return Err(KeyError::NotEcdsaP256),
    };
    // PKCS#8 only: rustls would also load a SEC1 `EC PRIVATE KEY`, which
    // the fixtures have no use for, so one form is accepted.
    if kind != SectionKind::PrivateKey {
        wipe(&mut der);
        return Err(KeyError::NotEcdsaP256);
    }
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der));
    // rustls wraps the DER in `Zeroizing`, so it is wiped on every path.
    let key = rustls::crypto::ring::default_provider()
        .key_provider
        .load_private_key(der)
        .map_err(|_| KeyError::NotEcdsaP256)?;
    if key.algorithm() != SignatureAlgorithm::ECDSA {
        return Err(KeyError::NotEcdsaP256);
    }
    // A P-384 key offers only its own scheme, so this refuses it.
    let signer = key
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .ok_or(KeyError::NotEcdsaP256)?;
    let spki = key.public_key().ok_or(KeyError::NotEcdsaP256)?;
    let public_key = PublicKey::from_spki_der(&spki).map_err(|_| KeyError::NotEcdsaP256)?;
    if public_key.kind() != KeyKind::EcdsaP256 {
        return Err(KeyError::NotEcdsaP256);
    }
    Ok(EcdsaP256Key { signer, public_key })
}
