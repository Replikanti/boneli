//! Ed25519 signatures: the scheme a Rekor v2 log signs its checkpoints
//! with, so the tests of `boneli-sigstore` sign synthetic checkpoints at
//! test time with the scheme production verifies (ADR-038, D6 and D7).
//!
//! As [`EcdsaP256Key`](crate::EcdsaP256Key), the key is loaded and used
//! through rustls' public key-provider API: the ring provider signs with
//! ring's `Ed25519KeyPair`, which needs no random source (RFC 8032
//! signatures are deterministic). No crate and no dependency edge is
//! added, and ring stays in this crate (ADR-005). It is a test signer:
//! production never signs with it.

use std::fmt;

use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;
use rustls::pki_types::pem::{self, SectionKind};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::Signer;

use crate::rsa::{begins_section, has_encryption_headers, lines, wipe};
use crate::{KeyError, KeyKind, PublicKey};

/// An Ed25519 private key (RFC 8032), whose signatures are the raw 64
/// bytes a signed note carries.
///
/// `Debug` shows nothing of the key. ring keeps the key in memory for the
/// key's lifetime and does not wipe it on drop; the DER rustls decodes is
/// wiped (rustls' `Zeroizing`), and so is the caller's PEM buffer
/// ([`Ed25519Key::from_pem`]).
pub struct Ed25519Key {
    signer: Box<dyn Signer>,
    public_key: PublicKey,
}

impl Ed25519Key {
    /// The longest PEM input accepted: 16,384 bytes. An Ed25519 key is 119
    /// bytes of PKCS#8 PEM, so any key with text around it fits; it equals
    /// [`EcdsaP256Key::MAX_PEM_LEN`](crate::EcdsaP256Key::MAX_PEM_LEN) and
    /// [`RsaSha256Key::MAX_PEM_LEN`](crate::RsaSha256Key::MAX_PEM_LEN), so
    /// the one fixed sentence of [`KeyError::TooLarge`] stays true for every
    /// key type.
    pub const MAX_PEM_LEN: usize = 16_384;

    /// Reads the one PEM section in `pem`: an unencrypted PKCS#8 `PRIVATE
    /// KEY` holding an Ed25519 key. A key of another type and an encrypted
    /// key are refused with [`KeyError::NotEd25519`]. Text outside the
    /// section is ignored; a second section of any kind is refused.
    ///
    /// `pem` is wiped (filled with zeros) before this returns, on success
    /// and on every refusal, as
    /// [`EcdsaP256Key::from_pem`](crate::EcdsaP256Key::from_pem) does, with
    /// the same limits: copies the PEM parser makes are not wiped.
    pub fn from_pem(pem: &mut [u8]) -> Result<Ed25519Key, KeyError> {
        let key = parse(pem);
        wipe(pem);
        key
    }

    /// The signature of `message`: 64 bytes, the same for the same
    /// message (RFC 8032, section 5.1.6).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.signer.sign(message).map_err(|_| KeyError::SignFailed)
    }

    /// The public key, which verifies this key's signatures with
    /// [`PublicKey::verify`].
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl fmt::Debug for Ed25519Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Key").finish_non_exhaustive()
    }
}

fn parse(pem: &[u8]) -> Result<Ed25519Key, KeyError> {
    if pem.len() > Ed25519Key::MAX_PEM_LEN {
        return Err(KeyError::TooLarge);
    }
    // The rustls parser skips sections it does not know, so the count
    // comes from the markers themselves, as `RsaSha256Key` counts them.
    let sections = lines(pem).filter(|line| begins_section(line)).count();
    if sections != 1 {
        return Err(KeyError::NotOneSection);
    }
    if has_encryption_headers(pem) {
        return Err(KeyError::NotEd25519);
    }
    let mut iter = pem::SliceIter::<(SectionKind, Vec<u8>)>::new(pem);
    let (kind, mut der) = match iter.next() {
        Some(Ok(section)) => section,
        Some(Err(_)) => return Err(KeyError::CorruptPem),
        None => return Err(KeyError::NotEd25519),
    };
    if kind != SectionKind::PrivateKey {
        wipe(&mut der);
        return Err(KeyError::NotEd25519);
    }
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der));
    // rustls wraps the DER in `Zeroizing`, so it is wiped on every path.
    let key = rustls::crypto::ring::default_provider()
        .key_provider
        .load_private_key(der)
        .map_err(|_| KeyError::NotEd25519)?;
    if key.algorithm() != SignatureAlgorithm::ED25519 {
        return Err(KeyError::NotEd25519);
    }
    let signer = key
        .choose_scheme(&[SignatureScheme::ED25519])
        .ok_or(KeyError::NotEd25519)?;
    let spki = key.public_key().ok_or(KeyError::NotEd25519)?;
    let public_key = PublicKey::from_spki_der(&spki).map_err(|_| KeyError::NotEd25519)?;
    if public_key.kind() != KeyKind::Ed25519 {
        return Err(KeyError::NotEd25519);
    }
    Ok(Ed25519Key { signer, public_key })
}
