//! The verdict over one piece of evidence (ADR-029, S2): whether it
//! signs a given digest under a given trust.
//!
//! [`verify`] first checks what is signed: the simple-signing payload's
//! `docker-manifest-digest`, or one of the statement's subjects and its
//! predicate type. Then the signature:
//!
//! - **Keyed:** some trusted key verifies the signature over the signed
//!   bytes (the payload, or DSSE's PAE). Nothing else is checked: keyed
//!   signatures have no transparency and no revocation, and a key is
//!   trusted by configuration alone.
//! - **Keyless:** the evidence carries a certificate and the trust has a
//!   trusted root and identities. Exactly one log entry with an inclusion
//!   promise; its integrated time inside `i64` and comparable in
//!   milliseconds; a Rekor log of the root that knows it, its SET and its
//!   body (`rekor`); a Fulcio authority of the root whose window holds the
//!   integrated time and whose chain webpki verifies the certificate
//!   through for code signing at that time (only the root's
//!   intermediates); an embedded SCT from a CT log of the root; the
//!   certificate's key verifying the signature; exactly one SAN; the OIDC
//!   issuer from extension 1.3.6.1.4.1.57264.1.8, else 1.1 (both present
//!   and different is refused); and an identity matching issuer and SAN.
//!
//! - **Certificate claims (ADR-033):** under a trust with
//!   [`CertificateClaims`], the keyless leaf that passed must also meet
//!   them (`fulcio`), on every carrier, before any statement is read.
//! - **Claims (ADR-031):** under a trust with [`Claims`], a cosign layer
//!   is refused before any other check (it carries no provenance), and a
//!   bundle whose signature passed must also meet the claims
//!   (`provenance`), after agreeing with the certificate when the
//!   certificate claims ask for it. A trust without claims never reads
//!   the predicate.
//!
//! No step reads the wall clock: the only time is the log's, so the same
//! inputs give the same verdict forever.

use std::fmt;
use std::sync::Arc;

use boneli_https::{CertError, CodeSigningCert, PublicKey, verify_code_signing};

use crate::dsse::Statement;
use crate::error::{ConfigError, Refusal};
use crate::fulcio::{self, CertificateClaims, Facts, GITHUB_ACTIONS_ISSUER, utf8_string};
use crate::identity::{Identity, printable};
use crate::provenance::{self, Claims};
use crate::rekor::{self, Expected, TlogEntry};
use crate::root::TrustedRoot;

/// The predicate type of `cosign sign` with a bundle, the default list.
pub const COSIGN_SIGN_PREDICATE: &str = "https://sigstore.dev/cosign/sign/v1";
/// The predicate type of SLSA provenance v1, opt-in.
pub const SLSA_PROVENANCE_V1_PREDICATE: &str = "https://slsa.dev/provenance/v1";

/// Fulcio's OIDC issuer extensions: 1.3.6.1.4.1.57264.1.1, the raw
/// issuer bytes (deprecated), and 1.3.6.1.4.1.57264.1.8, a DER
/// UTF8String.
const ISSUER_V1: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x01];
const ISSUER_V2: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x08];

/// One candidate signature, parsed from a cosign layer
/// ([`Evidence::from_cosign_layer`]) or a bundle
/// ([`Evidence::from_bundle`]).
///
/// `Debug` shows the form only, never the evidence's content.
#[derive(Clone)]
pub struct Evidence {
    pub(crate) form: Form,
}

#[derive(Clone)]
pub(crate) enum Form {
    Cosign {
        payload: Vec<u8>,
        digest: [u8; 32],
        signature: Vec<u8>,
        certificate: Option<Vec<u8>>,
        tlog: Option<TlogEntry>,
    },
    Bundle {
        payload: Vec<u8>,
        /// PAE(payloadType, payload): the signed bytes.
        message: Vec<u8>,
        signature: Vec<u8>,
        certificate: Option<Vec<u8>>,
        statement: Statement,
        tlogs: Vec<TlogEntry>,
    },
}

impl fmt::Debug for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (form, keyless) = match &self.form {
            Form::Cosign { certificate, .. } => ("cosign", certificate.is_some()),
            Form::Bundle { certificate, .. } => ("bundle", certificate.is_some()),
        };
        f.debug_struct("Evidence")
            .field("form", &form)
            .field("keyless", &keyless)
            .finish()
    }
}

impl Evidence {
    /// Whether the evidence carries a signing certificate.
    pub fn is_keyless(&self) -> bool {
        match &self.form {
            Form::Cosign { certificate, .. } | Form::Bundle { certificate, .. } => {
                certificate.is_some()
            }
        }
    }

    /// The bytes the signature is over.
    fn message(&self) -> &[u8] {
        match &self.form {
            Form::Cosign { payload, .. } => payload,
            Form::Bundle { message, .. } => message,
        }
    }

    fn signature(&self) -> &[u8] {
        match &self.form {
            Form::Cosign { signature, .. } | Form::Bundle { signature, .. } => signature,
        }
    }
}

/// What a rule trusts: keys, a keyless part (a trusted root and the
/// identities it may vouch for), the predicate types a bundle's statement
/// may have, and optionally the SLSA provenance claims (ADR-031) and the
/// Fulcio certificate claims (ADR-033) it must meet.
///
/// `Debug` shows the counts only, `claims: true` when claims are set and
/// `certificate_claims: true` when certificate claims are.
#[derive(Clone)]
pub struct Trust {
    keys: Vec<PublicKey>,
    keyless: Option<(Arc<TrustedRoot>, Vec<Identity>)>,
    predicate_types: Vec<String>,
    claims: Option<Claims>,
    certificate_claims: Option<CertificateClaims>,
}

impl fmt::Debug for Trust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("Trust");
        out.field("keys", &self.keys.len())
            .field(
                "identities",
                &self.keyless.as_ref().map_or(0, |(_, ids)| ids.len()),
            )
            .field("predicate_types", &self.predicate_types.len());
        // Named only when set, so a trust without claims reads as in #57.
        if self.claims.is_some() {
            out.field("claims", &true);
        }
        if self.certificate_claims.is_some() {
            out.field("certificate_claims", &true);
        }
        out.finish()
    }
}

impl Trust {
    /// A trust. It needs keys or a keyless part; a keyless part needs an
    /// identity; every predicate type must be non-empty printable ASCII
    /// without spaces. An empty predicate list admits cosign layers only.
    pub fn new(
        keys: Vec<PublicKey>,
        keyless: Option<(Arc<TrustedRoot>, Vec<Identity>)>,
        predicate_types: Vec<String>,
    ) -> Result<Trust, ConfigError> {
        if keys.is_empty() && keyless.is_none() {
            return Err(ConfigError::TrustEmpty);
        }
        if keyless.as_ref().is_some_and(|(_, ids)| ids.is_empty()) {
            return Err(ConfigError::NoIdentities);
        }
        if !predicate_types.iter().all(|p| printable(p)) {
            return Err(ConfigError::PredicateTypeNotAscii);
        }
        Ok(Trust {
            keys,
            keyless,
            predicate_types,
            claims: None,
            certificate_claims: None,
        })
    }

    /// The predicate types a bundle's statement may have.
    pub fn predicate_types(&self) -> &[String] {
        &self.predicate_types
    }

    /// This trust with SLSA provenance `claims` (ADR-031): it then admits
    /// only SLSA v1 statements that meet them. Refused unless the predicate
    /// list is exactly [`SLSA_PROVENANCE_V1_PREDICATE`]: a claim list next
    /// to another predicate type could never be met by that type's
    /// statements, and a cosign layer would carry none.
    pub fn with_claims(self, claims: Claims) -> Result<Trust, ConfigError> {
        if self.predicate_types != [SLSA_PROVENANCE_V1_PREDICATE] {
            return Err(ConfigError::ClaimsPredicateTypes);
        }
        Ok(Trust {
            claims: Some(claims),
            ..self
        })
    }

    /// The SLSA provenance claims, if any.
    pub fn claims(&self) -> Option<&Claims> {
        self.claims.as_ref()
    }

    /// This trust with Fulcio certificate `claims` (ADR-033): its keyless
    /// signatures then pass only from leaves that meet them. Refused for a
    /// trust with keys (a keyed signature has no certificate), unless
    /// every identity's issuer is exactly [`GITHUB_ACTIONS_ISSUER`] (other
    /// issuers give these extensions other meanings), and for the
    /// statement agreement without provenance claims (set them first).
    pub fn with_certificate_claims(self, claims: CertificateClaims) -> Result<Trust, ConfigError> {
        if !self.keys.is_empty() {
            return Err(ConfigError::CertificateClaimsWithKeys);
        }
        let github = self
            .keyless
            .as_ref()
            .is_some_and(|(_, ids)| ids.iter().all(|id| id.issuer() == GITHUB_ACTIONS_ISSUER));
        if !github {
            return Err(ConfigError::CertificateClaimsIssuer);
        }
        if claims.agreement && self.claims.is_none() {
            return Err(ConfigError::AgreementWithoutClaims);
        }
        Ok(Trust {
            certificate_claims: Some(claims),
            ..self
        })
    }

    /// The Fulcio certificate claims, if any.
    pub fn certificate_claims(&self) -> Option<&CertificateClaims> {
        self.certificate_claims.as_ref()
    }
}

/// How evidence passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepted {
    /// The trust's key at this index verified the signature.
    Keyed {
        /// The index into the trust's keys.
        key: usize,
    },
    /// A certificate of the trusted root, logged in Rekor.
    Keyless {
        /// The integrated time, Unix seconds.
        integrated_time: u64,
        /// The entry's log index.
        log_index: u64,
        /// The index of the first identity that matched.
        identity: usize,
    },
}

/// Whether `evidence` signs the image digest `subject` (SHA-256) under
/// `trust` (module doc).
pub fn verify(evidence: &Evidence, subject: &[u8; 32], trust: &Trust) -> Result<Accepted, Refusal> {
    match &evidence.form {
        Form::Cosign { digest, .. } => {
            if trust.claims.is_some() {
                return Err(Refusal::NotProvenance);
            }
            if digest != subject {
                return Err(Refusal::SubjectMismatch);
            }
        }
        Form::Bundle { statement, .. } => {
            if !trust.predicate_types.contains(&statement.predicate_type) {
                return Err(Refusal::PredicateType);
            }
            if !statement.subjects.contains(subject) {
                return Err(Refusal::SubjectMismatch);
            }
        }
    }
    let (accepted, cert) = signature(evidence, trust)?;
    // Fulcio's facts first: no statement is read for a leaf that fails.
    let facts = match (&trust.certificate_claims, &cert) {
        (None, _) => None,
        (Some(_), None) => return Err(Refusal::NoCertificate),
        (Some(claims), Some(cert)) => Some((Facts::read(cert)?, claims)),
    };
    let agreement = match &facts {
        Some((facts, claims)) => fulcio::check(facts, claims)?,
        None => None,
    };
    // Only a statement a trusted signer signed is read for its claims.
    if let (Some(claims), Form::Bundle { payload, .. }) = (&trust.claims, &evidence.form) {
        provenance::check(payload, claims, agreement.as_ref())?;
    }
    Ok(accepted)
}

/// The signature checks of [`verify`], after the subject check: a trusted
/// key, else the keyless path, which also gives the verified leaf.
fn signature(
    evidence: &Evidence,
    trust: &Trust,
) -> Result<(Accepted, Option<CodeSigningCert>), Refusal> {
    let message = evidence.message();
    let signature = evidence.signature();
    if let Some(key) = trust
        .keys
        .iter()
        .position(|key| key.verify(message, signature).is_ok())
    {
        return Ok((Accepted::Keyed { key }, None));
    }
    let (Some((root, identities)), true) = (&trust.keyless, evidence.is_keyless()) else {
        return Err(if trust.keys.is_empty() {
            Refusal::NoCertificate
        } else {
            Refusal::NoTrustedKey
        });
    };
    let (accepted, cert) = keyless(evidence, root, identities)?;
    Ok((accepted, Some(cert)))
}

/// The keyless path of [`verify`], after the subject check; gives the
/// leaf webpki verified too.
fn keyless(
    evidence: &Evidence,
    root: &TrustedRoot,
    identities: &[Identity],
) -> Result<(Accepted, CodeSigningCert), Refusal> {
    let (entry, expected, certificate) = match &evidence.form {
        Form::Cosign {
            payload,
            signature,
            certificate: Some(certificate),
            tlog,
            ..
        } => (
            tlog.as_ref().ok_or(Refusal::TlogEntries)?,
            Expected::HashedRekord {
                payload,
                signature,
                certificate,
            },
            certificate,
        ),
        Form::Bundle {
            payload,
            signature,
            certificate: Some(certificate),
            tlogs,
            ..
        } => {
            let [entry] = tlogs.as_slice() else {
                return Err(Refusal::TlogEntries);
            };
            (
                entry,
                Expected::Dsse {
                    payload,
                    signature,
                    certificate,
                },
                certificate,
            )
        }
        _ => return Err(Refusal::NoCertificate),
    };
    // The readers refuse a negative time or one above `i64` (Rekor's type);
    // what is left must still fit milliseconds in a `u64`.
    let at = entry.integrated_time;
    let at_ms = at.checked_mul(1_000).ok_or(Refusal::IntegratedTimeRange)?;
    rekor::check(entry, root, at_ms, &expected)?;
    let cert = chain(certificate, root, at, at_ms)?;
    cert.verify_embedded_sct(&root.ctlogs)
        .map_err(Refusal::Sct)?;
    cert.public_key()
        .verify(evidence.message(), evidence.signature())
        .map_err(|_| Refusal::SignatureInvalid)?;
    let [san] = cert.sans() else {
        return Err(Refusal::SanCount);
    };
    let issuer = issuer(&cert)?;
    let identity = identities
        .iter()
        .position(|id| id.matches(issuer, san))
        .ok_or(Refusal::IdentityMismatch)?;
    let accepted = Accepted::Keyless {
        integrated_time: at,
        log_index: entry.log_index,
        identity,
    };
    Ok((accepted, cert))
}

/// The certificate, verified through the first authority whose window
/// holds `at_ms` and whose chain verifies it at `at` (seconds). Windows
/// may overlap (the public-good root's do); a refusal names the most
/// telling error: `UnknownIssuer` only when no authority knew the issuer.
fn chain(der: &[u8], root: &TrustedRoot, at: u64, at_ms: u64) -> Result<CodeSigningCert, Refusal> {
    let mut error = None;
    for authority in root.authorities.iter().filter(|a| a.window.contains(at_ms)) {
        let intermediates: Vec<&[u8]> = authority.intermediates.iter().map(Vec::as_slice).collect();
        match verify_code_signing(der, &intermediates, &[&authority.root], at) {
            Ok(cert) => return Ok(cert),
            Err(e) if error.is_none() || error == Some(CertError::UnknownIssuer) => {
                error = Some(e);
            }
            Err(_) => {}
        }
    }
    Err(error.map_or(Refusal::NoCaAtTime, Refusal::Certificate))
}

/// The OIDC issuer of a Fulcio certificate (module doc).
fn issuer(cert: &CodeSigningCert) -> Result<&[u8], Refusal> {
    let v2 = match cert.extension(ISSUER_V2) {
        None => None,
        Some(value) => Some(utf8_string(value).ok_or(Refusal::MalformedIssuer)?),
    };
    match (v2, cert.extension(ISSUER_V1)) {
        (Some(a), Some(b)) if a != b => Err(Refusal::IssuerDisagree),
        (Some(a), _) => Ok(a),
        (None, Some(b)) => Ok(b),
        (None, None) => Err(Refusal::NoIssuer),
    }
}
