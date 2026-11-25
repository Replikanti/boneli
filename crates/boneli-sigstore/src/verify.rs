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
//!   trusted root and identities. Exactly one log entry. The verified
//!   times (ADR-038, D1): the entry's integrated time when it has an
//!   inclusion promise (inside `i64`, comparable in milliseconds, a Rekor
//!   log of the root that knows it, its SET and its body, `rekor`), and
//!   the genTime of every RFC 3161 timestamp of a bundle that a timestamp
//!   authority of the root verifies (`timestamp`; a token that does not
//!   is skipped, D5); none is `NoTimeSource`, or the first token's
//!   refusal. An entry without a promise must be a bundle's and name a
//!   Rekor v2 log of the root (a Rekor v1 log's is `TlogEntries`, an
//!   unknown log `UnknownLog`, ADR-038 D2). Then, at every verified time,
//!   a Fulcio authority of the
//!   root whose window holds it and whose chain webpki verifies the
//!   certificate through for code signing (only the root's
//!   intermediates); for a Rekor v2 entry, its body rebuilt from the
//!   bundle and the verified leaf, its inclusion proof, the checkpoint the
//!   log signed and the log's window at every verified time
//!   (`rekor::check_v2`, D7); an embedded SCT from a CT log of the root; the
//!   certificate's key verifying the signature; exactly one SAN; the OIDC
//!   issuer from extension 1.3.6.1.4.1.57264.1.8, else 1.1 (both present
//!   and different is refused); and an identity matching issuer and SAN.
//!
//! - **Certificate claims (ADR-034):** under a trust with
//!   [`CertificateClaims`], the keyless leaf that passed must also meet
//!   them (`fulcio`), on every carrier, before any statement is read.
//! - **Claims (ADR-031):** under a trust with [`Claims`], a cosign layer
//!   is refused before any other check (it carries no provenance), and a
//!   bundle or attestation whose signature passed must also meet the
//!   claims (`provenance`), after agreeing with the certificate when the
//!   certificate claims ask for it. A trust without claims never reads
//!   the predicate.
//! - **Attestations (ADR-036):** a cosign `.att` layer counts only under a
//!   trust with claims; without them it is refused before any other check
//!   (`AttestationNeedsClaims`), so the verdict over kept evidence never
//!   differs from a cold pull's, which does not ask for `.att` then. Past
//!   that it is checked exactly as a bundle: predicate type, subject,
//!   signature, certificate claims, then the claims. Its log entry is
//!   Rekor `dsse` 0.0.1, as a bundle's, or `intoto` 0.0.1 over the exact
//!   envelope bytes (ADR-037); a bundle or a cosign layer never takes an
//!   `intoto` entry.
//!
//! No step reads the wall clock: the only times are the log's and the
//! timestamp authorities', so the same inputs give the same verdict
//! forever.

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
use crate::timestamp;

/// The predicate type of `cosign sign` with a bundle, the default list.
pub const COSIGN_SIGN_PREDICATE: &str = "https://sigstore.dev/cosign/sign/v1";
/// The predicate type of SLSA provenance v1, opt-in.
pub const SLSA_PROVENANCE_V1_PREDICATE: &str = "https://slsa.dev/provenance/v1";
/// The predicate type of SLSA provenance v0.2, opt-in and only under
/// claims (ADR-036).
pub const SLSA_PROVENANCE_V02_PREDICATE: &str = "https://slsa.dev/provenance/v0.2";

/// Fulcio's OIDC issuer extensions: 1.3.6.1.4.1.57264.1.1, the raw
/// issuer bytes (deprecated), and 1.3.6.1.4.1.57264.1.8, a DER
/// UTF8String.
const ISSUER_V1: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x01];
const ISSUER_V2: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x08];

/// One candidate signature, parsed from a cosign layer
/// ([`Evidence::from_cosign_layer`]), a bundle
/// ([`Evidence::from_bundle`]) or a cosign attestation layer
/// ([`Evidence::from_cosign_attestation`]).
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
    Bundle(Dsse),
    /// A cosign `.att` layer: its envelope and the SHA-256 of the exact
    /// envelope bytes, which a Rekor `intoto` 0.0.1 entry names (ADR-037).
    Attestation(Dsse, [u8; 32]),
}

/// A DSSE envelope over an in-toto statement, with what verifies it: the
/// content of a bundle and of a cosign attestation alike.
#[derive(Clone)]
pub(crate) struct Dsse {
    pub(crate) payload: Vec<u8>,
    /// PAE(payloadType, payload): the signed bytes.
    pub(crate) message: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) certificate: Option<Vec<u8>>,
    pub(crate) statement: Statement,
    pub(crate) tlogs: Vec<TlogEntry>,
    /// The RFC 3161 tokens of a bundle, DER `TimeStampResp`s, unparsed
    /// (ADR-038); a cosign attestation carries none.
    pub(crate) timestamps: Vec<Vec<u8>>,
}

impl fmt::Debug for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let form = match &self.form {
            Form::Cosign { .. } => "cosign",
            Form::Bundle(_) => "bundle",
            Form::Attestation(..) => "attestation",
        };
        let keyless = self.is_keyless();
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
            Form::Cosign { certificate, .. }
            | Form::Bundle(Dsse { certificate, .. })
            | Form::Attestation(Dsse { certificate, .. }, _) => certificate.is_some(),
        }
    }

    /// The bytes the signature is over.
    fn message(&self) -> &[u8] {
        match &self.form {
            Form::Cosign { payload, .. } => payload,
            Form::Bundle(dsse) | Form::Attestation(dsse, _) => &dsse.message,
        }
    }

    fn signature(&self) -> &[u8] {
        match &self.form {
            Form::Cosign { signature, .. }
            | Form::Bundle(Dsse { signature, .. })
            | Form::Attestation(Dsse { signature, .. }, _) => signature,
        }
    }
}

/// What a rule trusts: keys, a keyless part (a trusted root and the
/// identities it may vouch for), the predicate types a bundle's statement
/// may have, and optionally the SLSA provenance claims (ADR-031) and the
/// Fulcio certificate claims (ADR-034) it must meet.
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
    /// only SLSA statements that meet them, v1 and, when listed, v0.2 from
    /// a cosign attestation (ADR-036). Refused unless the predicate list
    /// holds [`SLSA_PROVENANCE_V1_PREDICATE`] or
    /// [`SLSA_PROVENANCE_V02_PREDICATE`] or both, each once, and nothing
    /// else: a claim list next to another predicate type could never be
    /// met by that type's statements, and a cosign layer would carry none.
    /// A list with v0.2 also needs a claim that names an owner
    /// (`ClaimsWithoutSource`): an exact repository, a repository prefix of
    /// at least `<scheme>://<host>/<owner>/`, or a `git+` repository
    /// material. The v0.2 producer's identity is a builder workflow every
    /// project shares, so a builder or ref claim, or a host-wide prefix,
    /// would accept any project's image.
    pub fn with_claims(self, claims: Claims) -> Result<Trust, ConfigError> {
        let types = &self.predicate_types;
        let known =
            |t: &String| t == SLSA_PROVENANCE_V1_PREDICATE || t == SLSA_PROVENANCE_V02_PREDICATE;
        let repeated = types
            .iter()
            .enumerate()
            .any(|(i, t)| types[..i].contains(t));
        if types.is_empty() || !types.iter().all(known) || repeated {
            return Err(ConfigError::ClaimsPredicateTypes);
        }
        if types.iter().any(|t| t == SLSA_PROVENANCE_V02_PREDICATE) && !claims.names_source() {
            return Err(ConfigError::ClaimsWithoutSource);
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

    /// This trust with Fulcio certificate `claims` (ADR-034): its keyless
    /// signatures then pass only from leaves that meet them. Refused for a
    /// trust with keys (a keyed signature has no certificate), unless
    /// every identity's issuer is exactly [`GITHUB_ACTIONS_ISSUER`] (other
    /// issuers give these extensions other meanings), and for the
    /// statement agreement without provenance claims (set them first), and
    /// for a workflow-path rule with neither a repository rule nor a
    /// repository ID, which would bind no repository.
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
        if claims.path_binds_no_repository() {
            return Err(ConfigError::WorkflowPathWithoutRepository);
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
        /// The integrated time of a Rekor v1 entry with its promise, Unix
        /// seconds; `None` for a Rekor v2 entry, which has none.
        integrated_time: Option<u64>,
        /// How many of the bundle's RFC 3161 timestamps verified
        /// (ADR-038); 0 for a cosign layer or attestation.
        signed_timestamps: usize,
        /// The entry's log index.
        log_index: u64,
        /// The index of the first identity that matched.
        identity: usize,
    },
}

/// Whether `evidence` signs the image digest `subject` (SHA-256) under
/// `trust` (module doc).
pub fn verify(evidence: &Evidence, subject: &[u8; 32], trust: &Trust) -> Result<Accepted, Refusal> {
    if matches!(evidence.form, Form::Attestation(..)) && trust.claims.is_none() {
        return Err(Refusal::AttestationNeedsClaims);
    }
    match &evidence.form {
        Form::Cosign { digest, .. } => {
            if trust.claims.is_some() {
                return Err(Refusal::NotProvenance);
            }
            if digest != subject {
                return Err(Refusal::SubjectMismatch);
            }
        }
        Form::Bundle(Dsse { statement, .. }) | Form::Attestation(Dsse { statement, .. }, _) => {
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
        (Some(claims), Some(cert)) => Some((Facts::read(cert, claims)?, claims)),
    };
    let agreement = match &facts {
        Some((facts, claims)) => fulcio::check(facts, claims)?,
        None => None,
    };
    // Only a statement a trusted signer signed is read for its claims.
    if let (Some(claims), Form::Bundle(dsse) | Form::Attestation(dsse, _)) =
        (&trust.claims, &evidence.form)
    {
        provenance::check(
            &dsse.payload,
            &dsse.statement.predicate_type,
            claims,
            agreement.as_ref(),
        )?;
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
    let (entry, expected, certificate, tokens) = match &evidence.form {
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
            &[][..],
        ),
        Form::Bundle(Dsse {
            payload,
            signature,
            certificate: Some(certificate),
            tlogs,
            timestamps,
            ..
        }) => (
            one_entry(tlogs)?,
            Expected::Dsse {
                payload,
                signature,
                certificate,
            },
            certificate,
            timestamps.as_slice(),
        ),
        Form::Attestation(
            Dsse {
                payload,
                signature,
                certificate: Some(certificate),
                tlogs,
                ..
            },
            envelope,
        ) => (
            one_entry(tlogs)?,
            Expected::Attestation {
                payload,
                signature,
                certificate,
                envelope,
            },
            certificate,
            &[][..],
        ),
        _ => return Err(Refusal::NoCertificate),
    };
    // Time (ADR-038, D1): the SET's integrated time, and the genTime of
    // every token a TSA of the root verifies over the signature bytes.
    let mut times = Vec::new();
    if entry.set.is_some() {
        // The readers refuse a negative time or one above `i64` (Rekor's
        // type), and read one with every promise; what is left must still
        // fit milliseconds in a `u64`.
        let at = entry.integrated_time.ok_or(Refusal::MalformedTlogEntry)?;
        let at_ms = at.checked_mul(1_000).ok_or(Refusal::IntegratedTimeRange)?;
        rekor::check(entry, root, at_ms, &expected)?;
        times.push(at);
    }
    let (verified, first_failure) = timestamp::verified_times(tokens, evidence.signature(), root);
    let signed_timestamps = verified.len();
    times.extend(verified);
    let Some(&first) = times.first() else {
        return Err(first_failure.unwrap_or(Refusal::NoTimeSource));
    };
    // Transparency (D2): a Rekor v1 entry was checked with its promise;
    // an entry without one must be of a Rekor v2 log of the root, and only
    // a bundle's (cosign layers carry a promise always).
    let v2 = match (&entry.set, &expected) {
        (Some(_), _) => None,
        (None, Expected::Dsse { .. }) => {
            if root
                .tlogs
                .iter()
                .any(|log| log.key.key_id() == entry.log_id)
            {
                return Err(Refusal::TlogEntries);
            }
            let log = root
                .note_logs
                .iter()
                .find(|log| log.key_id == entry.log_id)
                .ok_or(Refusal::UnknownLog)?;
            Some(log)
        }
        (None, _) => return Err(Refusal::TlogEntries),
    };
    // The leaf and its CA must be valid at every verified time, so times
    // that contradict each other refuse; the first time gives the leaf.
    let cert = chain(certificate, root, first, first.saturating_mul(1_000))?;
    for &at in &times[1..] {
        chain(certificate, root, at, at.saturating_mul(1_000))?;
    }
    // A Rekor v2 entry is checked against the leaf webpki verified.
    if let Some(log) = v2 {
        rekor::check_v2(
            entry,
            log,
            &times,
            cert.public_key().kind(),
            evidence.message(),
            evidence.signature(),
            certificate,
        )?;
    }
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
        integrated_time: entry.set.as_ref().and(entry.integrated_time),
        signed_timestamps,
        log_index: entry.log_index,
        identity,
    };
    Ok((accepted, cert))
}

/// The one log entry a DSSE carrier must have.
fn one_entry(tlogs: &[TlogEntry]) -> Result<&TlogEntry, Refusal> {
    match tlogs {
        [entry] => Ok(entry),
        _ => Err(Refusal::TlogEntries),
    }
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
