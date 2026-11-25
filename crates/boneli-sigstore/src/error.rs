//! Why a signature was refused, and why a configuration was. Every
//! variant is a fixed rule with a fixed text: no certificate, SAN, payload,
//! key or log text is ever echoed, so a caller may put a `Refusal` into a
//! log line or a pull's failure detail as it is (ADR-029, item 8).

use std::fmt;

use boneli_https::{CertError, SctError, TimestampError};

use crate::fulcio::CertificateRefusal;
use crate::provenance::ClaimRefusal;

/// Why one piece of evidence does not let an image pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The simple-signing payload is longer than
    /// [`MAX_PAYLOAD_BYTES`](crate::MAX_PAYLOAD_BYTES).
    PayloadTooLarge,
    /// The simple-signing payload is not JSON of its shape.
    MalformedPayload,
    /// `critical.type` is not `cosign container image signature`.
    PayloadType,
    /// A digest is not `sha256:` and 64 lower-case hex digits.
    MalformedDigest,
    /// A layer's annotations are not one string per key, or the signature
    /// annotation is missing.
    MalformedAnnotations,
    /// A signature is not canonical base64.
    MalformedSignature,
    /// A certificate is not one canonical PEM or base64 DER certificate.
    MalformedCertificate,
    /// The transparency log entry or its promise cannot be read.
    MalformedTlogEntry,
    /// The bundle is longer than [`MAX_BUNDLE_BYTES`](crate::MAX_BUNDLE_BYTES).
    BundleTooLarge,
    /// The bundle is not JSON of the bundle's shape.
    MalformedBundle,
    /// The bundle is not of media type v0.3, or has a v0.1/v0.2 field.
    BundleVersion,
    /// The bundle holds a `messageSignature`, not a DSSE envelope.
    MessageSignature,
    /// The DSSE envelope has not exactly one signature, or another
    /// `payloadType` than in-toto's.
    DsseShape,
    /// A cosign attestation's DSSE envelope is longer than
    /// [`MAX_BUNDLE_BYTES`](crate::MAX_BUNDLE_BYTES).
    EnvelopeTooLarge,
    /// A cosign attestation's DSSE envelope is not JSON of the envelope's
    /// shape, or its payload is not canonical base64.
    MalformedEnvelope,
    /// The DSSE payload is not an in-toto statement.
    MalformedStatement,
    /// The statement's `_type` is not one the carrier admits: Statement v1
    /// in a bundle, v0.1 or v1 in a cosign attestation.
    StatementType,
    /// The statement's predicate type is not on the trust's list.
    PredicateType,
    /// The evidence does not name the subject's digest.
    SubjectMismatch,
    /// No trusted key verifies the signature, and the evidence is not
    /// keyless or the trust has no keyless part.
    NoTrustedKey,
    /// The trust is keyless only and the evidence has no certificate.
    NoCertificate,
    /// A keyless signature needs exactly one transparency log entry with
    /// an inclusion promise.
    TlogEntries,
    /// The integrated time is too large to compare in milliseconds (a
    /// negative one, or one above `i64`, does not parse).
    IntegratedTimeRange,
    /// The entry's log ID is no transparency log of the trusted root.
    UnknownLog,
    /// The log's key is not valid at the integrated time.
    LogOutsideWindow,
    /// The inclusion promise (SET) does not verify under the log's key.
    SetInvalid,
    /// The entry is not of the kind and version this evidence needs.
    EntryKind,
    /// The entry body does not match the signature, payload or
    /// certificate.
    BodyMismatch,
    /// No certificate authority of the trusted root is valid at a
    /// verified time: the integrated time or a timestamp's (ADR-038).
    NoCaAtTime,
    /// A keyless signature has neither a Rekor v1 inclusion promise nor
    /// an RFC 3161 timestamp that verifies (ADR-038, D1).
    NoTimeSource,
    /// No timestamp authority of the trusted root is valid at a token's
    /// genTime.
    NoTsaAtTime,
    /// The bundle carries more than
    /// [`MAX_TIMESTAMPS`](crate::MAX_TIMESTAMPS) RFC 3161 timestamps.
    TooManyTimestamps,
    /// An RFC 3161 timestamp does not verify (the first one that failed,
    /// when no time source verified).
    Timestamp(TimestampError),
    /// The certificate chain does not verify.
    Certificate(CertError),
    /// No embedded SCT verifies.
    Sct(SctError),
    /// The certificate's key does not verify the signature.
    SignatureInvalid,
    /// The certificate does not hold exactly one subject alternative name.
    SanCount,
    /// The certificate names no OIDC issuer.
    NoIssuer,
    /// The issuer extension 1.3.6.1.4.1.57264.1.8 is not a UTF8String.
    MalformedIssuer,
    /// The two issuer extensions name different issuers.
    IssuerDisagree,
    /// No configured identity matches the issuer and the SAN.
    IdentityMismatch,
    /// The rule has provenance claims and the evidence is a cosign
    /// simple-signing layer, which carries none (ADR-031).
    NotProvenance,
    /// The evidence is a cosign attestation and the rule has no provenance
    /// claims (ADR-036).
    AttestationNeedsClaims,
    /// The SLSA predicate lacks a field the reader models, or one has the
    /// wrong type.
    MalformedProvenance,
    /// The statement names a known build type with a parameter or
    /// invocation member that type does not define.
    UnknownParameters,
    /// The SLSA v0.2 statement of the container generator records
    /// non-empty workflow-dispatch inputs (ADR-036, D1).
    WorkflowInputs,
    /// The rule has a repository or ref claim and the statement's build
    /// type is not one whose source the reader knows.
    UnknownBuildType,
    /// A claim of the rule is not met.
    Claim(ClaimRefusal),
    /// A Fulcio certificate claim of the rule is not met, or the
    /// statement disagrees with the certificate (ADR-034).
    CertificateClaim(CertificateRefusal),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Refusal::PayloadTooLarge => "the signed payload is too large",
            Refusal::MalformedPayload => "the signed payload is malformed",
            Refusal::PayloadType => "the signed payload is not a cosign image signature",
            Refusal::MalformedDigest => "a digest is not sha256 in lower-case hex",
            Refusal::MalformedAnnotations => "the signature annotations are malformed",
            Refusal::MalformedSignature => "the signature is malformed",
            Refusal::MalformedCertificate => "the certificate is malformed",
            Refusal::MalformedTlogEntry => "the transparency log entry is malformed",
            Refusal::BundleTooLarge => "the bundle is too large",
            Refusal::MalformedBundle => "the bundle is malformed",
            Refusal::BundleVersion => "the bundle is not a Sigstore bundle v0.3",
            Refusal::MessageSignature => "the bundle holds a message signature, not DSSE",
            Refusal::DsseShape => "the DSSE envelope is not one in-toto signature",
            Refusal::EnvelopeTooLarge => "the DSSE envelope is too large",
            Refusal::MalformedEnvelope => "the DSSE envelope is malformed",
            Refusal::MalformedStatement => "the in-toto statement is malformed",
            Refusal::StatementType => "the payload is not an in-toto statement of an accepted type",
            Refusal::PredicateType => "the predicate type is not trusted",
            Refusal::SubjectMismatch => "the signature is not over this digest",
            Refusal::NoTrustedKey => "no trusted key verifies the signature",
            Refusal::NoCertificate => "the signature has no certificate",
            Refusal::TlogEntries => {
                "a keyless signature needs exactly one log entry with an inclusion promise"
            }
            Refusal::IntegratedTimeRange => "the integrated time is out of range",
            Refusal::UnknownLog => "the transparency log is not trusted",
            Refusal::LogOutsideWindow => {
                "the transparency log key is not valid at the integrated time"
            }
            Refusal::SetInvalid => "the inclusion promise does not verify",
            Refusal::EntryKind => "the transparency log entry is of the wrong kind",
            Refusal::BodyMismatch => "the transparency log entry does not match the signature",
            Refusal::NoCaAtTime => {
                "no trusted certificate authority is valid at a verified signing time"
            }
            Refusal::NoTimeSource => {
                "a keyless signature needs an inclusion promise or a verified timestamp"
            }
            Refusal::NoTsaAtTime => {
                "no trusted timestamp authority is valid at the timestamp's time"
            }
            Refusal::TooManyTimestamps => "the bundle carries too many timestamps",
            Refusal::Timestamp(_) => "the timestamp does not verify",
            Refusal::Certificate(_) => "the certificate does not verify",
            Refusal::Sct(_) => "no embedded SCT verifies",
            Refusal::SignatureInvalid => "the certificate's key does not verify the signature",
            Refusal::SanCount => "the certificate does not hold exactly one SAN",
            Refusal::NoIssuer => "the certificate names no OIDC issuer",
            Refusal::MalformedIssuer => "the certificate's OIDC issuer is malformed",
            Refusal::IssuerDisagree => "the certificate names two different OIDC issuers",
            Refusal::IdentityMismatch => "the signer is not a trusted identity",
            Refusal::NotProvenance => {
                "the rule requires SLSA provenance claims, which a simple-signing signature does not carry"
            }
            Refusal::AttestationNeedsClaims => {
                "a cosign attestation counts only under a rule with provenance claims"
            }
            Refusal::MalformedProvenance => "the SLSA provenance predicate is malformed",
            Refusal::UnknownParameters => {
                "the provenance has external parameters its build type does not define"
            }
            Refusal::WorkflowInputs => {
                "the provenance records workflow inputs, which can change what was built"
            }
            Refusal::UnknownBuildType => {
                "the provenance's build type is not one whose source the rule can read"
            }
            Refusal::Claim(claim) => return claim.fmt(f),
            Refusal::CertificateClaim(claim) => return claim.fmt(f),
        };
        f.write_str(text)?;
        match self {
            Refusal::Certificate(e) => write!(f, ": {e}"),
            Refusal::Sct(e) => write!(f, ": {e}"),
            Refusal::Timestamp(e) => write!(f, ": {e}"),
            _ => Ok(()),
        }
    }
}

impl std::error::Error for Refusal {}

/// Why a trusted root, an identity, a trust, a claim list or certificate
/// claims were refused at configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The trusted root is longer than
    /// [`MAX_TRUSTED_ROOT_BYTES`](crate::MAX_TRUSTED_ROOT_BYTES).
    RootTooLarge,
    /// The trusted root is not JSON of its shape.
    RootMalformed,
    /// The trusted root's media type is not version 0.1's.
    RootMediaType,
    /// A key of the trusted root is unreadable or of no supported kind.
    RootKey,
    /// A key's `keyDetails` does not name its kind.
    RootKeyDetails,
    /// A log's `hashAlgorithm` is not `SHA2_256`.
    RootHashAlgorithm,
    /// A log's `logId.keyId` is not the SHA-256 of its key.
    RootLogId,
    /// Two logs of the trusted root have the same log ID.
    RootDuplicateLogId,
    /// A `validFor` window ends before it starts.
    RootReversedWindow,
    /// A `validFor` time is not an accepted RFC 3339 timestamp.
    RootTime,
    /// A certificate authority has no certificate, or one is not base64.
    RootCertificate,
    /// An identity's issuer or SAN is empty or not printable ASCII.
    IdentityNotAscii,
    /// A SAN prefix does not end in `/`.
    PrefixWithoutBoundary,
    /// A trust has neither keys nor a keyless part.
    TrustEmpty,
    /// A keyless trust has no identity.
    NoIdentities,
    /// A predicate type is empty or not printable ASCII.
    PredicateTypeNotAscii,
    /// A claim list names no claim (ADR-031).
    ClaimsEmpty,
    /// A claim's text is empty or not printable ASCII.
    ClaimNotAscii,
    /// A repository or ref prefix does not end in `/`.
    ClaimPrefixWithoutBoundary,
    /// A material digest is empty or not lower-case hex.
    MaterialDigestNotHex,
    /// A trust with claims lists a predicate type other than SLSA
    /// provenance v1 and v0.2, one of them twice, or none.
    ClaimsPredicateTypes,
    /// Certificate claims list no build trigger (ADR-034).
    TriggersEmpty,
    /// A repository ID is not ASCII digits without a leading zero.
    RepositoryIdNotDecimal,
    /// A trust with keys was given certificate claims.
    CertificateClaimsWithKeys,
    /// A trust with certificate claims has an identity whose issuer is not
    /// GitHub Actions'.
    CertificateClaimsIssuer,
    /// The statement agreement was asked for on a trust without
    /// provenance claims.
    AgreementWithoutClaims,
    /// A workflow path is empty, not printable ASCII, absolute, holds an
    /// `@`, or has an empty, `.` or `..` segment.
    WorkflowPathNotPlain,
    /// A workflow-path rule is set with neither a source repository rule
    /// (1.12) nor a repository ID (1.15).
    WorkflowPathWithoutRepository,
    /// A trust with claims lists SLSA provenance v0.2 and no claim names an
    /// owner: neither an exact repository, nor a repository prefix of at
    /// least `<scheme>://<host>/<owner>/`, nor a `git+` repository material
    /// whose repository names one (ADR-036, item 4).
    ClaimsWithoutSource,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConfigError::RootTooLarge => "the trusted root is too large",
            ConfigError::RootMalformed => "the trusted root is malformed",
            ConfigError::RootMediaType => "the trusted root is not of media type version 0.1",
            ConfigError::RootKey => "a key of the trusted root is unreadable or unsupported",
            ConfigError::RootKeyDetails => "a key's keyDetails does not match the key",
            ConfigError::RootHashAlgorithm => "a log's hash algorithm is not SHA2_256",
            ConfigError::RootLogId => "a log ID is not the SHA-256 of its key",
            ConfigError::RootDuplicateLogId => "two logs of the trusted root have the same log ID",
            ConfigError::RootReversedWindow => "a validity window ends before it starts",
            ConfigError::RootTime => "a validity time is not an accepted RFC 3339 timestamp",
            ConfigError::RootCertificate => "a certificate authority's chain is malformed",
            ConfigError::IdentityNotAscii => {
                "an identity's issuer or SAN is empty or not printable ASCII"
            }
            ConfigError::PrefixWithoutBoundary => "a SAN prefix does not end in /",
            ConfigError::TrustEmpty => "a trust has neither keys nor a keyless part",
            ConfigError::NoIdentities => "a keyless trust has no identity",
            ConfigError::PredicateTypeNotAscii => {
                "a predicate type is empty or not printable ASCII"
            }
            ConfigError::ClaimsEmpty => "a claim list names no claim",
            ConfigError::ClaimNotAscii => "a claim's text is empty or not printable ASCII",
            ConfigError::ClaimPrefixWithoutBoundary => "a claim prefix does not end in /",
            ConfigError::MaterialDigestNotHex => "a material digest is not lower-case hex",
            ConfigError::ClaimsPredicateTypes => {
                "a trust with claims must list SLSA provenance v1 or v0.2, each at most once, and nothing else"
            }
            ConfigError::ClaimsWithoutSource => {
                "a trust that lists SLSA provenance v0.2 needs an exact source repository, or a repository prefix or material that names an owner"
            }
            ConfigError::TriggersEmpty => "certificate claims list no trigger",
            ConfigError::RepositoryIdNotDecimal => {
                "a repository ID is not a decimal number without a leading zero"
            }
            ConfigError::CertificateClaimsWithKeys => {
                "a trust with keys cannot have certificate claims"
            }
            ConfigError::CertificateClaimsIssuer => {
                "certificate claims need every identity's issuer to be GitHub Actions'"
            }
            ConfigError::AgreementWithoutClaims => {
                "the statement agreement needs provenance claims, set first"
            }
            ConfigError::WorkflowPathNotPlain => {
                "a workflow path is not a plain relative path of printable ASCII without @"
            }
            ConfigError::WorkflowPathWithoutRepository => {
                "a workflow path needs a source repository rule or a repository ID"
            }
        })
    }
}

impl std::error::Error for ConfigError {}
