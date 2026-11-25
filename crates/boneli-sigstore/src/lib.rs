//! Offline verification of Sigstore image signatures (ADR-029).
//!
//! Two carriers count as a signature (S1): a layer of cosign's legacy
//! `.sig` manifest, a simple-signing payload with its annotations
//! ([`Evidence::from_cosign_layer`]), and a Sigstore bundle v0.3 with a
//! DSSE envelope over an in-toto statement ([`Evidence::from_bundle`]).
//! A third, a layer of cosign's `.att` manifest (a DSSE envelope with the
//! `.sig` layer's annotations, [`Evidence::from_cosign_attestation`],
//! ADR-036), counts only under a trust with provenance claims.
//! [`verify`] decides whether one of them signs an image digest under a
//! [`Trust`]: keys (ECDSA P-256 and P-384, Ed25519, RSA), or keyless,
//! against the operator's [`TrustedRoot`] (`trusted_root.json`) and
//! [`Identity`]s: the Fulcio chain at every verified time, an embedded
//! SCT, one Rekor entry, and the OIDC issuer and SAN (S2). The entry is
//! Rekor v1's with its inclusion promise (SET) and its body, or, for a
//! bundle, Rekor v2's `hashedrekord` 0.0.2 with its body rebuilt from the
//! bundle, its inclusion proof and a checkpoint the log's key signed
//! (ADR-038). The verified times are Rekor v1's integrated time and the
//! genTime of every RFC 3161 timestamp of a bundle that a timestamp
//! authority of the root verifies (ADR-038); a Rekor v2 entry has no
//! time, so its bundle needs a timestamp.
//!
//! A trust may also carry SLSA provenance claims ([`Claims`], ADR-031):
//! an exact builder ID, a source repository and ref (exact, or a prefix
//! ending in `/`), and resolved dependencies by URI and digest. Such a
//! trust admits only SLSA statements that meet them, read strictly and
//! only after their signature verified: v1, and v0.2 from a cosign `.att`
//! when the trust lists it (ADR-036, the container build type of
//! `slsa-github-generator`); without claims the predicate is never read.
//!
//! A trust of GitHub Actions identities may also carry Fulcio certificate
//! claims ([`CertificateClaims`], ADR-034): the Source Repository URI and
//! Ref Fulcio wrote into the leaf from the OIDC token (exact, or a prefix
//! ending in `/`), the repository's numeric ID, the calling workflow file
//! (the path in the Build Config URI), and a required list of build
//! triggers. They apply to every keyless carrier, `.sig` and `.att` layers
//! included, and are read only from a leaf webpki verified. An opt-in
//! statement agreement also makes an SLSA v1 statement's builder, source
//! repository, ref and source commit equal what the certificate says; a
//! v0.2 statement under it is refused (ADR-036).
//!
//! Finding the evidence is the caller's job (`boneli-oci` reads the
//! registry); everything here is pure, reads no clock, no file and no
//! network, and gives the same verdict for the same bytes forever. The
//! cryptography is `boneli-https`'s (`PublicKey`, `verify_code_signing`,
//! `TimestampToken`, ring through webpki, ADR-029 item 7); this crate owns
//! the formats around it and uses no external crate (S3). Every parser is
//! strict where its output decides, and every refusal is a fixed reason
//! ([`Refusal`]) that echoes none of the input.
//!
//! Out of scope (ADR-029, ADR-038): Rekor v1 inclusion proofs, Rekor v2
//! `dsse` 0.0.2 entries and v2 entries of leaves other than P-256,
//! witness cosignatures and consistency proofs, keyless bundles with no
//! log entry, RFC 3161 timestamps on cosign layers and on keyed
//! signatures, fractional genTimes, TSA revocation,
//! `messageSignature` bundles and bundles before v0.3, Notation, Rekor
//! `intoto` 0.0.2 entries, and `intoto` entries for bundles or `.sig`
//! layers (ADR-037), SLSA v0.2 build types other than the container
//! generator's, certificate claims under issuers other than GitHub
//! Actions (ADR-034), and keeping `trusted_root.json` current (TUF).
#![doc(test(attr(forbid(unsafe_code))))]

mod attestation;
pub mod base64;
mod bundle;
mod checkpoint;
mod cosign;
mod dsse;
mod error;
mod fulcio;
mod hex;
mod identity;
mod json;
mod pem;
mod provenance;
mod rekor;
mod root;
pub mod time;
mod timestamp;
mod verify;

pub use attestation::{DSSE_ENVELOPE_MEDIA_TYPE, PREDICATE_TYPE_ANNOTATION};
pub use bundle::BUNDLE_V03_MEDIA_TYPE;
pub use cosign::{
    BUNDLE_ANNOTATION, CERTIFICATE_ANNOTATION, SIGNATURE_ANNOTATION, SIMPLE_SIGNING_MEDIA_TYPE,
    SIMPLE_SIGNING_TYPE,
};
pub use dsse::{IN_TOTO_PAYLOAD_TYPE, STATEMENT_V01, STATEMENT_V1, pae};
pub use error::{ConfigError, Refusal};
pub use fulcio::{CertificateClaims, CertificateRefusal, Extension, GITHUB_ACTIONS_ISSUER};
pub use identity::{Identity, SanRule};
pub use provenance::{
    ClaimMatch, ClaimRefusal, Claims, GITHUB_WORKFLOW_BUILD_TYPE, Material,
    SLSA_GITHUB_GENERATOR_CONTAINER_BUILD_TYPE,
};
pub use root::{TRUSTED_ROOT_MEDIA_TYPE, TrustedRoot};
pub use verify::{
    Accepted, COSIGN_SIGN_PREDICATE, Evidence, SLSA_PROVENANCE_V1_PREDICATE,
    SLSA_PROVENANCE_V02_PREDICATE, Trust, verify,
};

/// The longest simple-signing payload accepted: 64 KiB. Measured payloads
/// are 239, 295 and 319 bytes; `cosign sign -a` annotations go into
/// `optional`, so 64 KiB is 205 times the largest seen, and 16 of them per
/// carrier (`boneli-oci`'s cap) are 1 MiB of memory. Lower refuses
/// annotated signatures; higher only costs memory (ADR-029, limits).
pub const MAX_PAYLOAD_BYTES: usize = 65_536;

/// The longest bundle accepted, and the longest `.att` DSSE envelope
/// (ADR-036: an envelope is a bundle without its verification material,
/// measured 12,624 to 13,644 bytes), and the bound on every JSON document
/// read from one (the statement, a Rekor body, a cosign bundle annotation):
/// 4 MiB, the document limit of ADR-009 D12. Measured: 4,537 bytes; a
/// DSSE bundle carries the whole statement, and unsigned SLSA provenance
/// already reaches 23,707 bytes (`node:22`), so 4 MiB holds 177 times
/// that. Lower refuses provenance with large material lists; higher only
/// costs memory (ADR-029, limits).
pub const MAX_BUNDLE_BYTES: usize = 4_194_304;

/// The longest `trusted_root.json` accepted: 1 MiB. Measured 6,787 bytes;
/// it grows by about 1 KB per rotated key or CA, so 1 MiB is 154 times
/// today's size. Lower risks refusing a future root; higher only costs
/// memory, read once per configuration (ADR-029, limits).
pub const MAX_TRUSTED_ROOT_BYTES: usize = 1_048_576;

/// The nesting depth of every JSON document read here: 16, the document
/// limit of ADR-009 D12. Measured: bundle 7, trusted root 7; in-toto
/// statements and Rekor bodies are shallower than their bundle.
pub const MAX_JSON_DEPTH: usize = 16;

/// The value count of every JSON document read here: 65,536, the
/// document limit of ADR-009 D12. Measured: bundle 58, trusted root 85.
pub const MAX_JSON_VALUES: usize = 65_536;

/// The most RFC 3161 timestamps a bundle may carry: 32 (ADR-038, limits).
/// Measured: 1 per bundle in 6 of 6. 32 is sigstore-go's
/// `MaxAllowedTimestamps`, so no bundle cosign verifies is refused by
/// count alone; a token costs one parse of about 718 bytes and, per TSA
/// of the root whose window holds its time (1 in the public-good root),
/// one webpki check and one ECDSA verification. Lower refuses bundles
/// cosign accepts; higher only lets a hostile bundle force more checks
/// (the 4 MiB bundle cap alone allows about 4,258 tokens).
pub const MAX_TIMESTAMPS: usize = 32;
