# ADR-029: Image signatures and provenance

- Status: accepted
- Date: 2026-11-24

## Context

ADR-009 pins every image by digest and checks every byte against it, so
the store unpacks exactly the bytes the pinned digest names. It does not
show who built or published that digest. When a reference comes from a
customer or from an agent (`docs/ARCHITECTURE.md`, plan step 3), digest
pinning trusts whoever chose the digest. Issue #57 asks for a policy under
which the store refuses an image, before it unpacks anything, unless the
digest carries a valid signature or provenance attestation from a
configured trust root.

Measured on 2026-11-20 through the anonymous registry API (and on
2026-11-23 for the captures that PR 1 commits,
`crates/boneli-https/tests/data/README.md`):

- **Docker Official Images are unsigned.** `library/node` index
  `sha256:e13726ca…`, the digest the weekly acceptance pins, has no
  signature anywhere: the `.sig`, `.att` and `sha256-<hex>` tags all
  return 404 and the referrers API returns 200 with an empty list; its
  amd64 manifest gives the same answers. The index carries BuildKit
  attestation manifests (`unknown/unknown`) whose layers are plain
  unsigned `application/vnd.in-toto+json`: an SPDX SBOM of 16,149,600 B
  and SLSA provenance v0.2 of 23,707 B. Whoever can push the index can
  write them.
- **Kubernetes** (`pause:3.10`, through Artifact Registry): one keyless
  `.sig` layer. The SAN is an email, the issuer
  `https://accounts.google.com`, the certificate is valid for 10 minutes
  and carries an embedded SCT. The Rekor entry is `hashedrekord` 0.0.1
  with a SET; the `.sig` manifest is 5,924 B. The referrers API answers
  `"manifests": null`. `registry.k8s.io` itself answers manifest requests
  with `307`, so it is not pullable today (ADR-009 D10).
- **Chainguard** `node` index `sha256:3fb5318a…`, on `cgr.dev` and with
  the same digest on Docker Hub as `chainguard/node`: one keyless `.sig`
  layer. The SAN is the URI
  `https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main`,
  the issuer `https://token.actions.githubusercontent.com`. The leaf is
  P-256, signed with ECDSA-SHA384, valid for 10 minutes, with a
  2-certificate chain annotation and a Rekor v1 SET. The payload is 239 B
  of simple signing whose `docker-manifest-digest` is the index digest;
  the manifest is 9,958 B. Chainguard signs again from time to time and
  replaces the `.sig` tag: the 2026-11-20 capture had `integratedTime`
  1795194128, the 2026-11-23 one 1795470488.
- **cosign images on GHCR:** v2.4.1 and v3.0.2 carry a legacy `.sig` with
  2 layers each, the first keyed (signature and bundle annotations, no
  certificate). The current `latest` has no `.sig`; it carries 2 Sigstore
  bundle v0.3 referrers (`artifactType
  application/vnd.dev.sigstore.bundle.v0.3+json`, 4,537 B, JSON depth 7,
  58 values). The one inspected holds a keyed DSSE in-toto statement with
  predicate `https://sigstore.dev/cosign/sign/v1` whose subject is the
  index digest, a Rekor v1 `dsse` 0.0.1 entry with inclusion promise and
  inclusion proof, and an RFC 3161 timestamp. GHCR's referrers API returns
  404, so these bundles are reachable only through the tag
  `sha256-<hex>`; where no referrers tag exists, GHCR answers that tag with
  the image's own index (identical SHA-256 for v2.4.1 and v3.0.2).
- **Docker Hub and `cgr.dev`** answer the referrers API with 200 and an
  empty list.
- **Sigstore public-good `trusted_root.json`** (`sigstore/root-signing`,
  6,787 B, depth 7, 85 values): Rekor v1 `rekor.sigstore.dev` (ECDSA
  P-256, since 2021-01-12), whose log ID matches the measured 2026
  entries; Rekor v2 `log2025-1.rekor.sigstore.dev` (Ed25519, since
  2025-09-23); two Fulcio CA entries with overlapping windows, 2021-03-07
  to 2022-12-31 and from 2022-04-13 with no end, whose intermediate
  carries the Code Signing EKU and whose root is valid until 2031-10-05;
  two CT logs (P-256), `ctfe.sigstore.dev/test` (2021-03-14 to 2022-10-31)
  and `ctfe.sigstore.dev/2022` (from 2022-10-20); and one TSA.
- **Dependencies.** `sigstore` 0.15.0 pulls 108 crates with no features,
  tokio, serde, serde_json, thiserror and tracing among them; with
  `verify` and `rustls-tls` 209, adding reqwest, hyper, anyhow and
  aws-lc-sys; the default features 282. `sigstore-verify` 0.16.0 pulls 50
  crates without default features, serde, serde_json, thiserror, tracing
  and the proc macros `serde_derive` and `der_derive` among them, and its
  `sigstore-crypto` has only an aws-lc-rs backend. Every one of these trees
  contains crates on `deny.toml`'s list. The whole external graph of the
  workspace is 36 crate names today.
- **Public key sizes.** An RSA-8192 SPKI PEM is 1,491 B, or 4,968 B with
  `openssl pkey -pubin -text` in front; a P-256 PEM is 178 B.
- **What webpki 0.103.17 does with a code-signing chain.**
  `KeyUsage::required(id-kp-codeSigning)` is checked on the leaf and on
  every intermediate on the path (`check_issuer_independent_properties`
  for each), not on the anchor; a leaf with `CA:TRUE` is
  `CaUsedAsEndEntity`; validity is inclusive at both ends
  (`check_validity`); a leaf whose SCT list extension is not an OCTET
  STRING is refused at parse time, while the list itself is only parsed on
  demand (`webpki::sct` exposes log IDs and timestamps, no signature
  check).

## Decision

The decisions of STOP 1 (S1 to S6), all as recommended, then what each
of the three PRs of #57 builds. PR 1 builds item 7, PR 2 item 8 and PR 3
item 9, each with the limits it names; this ADR became `accepted` in PR 3
after the acceptance run.

1. **What counts as a signature (S1).** cosign's legacy `.sig` tag with
   simple-signing layers, and Sigstore bundles v0.3 found as OCI 1.1
   referrers (the referrers API, else the `sha256-<hex>` tag schema), with
   DSSE content only. A `messageSignature` bundle or a bundle older than
   v0.3 is a failed candidate. Basis: the legacy `.sig` covers Kubernetes,
   Chainguard (also on Docker Hub) and cosign 2.x/3.0.x; bundles cover
   cosign's current releases; BuildKit attestations are unsigned and
   prove nothing; no measured image uses Notation, which has no Rust
   implementation. Weak spot: two carriers mean two parsers, and an image
   signed only with Notation or only through `.att` is refused under
   `Required`.

2. **Trust roots and identities (S2).** Keys: ECDSA P-256 and P-384,
   Ed25519, RSA 2,048 to 8,192 bits. Keyless: the Fulcio chain verified by
   webpki at the Rekor-integrated time with the Code Signing EKU, with
   intermediates from the trusted root only; at least one embedded SCT
   from a CT log of the root; a Rekor v1 inclusion promise (SET) whose
   entry body matches the signature, payload and certificate. The trusted
   root is `trusted_root.json` supplied by the operator as bytes, with no
   embedded copy and no TUF client. An identity is the OIDC issuer,
   matched exactly, plus the SAN: an exact email, an exact URI, or a URI
   prefix that ends in `/`; no regex. Rekor v2 entries and TSA-only
   time are refused (follow-up). Basis: a Fulcio leaf lives 10
   minutes (both measured leaves), so its validity can only be checked at
   the log's time, never at the wall clock; every measured 2026 signature
   is in Rekor v1 with a SET; Fulcio's documented SAN form for GitHub
   workflows is `<workflow>@<ref>`, so a workflow that releases from tags
   gets a SAN ending in `@refs/tags/<version>`, and exact matching alone
   would need a policy edit for every release. **Changed at review of PR
   2 (operator decision):** STOP 1 accepted `/` or `@` as the prefix
   boundary; `@` is dropped. A prefix ending in `@` (`…/release.yaml@`)
   trusts every ref the workflow can run at, any branch, any commit SHA
   and `refs/pull/N/merge`, so anyone who may push a branch to the
   repository could add `id-token: write` on that branch and sign as the
   release workflow: the SAN is the `job_workflow_ref` of GitHub's OIDC
   token, which names the ref the job ran at. Tag releases are covered by `…@refs/tags/`, which ends in
   `/`, and a protected branch by its exact SAN (`…@refs/heads/main`);
   `…@refs/heads/` trusts every branch and has to be written out on
   purpose.

3. **Where the code lives (S3).** The ring- and webpki-backed primitives
   go into `boneli-https`, where ring already is (ADR-005, ADR-009 D6,
   ADR-014 D4). The Sigstore formats and trust evaluation go into a new
   support crate, `boneli-sigstore`, whose dependencies are `boneli-https`
   and `boneli-json`, with no external crate and no new external edge.
   Discovery and policy stay in `boneli-oci`. Tests outside
   `boneli-https` sign at test time with `boneli_https::RsaSha256Key` and
   RSA test keys made by `openssl`, so the synthetic test PKI there is RSA
   and the real known answers cover ECDSA; a test-only `boneli-sigstore ->
   ring` edge would take ring outside its one crate. `boneli-sigstore`
   joins the always-review list. Rust was the language of every option:
   the alternatives were Rust crates and our own Rust code.

4. **Policy (S4).** Two modes, `Off` and `Required`. Rules are keyed by
   registry (exactly `Registry::name()`) and repository (exact, or a
   prefix ending in `/`); the most specific rule wins and the default is
   `Off`. Under `Required` only a verified candidate lets the pull pass;
   errors, absences and caps never do. Why the default is `Off`: every
   first-stack image (Docker Official Images) is unsigned, so `Required`
   by default would refuse the M0 demo images.

5. **Provenance (S5).** A signed in-toto statement (DSSE) counts when its
   predicate type is on the rule's list. The default list is
   `https://sigstore.dev/cosign/sign/v1`; `https://slsa.dev/provenance/v1`
   is opt-in. Its claims (builder, source, materials) are not evaluated
   here, and unsigned BuildKit provenance never counts.

6. **Warm pulls (S6).** The verified evidence is kept by digest,
   re-hashed on read, with one pointer file per subject, and re-verified
   offline under the current policy on every pull. That keeps ADR-009
   D8's "a pull of an image already in the store makes no request", and
   with it the tolerance of registry outages. The evidence directory
   follows ADR-009 D8, ADR-021 and the lock rules of ADR-025, ADR-026 and
   ADR-028.

7. **The primitives in `boneli-https` (PR 1).**
   - **`PublicKey`.** `from_pem` reads exactly one `PUBLIC KEY` section of
     at most `MAX_PUBLIC_KEY_PEM_LEN` bytes, counted by its markers as
     `RsaSha256Key` counts them; `from_spki_der` reads a whole
     SubjectPublicKeyInfo strictly: an uncompressed point of 65 (P-256)
     or 97 (P-384) bytes, 32 bytes of Ed25519, an RSAPublicKey whose
     modulus is a positive minimal INTEGER of 2,048 to 8,192 bits, and
     rsaEncryption only with its NULL parameters. `key_id` is the SHA-256
     of the SPKI DER, RFC 6962's log ID, which Rekor uses too. `verify`
     uses the webpki algorithms of rustls' ring provider, as ADR-020
     does, with the algorithm fixed by the key kind: P-256 →
     `ECDSA_P256_SHA256`, P-384 → `ECDSA_P384_SHA384`, Ed25519 →
     `ED25519`, RSA → `RSA_PKCS1_2048_8192_SHA256`. The input never
     chooses it, so a P-256 key's valid ECDSA-SHA384 signature does not
     verify. Errors are fixed text, and `Debug` prints the kind only.
   - **`verify_code_signing`.** webpki's `verify_for_usage` with
     `KeyUsage::required(id-kp-codeSigning)` at the caller's `at_secs`,
     with the caller's intermediates and roots only and no CRL (Fulcio
     publishes none and its leaves expire in minutes). webpki's errors map
     to fixed reasons (`NotCodeSigning`, `IsCa`, `OutsideValidity`,
     `UnknownIssuer`, `Invalid`). Because webpki demands the EKU of every
     intermediate, an intermediate without it refuses the chain; Sigstore's
     public-good intermediate carries it.
   - **The readers of `CodeSigningCert`,** which decide in PR 2, read the
     leaf webpki accepted with the DER reader of ADR-017 item 9, strictly:
     an extension OID seen twice refuses the leaf; `sans()` returns
     `Email`, `Uri` or `Other` in certificate order, and an `rfc822Name`,
     `dNSName` or URI that is not ASCII refuses the leaf; `extension(oid)`
     returns the raw `extnValue` contents; a leaf key of no supported kind
     refuses the leaf.
   - **`verify_embedded_sct`** follows RFC 6962 3.2: v1 SCTs only (other
     versions are skipped by their length); the precertificate TBS is the
     leaf's TBS with the SCT list extension removed, every other field and
     extension byte for byte, the lengths re-encoded, and without the
     `[3]` field when the list was the only extension (as Go's
     `x509.RemoveSCTList`); the issuer key hash is the SHA-256 of the
     issuer SPKI on webpki's verified path. An SCT counts when its log ID
     is the key ID of a listed `CtLog`, its timestamp lies in that log's
     window, its algorithm is SHA-256 with the key's kind (ECDSA for
     P-256, RSA for RSA), and its signature verifies; at least one must.
     A list that is malformed anywhere is an error, not a skip.
   - **The DER reader** moves from `src/revocation/der.rs` to `src/der.rs`
     unchanged but for `read_tlv`, wider visibility of three tag
     constants and a test-only time encoder shared with the OCSP tests.

8. **The Sigstore formats (PR 2)**, in the support crate `boneli-sigstore`
   (dependencies `boneli-https` and `boneli-json`, no external crate).
   Every reader is strict where its output decides, and every refusal is
   a fixed `Refusal` or `ConfigError` reason that echoes no certificate,
   SAN, key or payload text.
   - **Encodings.** Base64 of RFC 4648 section 4 with padding, canonical
     trailing bits and nothing outside the alphabet, so every value has
     one encoding and the SET's rebuilt bytes equal the input. RFC 3339
     only as `YYYY-MM-DDTHH:MM:SS[.f{1,9}]Z` from 1970 on, no leap second;
     a sub-millisecond fraction rounds a window's start up and its end
     down. Digests and log IDs in lower-case hex only. Certificates in
     annotations and Rekor bodies only as Go's `pem.Encode` writes them
     (one `CERTIFICATE` block, `\n`, lines of at most 64). Integers: JSON
     numbers in cosign's annotation, protobuf int64 strings in canonical
     decimal in bundles, both from 0 to `i64::MAX` (Rekor's type).
   - **`TrustedRoot::from_json`.** Media type
     `application/vnd.dev.sigstore.trustedroot+json;version=0.1` byte for
     byte; `tlogs`, `certificateAuthorities` and `ctlogs` (absent means
     empty, as protobuf JSON omits empty lists); `timestampAuthorities`,
     `baseUrl`, `uri` and `subject` are not read. Each log: `hashAlgorithm`
     `SHA2_256`, a key `PublicKey` supports, `keyDetails` naming that key's
     kind, `validFor.start` required. A CA: its chain, the last
     certificate the anchor and the others the only intermediates, and
     its window. No log ID twice across Rekor and CT logs, no reversed
     window. **Learned in PR 2:** the public-good root's Rekor v2 log
     (`log2025-1`) carries its signed-note key ID as `logId.keyId`, not
     the SHA-256 of its key, so a Rekor log whose `keyId` is not that
     hash is read, checked and left out (a v2 log issues no SET, and
     entries are looked up by the SHA-256 of the key, never by the file's
     `keyId`); a CT log with such a `keyId` refuses the file, because RFC
     6962 defines the log ID so. A left-out key still counts for the
     duplicate check, so the same key once kept and once left out is
     refused like any duplicate (review of PR 2; the public-good root has
     no such pair and reads). A key of a kind `PublicKey` does not
     support refuses the whole file: the operator keeps the file that
     worked.
   - **Identities.** Issuer and SAN text non-empty and from `!` to `~`; a
     `UriPrefix` ends in `/` (S2, `@` dropped at review); byte-exact
     matching, an email rule never matches a URI SAN and the reverse.
   - **cosign layers** (`Evidence::from_cosign_layer`): the signature
     annotation required, the certificate optional (absent or empty is a
     keyed signature), the Rekor bundle annotation optional; a key the
     reader uses that occurs twice refuses the layer; the chain annotation
     is never read. The payload: at most `MAX_PAYLOAD_BYTES`,
     `critical.type` exact, `critical.image.docker-manifest-digest` exact
     form.
   - **Bundles** (`Evidence::from_bundle`): media type
     `application/vnd.dev.sigstore.bundle.v0.3+json` only; a
     `messageSignature` is refused; exactly one of `certificate` and
     `publicKey` (whose hint is not read, so it cannot pick a key);
     `x509CertificateChain`, the v0.1/v0.2 field, is refused as a version
     mismatch rather than ignored, so a chain sent along is never parsed;
     DSSE with in-toto's payload type and exactly one signature over PAE;
     an in-toto Statement v1 whose subjects match by `digest.sha256`; each
     log entry's `kindVersion` must name its body's kind and version, as
     sigstore-go requires.
   - **Rekor v1** (`rekor.rs`). The SET is verified under the key of the
     root's Rekor log whose key SHA-256 is the entry's log ID, inside
     that log's window, over the JCS bytes
     `{"body":…,"integratedTime":…,"logID":…,"logIndex":…}` that we build
     from validated parts; the real Kubernetes, Chainguard and cosign
     entries verify (`jcs_matches_rekor`). The body must say what the
     evidence says, field by field as sigstore-go's `VerifyTlogEntry`
     compares Rekor v1 entries: `hashedrekord` 0.0.1 for a cosign layer
     (SHA-256 of the payload, the signature, the certificate DER) and
     `dsse` 0.0.1 for a bundle (SHA-256 of the DSSE payload, exactly one
     signature with the certificate as verifier). The `dsse` body's
     `envelopeHash` is not checked: Rekor hashed the envelope as cosign
     submitted it, and the bundle carries no copy of those bytes.
   - **`verify(evidence, subject, trust)`.** What is signed first: the
     payload's digest, or the statement's predicate type on the trust's
     list and one subject naming the digest. Then any trusted key that
     verifies the signature over the signed bytes passes (keyed). A
     keyless candidate needs a certificate, exactly one log entry with an
     inclusion promise, an integrated time that fits milliseconds in a
     `u64`, the Rekor check above, a CA whose window holds the integrated
     time and whose chain webpki verifies the certificate through at that
     time (overlapping windows: any such CA), an embedded SCT from a CT
     log of the root, the certificate's key verifying the signature,
     exactly one SAN, the issuer from 1.3.6.1.4.1.57264.1.8 (a DER
     UTF8String) else 1.1 (both present and different refused), and a
     matching identity. `Trust::new` refuses a trust with neither keys nor
     a keyless part, a keyless part without identities, and a predicate
     type that is empty or not printable ASCII; an empty predicate list
     admits cosign layers only.
   - **Fixtures** (`crates/boneli-sigstore/tests/data/README.md`):
     captured again on 2026-11-24 with the same SHA-256 for both `.sig`
     manifests and `trusted_root.json` as on 2026-11-20 and 2026-11-23;
     cosign's `latest` is now v3.1.4 (index `sha256:0f061548…`), its first
     bundle referrer a keyed DSSE whose key hint is the SHA-256 of
     `release-cosign.pub`'s SPKI (checked). The synthetic instance (RSA
     root, intermediate with the Code Signing EKU, Fulcio-shaped leaves
     with issuer extensions and SCTs, test CT log and Rekor) is built at
     test time and signed with `RsaSha256Key`.

9. **Discovery and policy (PR 3)**, in `boneli-oci`.
   - **Policy.** `StoreConfig::signatures`, `SignaturePolicy::off()` by
     default. `SignaturePolicy::new(default, rules)` refuses two rules
     with one registry and scope and a prefix that is not repository
     components (ADR-009 D9) ending in `/` (`Error::InvalidPolicy`);
     `OciImageStore::open` refuses a rule for a registry that is neither
     the default nor listed, before it creates anything. The lookup ranks
     an exact repository over any prefix, a longer prefix over a shorter
     one, a prefix over the registry-wide rule and that over the default,
     and reads the repository as written (`node` is not `library/node`).
     A `Trust` is never empty (`Trust::new`), so `Required` needs no
     check of its own.
   - **Where it runs.** After the first `resolve_with` and before any
     layer is pinned or its blob requested; with no `Required` rule
     nothing of this item runs, and the request log of #7, recorded at
     the merge base, is unchanged byte for byte (`policy_off_requests_unchanged`).
   - **Order.** The kept evidence of every subject first, offline, then
     discovery subject by subject (the named digest, then the platform
     manifest), the `.sig` carrier before the referrers carrier, and the
     first verified candidate ends the check. **Learned in PR 3:** the
     plan's "per subject, the pointer first, then discovery" would make
     the warm pull of an image signed only on its platform manifest
     discover the index's signatures over the network on every pull;
     checking every pointer before any request keeps S6's "no request".
   - **Fetches** (`registry.rs`): a signature tag (`sha256-<hex>.sig`,
     `sha256-<hex>`, built only from a digest) and the referrers listing
     are read like a manifest of at most the document limit: `200` is the
     document, `404` is absent, every other status and any redirect is
     an error, and a second `401` is `Failed`, never `NotFound`. A
     payload or bundle is a blob of at most `MAX_PAYLOAD_BYTES` or
     `MAX_BUNDLE_BYTES`, size and digest exact, checked before the
     request, redirects as for every blob (D10). Deadlines are D12's.
   - **Parsers** (`signatures.rs`): an artifact manifest is an OCI or
     Docker schema 2 manifest by the rule of `parse_document` (field, else
     `Content-Type`), with a config of any media type, layers with string
     annotations and optional `artifactType` and `subject`; a listing is
     an OCI index (schema 2, `manifests` an array or `null`) whose entries
     are descriptors with optional `artifactType` and string annotations,
     `platform` not read. Media types, artifact types and the predicate
     annotation `dev.sigstore.bundle.predicateType` compare byte for
     byte. A referrer counts only when its manifest names the subject,
     the bundle artifact type and exactly one layer of the bundle media
     type. A tag-schema answer whose SHA-256 is the subject's lists
     nothing.
   - **Failure detail.** `signature policy: no trusted signature for
     <subjects> in <repository>: …`, per subject and carrier the count
     listed and at most one fixed reason per candidate (a `Refusal`, a
     parser's fixed text, or the fetch error's detail of hosts, digests
     and statuses); every character outside printable ASCII is escaped.
   - **Kept evidence** (S6): every artifact fetched that parsed (the
     `.sig` manifest, payloads, referrer manifests, bundles) is kept in
     `blobs/sha256/` with its `.type`, re-hashed on every read, and only
     when the store does not hold that digest yet; the pointer file
     `signatures/sha256/<subject hex>` holds up to `MAX_KEPT` = 32 lines,
     each `legacy <manifest> <payload>` or `bundle <manifest> <bundle>`,
     none twice, parsed exactly and written by the store's
     `write_durably` under an owned temporary name. The warm check tries
     every line under the current trust; a pass adds its line last,
     drops lines whose blobs are gone, and past 32 the oldest.
     **Changed at review of PR 3:** one line per subject, replaced on
     every pass, let two `Required` rules with different trusts over one
     digest overwrite each other's evidence, so a warm pull under the
     first went back to the network (and failed in a registry outage)
     after a pull under the second. 32 is every candidate the two
     carriers can list for one subject at once (2 × `MAX_SIGNATURES`),
     so while the listings stay as they are no rule's evidence is pushed
     out, at 4,832 bytes per file at most. Two stores that add a line at
     once may lose one; its rule then discovers again.
   - **Kept documents and their type** (review of PR 3). A kept
     document's bytes are its digest's, but its `.type` is what the
     response that brought it said, and a registry chooses it: a `.sig`
     answer, or an index in another repository, can serve another
     image's bytes under another type. So a signature lookup never
     replaces a kept document and keeps only what parsed, and the
     resolution of ADR-009 D9 takes a kept index or manifest only when
     it parses and is what the index names (its media type); otherwise
     it fetches the document again from the image's own repository and
     replaces the copy, and it keeps a fetched document only when the
     pull can use it. This extends D8's "a mismatch removes it and it is
     fetched again" from the bytes to the type, and closes the same
     spoiling through an image pull, which ADR-009 had too. Cost: a
     manifest without a `mediaType` field that two repositories serve as
     Docker and as OCI is fetched again by whichever pull finds the
     other's type kept (`kept_document_of_another_type_refetched`); the
     verdict never changes. The sweep of ADR-009 D8 and ADR-025 D1 covers the directory
     (dead owners judged by their lock files, ADR-028), it is created
     with `boneli-private-dir`'s rules (ADR-021), and the trim, which
     evicts kept artifacts like any unpinned document (they serve no
     layer, so no layer lock holds them, ADR-025 D7), removes a pointer
     whose evidence is gone. **Added in PR 3:** that removal; without it
     `signatures/` would keep one file for every subject ever checked.

Decided in the plan and reviewable: the subjects are the digest the
reference names and then, when it names an index, the selected platform
manifest, nothing else; a refusal is `Failed`, never `NotFound`; the
`ImageStore` port gets no new contract clause; `critical.identity.
docker-reference` and `optional` of simple signing are ignored, because
the digest binds the bytes and mirrors are legitimate.

### Limits and how each number was derived

- **`MAX_PUBLIC_KEY_PEM_LEN` = 8,192 B.** The largest accepted key is
  RSA-8192, whose PEM is 1,491 B and 4,968 B with OpenSSL's text dump in
  front (measured, OpenSSL 3.5); 8,192 / 4,968 = 1.65. Lower refuses such
  a key file; higher only admits more text around the one section. The
  cap is inclusive: 8,192 bytes pass, 8,193 are refused before parsing
  (`tests/keys.rs`).
- **RSA 2,048 to 8,192 bits.** Ring's range for
  `RSA_PKCS1_2048_8192_SHA256`, not a number of ours; checked at parse
  time so a key ring would never verify with is refused when configured.
- **Windows are inclusive at both ends, in milliseconds.** A `CtLog`
  window holds a timestamp `t` when `valid_from_ms <= t <= valid_to_ms`,
  the trusted root's `validFor` semantics; PR 2 compares Rekor's integrated
  time (seconds) as seconds × 1,000. The leaf's validity is webpki's,
  checked at the integrated time and inclusive at both ends
  (`check_validity` in rustls-webpki 0.103.17). Verification reads no wall
  clock, so the same inputs give the same verdict forever and replay
  stays deterministic.
- **`MAX_KEPT` = 32 lines per pointer file (PR 3, review).** 2 ×
  `MAX_SIGNATURES`: every candidate both carriers can list for one
  subject at once, so rules with different trusts never push out each
  other's evidence while the listings stay; at most 151 bytes a line,
  4,832 bytes a file (`MAX_POINTER_BYTES` = 8,192 read). Lower lets
  enough rules over one digest send each other's warm pulls to the
  network; higher only keeps lines no listing can produce.
- **`MAX_SIGNATURES` = 16 per carrier listing per subject (PR 3).**
  Measured: 1 to 2 signatures per digest (Kubernetes 1, Chainguard 1,
  cosign 2.4.1 2, 3.0.2 2, `latest` 2 referrers); each `cosign sign` run
  adds one, for example after a key rotation or from a second signer. 16
  is 8 times the maximum seen; the limit is inclusive: 16 listed are all
  examined, 17 make that carrier yield no candidate. Lower than about 4
  refuses images re-signed a few times; higher adds requests a hostile
  listing can force. The cap gives a pusher no new denial of service:
  whoever can append to a listing can also delete it.
- **`MAX_PAYLOAD_BYTES` = 65,536 (PR 2).** Measured payloads are 239, 295
  and 319 B. `cosign sign -a` annotations go into `optional`, so 64 KiB is
  205 times the largest seen (65,536 / 319), and 16 of them per carrier
  are 1 MiB of memory. Lower refuses annotated signatures; higher only
  costs memory.
- **Bundle: at most 4,194,304 B, depth 16, 65,536 values (PR 2), the
  document JSON limits of ADR-009 D12.** Measured: 4,537 B, depth 7, 58
  values. A DSSE bundle carries the whole statement, and unsigned SLSA
  provenance already reaches 23,707 B (node:22); 4 MiB holds 177 times
  that. Peak memory is D12's, about 16.5 MiB, one document at a time.
  Lower refuses provenance with large material lists; higher only costs
  memory. SBOM referrers are never fetched, because the predicate filter
  comes first. The JSON documents nested in one (the in-toto statement,
  a Rekor entry body, cosign's bundle annotation) are read under the
  same three limits: each is part of a document of at most that size.
- **Trusted root: at most 1,048,576 B, depth 16, 65,536 values (PR 2).**
  Measured 6,787 B, depth 7, 85 values. It grows by about 1 KB per rotated
  key or CA, so 1 MiB is 154 times today's size. Lower risks refusing a
  future root; higher only costs memory, read once per configuration.
- **Deadlines are D12's formula, `setup` + size ÷ `min_rate` (PR 3).** A
  payload gets 30 s + 65,536 ÷ 1,048,576 s = 30.06 s; a listing or bundle
  at the document limit 30 + 4 = 34 s. Worst case, a registry that
  trickles every response up to its deadline and lists 16 candidates per
  carrier, none valid: 34 (`.sig`) + 16 × 30.06 (payloads) + 34 + 34
  (referrers 404, then the fallback tag) + 16 × (34 + 34) (referrer
  manifests and bundles) = 34 + 481 + 68 + 1,088 = 1,671 s per subject;
  for two subjects 3,342 s, about 56 min, against the about 69 min one
  4 GiB blob may already take (D12). Requests in that case: 1 + 16 + 2 +
  32 = 51 per subject, 102 in total. An honest unsigned Docker Official
  Image costs 2 requests per subject (`.sig` 404, then referrers 200
  empty), 4 in total; an honest Chainguard pull costs 2, the `.sig` and
  the payload.
- **The SCT count is not capped.** The SCT check runs only on a leaf
  webpki verified, so the issuing CA (Fulcio) chose the list; the list
  length is bounded by its 16-bit length field: 65,535 / 49 = at most
  1,337 SCTs of the minimal 49 bytes (47 plus a 2-byte length), one
  signature check for each whose log ID is listed.

## Consequences

- PR 1 adds no crate and no dependency edge: `rustls`, `rustls-webpki`
  and `ring` were direct dependencies of `boneli-https` already
  (ADR-005, ADR-020). Its exported surface widens by `PublicKey`,
  `KeyKind`, `PublicKeyError`, `SignatureError`, `MAX_PUBLIC_KEY_PEM_LEN`,
  `verify_code_signing`, `CodeSigningCert`, `San`, `CtLog`, `CertError`
  and `SctError`, all with fixed algorithms and no switch to skip a check.
- PR 3 adds the edge `boneli-oci -> boneli-sigstore` (a support crate)
  and no external one. `boneli-oci`'s API gains `SignaturePolicy`,
  `PolicyRule`, `RepoScope`, `Requirement`, `MAX_SIGNATURES`,
  `StoreConfig::signatures` and `Error::InvalidPolicy`; the store root
  gains `signatures/sha256/`.
- PR 2 adds the support crate `boneli-sigstore` (`roles.support` in
  `tools/architecture.toml`) with edges to `boneli-https` and
  `boneli-json` only, so the external graph is unchanged. It is pure: no
  clock, file, network or thread, and the same bytes give the same
  verdict forever.
- We own a security-critical verifier. Mitigations: every check has a
  negative test and a mutant that a named test kills (PR 1: 23 mutants
  over `keys.rs` and `codesign.rs`, all killed; PR 2: 73 mutants over
  every check of `boneli-sigstore`, all killed, the one survivor of the
  first run, PEM line length, by a test added for it; PR 3: 43 mutants
  over the policy, the discovery, the parsers, the fetches, the store
  wiring and the pointer files, all killed; the first run's survivors
  were three checks no input could reach, a payload cap repeated before
  the fetch's own, a duplicate-annotation check behind `boneli-json`'s
  duplicate-key refusal and a pointer re-render behind strict parts, and
  each was removed; at review 17 more over the fixes (pointer lines,
  kept-document types), all killed once tests were added for the five
  survivors of their first run); the real Kubernetes
  and Chainguard leaves are known answers against the public-good chain
  and CT log (PR 1), and the whole Kubernetes and Chainguard keyless
  signatures and cosign's keyed bundle pass `verify` against the
  public-good root and cosign's release key (PR 2); the reviewer runs on
  every PR.
- Rebuilt bytes can only cause refusals: the precertificate TBS (PR 1)
  and the SET's JCS bytes (PR 2) feed a signature check, and the known
  answers prove that valid inputs pass. The readers whose output decides
  (SAN, issuer extension, subject digest, predicate type) can accept
  wrongly, so each one has negative tests and is in the mutation pass.
- **Known limits**, each with where it closes:
  - Protection exists only where the operator writes a `Required` rule,
    and an `Off` rule under a `Required` prefix is an exemption by
    design. Forcing `Required` for references an agent chose is a
    follow-up issue (filed at STOP 1).
  - A URI prefix trusts everyone who can run the workflow at a matching
    ref. `…@refs/tags/` trusts whoever may push tags to the signer's
    repository, `…@refs/heads/` whoever may push branches, and an org or
    repository prefix ending in `/` every workflow and ref under it. A
    prefix is as broad as the operator writes it: under the GitHub issuer
    `https://github.com/` (or `https://`) trusts every repository on
    GitHub, and nothing refuses such a rule. What
    makes `@refs/tags/` mean "releases" is the signer's tag protection,
    which boneli cannot see. It stays open by design: an operator who
    needs less trust writes the exact SAN of a protected branch or of one
    tag.
  - Rotation depends on the operator replacing `trusted_root.json`; a
    stale file refuses signatures from new logs or CAs, which fails
    closed. A TUF client is a follow-up issue (filed at STOP 1).
  - A `trusted_root.json` that holds a key of a kind `PublicKey` does
    not support, or any other defect, refuses the whole file (PR 2); the
    one entry left out instead is a Rekor log whose `keyId` is not its
    key's SHA-256 (a v2 log, item 8). Skipping unreadable entries would
    hide an operator's mistake behind refusals that name no cause. If
    Sigstore adds such a key, the operator keeps the previous file until
    this crate supports the kind; signatures from the new log or CA are
    refused meanwhile (fails closed).
  - A keyless signature needs exactly one log entry with an inclusion
    promise (PR 2). Every measured signature has one; a bundle with two
    would make the integrated time ambiguous, so it is refused rather
    than tried entry by entry.
  - A signer that moves to Rekor v2 or to TSA time is refused until the
    follow-up issue (filed at STOP 1) lands.
  - A SET is Rekor's signed promise, and boneli has no witness for it;
    without a witness, an inclusion proof would also rest on Rekor's key,
    so it is not checked. Inclusion proofs, checkpoints and witnesses stay
    out of scope (recorded here only).
  - Keyed signatures have no transparency and no revocation; rotating a
    key means a policy change. A signature deleted upstream still
    verifies from the kept copy (S6): the policy revokes, not the
    registry.
  - "Provenance" means "signed by the trusted identity", not "built from
    source X by builder Y". SLSA claim checks are a follow-up issue
    (filed at STOP 1). ADR-031 (#104) checks the builder, source and
    materials of SLSA v1 provenance under a rule with claims.
  - An intermediate without the Code Signing EKU refuses the chain
    (webpki's rule, item 7). Go's verifier treats such an intermediate as
    unrestricted; Sigstore's public-good intermediate carries the EKU, so
    only a private Fulcio whose intermediate lacks it is refused.
  - SCTs issued through a precertificate signing certificate (RFC 6962
    3.1's special issuer) are untested. By RFC 6962 3.2 they verify with
    this code, because the log signs the final issuer's key hash and a TBS
    whose issuer is the final issuer, which is what the reconstruction
    from the leaf yields; no fixture exercises it, since Fulcio signs its
    precertificates with its CA key directly.
  - Notation, cosign `.att`, `intoto` 0.0.2 entries, `messageSignature`
    bundles, bundles before v0.3, signatures stored in another repository
    (`COSIGN_REPOSITORY`), the policy's configuration file format (#32,
    #33), registry allowlist presets for GHCR and `cgr.dev`, re-checking
    handles in `layers()` and `config()` after a policy change, signing,
    and private registries (#55) are out of scope (recorded here only).

## Alternatives considered

- **`sigstore-rs` (`sigstore` 0.15.0).** Rejected: its tree contains
  crates on `deny.toml`'s list in every feature set measured (108 crates
  with none, tokio and serde among them).
- **The `sigstore-verify` family (0.16.0).** Rejected: 50 crates with
  serde, thiserror, tracing and two proc macros, and an aws-lc-rs-only
  crypto backend, which `deny.toml` bans (a CMake C build, ADR-005).
- **Our own code in `boneli-oci` only.** Rejected: an adapter cannot
  depend on another adapter, and npm and PyPI provenance are Sigstore
  bundles too; #66 (ADR-021) just paid for extracting shared code after
  the fact.
- **A test-only `boneli-sigstore -> ring` edge** for synthetic ECDSA
  fixtures. Rejected: ring would leave its one crate.
- **A policy mode "optional"** (verify if present). Rejected: the threat is
  whoever chooses the digest, and that person would choose an unsigned
  image; besides, anyone who can push could block an unsigned image by
  attaching junk.
- **Keys only, keyless as a follow-up.** Rejected at STOP 1: it drops
  the SCT, chain, root and identity code, about half of PR 1 and PR 2,
  but every measured public signer (Kubernetes, Chainguard) is keyless.
- **The algorithm from the signature or envelope** (as `signature.rs`
  tries every algorithm whose ids match for OCSP). Rejected for keys:
  Sigstore's formats do not carry a signed algorithm identifier, so the
  input would choose it.
- **Exact SAN matching only.** Rejected: a tag-released workflow's SAN
  changes with every release.
- **`@` as a prefix boundary** (accepted at STOP 1, dropped at the
  review of PR 2 by the operator). Rejected: `…/release.yaml@` trusts every
  ref of the workflow, branches, commit SHAs and pull request merge refs
  included (item 2).

## Accept when

PR 3's fake-registry acceptance passes (keyed on both carriers, and
keyless with Chainguard's real `.sig`), and the `oci-acceptance` run on
PR 3 passes `network::signatures_on_docker_hub` on x86_64 and arm64.

**Result (PR 3, 2026-11-24).** The fake-registry acceptance passes: a
trusted keyed signature pulls on both carriers, and an unsigned image,
another key and a signature over another digest are refused before any
layer request on both; Chainguard's real keyless `.sig` verifies against
the public-good root with its exact workflow SAN and with the prefix
`…@refs/heads/`, and the pull goes on to its first layer request;
cosign's real keyed bundle passes through GHCR's tag schema exactly as
GHCR serves it. Live on x86_64 (local run): `signatures_on_docker_hub`
pulls `chainguard/node` with all 11 layers in 23.5 s over 31
connections, pulls it again from the kept evidence with no connection,
and refuses `library/node` `sha256:e13726ca…` after 4 signature requests
(`.sig` 404 and referrers `[]` for the index and its amd64 manifest)
with one CDN connection, the config's, and no layer committed;
`signatures_elsewhere` pulls cosign v3.1.4 from GHCR (15 layers, 20.6 s,
the second-listed bundle never needed), `chainguard/node` from `cgr.dev`
(11 layers, 24.3 s) and `pause:3.10` through Artifact Registry (1
layer, 1.8 s: no token, a blob redirect relative to the API host), and
refuses each under another identity. Learned on the way: GHCR lists
referrers with `"platform": null` and also answers the platform
manifest's `sha256-<hex>` tag with a real listing (cosign signs both),
and `cgr.dev` redirects blobs to `*.r2.cloudflarestorage.com`. The
`oci-acceptance` run on PR 3 (run 45315915777) passes
`signatures_on_docker_hub`, `signatures_elsewhere` and
`node_and_postgres_run_in_sandbox` on x86_64 and arm64: `chainguard/node`
from Docker Hub in 7.9 s (x86_64) and 16.9 s (arm64), cosign from GHCR in
6.7 s and 14.1 s, `chainguard/node` from `cgr.dev` in 9.1 s and 17.0 s,
`pause:3.10` in 4.7 s and 6.4 s, and `library/node` refused on both.
