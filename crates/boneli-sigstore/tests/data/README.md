# Test data of boneli-sigstore

## Real captures (known answers)

Captured on 2026-11-24 through the anonymous registry API. Each file is
the bytes the source served; the SHA-256 of the two `.sig` manifests and
of `trusted_root.json` equal those of the 2026-11-20 and 2026-11-23
measurements recorded in ADR-029 and in `crates/boneli-https/tests/data/README.md`,
so these are the signatures whose leaves boneli-https holds.

| File | SHA-256 | What |
| --- | --- | --- |
| `sigstore-trusted-root.json` | `6494e21e…e6bc0b66` | Sigstore's public-good `trusted_root.json` from `sigstore/root-signing` (6,787 bytes): Rekor v1 and v2, two Fulcio CAs, two CT logs, one TSA |
| `kubernetes-pause-3.10.sig.json` | `1b5166e7…0f421acf` | the `.sig` manifest of `registry.k8s.io/pause:3.10` (index `sha256:ee6521f2…8199917a`), served by Artifact Registry: one keyless layer, `hashedrekord` 0.0.1, integrated time 1716500129 |
| `kubernetes-pause-3.10.payload.json` | `a0297626…6ce7d3c4` | its simple-signing payload (295 bytes) |
| `chainguard-node.sig.json` | `b36df08e…3c6c0777` | the `.sig` manifest of `chainguard/node` on Docker Hub (index `sha256:3fb5318a…d6385dbe`): one keyless layer, integrated time 1795470488 |
| `chainguard-node.payload.json` | `c2be04e4…9f24936a` | its simple-signing payload (239 bytes) |
| `cosign-latest.bundle.json` | `53aebb2c…d8d3ee9a` | the first Sigstore bundle v0.3 referrer of `ghcr.io/sigstore/cosign/cosign:latest` (index `sha256:0f061548…48f69c2d`, cosign v3.1.4), reached through the tag `sha256-<index hex>` (GHCR's referrers API answers 404): referrer manifest `sha256:9c257e53…8ebc439f`, bundle 4,537 bytes, keyed DSSE with predicate `https://sigstore.dev/cosign/sign/v1`, Rekor v1 `dsse` 0.0.1 entry 3341383598 |
| `release-cosign.pub` | `f4cea466…4179f126` | cosign's release key, `release/release-cosign.pub` of `sigstore/cosign`; the SHA-256 of its SPKI is the bundle's `publicKey.hint` (`tests/verify.rs` checks it) |
| `actions-runner.bundle.json` | `3a9ba514…37124876` | the SLSA provenance v1 bundle of `ghcr.io/actions/actions-runner` (index `sha256:6d0b2d80…b8c31300`, ADR-031), the one referrer listed by the tag `sha256-<index hex>`: referrer manifest `sha256:8a56a057…7c3ca515`, bundle 10,794 bytes, keyless GitHub artifact attestation (`docker-publish.yml@refs/heads/main`), Rekor v1 `dsse` 0.0.1 entry 3816483043, integrated time 1794424176; statement 1,026 bytes |
| `jq-1.8.2.bundle.json` | `98860952…703ed018` | the SLSA provenance v1 bundle of `ghcr.io/jqlang/jq:1.8.2` (index `sha256:b9c68867…5344e486`, ADR-031), reached the same way: referrer manifest `sha256:07f60e20…c3855de3`, bundle 10,151 bytes, keyless (`ci.yml@refs/tags/jq-1.8.2`), Rekor v1 `dsse` 0.0.1 entry 1884124456, integrated time 1781962736; statement 964 bytes |

From an empty directory, with `jq`:

```sh
curl -sS -o sigstore-trusted-root.json \
  https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json
acc='application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json'
k8s=https://europe-west3-docker.pkg.dev/v2/k8s-artifacts-prod/images/pause
curl -sS -H "Accept: $acc" -o kubernetes-pause-3.10.sig.json \
  "$k8s/manifests/sha256-ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a.sig"
curl -sSL -o kubernetes-pause-3.10.payload.json \
  "$k8s/blobs/$(jq -r '.layers[0].digest' kubernetes-pause-3.10.sig.json)"
hub=https://registry-1.docker.io/v2/chainguard/node
tok=$(curl -fsS 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:chainguard/node:pull' | jq -r .token)
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o chainguard-node.sig.json \
  "$hub/manifests/sha256-3fb5318a58807dec0f2ece547efbe8d62c67b7b2fd91a16795b98651d6385dbe.sig"
curl -sSL -H "Authorization: Bearer $tok" -o chainguard-node.payload.json \
  "$hub/blobs/$(jq -r '.layers[0].digest' chainguard-node.sig.json)"
gh=https://ghcr.io/v2/sigstore/cosign/cosign
tok=$(curl -fsS 'https://ghcr.io/token?scope=repository:sigstore/cosign/cosign:pull' | jq -r .token)
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o index.json "$gh/manifests/latest"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o referrers.json \
  "$gh/manifests/sha256-$(sha256sum index.json | cut -c1-64)"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o referrer.json \
  "$gh/manifests/$(jq -r '.manifests[0].digest' referrers.json)"
curl -sSL -H "Authorization: Bearer $tok" -o cosign-latest.bundle.json \
  "$gh/blobs/$(jq -r '.layers[0].digest' referrer.json)"
curl -sS -o release-cosign.pub \
  https://raw.githubusercontent.com/sigstore/cosign/main/release/release-cosign.pub
slsa() { # repository, index digest, output
  gh=https://ghcr.io/v2/$1
  tok=$(curl -fsS "https://ghcr.io/token?scope=repository:$1:pull" | jq -r .token)
  curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o referrers.json "$gh/manifests/sha256-$2"
  curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o referrer.json \
    "$gh/manifests/$(jq -r '[.manifests[] | select(.annotations["dev.sigstore.bundle.predicateType"] == "https://slsa.dev/provenance/v1")][0].digest' referrers.json)"
  curl -sSL -H "Authorization: Bearer $tok" -o "$3" "$gh/blobs/$(jq -r '.layers[0].digest' referrer.json)"
}
slsa actions/actions-runner 6d0b2d80d80f143f77dcb676e50920100bbb547e39e883454d57f45ab8c31300 actions-runner.bundle.json
slsa jqlang/jq b9c68867e5766576263a222e91db3de422d802069c7af70440e667a95344e486 jq-1.8.2.bundle.json
```

Chainguard signs its images again from time to time and replaces the
`.sig` tag, and `latest` moves with every cosign release; a later capture
may differ, and these files then stay as they are. The two SLSA bundles
attest fixed index digests, so a later capture gives the same bytes while
GitHub keeps them; if it differs, the files and the hashes above stay.

## Synthetic test instance

`tests/support/pki.rs` builds a Sigstore instance at test time from the
RSA test keys below, made with OpenSSL 3.5:

```sh
for k in root intermediate attacker-ca leaf ct-log rekor signer other; do
  openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-only-$k.key
  openssl pkey -in test-only-$k.key -pubout -out test-only-$k.pub.pem
done
```

The keys are test-only and sign nothing outside these tests. They are
RSA because the tests sign with `boneli_https::RsaSha256Key`, the one
signer `boneli-https` exports; the real captures cover ECDSA (ADR-029,
S3).

| Key | Role |
| --- | --- |
| `test-only-root` | the test root CA (self-signed, `CA:TRUE`) |
| `test-only-intermediate` | the intermediate, `CA:TRUE`, EKU codeSigning, signed by the root: it issues the leaves |
| `test-only-attacker-ca` | a self-signed intermediate with the intermediate's name and its own key, which no root vouches for |
| `test-only-leaf` | the key of every built leaf: it signs payloads and DSSE envelopes |
| `test-only-ct-log` | the test CT log: it signs the embedded SCTs |
| `test-only-rekor` | the test Rekor: it signs the SETs |
| `test-only-signer` | the trusted key of the keyed cases |
| `test-only-other` | an untrusted key: SCTs, SETs and signatures from outside the trust |
