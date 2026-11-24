# Test data of boneli-oci

## Request log

`policy-off-requests.txt` is the request log of `tests/signatures.rs`'s
`logged_pulls` (a cold pull by index and a warm one, then a cold pull by
manifest through the CDN), recorded at the merge base of #57 PR 3, before
the signature policy existed: `policy_off_requests_unchanged` holds every
later pull without a `Required` rule to it, byte for byte.

## Real captures (known answers)

Captured on 2026-11-24 through the anonymous registry API. The digests
are the ones ADR-029 measured on 2026-11-20, and jq's the one ADR-031
measured on 2026-11-24; `sigstore-trusted-root.json`
and `release-cosign.pub` are the files of `crates/boneli-sigstore/tests/data`
(same SHA-256), where their sources are listed.

| File | SHA-256 | What |
| --- | --- | --- |
| `chainguard-node.index.json` | `3fb5318a…d6385dbe` | the index of `chainguard/node` on Docker Hub |
| `chainguard-node.amd64.json` | `9f6cbf80…b22cfb29` | its `linux/amd64` manifest |
| `chainguard-node.amd64-config.json` | `a4e4a9b8…9707a0eb` | that manifest's config |
| `chainguard-node.sig.json` | `b36df08e…3c6c0777` | the `.sig` manifest of the index (one keyless layer) |
| `chainguard-node.payload.json` | `c2be04e4…9f24936a` | its simple-signing payload |
| `cosign.index.json` | `0f061548…48f69c2d` | the index of `ghcr.io/sigstore/cosign/cosign:v3.1.4` |
| `cosign.amd64.json` | `dfc0619d…7e9f935b` | its `linux/amd64` manifest |
| `cosign.amd64-config.json` | `19fc3f59…f361e6e8` | that manifest's config |
| `cosign.referrers-tag.json` | `87565cc0…6bcda46f` | GHCR's answer to the tag `sha256-<index hex>` (the referrers API answers `404`): two bundle referrers |
| `cosign.referrer.json` | `9c257e53…8ebc439f` | the first referrer's manifest |
| `cosign.bundle.json` | `53aebb2c…d8d3ee9a` | its bundle (keyed DSSE, cosign's release key) |
| `sigstore-trusted-root.json` | `6494e21e…e6bc0b66` | Sigstore's public-good `trusted_root.json` |
| `release-cosign.pub` | `f4cea466…4179f126` | cosign's release key |
| `jq.index.json` | `b9c68867…5344e486` | the index of `ghcr.io/jqlang/jq:1.8.2`, a Docker manifest list of 2,397 bytes (ADR-031) |
| `jq.amd64.json` | `1e7ad54d…d119029a` | its `linux/amd64` manifest (Docker schema 2, 697 bytes) |
| `jq.amd64-config.json` | `ac37bcf3…debd25be` | that manifest's config |
| `jq.referrers-tag.json` | `1b9c2acf…3fc2ba60` | GHCR's answer to the tag `sha256-<index hex>` (the referrers API answers `404`, and so does the amd64 manifest's tag): one SLSA provenance v1 bundle referrer, 496 bytes |
| `jq.referrer.json` | `07f60e20…c3855de3` | that referrer's manifest, 831 bytes |
| `jq.bundle.json` | `98860952…703ed018` | its bundle: GitHub's keyless artifact attestation, the file `jq-1.8.2.bundle.json` of `crates/boneli-sigstore/tests/data` (same SHA-256) |

From an empty directory, with `jq`:

```sh
acc='application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json'
hub=https://registry-1.docker.io/v2/chainguard/node
tok=$(curl -fsS 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:chainguard/node:pull' | jq -r .token)
cg=3fb5318a58807dec0f2ece547efbe8d62c67b7b2fd91a16795b98651d6385dbe
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o chainguard-node.index.json "$hub/manifests/sha256:$cg"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o chainguard-node.amd64.json \
  "$hub/manifests/$(jq -r '.manifests[] | select(.platform.architecture == "amd64") | .digest' chainguard-node.index.json)"
curl -sSL -H "Authorization: Bearer $tok" -o chainguard-node.amd64-config.json \
  "$hub/blobs/$(jq -r .config.digest chainguard-node.amd64.json)"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o chainguard-node.sig.json "$hub/manifests/sha256-$cg.sig"
curl -sSL -H "Authorization: Bearer $tok" -o chainguard-node.payload.json \
  "$hub/blobs/$(jq -r '.layers[0].digest' chainguard-node.sig.json)"
gh=https://ghcr.io/v2/sigstore/cosign/cosign
tok=$(curl -fsS 'https://ghcr.io/token?scope=repository:sigstore/cosign/cosign:pull' | jq -r .token)
co=0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o cosign.index.json "$gh/manifests/sha256:$co"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o cosign.amd64.json \
  "$gh/manifests/$(jq -r '.manifests[] | select(.platform.architecture == "amd64" and .platform.os == "linux") | .digest' cosign.index.json)"
curl -sSL -H "Authorization: Bearer $tok" -o cosign.amd64-config.json \
  "$gh/blobs/$(jq -r .config.digest cosign.amd64.json)"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o cosign.referrers-tag.json "$gh/manifests/sha256-$co"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o cosign.referrer.json \
  "$gh/manifests/$(jq -r '.manifests[0].digest' cosign.referrers-tag.json)"
curl -sSL -H "Authorization: Bearer $tok" -o cosign.bundle.json \
  "$gh/blobs/$(jq -r '.layers[0].digest' cosign.referrer.json)"
acc="$acc, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"
gh=https://ghcr.io/v2/jqlang/jq
tok=$(curl -fsS 'https://ghcr.io/token?scope=repository:jqlang/jq:pull' | jq -r .token)
jd=b9c68867e5766576263a222e91db3de422d802069c7af70440e667a95344e486
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o jq.index.json "$gh/manifests/sha256:$jd"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o jq.amd64.json \
  "$gh/manifests/$(jq -r '.manifests[] | select(.platform.architecture == "amd64" and .platform.os == "linux") | .digest' jq.index.json)"
curl -sSL -H "Authorization: Bearer $tok" -o jq.amd64-config.json \
  "$gh/blobs/$(jq -r .config.digest jq.amd64.json)"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o jq.referrers-tag.json "$gh/manifests/sha256-$jd"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o jq.referrer.json \
  "$gh/manifests/$(jq -r '.manifests[0].digest' jq.referrers-tag.json)"
curl -sSL -H "Authorization: Bearer $tok" -o jq.bundle.json \
  "$gh/blobs/$(jq -r '.layers[0].digest' jq.referrer.json)"
```

## Test keys

RSA test keys for the keyed cases, made with OpenSSL 3.5 (RSA because
the tests sign with `boneli_https::RsaSha256Key`, ADR-029 S3):

```sh
for k in signer other; do
  openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-only-$k.key
  openssl pkey -in test-only-$k.key -pubout -out test-only-$k.pub.pem
done
```

They are test-only and sign nothing outside these tests:
`test-only-signer` is the trusted key, `test-only-other` an untrusted
one.
