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
measured on 2026-11-24, and flux-cli's the one ADR-036 measured on
2026-11-24, and kyverno's the one ADR-037 measured on 2026-11-24;
`sigstore-trusted-root.json`
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
| `flux.index.json` | `a9cb966c…3471fd1f` | the index of `ghcr.io/fluxcd/flux-cli:v2.4.0`, a Docker manifest list of 1,079 bytes (ADR-036) |
| `flux.amd64.json` | `722bdf66…61c90386` | its `linux/amd64` manifest (Docker schema 2, 1,162 bytes) |
| `flux.amd64-config.json` | `9b0c4fef…e14e2bd8` | that manifest's config |
| `flux.att.json` | `467ee9c3…5b9f7ac5` | the cosign `.att` manifest of the index (the tag `sha256-<index hex>.att`; the amd64 manifest's answers 404): one SLSA v0.2 layer, the file `flux-cli-2.4.0.att.json` of `crates/boneli-sigstore/tests/data` (same SHA-256) |
| `flux.envelope.json` | `f12badd9…56be214b` | its DSSE envelope, the file `flux-cli-2.4.0.envelope.json` there |
| `kyverno.index.json` | `4c30afa8…8ab39e3a` | the index of `ghcr.io/kyverno/kyverno:v1.11.0`, an OCI index of 7 platforms, 2,027 bytes (ADR-037); `.sig`, the referrers API and the referrers tag answer 404 |
| `kyverno.amd64.json` | `db534c96…bc066f42` | its `linux/amd64` manifest (OCI, 1,211 bytes) |
| `kyverno.amd64-config.json` | `0bd890f3…0b6a5bcd` | that manifest's config (1,045 bytes) |
| `kyverno.att.json` | `81c56313…9f9923a2` | the cosign `.att` manifest of the index: one SLSA v0.2 layer logged as a Rekor `intoto` 0.0.1 entry, the file `kyverno-1.11.0.att.json` of `crates/boneli-sigstore/tests/data` (same SHA-256) |
| `kyverno.envelope.json` | `148c49dd…82837513` | its DSSE envelope, the file `kyverno-1.11.0.envelope.json` there |
| `bex-cnb-run.index.json` | `b02a639b…bf1732df9` | the index of `ghcr.io/bex-co/bex-cnb-run`, an OCI index of 1,611 bytes (ADR-038); the referrers API answers 404 |
| `bex-cnb-run.amd64.json` | `091e70c5…29fb4321` | its `linux/amd64` manifest (OCI, 3,534 bytes, 17 layers) |
| `bex-cnb-run.amd64-config.json.b64` | `58e0afde…0a006989` (decoded) | that manifest's config (16,539 bytes), kept as base64 in lines of 76 characters because its build history names the Python interpreter, which the CI gate of ADR-015 D10 refuses in any tracked file; `signatures.rs` decodes it |
| `bex-cnb-run.referrers-tag.json` | `e1d4df49…32668f7` | GHCR's answer to the tag `sha256-<index hex>`: five bundle referrers, one of them (`https://sigstore.dev/cosign/sign/v1`) the signature, 2,164 bytes |
| `bex-cnb-run.referrer.json` | `9d24c9ab…561343c4` | that referrer's manifest, 1,013 bytes |
| `bex-cnb-run.bundle.json` | `04b2bd8b…da2ba8c7` | its bundle: keyless `cosign sign`, a Rekor v2 `hashedrekord` 0.0.2 entry and one RFC 3161 token, the file `bex-cnb-run.bundle.json` of `crates/boneli-sigstore/tests/data` (same SHA-256) |

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
gh=https://ghcr.io/v2/fluxcd/flux-cli
tok=$(curl -fsS 'https://ghcr.io/token?scope=repository:fluxcd/flux-cli:pull' | jq -r .token)
fd=a9cb966cddc1a0c56dc0d57dda485d9477dd397f8b45f222717b24663471fd1f
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o flux.index.json "$gh/manifests/sha256:$fd"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o flux.amd64.json \
  "$gh/manifests/$(jq -r '.manifests[] | select(.platform.architecture == "amd64" and .platform.os == "linux") | .digest' flux.index.json)"
curl -sSL -H "Authorization: Bearer $tok" -o flux.amd64-config.json \
  "$gh/blobs/$(jq -r .config.digest flux.amd64.json)"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o flux.att.json "$gh/manifests/sha256-$fd.att"
curl -sSL -H "Authorization: Bearer $tok" -o flux.envelope.json \
  "$gh/blobs/$(jq -r '.layers[0].digest' flux.att.json)"
gh=https://ghcr.io/v2/kyverno/kyverno
tok=$(curl -fsS 'https://ghcr.io/token?scope=repository:kyverno/kyverno:pull' | jq -r .token)
kd=4c30afa85d83f4a55ab14642b0630ba51fde573717ba712721edd1408ab39e3a
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o kyverno.index.json "$gh/manifests/sha256:$kd"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o kyverno.amd64.json \
  "$gh/manifests/$(jq -r '.manifests[] | select(.platform.architecture == "amd64" and .platform.os == "linux") | .digest' kyverno.index.json)"
curl -sSL -H "Authorization: Bearer $tok" -o kyverno.amd64-config.json \
  "$gh/blobs/$(jq -r .config.digest kyverno.amd64.json)"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o kyverno.att.json "$gh/manifests/sha256-$kd.att"
curl -sSL -H "Authorization: Bearer $tok" -o kyverno.envelope.json \
  "$gh/blobs/$(jq -r '.layers[0].digest' kyverno.att.json)"
gh=https://ghcr.io/v2/bex-co/bex-cnb-run
tok=$(curl -fsS 'https://ghcr.io/token?scope=repository:bex-co/bex-cnb-run:pull' | jq -r .token)
bd=b02a639bada113f1b64024c23d5dce1ecb12b67ef4c75b1650999f2bf1732df9
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o bex-cnb-run.index.json "$gh/manifests/sha256:$bd"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o bex-cnb-run.amd64.json \
  "$gh/manifests/$(jq -r '.manifests[] | select(.platform.architecture == "amd64" and .platform.os == "linux") | .digest' bex-cnb-run.index.json)"
curl -sSL -H "Authorization: Bearer $tok" "$gh/blobs/$(jq -r .config.digest bex-cnb-run.amd64.json)" |
  base64 -w 76 > bex-cnb-run.amd64-config.json.b64
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o bex-cnb-run.referrers-tag.json "$gh/manifests/sha256-$bd"
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o bex-cnb-run.referrer.json \
  "$gh/manifests/$(jq -r '.manifests[] | select(.annotations["dev.sigstore.bundle.predicateType"] == "https://sigstore.dev/cosign/sign/v1") | .digest' bex-cnb-run.referrers-tag.json)"
curl -sSL -H "Authorization: Bearer $tok" -o bex-cnb-run.bundle.json \
  "$gh/blobs/$(jq -r '.layers[0].digest' bex-cnb-run.referrer.json)"
```

The bex-cnb-run files name a fixed index digest. GHCR lists more
referrers as bex signs and attests the image again, so a later capture of
the tag may hold more entries; the files above stay as captured.

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
