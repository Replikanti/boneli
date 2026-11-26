# Test data of boneli-tuf

## Sigstore's TUF roots (known answers)

Captured on 2026-11-24 from Sigstore's public-good TUF repository, each
file the bytes `https://tuf-repo-cdn.sigstore.dev/<N>.root.json` served
for N from 3 to 16 (`17.root.json` was 404). The tests check that v5 to
v16 chain under ADR-033's rules, that each verifies against its own
threshold, that v15 had expired on the capture date and v16 had not, and
that v4 (hex keys) and v3 (fractional `expires`) are refused as pins.

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `sigstore-3.root.json` | 4809 | `f612679ba5a4d31421e65068faa035ea363257edcaf22a555b9c49d189a2d4ef` |
| `sigstore-4.root.json` | 5287 | `db9f88395e55e837c6926a5774f1031fd37faccdae828cc0e39304b63bb0378f` |
| `sigstore-5.root.json` | 6388 | `e2a930b2d1d4053dd56e8faf66fd113658545d522e35d222ccf58fea87ccccf4` |
| `sigstore-6.root.json` | 5642 | `62ec47d19857cb6cecf385ad72290c21f7600eea11b98576ea69dcadb1affea5` |
| `sigstore-7.root.json` | 5404 | `c86f493b010dc9656004c86029570b2cf9b1f9ce2c57e2e0ce91fbb008067570` |
| `sigstore-8.root.json` | 5406 | `1c86543d6777efe42d609b4e45f9fa1904c1c412bb5e2d3b64128e8b042fc641` |
| `sigstore-9.root.json` | 6766 | `d9a9799ffe80d937ef4a641e2111a71163712ca6298224dee7d60f57021cd403` |
| `sigstore-10.root.json` | 6911 | `836bff947925edfc23eb9ce17af66fb1e43bb5e2bdd240520985ae52b585eae9` |
| `sigstore-11.root.json` | 5697 | `641adcaddce7b4af7d7ce81d8b58fa5dc871f13af48097dbf543597677702587` |
| `sigstore-12.root.json` | 5413 | `5fe1e509a47277183a004745942c0a116379297da9f1cca529774320f1a5dfab` |
| `sigstore-13.root.json` | 5730 | `39277f1fbd482f84d924b6cb77748f62ab0f031b3b5b9b29e681dae056c32250` |
| `sigstore-14.root.json` | 5490 | `c8c41ec13f06ccabf5b48541ee2550098b4c7b5349e1d180390c29a7d5c2642c` |
| `sigstore-15.root.json` | 5630 | `73747011d0857ada15479a16c4cae0f3ed03aac698b523b97e1de314ac9d9ca8` |
| `sigstore-16.root.json` | 5630 | `27aea7e372aa7864065174f0661784fcf8b0e28b1dbfebeada31a0f1fb19167f` |

```sh
for n in $(seq 3 16); do
  curl -sSf -o "sigstore-$n.root.json" "https://tuf-repo-cdn.sigstore.dev/$n.root.json"
done
sha256sum sigstore-*.root.json
```

## Sigstore's online metadata (known answers)

Captured on 2026-11-24 from the same repository, with the roots above:
`timestamp.json` (v842, which named snapshot v166) and the files it led
to, `166.snapshot.json` and `14.targets.json`. They are signed by root
v16's keys. The tests check that they verify under v16 at the capture
date, that the timestamp expires at 2026-11-30T01:20:52Z, and that the
`trusted_root.json` target has the length and SHA-256 of
`crates/boneli-sigstore/tests/data/sigstore-trusted-root.json`. The
repository has signed newer timestamps since; the tests do not depend on
which one is current.

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `sigstore-timestamp.json` | 447 | `d886518ebf54f8dd0aa9a29b3ce5f22b32bd9f6275092f582dc5fb5e96c8ab5f` |
| `sigstore-166.snapshot.json` | 1760 | `6d61405faa993ba3d07556b79d1e319627cdc06ff879a7b5700967dc25d1d224` |
| `sigstore-14.targets.json` | 4942 | `6a697f7f8908c8ab26c11786ecb490b54acec97fa8c802e399f065f8a0cc1acd` |

```sh
base=https://tuf-repo-cdn.sigstore.dev
curl -sSf -o sigstore-timestamp.json "$base/timestamp.json"
curl -sSf -o sigstore-166.snapshot.json "$base/166.snapshot.json"
curl -sSf -o sigstore-14.targets.json "$base/14.targets.json"
sha256sum sigstore-timestamp.json sigstore-166.snapshot.json sigstore-14.targets.json
```

## GitHub's TUF roots (known answers, ADR-041)

Captured on 2026-11-26 from GitHub's TUF repository, each file the bytes
`https://tuf-repo.github.com/<N>.root.json` served for N from 1 to 9
(`10.root.json` was 404). The tests check that each verifies against its
own threshold and publishes consistent snapshots, that v1 to v9 chain
under ADR-033's rules with no online key change, that every version is a
pin the rules accept, and that only v9 had not expired on the capture
date.

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `github-1.root.json` | 7660 | `b73aa59b16d2c4989de18e402e168183d0e58f8cf9249d7cb4dd0d1774830c6e` |
| `github-2.root.json` | 7234 | `9fc6e4cf2bddf3005388d347c624b9f4feb8cd95b5507dbda41344d6238be0be` |
| `github-3.root.json` | 7480 | `98cba97be9075bc98b2322de3de85fbd1b70ec7392991dfd2f53d215bede1a8d` |
| `github-4.root.json` | 6537 | `a9fdd07ba2dfc9cc603e6250ea210356f5a5cf06028f329f527abc055af34fd3` |
| `github-5.root.json` | 7482 | `546470a4aa294c76c75039d87ccca20b9e7e3494bfc89026afcd3b83c2d1541e` |
| `github-6.root.json` | 7376 | `42e225b5eaed55755a637fb5150135d2930ecdf0b291c615fcd54a52a3fd2522` |
| `github-7.root.json` | 6679 | `5f14db09da4f13783f2e25778f0f02685a5b5d3270cfca2763b720acc020db8b` |
| `github-8.root.json` | 6976 | `87a67338159679a4e3f7b5c8cdc302cb364fd5e1d7d37ee2531a1cd8eb782999` |
| `github-9.root.json` | 6734 | `eb303461e0109458144b6ebcbfd62aaa6f6d7481e9ca77504b85f17761661462` |

`github-3.root.json` is the pin of ADR-041. It is byte for byte the root
that `cli/cli` embeds for `tuf-repo.github.com`:

```sh
gh api repos/cli/cli/contents/pkg/cmd/attestation/verification/embed/tuf-repo.github.com/root.json \
  -H 'Accept: application/vnd.github.raw' | cmp - github-3.root.json
```

## GitHub's online metadata and target (known answers, ADR-041)

Captured on 2026-11-26 from the same repository, with the roots above:
`timestamp.json` (v1027, which named snapshot v84), the files it led to,
`84.snapshot.json` and `10.targets.json`, and the `trusted_root.json`
target at its consistent-snapshot path. They are signed by root v9's
keys. The tests check that they verify under v9 at the capture date,
that the timestamp expires at 2026-12-03T07:22:31Z, and that the target
is the same JSON as `crates/boneli-sigstore/tests/data/github-trusted-root.json`
in other bytes (pretty-printed here, the compact line of `gh
attestation trusted-root` there). The repository has signed newer
timestamps since; the tests do not depend on which one is current.

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `github-timestamp.json` | 450 | `4e49f1483a728c6f5b064d26a95e15414830f19d263a75707961495c199708c4` |
| `github-84.snapshot.json` | 446 | `7f2ee4dc13f4b3f4edfe828c4eb3b36ac61c4f3219f745c960395d5c8b5ec750` |
| `github-10.targets.json` | 2974 | `0fa9dec2a92ff98570d611080ae334b6f0db4af42551d957de0fc447a18acc9c` |
| `github-tuf-trusted-root.json` | 31645 | `484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7` |

```sh
base=https://tuf-repo.github.com
for n in $(seq 1 9); do
  curl -sSf -o "github-$n.root.json" "$base/$n.root.json"
done
curl -sSf -o github-timestamp.json "$base/timestamp.json"
curl -sSf -o github-84.snapshot.json "$base/84.snapshot.json"
curl -sSf -o github-10.targets.json "$base/10.targets.json"
curl -sSf -o github-tuf-trusted-root.json \
  "$base/targets/484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7.trusted_root.json"
sha256sum github-*.json
```

## Test-only signing keys

`test-only-p256-1.key` to `test-only-p256-7.key` are ECDSA P-256 keys in
PKCS#8 that sign fixture repositories at test time through
`boneli_https::EcdsaP256Key` (`tests/support/repo.rs`). They protect
nothing and no repository trusts them. Keys 1 to 5 are the root and
targets keys of the default fixture root (threshold 3), key 6 its online
timestamp and snapshot key, key 7 spare for rotations. Generated once
with OpenSSL 3.5:

```sh
for n in 1 2 3 4 5 6 7; do
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "test-only-p256-$n.key"
done
```

## Keys of kinds that never count

`pubkey-p384.pem`, `pubkey-ed25519.pem` and `pubkey-rsa2048.pem` are
copies of the files of the same name in `crates/boneli-https/tests/data`
(their README has the commands). Root fixtures list them under accepted
and other labels to show that they count zero towards a threshold.
