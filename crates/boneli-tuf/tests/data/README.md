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
