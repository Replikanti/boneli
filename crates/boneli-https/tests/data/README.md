# Test certificates and keys

Fixtures for `tests/tls.rs`, `tests/dial.rs`, `tests/rsa.rs`, `tests/ecdsa.rs`,
`tests/revocation.rs`, `tests/ocsp.rs`, `tests/intermediates.rs`,
`tests/keys.rs`, `tests/codesign.rs`, `tests/timestamp.rs` and the unit
tests of `src/revocation/`, `src/codesign.rs` and `src/timestamp.rs`, read
with `include_bytes!`. The
keys protect nothing: they exist only so that a local test server can
complete a TLS handshake, so that `RsaSha256Key` and `PublicKey` can be
checked against OpenSSL, and so that tests can sign OCSP answers,
code-signing leaves, SCTs and timestamp tokens. No system trusts these CAs (the real
captures at the end are public certificates of real hosts), and no
GitHub App or other account has any of these keys. The signing keys say
so in their names (`test-only-`).

| File | What |
| --- | --- |
| `ca.pem` | test CA, valid 2026-01-01 to 2126-01-01 |
| `leaf.pem`, `leaf.key` | `localhost` leaf signed by `ca.pem`: SAN `DNS:localhost, IP:127.0.0.1`, EKU serverAuth, same validity |
| `expired.pem`, `expired.key` | the same leaf, valid only from 2000-01-01 to 2001-01-01 |
| `other-ca.pem` | a second CA that the tests never trust |
| `other-leaf.pem`, `other-leaf.key` | a `localhost` leaf signed by `other-ca.pem` |

All keys are ECDSA P-256 in PKCS#8. The CA keys are not kept; regenerating
creates new ones, and every file changes together.

Why a 100-year window: the CA protects nothing, so a shorter validity would
only make CI fail on its expiry date. The expired leaf's window is in the
past for good.

Generated once with OpenSSL 3.5 (`-not_before` and `-not_after` need 3.4 or
newer), from this directory:

```sh
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }
key ca.key; key other-ca.key; key leaf.key; key expired.key; key other-leaf.key
for ca in ca:"Boneli test CA" other-ca:"Boneli other test CA"; do
  openssl req -x509 -new -key "${ca%%:*}.key" -subj "/CN=${ca#*:}" \
    -not_before 20260101000000Z -not_after 21260101000000Z \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out "${ca%%:*}.pem"
done
printf '%s\n' "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" \
  "subjectAltName=DNS:localhost,IP:127.0.0.1" > leaf.ext
sign() {
  openssl req -new -key "$1" -subj "/CN=localhost" |
    openssl x509 -req -CA "$2.pem" -CAkey "$2.key" -set_serial "$3" \
      -not_before "$4" -not_after "$5" -extfile leaf.ext -out "$6"
}
sign leaf.key ca 2 20260101000000Z 21260101000000Z leaf.pem
sign expired.key ca 3 20000101000000Z 20010101000000Z expired.pem
sign other-leaf.key other-ca 2 20260101000000Z 21260101000000Z other-leaf.pem
rm ca.key other-ca.key leaf.ext
```

Rust was weighed for the generator and lost: it needs `rcgen`, a crate the
dependency policy does not list, or about 150 lines of hand-written DER to
review, for files that are generated once and never in CI.

## Signing keys (`tests/rsa.rs`, ADR-014 D4)

| File | What |
| --- | --- |
| `test-only-rsa-2048-pkcs8.key` | 2048-bit RSA key, PKCS#8 (`PRIVATE KEY`) |
| `test-only-rsa-2048-pkcs1.key` | the same key in PKCS#1 (`RSA PRIVATE KEY`) |
| `test-only-rsa-1024.key` | 1024-bit RSA key, PKCS#8, below ring's 2048-bit minimum |
| `test-only-rsa-2304.key` | 2304-bit RSA key, PKCS#8: inside ring's 2048 to 4096 bits, but its primes are not a multiple of 512 bits long, which ring refuses |
| `test-only-p256.key` | ECDSA P-256 key, PKCS#8: a key ring accepts that is not RSA |
| `rs256-message.txt` | a JWT signing input: header `{"alg":"RS256","typ":"JWT"}`, claims `iat` 1699999940, `exp` 1700000540 and a made-up `iss`, base64url without padding, no newline |
| `rs256-test-only.sig` | OpenSSL's RS256 signature of `rs256-message.txt` with the 2048-bit key, 256 bytes |

Generated once with OpenSSL 3.5, from this directory:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-only-rsa-2048-pkcs8.key
openssl pkey -in test-only-rsa-2048-pkcs8.key -traditional -out test-only-rsa-2048-pkcs1.key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out test-only-rsa-1024.key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2304 -out test-only-rsa-2304.key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out test-only-p256.key
printf '%s' 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTk5OTk5NDAsImV4cCI6MTcwMDAwMDU0MCwiaXNzIjoiSXYxLjAxMjM0NTY3ODlhYmNkZWYifQ' > rs256-message.txt
openssl dgst -sha256 -sign test-only-rsa-2048-pkcs1.key -out rs256-test-only.sig rs256-message.txt
```

RSASSA-PKCS1-v1_5 is deterministic, so the signature is a known answer:
regenerating the 2048-bit key changes it, so the two 2048-bit files and
the signature change together; the other keys stand alone. `openssl pkey -in test-only-rsa-2048-pkcs8.key -pubout | openssl
dgst -sha256 -verify /dev/stdin -signature rs256-test-only.sig
rs256-message.txt` checks it independently of Boneli.

## ECDSA P-256 signing keys (`tests/ecdsa.rs`, ADR-033 S4)

`EcdsaP256Key` signs with `test-only-p256.key` from the table above; the
other files are keys it must refuse, and the public key OpenSSL derives
from the signing key, which its signatures must verify under.

| File | What |
| --- | --- |
| `test-only-p256.pub.pem` | the public key of `test-only-p256.key` (`PUBLIC KEY`), derived by OpenSSL |
| `test-only-p256-sec1.key` | the same P-256 key in SEC1 (`EC PRIVATE KEY`): refused, PKCS#8 only |
| `test-only-p384.key` | ECDSA P-384 key, PKCS#8: refused, P-256 only |
| `test-only-ed25519.key` | Ed25519 key, PKCS#8: refused |

Generated once with OpenSSL 3.5, from this directory:

```sh
openssl pkey -in test-only-p256.key -pubout -out test-only-p256.pub.pem
openssl ec -in test-only-p256.key -out test-only-p256-sec1.key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out test-only-p384.key
openssl genpkey -algorithm ED25519 -out test-only-ed25519.key
```

ECDSA signatures are randomized, so there is no signature to pin; the
test checks that `EcdsaP256Key::public_key` equals OpenSSL's public key
and that every signature verifies under it.

## Ed25519 signing key (`tests/ed25519.rs`, ADR-038)

`Ed25519Key` signs with `test-only-ed25519.key` from the table above (the
key `EcdsaP256Key` refuses); the other keys there are keys it must refuse.

| File | What |
| --- | --- |
| `test-only-ed25519.pub.pem` | the public key of `test-only-ed25519.key` (`PUBLIC KEY`), derived by OpenSSL 3.5 |

```sh
openssl pkey -in test-only-ed25519.key -pubout -out test-only-ed25519.pub.pem
```

The test checks that `Ed25519Key::public_key` equals OpenSSL's public key
and that every signature verifies under it.

## Hybrid key exchange values (`x25519mlkem768-kat.txt`, ADR-016)

The known-answer values of the X25519MLKEM768 unit tests in `src/pq.rs`,
which read the file with `include_str!`. RFC 10024 has no test vectors,
so each half comes from its own independent source, and the file records
both in its comments:

- **ML-KEM-768:** Wycheproof `testvectors_v1/mlkem_768_test.json` at
  commit `3fa63dd0344abb611f1fb1d77e119938603ea230` of
  `github.com/C2SP/wycheproof`, copied byte for byte: tcId 2 (group
  "FIPS 203", "official round 3 seeds 0", valid) and tcId 194 (group
  "mlkem-implicit-rejection", flag `MalleableCiphertext`, valid), each with
  `seed`, `ek`, `c` and `K`.
- **X25519:** RFC 7748, section 6.1: Alice's public key, Bob's public key
  and their shared secret.

The tests build the expected client share (`ek`, then Alice's key) and
the expected secret (`K`, then the X25519 secret) from these values, so
they pin the layout against literal bytes; whether that layout is RFC
10024's is checked by the OpenSSL interop test (`tests/interop.rs`).

## Revocation by CRL (`tests/revocation.rs`, ADR-017)

A second test CA with leaves that name CRL distribution points, and CRLs
it signed. Every leaf has SAN `DNS:localhost, IP:127.0.0.1`, EKU
serverAuth, validity 2026-01-01 to 2126-01-01, and the one key
`crl-leaf.key`; `crl.boneli.test` and its siblings never resolve.

| File | What |
| --- | --- |
| `crl-ca.pem` | "Boneli CRL test CA", 2026-01-01 to 2126-01-01, `keyCertSign, cRLSign` |
| `crl-leaf.key` | the key of every `crl-*.pem` leaf |
| `crl-good.pem` | serial 0x10, point `http://crl.boneli.test/ca.crl` |
| `crl-revoked.pem` | serial 0x80 (DER `02 02 00 80`), the same point |
| `crl-revoked-first.pem` | serial 0x01, the same point |
| `crl-two-dp.pem` | serial 0x40, points `http://crl1.boneli.test/ca.crl` then `http://crl2.boneli.test/ca.crl` |
| `crl-five-urls.pem` | one point with five `http` URIs, `crl1` to `crl5` |
| `crl-ldap-only.pem` | one point with an `ldap` URI only |
| `crl-reasons-only.pem` | one point with `reasons` |
| `crl-dps.pem` | five points: `http` and `ldap` URIs; `reasons`; `cRLIssuer`; `nameRelativeToCRLIssuer`; `http` |
| `crl-stray.pem` | point `http://169.254.169.254/x.crl`, sent as an extra chain certificate |
| `crl-ca-fresh.crl` | 2026-01-01 to 2126-01-01, lists 0x01, 0x20, 0x40 and 0x80 (0x01 first, 0x80 last) |
| `crl-ca-fresh.pem` | the same list in PEM, which the check must refuse |
| `crl-ca-empty.crl` | 2026-01-01 to 2126-01-01, no entries |
| `crl-ca-week1.crl` | 2026-01-01 to 2026-01-08, no entries |
| `crl-ca-day2.crl` | 2026-01-02 to 2026-01-09, lists 0x80: the CA's next list a day after week1 |
| `crl-ca-idp.crl` | `issuingDistributionPoint` `http://crl.boneli.test/ca.crl`, lists 0x80 |
| `crl-ca-other-shard.crl` | `issuingDistributionPoint` `http://crl.boneli.test/other.crl`, no entries |
| `crl-ca-v1.crl` | no extensions, so version 1, which webpki refuses |
| `crl-ca-reversed.crl` | `thisUpdate` 2125-06-01 after `nextUpdate` 2125-01-01, signed by the CA |
| `crl-ca-forged.crl` | issuer name "Boneli CRL test CA" under another key, no entries |

The lists without a date above carry those of `crl-ca-fresh.crl`.

Generated once with OpenSSL 3.5 (`-not_before`, `-crl_lastupdate` and
`-crl_nextupdate`), from an empty directory, then copied here; the CA
keys (the CRL CA's and the forger's) are deleted at the end, as for the
fixtures above, and every file changes together when it runs again. Rust
for the generator stays rejected for the reason recorded above.

```sh
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }
key crl-ca.key; key crl-forged-ca.key; key crl-leaf.key
for ca in crl-ca crl-forged-ca; do
  openssl req -x509 -new -key "$ca.key" -subj "/CN=Boneli CRL test CA" \
    -not_before 20260101000000Z -not_after 21260101000000Z \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$ca.pem"
done
cat > leaf.cnf <<'CNF'
[one]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
crlDistributionPoints = URI:http://crl.boneli.test/ca.crl
[two]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
crlDistributionPoints = dp_crl1, dp_crl2
[five]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
crlDistributionPoints = URI:http://crl1.boneli.test/ca.crl, URI:http://crl2.boneli.test/ca.crl, URI:http://crl3.boneli.test/ca.crl, URI:http://crl4.boneli.test/ca.crl, URI:http://crl5.boneli.test/ca.crl
[ldap]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
crlDistributionPoints = URI:ldap://ldap.boneli.test/cn=Boneli%20CRL%20test%20CA?certificateRevocationList
[reasons]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
crlDistributionPoints = dp_reasons
[dps]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
crlDistributionPoints = dp_mixed, dp_reasons, dp_issuer, dp_relative, dp_last
[stray]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
crlDistributionPoints = URI:http://169.254.169.254/x.crl
[dp_crl1]
fullname = URI:http://crl1.boneli.test/ca.crl
[dp_crl2]
fullname = URI:http://crl2.boneli.test/ca.crl
[dp_mixed]
fullname = URI:http://crl.boneli.test/a.crl, URI:ldap://ldap.boneli.test/cn=a
[dp_reasons]
fullname = URI:http://crl.boneli.test/b.crl
reasons = keyCompromise
[dp_issuer]
fullname = URI:http://crl.boneli.test/c.crl
CRLissuer = dirName:issuer_dn
[dp_relative]
relativename = rdn_partition
[dp_last]
fullname = URI:http://crl.boneli.test/e.crl
[issuer_dn]
CN = Boneli CRL indirect issuer
[rdn_partition]
CN = Boneli CRL partition
CNF
sign() {
  openssl req -new -key crl-leaf.key -subj "/CN=localhost" |
    openssl x509 -req -CA crl-ca.pem -CAkey crl-ca.key -set_serial "$1" \
      -not_before 20260101000000Z -not_after 21260101000000Z \
      -extfile leaf.cnf -extensions "$2" -out "$3"
}
sign 0x10 one crl-good.pem
sign 0x80 one crl-revoked.pem
sign 0x01 one crl-revoked-first.pem
sign 0x40 two crl-two-dp.pem
sign 0x12 five crl-five-urls.pem
sign 0x13 ldap crl-ldap-only.pem
sign 0x14 reasons crl-reasons-only.pem
sign 0x15 dps crl-dps.pem
sign 0x16 stray crl-stray.pem

# CRLs. The index lists the revoked serials; `openssl ca -gencrl` sorts
# them, so 0x01 comes first and 0x80 last.
cat > ca.cnf <<'CNF'
[ca]
default_ca = test
[test]
database = index.txt
crlnumber = crlnumber
default_md = sha256
crl_extensions = crl_ext
[test_v1]
database = index.txt
default_md = sha256
[crl_ext]
authorityKeyIdentifier = keyid:always
[crl_idp]
authorityKeyIdentifier = keyid:always
issuingDistributionPoint = critical, @idp_ca
[crl_other]
authorityKeyIdentifier = keyid:always
issuingDistributionPoint = critical, @idp_other
[idp_ca]
fullname = URI:http://crl.boneli.test/ca.crl
[idp_other]
fullname = URI:http://crl.boneli.test/other.crl
CNF
revoked() { printf 'R\t21260101000000Z\t260101000000Z\t%s\tunknown\t/CN=localhost\n' "$1"; }
gencrl() { # out ca from to serials...; $EXT names the extension section, $SECT the CA section
  out=$1 ca=$2 from=$3 to=$4; shift 4
  : > index.txt; for s in "$@"; do revoked "$s" >> index.txt; done
  echo 01 > crlnumber
  openssl ca -config ca.cnf -name "${SECT:-test}" ${EXT:+-crlexts "$EXT"} -gencrl \
    -keyfile "$ca.key" -cert "$ca.pem" \
    -crl_lastupdate "$from" -crl_nextupdate "$to" -out "$out.pem"
  openssl crl -in "$out.pem" -outform DER -out "$out"
}
gencrl crl-ca-fresh.crl crl-ca 20260101000000Z 21260101000000Z 01 20 40 80
cp crl-ca-fresh.crl.pem crl-ca-fresh.pem
gencrl crl-ca-empty.crl crl-ca 20260101000000Z 21260101000000Z
gencrl crl-ca-week1.crl crl-ca 20260101000000Z 20260108000000Z
gencrl crl-ca-day2.crl crl-ca 20260102000000Z 20260109000000Z 80
EXT=crl_idp gencrl crl-ca-idp.crl crl-ca 20260101000000Z 21260101000000Z 80
EXT=crl_other gencrl crl-ca-other-shard.crl crl-ca 20260101000000Z 21260101000000Z
SECT=test_v1 gencrl crl-ca-v1.crl crl-ca 20260101000000Z 21260101000000Z
gencrl crl-ca-reversed.crl crl-ca 21250601000000Z 21250101000000Z
gencrl crl-ca-forged.crl crl-forged-ca 20260101000000Z 21260101000000Z
rm -f index.txt index.txt.* crlnumber crlnumber.* ./*.crl.pem leaf.cnf ca.cnf \
  crl-ca.key crl-forged-ca.key crl-forged-ca.pem
```

## Revocation by OCSP (`tests/ocsp.rs`, `src/revocation/ocsp/`, ADR-020)

A third test CA with leaves that name OCSP responders (authorityInfoAccess)
and no CRL point, delegated responder certificates, and answers of
OpenSSL's own responder. Every leaf has SAN `DNS:localhost,
IP:127.0.0.1`, EKU serverAuth, validity 2026-01-01 to 2126-01-01, and the
key `crl-leaf.key`; `ocsp.boneli.test` and its siblings never resolve.
Unlike the other CAs, the OCSP CA's key and the responder's key are kept
(`test-only-`), so the unit tests can build and sign answers at test
time; they protect nothing.

| File | What |
| --- | --- |
| `ocsp-ca.pem` | "Boneli OCSP test CA", 2026-01-01 to 2126-01-01, `keyCertSign, cRLSign` |
| `test-only-ocsp-ca.key` | its key, P-256, PKCS#8 |
| `ocsp-decoy-ca.pem` | a CA named "Boneli OCSP test CA" under `test-only-p256.key`: the decoy and the forger |
| `ocsp-good.pem` | serial 0x10; AIA `caIssuers` first, then OCSP `http://ocsp.boneli.test` |
| `ocsp-revoked.pem` | serial 0x80 (DER `02 02 00 80`), the same AIA |
| `ocsp-three-urls.pem` | serial 0x12, OCSP `http://ocsp1.boneli.test`, `http://ocsp2.boneli.test/`, `http://ocsp3.boneli.test` |
| `ocsp-ldap-only.pem` | serial 0x13, an `ldap` OCSP URI only |
| `ocsp-query.pem` | serial 0x14, OCSP `http://ocsp.boneli.test/?a=b` |
| `ocsp-and-crl.pem` | serial 0x15, OCSP and the CRL point `http://crl.boneli.test/ocsp-ca.crl` |
| `ocsp-ldap-crl.pem` | serial 0x16, OCSP and an `ldap`-only CRL point |
| `ocsp-responder.pem` | "Boneli OCSP test responder": EKU OCSPSigning, `ocsp-nocheck`, issued by the CA |
| `test-only-ocsp-responder.key` | the key of every `ocsp-responder*.pem`, P-256, PKCS#8 |
| `ocsp-responder-no-eku.pem` | the same without an EKU |
| `ocsp-responder-other-ca.pem` | the same, issued by the decoy |
| `ocsp-responder-expired.pem` | the same, valid 2026-01-01 to 2026-01-02 only |
| `ocsp-responder-ca.pem` | the same with `CA:TRUE` |
| `ocsp-good.req` | `openssl ocsp -no_nonce -reqout` for `ocsp-good.pem`, 68 B |
| `ocsp-good.resp` | good for 0x10, by name, signed by the CA, no certificates, 100 years |
| `ocsp-good-bykey.resp` | the same with the responder ID by key hash |
| `ocsp-revoked.resp` | revoked for 0x80 |
| `ocsp-unknown.resp` | unknown for 0x10 (an empty index) |
| `ocsp-delegated.resp` | good for 0x10, signed by `ocsp-responder.pem`, which it carries |
| `ocsp-expired.resp` | good for 0x10, `nextUpdate` one minute after it was made |

Generated once with OpenSSL 3.5 from a directory holding copies of
`crl-leaf.key` and `test-only-p256.key`, then copied here; the answers
carry the time of the run as `thisUpdate`, so every file changes together
when it runs again.

```sh
set -eu
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }
key test-only-ocsp-ca.key; key test-only-ocsp-responder.key
openssl req -x509 -new -key test-only-ocsp-ca.key -subj "/CN=Boneli OCSP test CA" \
  -not_before 20260101000000Z -not_after 21260101000000Z \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out ocsp-ca.pem
# The decoy: the CA's name under another key, test-only-p256.key.
openssl req -x509 -new -key test-only-p256.key -subj "/CN=Boneli OCSP test CA" \
  -not_before 20260101000000Z -not_after 21260101000000Z \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out ocsp-decoy-ca.pem
cat > ocsp.cnf <<'CNF'
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
authorityInfoAccess = caIssuers;URI:http://ca.boneli.test/ca.der, OCSP;URI:http://ocsp.boneli.test
[three]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
authorityInfoAccess = OCSP;URI:http://ocsp1.boneli.test, OCSP;URI:http://ocsp2.boneli.test/, OCSP;URI:http://ocsp3.boneli.test
[ldap]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
authorityInfoAccess = OCSP;URI:ldap://ldap.boneli.test/cn=Boneli%20OCSP%20test%20CA
[query]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
authorityInfoAccess = OCSP;URI:http://ocsp.boneli.test/?a=b
[both]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
authorityInfoAccess = OCSP;URI:http://ocsp.boneli.test
crlDistributionPoints = URI:http://crl.boneli.test/ocsp-ca.crl
[ldap_crl]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
authorityInfoAccess = OCSP;URI:http://ocsp.boneli.test
crlDistributionPoints = URI:ldap://ldap.boneli.test/cn=Boneli%20OCSP%20test%20CA?certificateRevocationList
[responder]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = OCSPSigning
noCheck = ignored
[no_eku]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
noCheck = ignored
[responder_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyCertSign
extendedKeyUsage = OCSPSigning
noCheck = ignored
CNF
cert() { # serial section out key issuer issuer-key [from to]
  openssl req -new -key "$4" -subj "/CN=${CN:-localhost}" |
    openssl x509 -req -CA "$5" -CAkey "$6" -set_serial "$1" \
      -not_before "${7:-20260101000000Z}" -not_after "${8:-21260101000000Z}" \
      -extfile ocsp.cnf -extensions "$2" -out "$3"
}
leaf() { cert "$1" "$2" "$3" crl-leaf.key ocsp-ca.pem test-only-ocsp-ca.key; }
leaf 0x10 leaf ocsp-good.pem
leaf 0x80 leaf ocsp-revoked.pem
leaf 0x12 three ocsp-three-urls.pem
leaf 0x13 ldap ocsp-ldap-only.pem
leaf 0x14 query ocsp-query.pem
leaf 0x15 both ocsp-and-crl.pem
leaf 0x16 ldap_crl ocsp-ldap-crl.pem
CN="Boneli OCSP test responder"
r() { cert "$1" "$2" "$3" test-only-ocsp-responder.key "$4" "$5" ${6:+"$6"} ${7:+"$7"}; }
r 0x20 responder ocsp-responder.pem ocsp-ca.pem test-only-ocsp-ca.key
r 0x21 no_eku ocsp-responder-no-eku.pem ocsp-ca.pem test-only-ocsp-ca.key
r 0x22 responder ocsp-responder-other-ca.pem ocsp-decoy-ca.pem test-only-p256.key
r 0x23 responder ocsp-responder-expired.pem ocsp-ca.pem test-only-ocsp-ca.key \
  20260101000000Z 20260102000000Z
r 0x24 responder_ca ocsp-responder-ca.pem ocsp-ca.pem test-only-ocsp-ca.key
CN=
# Responses from openssl's own responder: 0x10 good, 0x80 revoked, a
# serial missing from the index unknown.
printf 'V\t21260101000000Z\t\t10\tunknown\t/CN=localhost\n' > index.txt
printf 'R\t21260101000000Z\t260101000000Z\t80\tunknown\t/CN=localhost\n' >> index.txt
: > empty.txt
openssl ocsp -issuer ocsp-ca.pem -cert ocsp-good.pem -no_nonce -reqout ocsp-good.req
openssl ocsp -issuer ocsp-ca.pem -cert ocsp-revoked.pem -no_nonce -reqout ocsp-revoked.req
resp() { # request out index signer key [options]
  in=$1 out=$2 idx=$3 signer=$4 rkey=$5; shift 5
  openssl ocsp -index "$idx" -CA ocsp-ca.pem -rsigner "$signer" -rkey "$rkey" \
    -reqin "$in" -respout "$out" "$@"
}
ca() { resp "$1" "$2" "$3" ocsp-ca.pem test-only-ocsp-ca.key -resp_no_certs "$4" "$5" ${6:+"$6"}; }
ca ocsp-good.req ocsp-good.resp index.txt -ndays 36500
ca ocsp-good.req ocsp-good-bykey.resp index.txt -ndays 36500 -resp_key_id
ca ocsp-revoked.req ocsp-revoked.resp index.txt -ndays 36500
ca ocsp-good.req ocsp-unknown.resp empty.txt -ndays 36500
ca ocsp-good.req ocsp-expired.resp index.txt -nmin 1
resp ocsp-good.req ocsp-delegated.resp index.txt ocsp-responder.pem \
  test-only-ocsp-responder.key -ndays 36500
rm -f index.txt index.txt.* empty.txt empty.txt.* ocsp.cnf ocsp-revoked.req
```

### Real captures

Public certificates and signed public OCSP answers, captured on
2026-11-20 between 13:24 and 13:29 UTC while planning #79; the unit tests
check each at its capture time and at its `nextUpdate`. Each chain is
what the server sent, leaf first.

| File | What |
| --- | --- |
| `capture-e36-chain.pem` | `github.com`, issued by Sectigo DV E36 (ECDSA) |
| `capture-e36.req`, `capture-e36.resp` | openssl's request (83 B) and Sectigo's answer, good, 279 B, fetched at 1,795,181,189 |
| `capture-r36-chain.pem` | `gitlab.com`, issued by Sectigo DV R36 (RSA), a 17-byte serial |
| `capture-r36.req`, `capture-r36.resp` | openssl's request (84 B) and Sectigo's answer, good, 599 B, fetched at 1,795,181,189 |
| `capture-globalsign-chain.pem`, `capture-globalsign.resp` | `www.globalsign.com` and GlobalSign's answer from a delegated responder, which it carries, good, fetched at 1,795,181,238 |
| `capture-sslcom-revoked-chain.pem`, `capture-sslcom-revoked.resp` | `revoked-rsa-dv.ssl.com` and SSL.com's answer, revoked, responder by name, fetched at 1,795,181,340 |

```sh
host=github.com   # gitlab.com, www.globalsign.com, revoked-rsa-dv.ssl.com
openssl s_client -connect "$host:443" -servername "$host" -showcerts </dev/null |
  awk '/BEGIN CERT/,/END CERT/' > chain.pem
csplit -s -z -f cert- chain.pem '/BEGIN CERT/' '{*}'
url=$(openssl x509 -in cert-00 -noout -ocsp_uri)
openssl ocsp -issuer cert-01 -cert cert-00 -no_nonce -reqout capture.req
curl -s "$url/$(base64 -w0 capture.req | sed 's/+/%2B/g; s#/#%2F#g; s/=/%3D/g')" \
  -o capture.resp
openssl ocsp -respin capture.resp -resp_text -noverify
```

## Revocation of intermediates (`tests/intermediates.rs`, `src/revocation/ca_list.rs`, ADR-027)

A fourth test hierarchy: a root, six CAs in a line, each issued by the one
before, and leaves under them. Every CA is `CA:TRUE` with `keyCertSign,
cRLSign` and names two points for its issuer's list,
`http://crl1.boneli.test/<issuer>.crl` and
`http://crl2.boneli.test/<issuer>.crl` (`<issuer>` is `root`, `ca1` ...
`ca5`); every leaf names one, `http://crl1.boneli.test/<issuer>.crl`. All
CAs share one key, so a leaf or CA under "CA 1" verifies under any of
CA 1's variants. The root's and the CAs' keys are kept (`test-only-`), so
the tests build and sign lists at test time; they protect nothing. All
validities are 2026-01-01 to 2126-01-01, every leaf has SAN
`DNS:localhost, IP:127.0.0.1`, EKU serverAuth and the key `crl-leaf.key`.

| File | What |
| --- | --- |
| `chain-root.pem` | "Boneli chain test root", self-signed, no point |
| `test-only-chain-root.key` | its key, P-256, PKCS#8 |
| `chain-ca1.pem` ... `chain-ca6.pem` | "Boneli chain test CA 1" ... "6", serials 0x11 ... 0x16, CA 1 issued by the root, each next one by the one before |
| `test-only-chain-ca.key` | the key of every CA, P-256, PKCS#8 |
| `chain-ca1-no-point.pem` | CA 1 without a CRL point, serial 0x21 |
| `chain-ca1-ldap.pem` | CA 1 with an `ldap` point only, serial 0x22 |
| `chain-ca1-five-urls.pem` | CA 1 with five points, `crl1` ... `crl5`, serial 0x23 |
| `chain-ca1-no-crl-sign.pem` | CA 1 with `keyCertSign` only, serial 0x24: the issuer of `chain-ca2.pem` that may not sign lists |
| `chain-stray-ca.pem` | "Boneli chain stray CA" under the root, point `http://169.254.169.254/x.crl`, serial 0x25, sent beside a path |
| `chain-leaf-ca1.pem`, `chain-leaf-ca2.pem`, `chain-leaf-ca5.pem`, `chain-leaf-ca6.pem` | leaves under CA 1, 2, 5 and 6, serials 0x31, 0x32, 0x35, 0x36 |
| `chain-leaf-ocsp-ca1.pem` | a leaf under CA 1 with OCSP `http://ocsp.boneli.test` and no CRL point, serial 0x37 |
| `chain-leaf-none-ca1.pem` | a leaf under CA 1 with neither, serial 0x38 |
| `chain-root-empty.crl` | the root's list from openssl, no entries, 2026-01-01 to 2126-01-01 |
| `chain-root-lists-ca1.crl` | the same with a critical issuingDistributionPoint `onlyContainsCACerts` and no name (Let's Encrypt's and GoDaddy's form), listing 0x11 |

Generated once with OpenSSL 3.5 from a directory holding a copy of
`crl-leaf.key`, then copied here; regenerating creates new keys, and every
file changes together. Rust for the generator stays rejected for the
reason recorded above.

```sh
set -eu
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }
key test-only-chain-root.key; key test-only-chain-ca.key
openssl req -x509 -new -key test-only-chain-root.key -subj "/CN=Boneli chain test root" \
  -not_before 20260101000000Z -not_after 21260101000000Z \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out chain-root.pem
cat > chain.cnf <<'CNF'
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
crlDistributionPoints = dp1, dp2
[ca_none]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
[ca_ldap]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
crlDistributionPoints = URI:ldap://ldap.boneli.test/cn=Boneli%20chain%20test%20root?certificateRevocationList
[ca_five]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
crlDistributionPoints = URI:http://crl1.boneli.test/${ENV::ISSUER}.crl, URI:http://crl2.boneli.test/${ENV::ISSUER}.crl, URI:http://crl3.boneli.test/${ENV::ISSUER}.crl, URI:http://crl4.boneli.test/${ENV::ISSUER}.crl, URI:http://crl5.boneli.test/${ENV::ISSUER}.crl
[ca_no_crl_sign]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign
crlDistributionPoints = dp1, dp2
[ca_stray]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
crlDistributionPoints = URI:http://169.254.169.254/x.crl
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
crlDistributionPoints = URI:http://crl1.boneli.test/${ENV::ISSUER}.crl
[leaf_ocsp]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
authorityInfoAccess = OCSP;URI:http://ocsp.boneli.test
[leaf_none]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
[dp1]
fullname = URI:http://crl1.boneli.test/${ENV::ISSUER}.crl
[dp2]
fullname = URI:http://crl2.boneli.test/${ENV::ISSUER}.crl
CNF
cert() { # serial section subject key issuer-pem issuer-key issuer-name out
  ISSUER=$7 openssl req -new -key "$4" -subj "/CN=$3" |
    ISSUER=$7 openssl x509 -req -CA "$5" -CAkey "$6" -set_serial "$1" \
      -not_before 20260101000000Z -not_after 21260101000000Z \
      -extfile chain.cnf -extensions "$2" -out "$8"
}
ca() { # serial section n issuer-pem issuer-key issuer-name out
  cert "$1" "$2" "Boneli chain test CA $3" test-only-chain-ca.key "$4" "$5" "$6" "$7"
}
ca 0x11 ca 1 chain-root.pem test-only-chain-root.key root chain-ca1.pem
for n in 2 3 4 5 6; do
  p=$((n - 1)); ca "0x1$n" ca "$n" "chain-ca$p.pem" test-only-chain-ca.key "ca$p" "chain-ca$n.pem"
done
ca 0x21 ca_none 1 chain-root.pem test-only-chain-root.key root chain-ca1-no-point.pem
ca 0x22 ca_ldap 1 chain-root.pem test-only-chain-root.key root chain-ca1-ldap.pem
ca 0x23 ca_five 1 chain-root.pem test-only-chain-root.key root chain-ca1-five-urls.pem
ca 0x24 ca_no_crl_sign 1 chain-root.pem test-only-chain-root.key root chain-ca1-no-crl-sign.pem
cert 0x25 ca_stray "Boneli chain stray CA" test-only-chain-ca.key chain-root.pem \
  test-only-chain-root.key root chain-stray-ca.pem
leaf() { # serial section n out
  cert "$1" "$2" localhost crl-leaf.key "chain-ca$3.pem" test-only-chain-ca.key "ca$3" "$4"
}
leaf 0x31 leaf 1 chain-leaf-ca1.pem
leaf 0x32 leaf 2 chain-leaf-ca2.pem
leaf 0x35 leaf 5 chain-leaf-ca5.pem
leaf 0x36 leaf 6 chain-leaf-ca6.pem
leaf 0x37 leaf_ocsp 1 chain-leaf-ocsp-ca1.pem
leaf 0x38 leaf_none 1 chain-leaf-none-ca1.pem
# Two lists from openssl, an encoder independent of the tests' own.
cat > ca.cnf <<'CNF'
[ca]
default_ca = test
[test]
database = index.txt
crlnumber = crlnumber
default_md = sha256
crl_extensions = crl_ext
[crl_ext]
authorityKeyIdentifier = keyid:always
[crl_ca_only]
authorityKeyIdentifier = keyid:always
issuingDistributionPoint = critical, @idp_ca_only
[idp_ca_only]
onlyCA = TRUE
CNF
gencrl() { # out serials...; $EXT names the extension section
  out=$1; shift
  : > index.txt
  for s in "$@"; do
    printf 'R\t21260101000000Z\t260101000000Z\t%s\tunknown\t/CN=x\n' "$s" >> index.txt
  done
  echo 01 > crlnumber
  openssl ca -config ca.cnf ${EXT:+-crlexts "$EXT"} -gencrl \
    -keyfile test-only-chain-root.key -cert chain-root.pem \
    -crl_lastupdate 20260101000000Z -crl_nextupdate 21260101000000Z -out "$out.pem"
  openssl crl -in "$out.pem" -outform DER -out "$out"
}
gencrl chain-root-empty.crl
EXT=crl_ca_only gencrl chain-root-lists-ca1.crl 11
```

### Real captures of CA lists

Public certificates and lists, captured on 2026-11-20 between 23:16 and
23:18 UTC while implementing #80 (the lists at 23:18:12, 1,795,216,692);
the unit tests check them at that time and at each list's `nextUpdate`.
Each chain is what the server sent, leaf first.

| File | What |
| --- | --- |
| `capture-isrgrootx1-chain.pem` | `valid-isrgrootx1.letsencrypt.org`: leaf, YR1, `Root YR` cross-signed by ISRG Root X1 |
| `capture-microsoft-chain.pem` | `www.microsoft.com`: leaf, Microsoft TLS G2 RSA CA OCSP, `Microsoft TLS RSA Root G2` cross-signed by DigiCert Global Root G2 |
| `capture-root-yr-superseded.pem` | the `Root YR` cross-sign that `x1.c.lencr.org` lists as superseded, serial `FAA6275DC258431D9766EC3045EF24AC`, from crt.sh (id 20947047101) |
| `capture-crl-*.crl` | the 16 distinct lists the 26 intermediates of 46 hosts named: Amazon Root CA 1 and 3, DigiCert Global Root G2, GlobalSign R3 and R46, GoDaddy G2 and TLS Root R1, GTS R4, Let's Encrypt `x1`, `x2`, `ye` and `yr`, Microsoft TLS RSA Root G2, Sectigo E46 and R46, SSL.com TLS RSA Root 2022 |

The measurement of ADR-027's Context, from an empty directory, with
`hosts.txt` holding the 46 host names, one per line; `path` is a scratch
Rust program, not committed, that runs `webpki::EndEntityCert::
verify_for_usage` with `webpki-roots` 1.0.12 (`serverAuth`, no revocation)
on a chain and writes the path's intermediates as `int<k>.der`, and that
prints webpki's verdict on a list (`OwnedCertRevocationList::from_der`):

```sh
while read -r h; do
  timeout 15 openssl s_client -connect "$h:443" -servername "$h" -showcerts </dev/null 2>/dev/null |
    awk '/BEGIN CERT/,/END CERT/' > "$h.pem"
  mkdir -p "path-$h"; path path "$h.pem" "path-$h"
done < hosts.txt
for f in path-*/int*.der; do
  openssl x509 -inform DER -in "$f" -noout -subject -issuer -ext crlDistributionPoints -ocsp_uri
done
# Each distinct URL:
curl -s -o list.crl -D list.head \
  -w '%{http_code} %{time_connect} %{time_starttransfer} %{time_total} %{size_download} %{num_redirects}' "$url"
openssl crl -inform DER -in list.crl -noout -text
path crl list.crl
curl -s 'https://crt.sh/?d=20947047101' > capture-root-yr-superseded.pem
```

## Image signatures (`tests/keys.rs`, `tests/codesign.rs`, `src/codesign/`, ADR-029)

Public keys of each `KeyKind`, signatures OpenSSL made with them, the
refused keys, and a code-signing test PKI whose leaves the unit tests of
`src/codesign.rs` build and sign at test time (`src/codesign/testing.rs`).

| File | What |
| --- | --- |
| `pubkey-message.txt` | the message every `pubkey-*.sig` signs, 64 bytes, no newline |
| `pubkey-p256.pem`, `pubkey-p256.sig` | ECDSA P-256 key, ECDSA-SHA256 signature (DER) |
| `pubkey-p256-sha384.sig` | the same key's valid ECDSA-SHA384 signature, which `PublicKey` must refuse: the kind fixes SHA-256 |
| `pubkey-p384.pem`, `pubkey-p384.sig` | ECDSA P-384 key, ECDSA-SHA384 signature |
| `pubkey-ed25519.pem`, `pubkey-ed25519.sig` | Ed25519 key and signature |
| `pubkey-rsa2048.pem`, `pubkey-rsa2048.sig` | RSA 2048-bit key, RSASSA-PKCS1-v1_5 SHA-256 signature |
| `pubkey-rsa8192.pem`, `pubkey-rsa8192.sig` | RSA 8192-bit key (1,491 bytes of PEM, the largest accepted), the same scheme |
| `pubkey-p521.pem`, `pubkey-rsa1024.pem`, `pubkey-dsa.pem` | refused keys: P-521, RSA below 2048 bits, DSA |
| `codesign-root.pem` | "Boneli code-signing test root", P-384, 2026-01-01 to 2126-01-01 |
| `codesign-intermediate.pem` | "Boneli code-signing test intermediate", signed by the root, `CA:TRUE, pathlen:0`, EKU codeSigning, as Sigstore's public-good intermediate |
| `codesign-intermediate-no-eku.pem` | the same key under another name, without an EKU |
| `test-only-codesign-ca.key` | the key of both intermediates, P-384, PKCS#8: it signs the leaves at test time |
| `test-only-ct-log.key`, `codesign-ct-log.pem` | the test CT log's key, P-256, and its public key: it signs the embedded SCTs |

The private keys of the `pubkey-*` files and the root's key are not kept;
ECDSA signatures are randomized, so regenerating changes every file and
they change together. The unit tests' leaves carry `pubkey-p256.pem`'s
key (`pubkey-p521.pem`'s for the refused one). Generated once with
OpenSSL 3.5, from an empty directory, then copied here; Rust for the
generator stays rejected for the reason recorded above:

```sh
ec() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$1" -out "$2"; }
# Keys for each KeyKind, and the refused ones.
ec P-256 p256.key; ec P-384 p384.key; ec P-521 p521.key
openssl genpkey -algorithm ED25519 -out ed25519.key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa2048.key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:8192 -out rsa8192.key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out rsa1024.key
openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -out dsa.param
openssl genpkey -paramfile dsa.param -out dsa.key
for k in p256 p384 p521 ed25519 rsa2048 rsa8192 rsa1024 dsa; do
  openssl pkey -in "$k.key" -pubout -out "pubkey-$k.pem"
done
printf '%s' 'Boneli public key test message: the image digest and its signer.' > pubkey-message.txt
openssl dgst -sha256 -sign p256.key -out pubkey-p256.sig pubkey-message.txt
openssl dgst -sha384 -sign p256.key -out pubkey-p256-sha384.sig pubkey-message.txt
openssl dgst -sha384 -sign p384.key -out pubkey-p384.sig pubkey-message.txt
openssl pkeyutl -sign -rawin -inkey ed25519.key -in pubkey-message.txt -out pubkey-ed25519.sig
openssl dgst -sha256 -sign rsa2048.key -out pubkey-rsa2048.sig pubkey-message.txt
openssl dgst -sha256 -sign rsa8192.key -out pubkey-rsa8192.sig pubkey-message.txt
# The code-signing test PKI: a P-384 root, an intermediate with codeSigning,
# the same key under a second name without an EKU, and a CT log key.
ec P-384 root.key; ec P-384 test-only-codesign-ca.key; ec P-256 test-only-ct-log.key
openssl req -x509 -new -key root.key -subj "/CN=Boneli code-signing test root" \
  -not_before 20260101000000Z -not_after 21260101000000Z \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out codesign-root.pem
printf '%s\n' "basicConstraints=critical,CA:TRUE,pathlen:0" \
  "keyUsage=critical,keyCertSign,cRLSign" "extendedKeyUsage=codeSigning" > ca.ext
printf '%s\n' "basicConstraints=critical,CA:TRUE,pathlen:0" \
  "keyUsage=critical,keyCertSign,cRLSign" > ca-no-eku.ext
inter() {
  openssl req -new -key test-only-codesign-ca.key -subj "/CN=$1" |
    openssl x509 -req -CA codesign-root.pem -CAkey root.key -set_serial "$2" \
      -not_before 20260101000000Z -not_after 21260101000000Z -extfile "$3" -out "$4"
}
inter "Boneli code-signing test intermediate" 2 ca.ext codesign-intermediate.pem
inter "Boneli code-signing test intermediate without EKU" 3 ca-no-eku.ext codesign-intermediate-no-eku.pem
openssl pkey -in test-only-ct-log.key -pubout -out codesign-ct-log.pem
rm p256.key p384.key p521.key ed25519.key rsa2048.key rsa8192.key rsa1024.key dsa.key dsa.param root.key ca.ext ca-no-eku.ext
```

`openssl pkey -pubin -in pubkey-p256.pem -out k.pem && openssl dgst -sha256
-verify k.pem -signature pubkey-p256.sig pubkey-message.txt` checks a
signature independently of Boneli (`-sha384` for P-384; `openssl pkeyutl
-verify -pubin -inkey pubkey-ed25519.pem -rawin -in pubkey-message.txt
-sigfile pubkey-ed25519.sig` for Ed25519).

### Real Sigstore captures (known answers)

Public certificates and keys of Sigstore's public-good instance, and the
Fulcio leaves of two real image signatures, captured on 2026-11-23:

| File | What |
| --- | --- |
| `sigstore-fulcio-intermediate.pem` | "sigstore-intermediate" (O=sigstore.dev), P-384, 2022-04-13 to 2031-10-05, EKU codeSigning, `CA:TRUE, pathlen:0`: the first certificate of the second `certificateAuthorities` entry of `trusted_root.json` |
| `sigstore-fulcio-root.pem` | "sigstore" (O=sigstore.dev), P-384, 2021-10-07 to 2031-10-05: the second certificate of that entry |
| `sigstore-ctfe-2022.pem` | the public key of `ctfe.sigstore.dev/2022`, P-256, log ID `dd3d306a…29ee8e` = SHA-256 of the key, valid from 2022-10-20 |
| `sigstore-leaf-kubernetes.pem` | the leaf of the `.sig` of `registry.k8s.io/pause:3.10` (index `sha256:ee6521f2…8199917a`, served by `europe-west3-docker.pkg.dev/k8s-artifacts-prod/images/pause`): SAN `email:krel-trust@k8s-releng-prod.iam.gserviceaccount.com`, issuer `https://accounts.google.com`, valid 2024-05-23 21:35:28 to 21:45:28 UTC, one SCT from the 2022 log at 21:35:28.451; Rekor `integratedTime` 1716500129 |
| `sigstore-leaf-chainguard.pem` | the leaf of the `.sig` of `chainguard/node` on Docker Hub (index `sha256:3fb5318a58807dec0f2ece547efbe8d62c67b7b2fd91a16795b98651d6385dbe`): SAN `URI:https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main`, issuer `https://token.actions.githubusercontent.com`, valid 2026-11-23 21:48:05 to 21:58:05 UTC, P-256 signed with ECDSA-SHA384, one SCT from the 2022 log at 21:48:05.986; Rekor `integratedTime` 1795470488 |

Chainguard signs its images again from time to time and replaces the
`.sig` tag, so a later capture of the same digest gives another leaf
(the one of 2026-11-20 had `integratedTime` 1795194128); the `.sig`
manifests captured here had SHA-256 `1b5166e7…0f421acf` (Kubernetes,
5,924 bytes) and `b36df08e…3c6c0777` (Chainguard, 9,958 bytes), and
`trusted_root.json` `6494e21e…6bc0b66` (6,787 bytes). From an empty
directory, with `jq`:

```sh
curl -sS -o trusted_root.json \
  https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json
cert() { jq -r ".certificateAuthorities[1].certChain.certificates[$1].rawBytes" trusted_root.json |
  base64 -d | openssl x509 -inform DER -out "$2"; }
cert 0 sigstore-fulcio-intermediate.pem; cert 1 sigstore-fulcio-root.pem
jq -r '.ctlogs[] | select(.baseUrl == "https://ctfe.sigstore.dev/2022") | .publicKey.rawBytes' \
  trusted_root.json | base64 -d | openssl pkey -pubin -inform DER -out sigstore-ctfe-2022.pem
acc='application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json'
# registry.k8s.io answers 307 to a regional Artifact Registry host.
k8s=https://europe-west3-docker.pkg.dev/v2/k8s-artifacts-prod/images/pause/manifests
curl -sS -H "Accept: $acc" -o k8s-sig.json \
  "$k8s/sha256-ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a.sig"
tok=$(curl -fsS 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:chainguard/node:pull' | jq -r .token)
curl -sS -H "Authorization: Bearer $tok" -H "Accept: $acc" -o cg-sig.json \
  https://registry-1.docker.io/v2/chainguard/node/manifests/sha256-3fb5318a58807dec0f2ece547efbe8d62c67b7b2fd91a16795b98651d6385dbe.sig
leaf() { jq -r '.layers[0].annotations["dev.sigstore.cosign/certificate"]' "$1" > "$2"; }
leaf k8s-sig.json sigstore-leaf-kubernetes.pem; leaf cg-sig.json sigstore-leaf-chainguard.pem
jq -r '.layers[0].annotations["dev.sigstore.cosign/bundle"]' k8s-sig.json | jq .Payload.integratedTime
openssl verify -CAfile sigstore-fulcio-root.pem -untrusted sigstore-fulcio-intermediate.pem \
  -attime 1716500129 sigstore-leaf-kubernetes.pem
```

## RFC 3161 timestamps (`tests/timestamp.rs`, `src/timestamp/`, ADR-038)

Sigstore's public-good timestamp authority and seven of its tokens,
captured on 2026-11-25 from the bundles named below; each `.tsr` is a
bundle's `signedTimestamp` (a whole DER `TimeStampResp`) and each `.sig`
the bytes it is over, the bundle's DSSE signature. Every token verifies
with OpenSSL against the two certificates
(`openssl ts -verify -in tsa-X.tsr -data tsa-X.sig -CAfile tsa-sigstore-root.pem -untrusted tsa-sigstore-leaf.pem`).

| File | SHA-256 | What |
| --- | --- | --- |
| `tsa-sigstore-leaf.pem` | `366bf80f…194f2bdf` | "sigstore-tsa" (O=sigstore.dev), P-384, 2025-04-08 to 2035-04-06, keyUsage digitalSignature and EKU timeStamping, both critical: the first certificate of `timestampAuthorities[0]` of `trusted_root.json` |
| `tsa-sigstore-root.pem` | `bf6960b2…22dbb03f` | "sigstore-tsa-selfsigned", P-384, the same validity, `CA:TRUE, pathlen:0`: the anchor, its second certificate |
| `tsa-aicr-recipe-catalog-1.3.0.tsr`, `.sig` | `2abe744c…92d4075c` | release asset `recipe-catalog.sigstore.json` of `NVIDIA/aicr` v1.3.0 (Rekor v2), genTime 1794873195 |
| `tsa-aicr-sbom-1.3.0.tsr`, `.sig` | `88eb548e…3ff69376` | release asset `aicr_1.3.0_linux_amd64.sbom.json.sigstore.json` (Rekor v2), genTime 1794873249 |
| `tsa-aicr-openvex-858ab1e4.tsr`, `.sig` | `16262f2a…9386c5c4` | the OpenVEX bundle `sha256:054f435f…` of `ghcr.io/nvidia/aicr`'s amd64 manifest `sha256:858ab1e4…` (referrer manifest `sha256:461cdf6c…`; Rekor v1 with a SET), genTime 1793656382 |
| `tsa-aicr-openvex-1.3.0.tsr`, `.sig` | `a5f6b43f…732976b7` | the OpenVEX bundle `sha256:6701dc50…` of aicr v1.3.0's amd64 manifest `sha256:21fb2bdb…` (referrer manifest `sha256:d20cc74d…`; Rekor v1 with a SET), genTime 1794873594 |
| `tsa-bex-cnb-run.tsr`, `.sig` | `eeb8fe5e…0768238d` | `crates/boneli-sigstore/tests/data/bex-cnb-run.bundle.json` (Rekor v2), genTime 1793371569 |
| `tsa-cosign-latest.tsr`, `.sig` | `376eb7ca…ab31c5b7` | `crates/boneli-sigstore/tests/data/cosign-latest.bundle.json` (keyed, Rekor v1), genTime 1792519726 |
| `tsa-trillian-log-server.tsr`, `.sig` | `62edc199…6b0b8710` | `crates/boneli-sigstore/tests/data/trillian-log-server.bundle.json` (Rekor v1 with a SET), genTime 1795367610 |
| `test-only-tsa.key`, `test-only-tsa.pub.pem` | | the test TSA's key, ECDSA P-256, PKCS#8, and its public key: `src/timestamp/testing.rs` signs tokens with it at test time (`EcdsaP256Key`), under leaves the code-signing test intermediate's key issues, with that intermediate as the anchor |

The SHA-256 is the token's. With the bundles in the current directory
(the three of `crates/boneli-sigstore/tests/data/` above, and the aicr
ones fetched as in that README: the release assets by
`https://github.com/NVIDIA/aicr/releases/download/v1.3.0/<name>`, the
OpenVEX bundles as the blob of their referrer manifest), with `jq`:

```sh
tsa() { jq -r ".timestampAuthorities[0].certChain.certificates[$1].rawBytes" trusted_root.json |
  base64 -d | openssl x509 -inform DER -out "$2"; }
tsa 0 tsa-sigstore-leaf.pem; tsa 1 tsa-sigstore-root.pem
token() { # bundle, name
  jq -r '.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0].signedTimestamp' "$1" |
    base64 -d > "tsa-$2.tsr"
  jq -r '.dsseEnvelope.signatures[0].sig' "$1" | base64 -d > "tsa-$2.sig"
}
token recipe-catalog.sigstore.json aicr-recipe-catalog-1.3.0
token aicr_1.3.0_linux_amd64.sbom.json.sigstore.json aicr-sbom-1.3.0
token openvex-858ab1e4.bundle.json aicr-openvex-858ab1e4
token openvex-1.3.0.bundle.json aicr-openvex-1.3.0
token bex-cnb-run.bundle.json bex-cnb-run
token cosign-latest.bundle.json cosign-latest
token trillian-log-server.bundle.json trillian-log-server
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out test-only-tsa.key
openssl pkey -in test-only-tsa.key -pubout -out test-only-tsa.pub.pem
```

The test key is test-only and signs nothing outside these tests; the
same key is in `crates/boneli-sigstore/tests/data/`.

### GitHub's Fulcio and TSA (`tests/codesign.rs`, `tests/timestamp.rs`, ADR-040)

The certificates of GitHub's private-repository instance and the tokens
of its two committed bundles (K1, attest-demo, window 0; K2, GitHub's
prober, window 4), captured on 2026-11-26 from
`crates/boneli-sigstore/tests/data/` (`github-trusted-root.json`,
`attest-demo-0.0.12.bundle.json`, `attest-prober-github.bundle.json`,
whose README names their sources). Each leaf verifies with OpenSSL
through l2 and l1 at its genTime (`openssl verify -purpose codesign
-CAfile github-root.pem -untrusted <l2 + l1> -attime <genTime>`), and each
token through its window's TSA leaf (`openssl ts -verify -CAfile
github-root.pem -untrusted <leaf + intermediate> -attime <genTime>`).

| File | SHA-256 | What |
| --- | --- | --- |
| `github-root.pem` | `6d6734c7…3beec26e` | "Internal Services Root" (O=GitHub, Inc.), 2023-08-07 to 2033-08-04, `CA:TRUE, pathlen:2`: the anchor of all 12 chains |
| `github-fulcio-l1.pem` | `3094cea7…cbc03148` | "Fulcio Intermediate l1", 2023-09-11 to 2028-09-09, `CA:TRUE, pathlen:1`, **no EKU**: the second certificate of every CA entry |
| `github-fulcio-0-l2.pem` | `82f6e41e…9c10c8f3` | "Fulcio Intermediate l2" of CA window 0, 2023-09-12 to 2024-09-11, EKU codeSigning, `pathlen:0` |
| `github-fulcio-3-l2.pem` | `d6eaae55…4369d88b` | the same name in window 3, 2025-05-27 to 2026-05-27, another key |
| `github-fulcio-4-l2.pem` | `7e157d19…e50a2d4d` | the same name in window 4, 2025-11-13 to 2026-11-13 |
| `github-tsa-intermediate.pem` | `ebfcb01e…99c96eac` | "TSA intermediate", 2023-08-07 to 2028-08-05, EKU timeStamping: the second certificate of every TSA entry |
| `github-tsa-0-leaf.pem` | `ddac887c…a31e78cc` | "TSA Timestamping" of TSA window 0, 2023-08-31 to 2024-08-30, EKU timeStamping (critical) |
| `github-tsa-4-leaf.pem` | `61cbc008…b0a1e44d` | the same name in window 4, 2025-11-13 to 2026-11-13 |
| `github-leaf-attest-demo.pem` | `9916d4b8…4038072a` | K1's leaf, SAN `URI:https://github.com/actions/attest-demo/.github/workflows/build-python.yml@refs/heads/main`, 2024-04-22 17:33:26 to 17:43:26 UTC, no SCT list |
| `github-leaf-prober.pem` | `79fabbc5…c11f98c0` | K2's leaf, SAN `URI:https://github.com/actions/attest-build-provenance/.github/workflows/prober.yml@refs/heads/main`, 2025-11-21 08:13:26 to 08:23:26 UTC, no SCT list |
| `tsa-github-attest-demo.tsr`, `.sig` | `c2754515…4e6d94e3` | K1's token (SHA-384, `ecdsa-with-SHA384`, genTime 1713807206) and the DSSE signature it is over |
| `tsa-github-prober.tsr`, `.sig` | `42ba708d…68cb087e` | K2's token (genTime 1763712806) and its signed bytes |
| `tsa-p256-sha384.tsr` | `5ab67998…b2841a2a` | a synthetic token OpenSSL made over `the DSSE signature bytes` (genTime 1795648254), signed P-256 `ecdsa-with-SHA384` by `test-only-tsa.key`: the pairing the SHA-384 triple refuses, which ring cannot sign at test time |
| `tsa-p256-sha384-leaf.pem` | `22d60115…64719bda` | its TSA leaf, P-256, issued by the code-signing test intermediate's key (`test-only-codesign-ca.key`), 2026-01-01 to 2126-01-01, keyUsage digitalSignature and EKU timeStamping, both critical |

The SHA-256 is the token's for the `.tsr`/`.sig` rows. From the three
GitHub files in the current directory, with `jq`:

```sh
R=github-trusted-root.json
tsa() { jq -r ".timestampAuthorities[$1].certChain.certificates[$2].rawBytes" $R |
  base64 -d | openssl x509 -inform DER -out "$3"; }
ca() { jq -r ".certificateAuthorities[$1].certChain.certificates[$2].rawBytes" $R |
  base64 -d | openssl x509 -inform DER -out "$3"; }
tsa 0 0 github-tsa-0-leaf.pem; tsa 4 0 github-tsa-4-leaf.pem
tsa 0 1 github-tsa-intermediate.pem; ca 0 2 github-root.pem; ca 0 1 github-fulcio-l1.pem
ca 0 0 github-fulcio-0-l2.pem; ca 3 0 github-fulcio-3-l2.pem; ca 4 0 github-fulcio-4-l2.pem
token() { # bundle, name
  jq -r '.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0].signedTimestamp' "$1" |
    base64 -d > "tsa-$2.tsr"
  jq -r '.dsseEnvelope.signatures[0].sig' "$1" | base64 -d > "tsa-$2.sig"
}
token attest-demo-0.0.12.bundle.json github-attest-demo
token attest-prober-github.bundle.json github-prober
leaf() { jq -r '.verificationMaterial.certificate.rawBytes' "$1" |
  base64 -d | openssl x509 -inform DER -out "$2"; }
leaf attest-demo-0.0.12.bundle.json github-leaf-attest-demo.pem
leaf attest-prober-github.bundle.json github-leaf-prober.pem
```

The synthetic token, from this directory, with OpenSSL 3.5 (`ts.cnf`
sets `signer_digest = sha384`, `digests = sha256`, `ess_cert_id_alg =
sha256`, `accuracy = secs:1`, `ordering = no`, `tsa_name = no` and the
policy `1.3.6.1.4.1.57264.2`):

```sh
printf 'keyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\nbasicConstraints=critical,CA:FALSE\n' > leaf.ext
openssl req -new -key test-only-tsa.key -subj "/CN=Boneli test TSA P-256 SHA-384" |
  openssl x509 -req -CA codesign-intermediate.pem -CAkey test-only-codesign-ca.key \
    -set_serial 12 -not_before 20260101000000Z -not_after 21260101000000Z \
    -extfile leaf.ext -sha384 -out tsa-p256-sha384-leaf.pem
printf 'the DSSE signature bytes' > msg
openssl ts -query -data msg -sha256 -no_nonce -out q.tsq
openssl ts -reply -config ts.cnf -queryfile q.tsq -signer tsa-p256-sha384-leaf.pem \
  -inkey test-only-tsa.key -out tsa-p256-sha384.tsr
rm leaf.ext msg q.tsq
```
