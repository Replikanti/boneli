# Test certificates and keys

Fixtures for `tests/tls.rs`, `tests/dial.rs`, `tests/rsa.rs` and
`tests/revocation.rs` and the unit tests of `src/revocation/`, read with
`include_bytes!`. The keys protect nothing: they exist only so that a local
test server can complete a TLS handshake and so that `RsaSha256Key` can be
checked against OpenSSL. No system trusts these CAs, and no GitHub App or
other account has any of these keys. The signing keys say so in their
names (`test-only-`).

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
