# Test certificates and keys

Fixtures for `tests/tls.rs`, `tests/dial.rs` and `tests/rsa.rs`, read with
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
| `test-only-p256.key` | ECDSA P-256 key, PKCS#8: a key ring accepts that is not RSA |
| `rs256-message.txt` | a JWT signing input: header `{"alg":"RS256","typ":"JWT"}`, claims `iat` 1699999940, `exp` 1700000540 and a made-up `iss`, base64url without padding, no newline |
| `rs256-test-only.sig` | OpenSSL's RS256 signature of `rs256-message.txt` with the 2048-bit key, 256 bytes |

Generated once with OpenSSL 3.5, from this directory:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-only-rsa-2048-pkcs8.key
openssl pkey -in test-only-rsa-2048-pkcs8.key -traditional -out test-only-rsa-2048-pkcs1.key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out test-only-rsa-1024.key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out test-only-p256.key
printf '%s' 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTk5OTk5NDAsImV4cCI6MTcwMDAwMDU0MCwiaXNzIjoiSXYxLjAxMjM0NTY3ODlhYmNkZWYifQ' > rs256-message.txt
openssl dgst -sha256 -sign test-only-rsa-2048-pkcs1.key -out rs256-test-only.sig rs256-message.txt
```

RSASSA-PKCS1-v1_5 is deterministic, so the signature is a known answer:
regenerating the key changes it, and every file of this table changes
together. `openssl pkey -in test-only-rsa-2048-pkcs8.key -pubout | openssl
dgst -sha256 -verify /dev/stdin -signature rs256-test-only.sig
rs256-message.txt` checks it independently of Boneli.
