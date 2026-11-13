# Test certificates

Fixtures for `tests/tls.rs`, read with `include_bytes!`. The keys protect
nothing: they exist only so that a local test server can complete a TLS
handshake, and no system trusts these CAs.

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
