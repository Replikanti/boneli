# Test key

`test-only-rsa-2048.key` is a 2048-bit RSA key in PKCS#8 that signs the
JWTs of the fake GitHub in this crate's tests. It protects nothing: no
GitHub App or other account has it, and its name says so. The tests read
it with `include_bytes!` and write it into a private temporary file when
they need a key file.

Generated once with OpenSSL 3.5, from this directory:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-only-rsa-2048.key
```
