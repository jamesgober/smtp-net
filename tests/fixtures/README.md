# Test fixtures

Certificates for the real-TLS tests (`tests/tls_real.rs`) and the CI interop job.
They are test material only: the private key is public, so never trust these
certificates anywhere else.

- `ca.pem`: a test CA (EC P-256), valid to 2036.
- `localhost.pem`, `localhost.key`: a certificate for `localhost` and `127.0.0.1`
  signed by that CA, and its key.
- `other-ca.pem`: an unrelated CA, for the "untrusted CA" test.
- `self-signed.pem`, `self-signed.key`: a self-signed certificate for `localhost`
  and `127.0.0.1` (EC P-256, valid to 2036), for the self-signed test (T-11).

The CA keys were not kept: nothing new can be signed with them.

## DKIM keys (`dkim/`)

Private keys for the DKIM tests (`src/dkim/`, `tests/dkim.rs`), made with
`openssl genpkey`. Their private halves are public: never publish their DNS
records for a real domain.

- `rsa-2048.pem` (PKCS#8), `rsa-2048-pkcs1.pem` (the same key as PKCS#1),
  `rsa-2048.der` (PKCS#8 DER), `rsa-2048-encrypted.pem` (encrypted PKCS#8,
  password `test`, which must be refused), `rsa-4096.pem`.
- `rsa-1023.pem`, `rsa-1024.pem`, `rsa-2047.pem`, `rsa-4098.pem`: the key-size
  limits (T-21). OpenSSL rounds odd sizes above 4096 down, so 4098 stands for
  "just over 4096".
- `ed25519.pem`: an Ed25519 key (PKCS#8).
