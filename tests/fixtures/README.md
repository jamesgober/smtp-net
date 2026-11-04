# Test fixtures

Certificates for the real-TLS tests (`tests/tls_real.rs`) and the CI interop job.
They are test material only: the private key is public, so never trust these
certificates anywhere else.

- `ca.pem`: a test CA (EC P-256), valid to 2036.
- `localhost.pem`, `localhost.key`: a certificate for `localhost` and `127.0.0.1`
  signed by that CA, and its key.
- `other-ca.pem`: an unrelated CA, for the "untrusted CA" test.

The CA keys were not kept: nothing new can be signed with them.
