# smtp-net - Platform notes

What differs between Linux, macOS, and Windows. smtp-net itself has no platform code: the operating system is reached through net-io (sockets and name resolution), tls-net (TLS), crypt-io (DKIM and SCRAM), mod-rand (random bytes), and `std::time`. CI runs the test suite on all three with Rust stable and 1.85. Linux is the production target, and the numbers in [`PERFORMANCE.md`](./PERFORMANCE.md) are Linux numbers.

---

## Building

| Features | Linux | macOS | Windows |
|---|---|---|---|
| default (`std`, `client`, `tls`) | a C compiler (gcc or clang) for aws-lc-rs | Xcode command line tools | Visual Studio Build Tools or clang; NASM is optional |
| `dkim` | as for `tls` (crypt-io signs through AWS-LC) | as for `tls` | as for `tls` |
| `default-features = false, features = ["client", "scram"]` | Rust only | Rust only | Rust only |
| `default-features = false` (the `no_std` core) | Rust only | Rust only | Rust only |

TLS and DKIM signing build C and assembly code. A deployment that only submits to a local MTA on `127.0.0.1` needs neither: `client` alone gives plaintext loopback submission, and `scram` adds SCRAM-SHA-256 in pure Rust. tls-net's own `docs/PLATFORM-NOTES.md` lists what each TLS build needs, FIPS included.

---

## Loopback and `localhost`

Plaintext submission (`Security::PlaintextLoopback`, `Server::local`, `send_local`) is allowed only when the host is a loopback literal (`127.0.0.0/8`, `::1`) or `localhost`, and only when the address the connection reached is loopback (T-8, T-32). A `localhost` that resolves anywhere else is refused at connect with `PlaintextRefused`, before a byte is sent.

| | Linux | macOS | Windows |
|---|---|---|---|
| `localhost` comes from | `/etc/hosts` through nsswitch | `/etc/hosts` | the resolver itself, not the `hosts` file |
| Usual answer | Debian and Ubuntu: `127.0.0.1` only; Fedora and others: `::1` and `127.0.0.1` | `127.0.0.1` and `::1` | `::1`, then `127.0.0.1` |
| A refused connect to `::1` | about 20 ms | immediate **[not measured here]** | about 2 s (Windows retries the SYN) |

The resolved addresses race (RFC 8305 through net-io, D-107): the first starts, the next starts 100 ms later for a loopback host (250 ms for any other), or at once when the first fails, and the first connection made wins. So `localhost` on Windows reaches an MTA that listens on `127.0.0.1` only in about 100 ms; before 0.7.1 it waited 1 s on every connect. `Server::local()` names `127.0.0.1` and skips resolution: prefer it, or an address literal, for a local MTA.

Measured on Windows 11 and WSL2 Ubuntu with a listener on `127.0.0.1` only: `localhost` resolved to `::1, 127.0.0.1` on Windows and to `127.0.0.1` on Ubuntu; a connect to `::1` was refused after 2.04 s on Windows and 0.02 s on Ubuntu.

On cPanel and most Linux MTAs, port 25 on `127.0.0.1` is the local submission path. Windows has no local MTA by default, so there local submission means a relay the deployment runs itself.

---

## Trust anchors

The default TLS client trusts the Mozilla root bundle compiled into the binary (tls-net feature `webpki-roots`). It gives the same answer on every machine and changes only with a tls-net release. Certificate verification cannot be turned off.

| Need | How |
|---|---|
| A public relay (Gmail, Microsoft 365, a hosting provider) | the default |
| A relay signed by a private CA | `ServerBuilder::tls(tls_net::client_with_ca_pem(&ca)?)` |
| The operating system's trust store, including roots an administrator added | build a `TlsClient` with tls-net's `platform-verifier` feature and pass it to `ServerBuilder::tls`. On Linux the platform verifier does not check revocation; on macOS and Windows it can block on a revocation fetch during the handshake, which counts against the TLS handshake timeout |

---

## Clocks

| Clock | Used for | After a clock step |
|---|---|---|
| Monotonic (`Instant`) | every stage timeout, the connect timeout, the pool's checkout wait and idle limit | unaffected |
| Wall (`SystemTime`) | the `Date` header; DKIM `t=` and `x=`; `HourlyLimit` and `DomainLimit` | the next message carries the new time. A step back keeps every count until the clock passes it again, so a gate refuses a little early; a step forward retires counts early, and a step of an hour or more empties the window (D-058, D-106) |

The gates read the wall clock on purpose: a provider's hourly limit (cPanel's, for example) counts on the same host's clock, and a gate shared by several processes or kept in a store needs a time every process agrees on. A forward step frees the gate exactly when the provider's own window moves on.

---

## Randomness

Message-IDs, MIME boundaries, and SCRAM nonces come from the operating system's CSPRNG through mod-rand: `getrandom(2)` on Linux, `getentropy(3)` on macOS, `BCryptGenRandom` on Windows. A failure is an error (`Random`), never a weaker source.

---

## Performance

- Ed25519 DKIM signing is several times slower under Windows MSVC than on Linux: 64 µs against 20 µs for a 10 KiB message on the same machine (D-092).
- Every other measured number in `PERFORMANCE.md` is from Linux; run `cargo bench` on the deployment's platform before relying on one elsewhere.
