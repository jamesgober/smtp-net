# smtp-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md). Public API: [`../docs/API.md`](../docs/API.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.
>
> API items are named by their section in `docs/API.md`; threat ids (T-n), requirement ids (FR-n, NFR-n), and edge-case numbers refer to `PLAN.md`.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock
Exit: `docs/API.md` written from the specification; every open decision answered or carried with a version (PLAN section 17); the parse-net interface agreed (what smtp-net consumes, D-014); the crypt-io `sign` and `kdf-pbkdf2` needs and the tls-net client needs written down for those crates (PLAN 3.4, D-006, D-026).
- [x] `dev/PLAN.md` rewritten from the specification; decisions D-005 to D-036.
- [x] `docs/API.md`: every public item, 0.3 to 1.0.
- [x] This roadmap aligned with the specification's version table, plus the 0.9.x polish pass.
- [x] Published to crates.io to claim the name (D-008).

## v0.3.0 - Core (DONE, 2026-11-04)
Exit: every transcript of PLAN 12.2 that applies to the plaintext path passes whole and split at every byte; T-1 to T-4, T-12 to T-18, T-23, T-24, T-26 to T-28, T-30, T-36 attack tests pass; a verification email and a reset email are sent through Exim and Mailpit containers in the CI interop job and the received bytes are checked (D-033: the cPanel host check moves to the 0.8 field test because it needs James's host).
Depends on: parse-net 0.9 (published), net-io 0.5 (published), mod-rand 1.0 (published).
- [x] Addresses (API 8.3): `Address`, `Mailbox`, `Domain`, `AddressError`, on parse-net's grammar.
- [x] Message builder (API 8.4): text, HTML, alternative, mixed, related, attachments, inline, quoted-printable, base64, RFC 2047, RFC 2231, `Message-ID`, `Date`, threading headers, `MessageLimits`, `build_with` and `RandomSource`.
- [x] Headers and encoding primitives (API 8.4.2), sinks (API 8.4.3).
- [x] Envelope (`new`, `return_path`) and `PreparedMessage::from_raw` (API 8.5).
- [x] Sans-IO session (API 8.6, 8.6.1): greeting, EHLO, HELO fallback, MAIL, RCPT, DATA, dot-stuffing, RSET, QUIT, PIPELINING, SIZE, 8BITMIME, reply parser, enhanced codes, classification, timeouts.
- [x] Blocking driver for `PlaintextLoopback` (API 8.8): `send`, `send_local`, `Client` (plaintext), `Report`.
- [x] Errors (API 8.12), timeouts (API 8.10), constants (API 8.14).
- [x] Test support (API 8.13): `Transcript`, `ScriptedServer`, `TestServer` (plaintext), `Fault`, `ReceivedMessage`.
- [x] Property tests (PLAN 12.3) for addresses, encoders, dot-stuffing, replies; fuzz targets for the reply parser, EHLO, session, address, content type, header value, raw message.
- [x] Counting-allocator tests for the 0.3 "0 alloc" items that hold (body path, replies, encoders, header gate, `write_to`); first benchmarks (build, encode, proto). Moved to 0.6 with measured numbers (D-047): build allocations (97, target 8), the envelope copy in `begin`, the owned reply in `Delivered`.
- [x] CI: `no_std` core build, interop job (Mailpit, Exim).

## v0.4.0 - Extended (DONE, 2026-11-04)
Exit: STARTTLS and implicit TLS run end to end against `TestServer` through the `TlsConnector` seam; T-5 to T-11, T-32, T-33 attack tests pass; a task-io integration test (or a stub of task-io's documented handler contract while task-io is unpublished) retries a temporary failure and dead-letters a permanent one.
Depends on: net-io (TLS seam, published). For the external relay check: tls-net with a client `TlsSession` and certificate verification.
- [x] STARTTLS and implicit TLS through the `TlsConnector` seam (D-025, D-026); the session's TLS states; the response-injection check.
- [x] AUTH PLAIN and LOGIN; `Secret`; `Credentials`, `MechanismList`.
- [x] `Server` builders, `ServerBuilder` (API 8.8) except `Pool`, `dkim`, `observer`.
- [x] Connection reuse with the idle and per-connection limits; transparent reconnect.
- [x] CHUNKING (BDAT), DSN, SMTPUTF8 and EAI addresses, too-many-recipients deferral.
- [x] `SendGate`, `HourlyLimit` (loom model).
- [x] `PreparedMessage::encode` and `decode` (CRC-32C), `send_prepared`.
- [x] List-Unsubscribe, Auto-Submitted, `allow_8bit`, `date_unix_with_offset`, `Part`/`Body` Tier 3 tree, `Envelope::null_sender`, `Session::noop`.
- [x] `TestServer` with a TLS engine.
- [x] Feature `tls` with tls-net 0.3's connector (default, D-051); real TLS tests with fixture certificates on every platform; CI interop against Mailpit with real STARTTLS and implicit TLS, verified against a private CA (D-064). A public relay (Gmail, Microsoft 365) needs James's credentials: part of the 0.8 field test.
- [x] Job-contract test against a stub of task-io's handler contract until task-io publishes (D-065).

## v0.5.0 - Feature complete - DONE
Exit: every P0, P1, P2 item present (or its move recorded here with a reason); DKIM passes at Gmail and Outlook.com (`Authentication-Results: dkim=pass` for both algorithms where the receiver supports Ed25519); RFC 6376 and RFC 8463 vectors pass; T-19 to T-22, T-29, T-31 pass.
Depends on: crypt-io 1.3 with `sign-ed25519`, `sign-rsa`, `kdf-pbkdf2` (published 2026-11-04); key-vault optional (not used: keys load from the seed or PKCS#8 bytes a vault hands over).
- [x] DKIM (API 8.7): Ed25519-SHA256, RSA-SHA256, relaxed and simple, oversigning, several signatures, DNS records, raw input; `Message::prepare_signed`, `PreparedMessage::sign`, `ServerBuilder::dkim`. RFC 8463 Appendix A reproduced byte for byte; every signature checked by dkimpy in CI (D-070).
- [x] `allow_rsa_1024`: not offered; crypt-io starts RSA at 2048 bits (D-066).
- [x] XOAUTH2 (D-074); SCRAM-SHA-256 with the RFC 7677 exchange as a vector (D-073); the `Mechanism` trait (D-075).
- [x] `Pool` with loom models (D-077); `Observer` (D-076); `Attachment::from_source`, `BodySource`, `ReadSource` (D-078).
- [x] `docs/DELIVERABILITY.md`, `docs/ARCHITECTURE.md`.
- [x] T-19 (no `l=`), T-20 (oversigning, checked by dkimpy), T-21 (key sizes), T-22 (no key in `Debug` or errors), T-29 (constant-time SCRAM check, both paths tested), T-31 (`cargo audit` and `cargo deny` pass with no ignores).
- Moved to v0.8.0: "DKIM passes at Gmail and Outlook.com" needs a sending domain with the keys in its DNS; it runs with the field test (D-070). Reason: James's domain and DNS.

## v0.5.1 - RFC 2047 B form - DONE
- [x] parse-net 0.9.1's `encode_words_b`: the B form for mostly non-ASCII headers when it is shorter (D-082, closes the D-015 gap).

## v0.6.0 - Optimisation - DONE
Exit: every target in PLAN 11.1 met, or the miss recorded with the measured number and the reason; `docs/PERFORMANCE.md` published.
- [x] Benchmarks against lettre, mail-builder, mail-send, and mail-auth in `smtp-net-bench` (D-035, D-091).
- [x] SWAR scanning (D-086); end-to-end send at 0, 1, 10 ms simulated round-trip time with `Fault::RoundTrip` (D-089): 25 µs, 3.8 ms, and 42 ms per message on a reused connection, against 70, 125, and 134 ms for lettre (round trips ran long under load for every client).
- [x] Allocation targets moved from 0.3 (D-047): `Session::begin` allocates nothing (D-084); a text plus HTML build allocates 21 times (D-083); `Event::Delivered` keeps its owned reply (D-087); unsigned mail is not streamed from the tree (D-088).
- Misses, recorded with numbers and reasons (D-093), re-measured on a quiet machine in the 0.9 pass:
  - Build allocations: 21 against an estimate of 8 (D-083).
  - Session memory: 19,176 bytes against 16 KiB, from the 16 KiB default output buffer; 6,888 bytes with a 4 KiB buffer (D-085).
  - Under the release-day load (D-090), five rows came in short: quoted-printable 0.53 to 0.63 GB/s (0.91 in a quieter run; target 0.8), single-line reply 61 to 94 ns (50 in a quieter run; target 50), dot-stuffing 2.9 to 3.6 GB/s (about 6 in a quieter run; target 4), EHLO with capabilities 661 to 788 ns (target 400; the reply alone 249 ns in a quieter run), and relaxed body canonicalization 1.22 to 1.50 GB/s (target 2; no quiet run). Each is re-measured on a quiet machine in the 0.9 pass and, if still short, fixed there (D-093).

## v0.7.0 - Hardening
Exit: 1 hour per fuzz target with no finding open; 24-hour soak passes (NFR-14); every row of PLAN 10.1 has a passing test.
- [ ] Every fuzz target running; every threat test complete; timing check for the SCRAM signature comparison; `docs/SECURITY.md`.

## v0.8.0 - Alpha
Exit: the first site sends verification and reset mail through task-io and smtp-net in production for two weeks with every failure classified correctly; interop matrix (Exim, Postfix, Mailpit, Microsoft 365, Gmail) green.
Depends on: task-io in production and the first site live (James).
- [ ] Field test on the cPanel host's Exim on `127.0.0.1` (moved from 0.3, D-033), Microsoft 365 and Gmail submission; O-21 (what cPanel counts) and O-24 (`Auto-Submitted`) checked.
- [ ] DKIM at public receivers (moved from 0.5, D-070): `Authentication-Results: dkim=pass` at Gmail and Outlook.com for RSA, and for Ed25519 where the receiver verifies it, from a domain with both keys published.
- [ ] XOAUTH2 against Gmail and Microsoft 365 with real tokens.
- [ ] `docs/PLATFORM-NOTES.md`.

## v0.9.x - Beta and the pre-1.0 polish pass
Exit: no API change request open; every review finding closed test-first; the 1.0 readiness note written and handed to James.
- [ ] Revisit every accepted gap and every item this file moved (D-025 `tls` default, D-033 field test, IDNA and SASLprep gaps, any 0.6 target miss), and close or re-record each with its reason.
- [ ] Re-tune performance against lettre and mail-builder on current versions; republish `docs/PERFORMANCE.md`.
- [ ] Re-run the security and edge-case review (PLAN 10, 12.10) with an adversarial reader; every finding fixed test-first.
- [ ] API freeze candidate; docs complete; `0.9.x` release candidates.
- [ ] `docs/STABILITY-1.0.md` draft and a 1.0 readiness note (what is done, what is open, the go/no-go recommendation).

## v1.0.0 - Stable
Exit: full audit (API, docs, tests, benchmarks, security) recorded in `docs/STABILITY-1.0.md`; the first site has used it end to end (DIRECTIVES 3.10); **James's explicit go.**

## After 1.0
P3 items, each in a minor version with its tests: OAUTHBEARER, SCRAM-SHA-256-PLUS, LMTP, REQUIRETLS, BINARYMIME, VERP helper, multiple From with Sender, `Group` syntax, IDNA when unicode-lang has it. (The display-name and bidi policies moved to 0.7, D-097.)
