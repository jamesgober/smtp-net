<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>smtp-net</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.8.0] - 2026-11-11

The first alpha: the same features, with the API simplified before the
field test. Every rename is mapped in `docs/release/v0.8.0.md`.

### Added

- `RejectedRecipient`: the address, reply, and disposition of a refused
  recipient, returned by both `Report::rejected` and `Error::rejected`.
- `ClientName::parse`, and `ConfigError::InvalidClientName`.
- `dev/SIMPLICITY-AUDIT.md`.

### Changed

- The Tier 3 surface moved out of the crate root: `smtp_net::protocol`
  (the sans-IO session), `smtp_net::mime` (parts, headers, encoders,
  sinks, randomness), `smtp_net::dkim` (the canonicalizers), and
  `smtp_net::testing`.
- `SendGate` has one method pair, `admit(&Envelope, now)` and
  `refund(&Envelope, now)`.
- `ServerBuilder::tls` takes any `TlsConnector`; `tls_connector` is gone.
- `ServerBuilder::mechanisms` and `ServerBuilder::client_name(&str)` return
  `Self` and are checked by `build()`.
- `Report::accepted` returns `&[Address]`.
- Renamed: `PORT_SUBMISSION` and `PORT_SUBMISSIONS` to `PORT_STARTTLS` and
  `PORT_IMPLICIT_TLS`; `DomainLimit::per_domain` to `recipients`;
  `ReplyCode::is_transient` to `is_temporary`; `QpState` to
  `QuotedPrintableState`; `Dsn::{ret, envelope_id, required,
  envelope_id_value}` to `Dsn::{with_return_content, with_envelope_id,
  with_policy, envelope_id}`; `Envelope::{return_path, dsn}` (setters) to
  `with_return_path` and `with_dsn`, and `Envelope::{from, dsn_parameters}`
  to `return_path` and `dsn`.
- `docs/API.md` covers every public item by task; its examples and the
  README's compile as doctests.

### Removed

- `Message::prepare_signed` (use `prepare()?.sign(..)`),
  `RecipientFailure`, `Error::recipients`.

### Fixed

- A `DomainLimit` reached through the count-based `SendGate::admit`
  admitted every message, so a caller or combinator that used that method
  had no per-domain limit.

---

## [0.7.1] - 2026-11-09

Platform notes, two fixes found writing them, and the current net-io and
tls-net.

### Added

- `docs/PLATFORM-NOTES.md`: builds, loopback and `localhost`, trust
  anchors, clocks, and randomness on Linux, macOS, and Windows.

### Changed

- net-io 0.7.1 and tls-net 0.9.0 (from 0.6.1 and 0.5).
- The resolved addresses of a host race (RFC 8305): the next address starts
  after 250 ms, 100 ms for a loopback host, or at once when one fails.

### Fixed

- On Windows, connecting to `localhost` when the server listened on
  `127.0.0.1` only took 1 s: `localhost` resolves to `::1` first and
  Windows retries a refused connect for about 2 s. It takes about 100 ms
  now.
- `DomainLimit` could lose a domain's count after the wall clock stepped
  back by 65 minutes or more, and then admit more than its budget. The
  count is kept, as `HourlyLimit` already did.

## [0.7.0] - 2026-11-08

Hardening: every row of the threat table has a passing test
(`docs/SECURITY.md`), one hour of fuzzing per target, the 24-hour soak,
and the SCRAM timing check.

### Added

- `docs/SECURITY.md`: every threat, its defence, the tests that prove it,
  and the 0.7 hardening record.
- `MessageBuilder::allow_bidi_controls` and
  `refuse_address_like_display_names`, with `HeaderError::BidiControl` and
  `HeaderError::AddressLikeDisplayName` (T-25, T-35).
- `DomainLimit` (feature `std`): a recipient budget per recipient domain.
  `SendGate::admit_envelope` and `refund_envelope` (default methods), and a
  pair of gates is a gate: `.gate((HourlyLimit::recipients(500),
  DomainLimit::per_domain(100)))`.
- Test support: `TestServerBuilder::record(false)` keeps no messages or
  transcript; `TestServer::messages` counts accepted messages.
- `tests/soak.rs` (the NFR-14 soak, ignored by default), `tests/threats.rs`,
  three transcripts for out-of-step replies, a self-signed certificate
  test, a dudect-style timing check of the SCRAM signature comparison, and
  a CI job for the loom models.

### Changed

- Bidirectional overrides and isolates (U+202A to U+202E, U+2066 to
  U+2069) in the Subject and display names are refused by default.
- The `prepared_decode` fuzz target frames half its inputs with a valid
  header and CRC-32C, so it reaches the fields behind the checksum.
- parse-net 0.9.2 is the minimum: MIME parameters are folded by its
  `write_mime_param_at`, with no change to the output.

### Fixed

- A reply whose class cannot answer its command (a `250` to DATA, a `354`
  to MAIL or to the end of data) was reported as a permanent `Rejected`.
  Under pipelining an extra reply from the server could do that to a
  good message, which a job queue would then dead-letter. It is now
  `Protocol(UnexpectedReply)`, temporary; the session closes; after the
  end of data the message is possibly delivered.

## [0.6.0] - 2026-11-06

Optimisation: every PLAN 11.1 target measured, the misses recorded with
their reasons (D-083, D-085, D-093), and the results published in
`docs/PERFORMANCE.md`.

### Added

- `docs/PERFORMANCE.md`: every target with its measured number, the
  comparison with lettre, mail-builder, mail-send, and mail-auth, the
  method, and the machine.
- Benchmarks `dkim`, `send` (0, 1, and 10 ms round trips), and `gate`, and
  `benches/examples/targets.rs`, which prints every target in one table.
- Test support: `Fault::RoundTrip(Duration)`: every byte the server writes
  reaches the client that much later, so a client pays one round trip
  each time it waits, the way a pipelining client does on a real link;
  `TestServer::client_waits` counts those waits.

### Changed

- Dot-stuffing, raw-message input, the header value check, and relaxed
  DKIM body canonicalization scan eight octets at a time (no `unsafe`):
  dot-stuffing ran at about 6 GB/s in a quiet run (0.46 at 0.5), the
  header check at about 18 GB/s.
- base64 encodes six octets per step through a 12-bit table (about
  2.9 GB/s, 1.75 at 0.5); quoted-printable copies literal runs through a
  class table (about 2.7 times faster in a quiet run).
- A text plus HTML build allocates 21 times (97 at 0.5); `Session::begin`
  allocates nothing: an `Envelope` is shared behind an `Arc`, so cloning
  one no longer copies its addresses.
- The relaxed body canonicalizer passes a line of prose out in one piece;
  an Ed25519 DKIM signature of a 10 KiB message takes about 20 µs (30 at
  0.5).
- EHLO capabilities keep the AUTH mechanism names in one buffer instead
  of one allocation per name.
- `TestServer` sets `TCP_NODELAY`, so a test conversation no longer waits
  on delayed acknowledgements.
- net-io 0.6.1 is the minimum.

## [0.5.1] - 2026-11-05

### Changed

- RFC 2047 encoded words (subjects, other unstructured headers, display
  names, `encode_word`) use the B form when most of the text is not ASCII
  and B is shorter, through parse-net 0.9.1's `encode_words_b`; a Japanese
  subject is about 40% shorter. Mostly ASCII text keeps the Q form.
- parse-net 0.9.1 is the minimum.

## [0.5.0] - 2026-11-04

Feature complete: DKIM, SCRAM-SHA-256, XOAUTH2, the connection pool, the
observer hook, and streamed attachments.

### Added

- DKIM signing (feature `dkim`): `DkimKey` (Ed25519 from a seed or PKCS#8,
  RSA 2048 to 4096 bits from PKCS#8 or PKCS#1, PEM or DER, `dns_record`),
  `DkimSigner` (relaxed or simple canonicalization, default header and
  oversign lists, `x=`, `i=`), `Message::prepare_signed`,
  `PreparedMessage::sign` for raw input, `ServerBuilder::dkim` (several
  signatures). RFC 8463 Appendix A is reproduced byte for byte.
- `BodyCanonicalizer` and `HeaderCanonicalizer`, streaming and `no_std`, in
  every build.
- SCRAM-SHA-256 (feature `scram`): server nonce, iteration range, and server
  signature checked (constant time); first in the default mechanism list.
- XOAUTH2: `Credentials::oauth2`; `Error::auth_detail` gives the server's
  error status.
- Custom SASL mechanisms: `Mechanism`, `Step`, `CustomMechanism`,
  `Credentials::Custom`.
- `Pool`: a bounded set of connections shared by threads, lock-free
  checkout (loom models), `PoolExhausted` after the wait limit.
- `Observer`, `ObservedEvent`, `SecurityEventKind`, `ServerBuilder::observer`;
  `Event::Reply` and `SessionConfig::reply_events` in the session.
- `Attachment::from_source`, `BodySource`, `ReadSource`, `SourceError`;
  `Attachment::len`, `is_empty`, `is_streamed`.
- Test support: `TestServerBuilder::oauth2`, SCRAM in `TestServer`,
  `Fault::BadScramSignature`, `C: <EMPTY>` in transcripts.
- `docs/ARCHITECTURE.md`, `docs/DELIVERABILITY.md`; examples
  `send_with_dkim` and `dkim_dns_record`; fuzz targets `dkim` and `sasl`;
  8 more transcripts (68 in all); CI checks every DKIM signature with
  dkimpy, an independent verifier.

### Changed

- The default mechanism list is `[ScramSha256 (feature scram), Plain, Login,
  XOAuth2, Other]`, filtered by the kind of credentials.
- crypt-io 1.3; tls-net 0.5 (from 0.3).

### Fixed

- Two CI flakes: the Exim delivery check now waits for deliveries in
  progress, and the hourly-limit refund test no longer reuses a released
  port.

## [0.4.0] - 2026-11-04

Extended: TLS relays, AUTH, CHUNKING, DSN, pacing, and job payloads.

### Added

- STARTTLS and implicit TLS in the driver through the `TlsConnector` seam
  over net-io's sans-IO TLS session; feature `tls` (on by default) uses
  tls-net's client with certificate verification always on; `Server::starttls`,
  `Server::implicit_tls`, `ServerBuilder::tls`, `tls_connector`.
- AUTH PLAIN and LOGIN with a caller allowlist (`Credentials`, `Secret`,
  `MechanismList`); credentials only over TLS or to a verified loopback peer;
  `Server::login`, `ServerBuilder::credentials`, `mechanisms`.
- CHUNKING (BDAT), DSN (`Dsn`, `Envelope::dsn`), `Envelope::null_sender`, and
  the too-many-recipients deferral (`Event::Deferred`; `Client` sends the
  deferred recipients in further transactions).
- `SendGate` and the lock-free `HourlyLimit` (never over-admits; loom models).
- `PreparedMessage::encode` and `decode` (versioned, CRC-32C checked) and
  `send_prepared`.
- `MessageBuilder::list_unsubscribe` (RFC 2369 and 8058), `auto_submitted`,
  `date_unix_with_offset`, `body`, and the public `Part` constructors.
- Test support: `TestTls`, real TLS engines through `tls_engine`, AUTH, BDAT,
  and DSN in `TestServer`; fixture certificates in `tests/fixtures/`.
- 21 more transcripts (60 in all), real-TLS tests with rustls on both sides,
  CI interop over real STARTTLS and implicit TLS against Mailpit, the
  `prepared_decode` fuzz target, examples `prepared_job` and `hourly_limit`.

### Fixed

- `Address` equality compared only the domain, so `b@example.org` equalled
  `d@example.org`.
- `MessageBuilder::date_unix` was ignored; the build time was stamped instead.

### Changed

- Default features are `std`, `client`, `tls`.
- `Event::Deferred` carries recipient indices instead of a range.
- crypt-io 1.3 (`zeroize` only) wipes credentials.

## [0.3.0] - 2026-11-04

The core: messages, the sans-IO session, and local submission.

### Added

- Addresses: `Address`, `Mailbox`, `Domain` on parse-net's RFC 5322 grammar,
  with the RFC 5321 path rules (lengths, LDH labels, no literals unless
  asked for, no control characters anywhere).
- Messages: `Message::text`, `Message::html`, and `MessageBuilder` for text,
  HTML, attachments, and inline parts (mixed, related, alternative);
  7bit, quoted-printable, or base64 per part, 7-bit output by default;
  RFC 2047 subjects and display names; RFC 2231 file names; generated
  `Message-ID` and `Date`; threading headers; `MessageLimits` budgets checked
  before encoding; Bcc only in the envelope; `encoded_len`, `write_to`,
  `to_bytes`, `prepare`.
- The header gate `check_header_value`, `encode_word`, `fold_header`,
  `base64_encode_lines`, `quoted_printable_encode`, and the `Sink` trait with
  `CountingSink` and `IoSink`.
- `Envelope` and `PreparedMessage::from_raw`, which refuses bare CR and bare
  LF (SMTP smuggling), lines over 998 octets, and messages without a header
  block or From.
- The sans-IO `Session`: greeting, EHLO and the loopback HELO fallback,
  STARTTLS states with the response-injection check, MAIL, RCPT, DATA with
  streaming dot-stuffing, RSET, NOOP, QUIT; PIPELINING in groups of at most
  4 KiB, SIZE, 8BITMIME, SMTPUTF8 checks; enhanced status codes; RFC 5321
  stage deadlines; every failure classified temporary or permanent, with
  `possibly_delivered` after the end of the data.
- The blocking driver: `send`, `send_local`, `Client` (connection reuse,
  idle and per-connection limits, one transparent reconnect), `Server`,
  `Report`. Plaintext only to a verified loopback peer.
- Test support (feature `testing`): `TestServer` with fault injection,
  `ScriptedServer` and `Transcript`.
- 39 conversation transcripts run whole and split into 1 to 16 octet
  pieces; property tests; counting-allocator tests; eight fuzz targets; an
  interop job against Mailpit and Exim; a `no_std` build job; benchmarks for
  message building, encoders, and the session.

### Changed

- net-io 0.6 (0.5.0 was yanked).
- `docs/API.md` section 8.16 lists the changes since the design lock.

## [0.2.0] - 2026-11-04

The design lock. No functional code yet.

### Added

- `docs/API.md`: the public API for every version up to 1.0 (Tier 1 functions,
  addresses, the message builder, encoding primitives, sinks, envelopes and job
  payloads, the sans-IO session, replies and capabilities, SASL, DKIM, the
  blocking client and its TLS seam, pacing, timeouts, observability, errors,
  test support, constants), with grade, tier, version, and cost targets for
  each item.
- `dev/PLAN.md`: requirements, threat model with an attack test per threat,
  failure classification, timeouts, message model, DKIM design, performance
  targets, testing plan, and the answers to every open decision (D-005 to
  D-036).

### Changed

- `dev/ROADMAP.md` follows the standard version table (0.3 core, 0.4 extended,
  0.5 feature complete, 0.6 optimisation, 0.7 hardening, 0.8 alpha, 0.9 beta
  with a pre-1.0 polish pass, 1.0 stable) instead of the scaffold's
  submission-then-DKIM plan.

## [0.1.0] - 2026-10-13

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md` (purpose, scope, architecture, threats, ecosystem, open
  decisions, decision log), `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/smtp-net/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/jamesgober/smtp-net/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/jamesgober/smtp-net/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/jamesgober/smtp-net/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jamesgober/smtp-net/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/jamesgober/smtp-net/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/jamesgober/smtp-net/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/smtp-net/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/smtp-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/smtp-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/smtp-net/releases/tag/v0.1.0
