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

[Unreleased]: https://github.com/jamesgober/smtp-net/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/jamesgober/smtp-net/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/smtp-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/smtp-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/smtp-net/releases/tag/v0.1.0
