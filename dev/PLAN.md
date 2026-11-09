# smtp-net - Project Plan

> The design, requirements, threat model, and decision record for `smtp-net`: an SMTP submission client with a sans-IO protocol core, a MIME message builder, DKIM signing, and a blocking driver over net-io. A living document: every design decision, idea, or open question about smtp-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md) &rarr; [`../docs/API.md`](../docs/API.md).
>
> **Status:** feature complete, `0.5.1`. The public API is written in `docs/API.md`; changes since the design lock are listed at its end and recorded in section 19.
>
> Numbers marked **[est.]** are estimates that the 0.6 benchmarks must replace with measurements. Every API item is graded P0 (must ship for its version) to P3 (allowed after 1.0) and placed in Tier 1 (one call, no configuration), Tier 2 (builders and configuration), or Tier 3 (the full, generic, allocation-free surface).

---

## Contents

1. [Header](#1-header)
2. [Purpose](#2-purpose)
3. [Position in the stack](#3-position-in-the-stack)
4. [Scope](#4-scope)
5. [Requirements](#5-requirements)
6. [Standards](#6-standards)
7. [Design and architecture](#7-design-and-architecture)
8. [API](#8-api)
9. [Parity matrix](#9-parity-matrix)
10. [Security](#10-security)
11. [Performance](#11-performance)
12. [Testing plan](#12-testing-plan)
13. [Documentation deliverables](#13-documentation-deliverables)
14. [Version roadmap, release routine, definition of done](#14-version-roadmap-release-routine-definition-of-done)
17. [Open decisions and their answers](#17-open-decisions-and-their-answers)
18. [References](#18-references)
19. [Decision log](#19-decision-log)

Section numbers follow the order the design was written in, so that the cross-references inside this file (for example "see 7.7" or "O-4") stay stable; sections 15 and 16 are folded into 14.

---

## 1. Header

| Field | Value |
|---|---|
| Crate | `smtp-net` (library name `smtp_net`) |
| Repository | `https://github.com/jamesgober/smtp-net` |
| State (2026-11-04) | design lock `0.2.0`: `docs/API.md` written, every open decision answered (section 17, decision log section 19). `src/lib.rs` holds only `VERSION`. |
| Owner | James Gober `<me@jamesgober.com>` |
| MSRV | 1.85 (edition 2024) |
| License | `Apache-2.0 OR MIT` |

## 2. Purpose

### 2.1 What it is

smtp-net sends email for services: account verification, password resets, alerts, receipts, and notifications. It does four jobs:

1. **Builds the message.** RFC 5322 headers and RFC 2045 to 2049 MIME bodies: plain text, HTML, `multipart/alternative`, attachments (`multipart/mixed`), inline images (`multipart/related`), quoted-printable and base64 transfer encodings with the line-length rules, RFC 2047 encoded words for non-ASCII header text, generated `Message-ID` and `Date`. Every header value is checked; a CR or LF anywhere is an error, never stripped.
2. **Signs the message** with DKIM (RFC 6376), Ed25519-SHA256 (RFC 8463) and RSA-SHA256 (RFC 8301 rules), relaxed or simple canonicalization.
3. **Speaks SMTP** (RFC 5321) as a client: a sans-IO state machine fed bytes and asked for bytes, with the submission extensions (PIPELINING, SIZE, 8BITMIME, SMTPUTF8, CHUNKING, DSN, ENHANCEDSTATUSCODES, STARTTLS, AUTH), strict reply parsing, timeouts per RFC 5321 4.5.3.2, and a precise classification of every failure as **temporary** or **permanent** so the job system (task-io) can retry or dead-letter it.
4. **Drives a connection** with a blocking driver over net-io (TCP) and tls-net (TLS): plaintext only to a loopback peer by explicit choice, STARTTLS on 587, implicit TLS on 465 (RFC 8314), connection reuse, and a send gate that paces messages against host limits such as cPanel's hourly caps.

### 2.2 What it is not

- **Not a mail server.** It does not receive mail, does not relay for others, does not run a queue, and does not deliver directly to recipient MX hosts. It submits to a Mail Submission Agent (RFC 6409) or relay, which delivers.
- **Not a queue or retry engine.** Queuing, retries with backoff, idempotency, and dead letters belong to task-io. smtp-net classifies; task-io acts.
- **Not a TLS implementation.** TLS is rustls behind tls-net.
- **Not a cryptography implementation.** Hashes, MACs, and signatures come from crypt-io.
- **Not an IMAP or POP client, not a mail parser for incoming mail, not an SPF, DKIM, or DMARC verifier.**
- **Not an async library.** No tokio, no async-std. The core is sans-IO; the provided driver is blocking; any other driver (net-io's reactor later) can sit on the same core.
- **Not a marketing email platform.** No templating, no tracking pixels, no list management. List-Unsubscribe headers are supported because receivers require them for bulk mail.

---

## 3. Position in the stack

### 3.1 Who uses it

| User | How | Source |
|---|---|---|
| The first site (via the users core and gate-net flows) | verification and password-reset emails, sent from a task-io job handler | the service stack's background-job design |
| task-io | the `send_email` handler calls smtp-net and maps `Disposition::Temporary` to `Fail::retry` and `Disposition::Permanent` to `Fail::permanent` | task-io's handler contract (integration at task-io 0.5.0) |
| service-kernel and the error core | alert emails to operators | operator alerts |
| Any Rust service | outgoing transactional email without an async runtime | crates.io users |


### 3.2 What it uses

State checked on crates.io on 2026-11-04.

| Crate | State | Used for | Feature | Needed by smtp-net version |
|---|---|---|---|---|
| `parse-net` | 0.9.0 published | RFC 5322 addresses (`mail::parse_addr_spec`, `parse_mailbox`), header checks and folding (`mail::check_header_value`, `is_field_name`, `fold`), RFC 2047 encoded words (`mail::encode_words`), RFC 2045 and 2231 parameters (`mail::write_mime_param`, `media`), `Message-ID` (`mail::write_msg_id`, `parse_msg_id`), RFC 5322 dates (`MailDate`) | always | 0.3 (D-014) |
| base64, quoted-printable, CRC-32C | private modules in smtp-net (encode-lib is not published) | MIME bodies, AUTH, DKIM, PEM; the `PreparedMessage` checksum | always | 0.3 and 0.4 (D-015, D-028) |
| `crypt-io` | 1.2.2 | SHA-256 (DKIM body and header hashes, SCRAM), HMAC-SHA-256 (SCRAM), constant-time comparison, `Zeroizing` | `dkim`, `scram` | 0.5 |
| `crypt-io` 1.3 | published 2026-11-04 | Ed25519 signing, RSA PKCS#1 v1.5 SHA-256 signing (2048 to 8192 bits), PBKDF2-HMAC-SHA-256; `Zeroizing` for `Secret` (D-050) | `dkim`, `scram`; `zeroize` always | 0.4 (`Secret`), 0.5 |
| `mod-rand` | 1.0.0, no dependencies | `tier3::fill_bytes` (OS CSPRNG) for `Message-ID`, MIME boundaries, SCRAM nonces | `std` | 0.3 |
| `std::time` | standard library | `SystemTime` for the `Date` header and the DKIM `t=` tag; `Instant` for the driver's deadlines | `std` | 0.3 (D-031) |
| `net-io` | 0.5.0 published | outbound TCP (`TcpConnection::connect_host`), deadlines, peer address (loopback check), the sans-IO TLS seam (`TlsSession`) | `client` | 0.3 (TLS seam at 0.4, D-026) |
| `tls-net` | 0.5.0 published (0.3 at smtp-net 0.4, D-081) | the client `TlsSession` over rustls with certificate verification (Mozilla roots or a private CA) | `tls` (default) | 0.4 (D-051) |
| `key-vault` | 1.1.0 | optional: credentials and DKIM private keys held in page-locked memory, passed to smtp-net by handle | `key-vault` | 0.5 (optional) |
| `throttle-net` | 2.0.0 | **not a dependency** (see 3.5) | none | none |

### 3.3 Where it sits

```
 handler ──▶ ctx.jobs.submit("send_email", PreparedMessage bytes, IdempotencyKey)    ~1 µs, request returns
 task-io worker ──▶ smtp-net
     SendGate::admit (hourly cap)  ──▶ refused: Temporary, retry_after ──▶ task-io delays the job
     Client (blocking driver)
        net-io TCP ──▶ [tls-net TLS] ──▶ Session (sans-IO SMTP state machine)
     outcome
        Delivered                       ──▶ task-io: complete
        Error, Disposition::Temporary   ──▶ task-io: retry with backoff and jitter
        Error, Disposition::Permanent   ──▶ task-io: dead-letter queue (inspect, replay)
```


### 3.4 Dependency gaps that block versions

| Gap | Where it must be added | What exactly | Blocks |
|---|---|---|---|
| Ed25519 signing | crypt-io, new `sign` module behind feature `sign-ed25519` | `Ed25519SigningKey::from_pkcs8_der(&[u8])`, `from_seed(&[u8; 32])`, `sign(&self, msg: &[u8]) -> [u8; 64]`, `public_key(&self) -> [u8; 32]`; key bytes wiped on drop | DKIM Ed25519 (0.5) |
| RSA signing | crypt-io, `sign` module behind feature `sign-rsa` | `RsaSigningKey::from_pkcs8_der`, `from_pkcs1_der`, `sign_pkcs1v15_sha256(&self, msg: &[u8]) -> Result<Vec<u8>>`, `modulus_bits(&self) -> u32`, `public_key_der(&self) -> Vec<u8>` (SubjectPublicKeyInfo for the DNS record); constant-time, blinded | DKIM RSA-SHA256 (0.5) |
| PBKDF2 | crypt-io `kdf` module, feature `kdf-pbkdf2` | `pbkdf2_hmac_sha256(password, salt, iterations, out: &mut [u8; 32]) -> Result<()>` with an iteration ceiling | SCRAM-SHA-256 (0.5) |
| SASLprep or PRECIS OpaqueString | unicode-lang (has normalization, no stringprep) | RFC 4013 SASLprep or RFC 8265 OpaqueString for SCRAM user names and passwords | SCRAM with non-ASCII credentials (see O-12) |
| IDNA (UTS 46 and RFC 5891 to 5893) | unicode-lang (searched 2026-10-21: no IDNA or Punycode code anywhere in the portfolio) | U-label to A-label conversion with validity checks | non-ASCII domains without SMTPUTF8 (see O-11) |
| base64 | encode-lib (missing) or parse-net | encode and decode, standard alphabet, line wrapping at 76 | 0.3 (see O-10) |

crypt-io's README states today that asymmetric cryptography is "a different problem, separate crate" and points to `ed25519-dalek`. Adding the `sign` module reverses that stance; jose-lib needs RSA and ECDSA in crypt-io too, so the reversal is wanted for more than smtp-net. The backend is `aws-lc-rs`, the same library tls-net uses (O-1, decided by James on 2026-10-21; D-006).

### 3.5 Why throttle-net is not a dependency

throttle-net 2.0 is first-party, but with its `std` feature it pulls `better-bucket`, `clock-lib`, `error-forge` (which carries `pastey` and `parking_lot`), `ahash`, and `hashbrown`, and its waiting surface needs tokio or smol. That breaks the zero-third-party and no-runtime rules for smtp-net. smtp-net instead defines a one-method `SendGate` trait and ships a small, lock-free `HourlyLimit` gate (section 8.9). A service that already runs throttle-net (for example inside task-io's handler) can implement `SendGate` over it in a few lines; the docs show how.

---


## 4. Scope

### 4.1 In scope

| Area | Detail |
|---|---|
| SMTP client core | sans-IO state machine (RFC 5321): greeting, EHLO (HELO fallback only on loopback plaintext), STARTTLS (RFC 3207), AUTH (RFC 4954), MAIL, RCPT, DATA with dot-stuffing, BDAT (RFC 3030), RSET, NOOP, QUIT; reply parsing with multi-line replies and budgets; enhanced status codes (RFC 2034, 3463) |
| Extensions | PIPELINING (RFC 2920), SIZE (RFC 1870), 8BITMIME (RFC 6152), SMTPUTF8 (RFC 6531), CHUNKING (RFC 3030), BINARYMIME (P3), DSN (RFC 3461), ENHANCEDSTATUSCODES, STARTTLS, AUTH, REQUIRETLS (RFC 8689, P3) |
| SASL | PLAIN (RFC 4616), LOGIN (draft-murchison-sasl-login), XOAUTH2 (Google), OAUTHBEARER (RFC 7628, P3), SCRAM-SHA-256 (RFC 7677), SCRAM-SHA-256-PLUS with `tls-exporter` (RFC 9266, P3) |
| Failure classification | every error maps to `Disposition::Temporary` or `Disposition::Permanent`, with `possibly_delivered`, `retry_after`, and per-recipient outcomes |
| Timeouts | per-stage defaults from RFC 5321 4.5.3.2, connect timeout, total deadline |
| Transport | blocking driver on net-io and tls-net: loopback plaintext, STARTTLS, implicit TLS; certificate verification on by default; connection reuse; a bounded pool |
| Pacing | `SendGate` trait and `HourlyLimit` gate for host caps |
| Message building | RFC 5322 headers, RFC 2045 to 2049 MIME, multipart alternative, mixed, related; attachments and inline images (RFC 2183, RFC 2392); base64 and quoted-printable; RFC 2047 encoded words; RFC 2231 parameters for file names; `Message-ID`, `Date`, `MIME-Version`; List-Unsubscribe (RFC 2369) and List-Unsubscribe-Post (RFC 8058); Auto-Submitted (RFC 3834) |
| Addresses | RFC 5321 and 5322 mailbox syntax, length limits, EAI addresses (RFC 6531, 6532) when SMTPUTF8 is used |
| Header injection defence | CR, LF, and NUL refused in every header value, display name, file name, address, and envelope parameter |
| DKIM | RFC 6376 signing, Ed25519-SHA256 (RFC 8463), RSA-SHA256 (RFC 8301), relaxed and simple canonicalization, oversigning, no `l=`; DNS record generation for the operator |
| Job hand-off | `PreparedMessage`: an immutable, versioned, checksummed byte form of envelope plus signed message for task-io payloads |
| Test support | a scripted sans-IO server, a blocking loopback test server with fault injection, recorded transcripts |
| Operator guide | SPF, DKIM, DMARC, PTR records; cPanel limits; bounce handling basics |

### 4.2 Out of scope, and where each item lives instead

| Item | Where it lives | Why |
|---|---|---|
| Receiving mail, SMTP server, MX delivery, relaying for others | not planned; a mail server is a different product (D-001) | services send mail; delivery to MX hosts needs a queue, DNS MX logic, and reputation management that the MSA already does |
| Queue, retries, backoff, idempotency, dead letters | task-io | D-004; smtp-net stays a sender |
| IMAP, POP3, JMAP | not planned | mailbox access is not sending |
| Parsing incoming mail, bounce (DSN, RFC 3464) parsing | parse-net for the grammar; a future mail-parsing crate (name open) for `multipart/report` | parsing received bounces requires receiving mail first |
| SPF, DKIM, DMARC, ARC verification | not planned for this crate; DNS records are an operator concern documented in `docs/DELIVERABILITY.md` (section 13) | verification is a receiver's job |
| ARC sealing (RFC 8617) | not planned | ARC is for intermediaries that modify mail, not originators |
| DNS resolution of MX records, DANE, MTA-STS | dns-net (later) if MX delivery is ever wanted | submission connects to one configured host |
| The `sendmail` binary transport | never (O-16) | spawning a program with user-influenced arguments caused lettre's RUSTSEC-2020-0069; loopback SMTP does the same job without a process boundary |
| TLS protocol | tls-net over rustls | never written in-house |
| Cryptographic primitives | crypt-io | accepted exception |
| OAuth token acquisition and refresh | oauth-net (planned) | smtp-net takes a token string for XOAUTH2 and OAUTHBEARER |
| Templates, HTML rendering, CSS inlining | the application or a template crate | presentation, not transport |
| S/MIME and OpenPGP signing or encryption | not planned before 1.0 (P3 idea only) | rare for service mail; large surface |
| Async runtimes | never in this crate | standard 2.8 |

---

## 5. Requirements

### 5.1 Functional requirements

| Id | Requirement | Grade | Version |
|---|---|---|---|
| FR-1 | Build a single-part `text/plain; charset=utf-8` message from From, To, Subject, and body with one call | P0 | 0.3 |
| FR-2 | Build `multipart/alternative` (text and HTML) with one call | P0 | 0.3 |
| FR-3 | Builder for any combination of text, HTML, attachments (`multipart/mixed`), and inline parts referenced by `cid:` (`multipart/related`), nested in the order mixed > related > alternative | P0 | 0.3 |
| FR-4 | Choose the transfer encoding per part: `7bit` when every line is ASCII and at most 998 octets; quoted-printable for mostly ASCII text; base64 for everything else; 8bit only on request (O-7) | P0 | 0.3 |
| FR-5 | Encode non-ASCII header text (Subject, display names, unstructured custom headers) as RFC 2047 encoded words, each at most 75 characters, never splitting a UTF-8 sequence; leave ASCII text untouched unless it contains a sequence that a reader would decode as an encoded word | P0 | 0.3 |
| FR-6 | Fold header lines at whitespace to at most 78 characters where possible and never exceed 998 octets; refuse a value that cannot be folded within 998 | P0 | 0.3 |
| FR-7 | Refuse CR, LF, and NUL in every header value, display name, subject, file name, Content-ID, address, and envelope parameter, with an error naming the field; never strip or replace | P0 | 0.3 |
| FR-8 | Validate addresses: local part at most 64 octets, domain at most 255 octets, path at most 256 octets (RFC 5321 4.5.3.1); dot-atom or quoted-string local part; LDH domain labels at most 63 octets; refuse address literals unless enabled | P0 | 0.3 |
| FR-9 | Generate `Message-ID` as `<` 26 base32 characters of 128 CSPRNG bits `@` the sender domain `>` unless the caller sets one | P0 | 0.3 |
| FR-10 | Generate `Date` in RFC 5322 format in UTC (`+0000`) unless the caller sets one | P0 | 0.3 |
| FR-11 | Never write `Bcc` into the message; include Bcc recipients only in the envelope | P0 | 0.3 |
| FR-12 | Derive the envelope (reverse-path and forward-paths) from From, To, Cc, Bcc, deduplicated, unless the caller supplies an explicit envelope | P0 | 0.3 |
| FR-13 | MIME boundaries of the form `=_` followed by 32 base32 characters of CSPRNG output; verify that no 7bit or 8bit part contains the boundary line, and regenerate if one does | P0 | 0.3 |
| FR-14 | Attachment file names encoded per RFC 2231 (with RFC 2047 fallback in `name=` for old readers) and refused if they contain `/`, `\`, control characters, or are empty | P0 | 0.3 |
| FR-15 | Sans-IO session: bytes in, bytes out, events out, deadlines out; no I/O, no clock reads, no randomness inside the state machine (all passed in) | P0 | 0.3 |
| FR-16 | Parse replies: three-digit code, `-` continuation lines with the same code, optional enhanced status code when ENHANCEDSTATUSCODES was advertised, text; refuse mismatched codes and lines over budget | P0 | 0.3 |
| FR-17 | Send EHLO first; fall back to HELO only when EHLO gets 500 or 502 and the session is loopback plaintext with no extension required | P0 | 0.3 |
| FR-18 | Parse EHLO capabilities: SIZE (with value), PIPELINING, 8BITMIME, SMTPUTF8, CHUNKING, BINARYMIME, DSN, ENHANCEDSTATUSCODES, STARTTLS, AUTH (mechanism list), REQUIRETLS; keep unknown keywords available | P0 | 0.3 |
| FR-19 | Dot-stuff DATA bodies in a streaming way that is correct across every chunk boundary, including the `CRLF CRLF .` case of RUSTSEC-2021-0069, and terminate with `CRLF . CRLF` | P0 | 0.3 |
| FR-20 | Refuse bare CR and bare LF in message bytes handed to the session (the builder never produces them); a raw message from the caller is checked before the first byte is sent | P0 | 0.3 |
| FR-21 | PIPELINING: send MAIL, every RCPT, and DATA (or BDAT LAST) as one group when advertised; match replies by count, never by code or text; when every RCPT failed and DATA still got 354, send a lone `.` and report failure | P1 | 0.3 |
| FR-22 | SIZE: send `SIZE=n` on MAIL when advertised; refuse locally before MAIL when the message exceeds the advertised maximum | P1 | 0.3 |
| FR-23 | 8BITMIME: send `BODY=8BITMIME` when the message contains 8bit parts; refuse locally when 8bit is needed and not advertised | P1 | 0.3 |
| FR-24 | Classify every failure as temporary or permanent per the table in 7.7, with `possibly_delivered` set when the end-of-data was sent and no reply was read | P0 | 0.3 |
| FR-25 | Per-recipient outcomes: report each RCPT reply; proceed when at least one recipient was accepted unless `RecipientPolicy::All` is set | P0 | 0.3 |
| FR-26 | Timeouts per stage with RFC 5321 4.5.3.2 defaults, a connect timeout, and an optional total deadline; a timeout closes the connection | P0 | 0.3 |
| FR-27 | Blocking driver: plaintext submission only when the configured host is a loopback literal or `localhost` **and** the connected peer address is loopback | P0 | 0.3 |
| FR-28 | STARTTLS: send only when advertised; require exactly one 220 reply and an empty receive buffer after it; hand the connection to TLS; discard capabilities; send EHLO again | P0 | 0.4 |
| FR-29 | When TLS is required and STARTTLS is not advertised, or the STARTTLS reply is not 220, end the session; no fallback to plaintext | P0 | 0.4 |
| FR-30 | Implicit TLS (port 465, RFC 8314) | P0 | 0.4 |
| FR-31 | Server certificate verification on by default against the configured host name; turning it off requires a method whose name says it is insecure and is refused for non-loopback hosts in release builds unless a second explicit flag is set (O-19) | P0 | 0.4 |
| FR-32 | AUTH PLAIN with initial response | P0 | 0.4 |
| FR-33 | AUTH LOGIN | P1 | 0.4 |
| FR-34 | Credentials sent only over TLS, or over loopback plaintext with explicit opt-in | P0 | 0.4 |
| FR-35 | Mechanism selection from a caller allowlist in the caller's order; never a silent downgrade to a weaker mechanism than the allowlist permits | P0 | 0.4 |
| FR-36 | Connection reuse: send many messages on one session, with limits on messages per connection and idle time; transparent reconnect when the server closed an idle connection before any byte of a new transaction was accepted | P1 | 0.4 |
| FR-37 | CHUNKING: use BDAT (no dot-stuffing) when advertised and enabled; pipeline BDAT with MAIL and RCPT | P2 | 0.4 |
| FR-38 | DSN: RET, ENVID on MAIL; NOTIFY, ORCPT on RCPT, xtext-encoded; policy `IfSupported` or `Required` | P2 | 0.4 |
| FR-39 | SMTPUTF8: send the `SMTPUTF8` parameter when any envelope address or header needs UTF-8; refuse when not advertised (no downgrade) | P2 | 0.4 |
| FR-40 | `SendGate` checked before connecting and before each transaction; refusal is temporary with `retry_after` | P1 | 0.4 |
| FR-41 | `PreparedMessage`: envelope plus final message bytes in a versioned, checksummed encoding for job payloads; decoding verifies the checksum and every budget | P1 | 0.4 |
| FR-42 | Too-many-recipients handling: a 452 (or legacy 552) on RCPT with enhanced code `x.5.3` defers the remaining recipients to a further transaction on the same connection | P1 | 0.4 |
| FR-43 | DKIM signing with Ed25519-SHA256 and RSA-SHA256, relaxed/relaxed by default, simple available; From always signed; oversigning of From, To, Cc, Subject, Date, Reply-To, Message-ID; no `l=`; `t=` set; optional `x=` | P0 | 0.5 |
| FR-44 | Several DKIM signatures on one message (RSA and Ed25519 under different selectors, RFC 8463 section 6) | P1 | 0.5 |
| FR-45 | DKIM key loading from PKCS#8 PEM or DER, and PKCS#1 PEM or DER for RSA; RSA keys under 2048 bits refused unless explicitly allowed down to the RFC 8301 floor of 1024 | P0 | 0.5 |
| FR-46 | DKIM DNS record value generation (`v=DKIM1; k=ed25519; p=...`) for the operator | P2 | 0.5 |
| FR-47 | XOAUTH2 | P2 | 0.5 |
| FR-48 | SCRAM-SHA-256 with server signature verification in constant time | P2 | 0.5 |
| FR-49 | Bounded connection pool for the blocking driver | P2 | 0.5 |
| FR-50 | Test servers: scripted sans-IO server and blocking loopback server with fault injection, behind the `testing` feature | P1 | 0.3 |
| FR-51 | List-Unsubscribe and List-Unsubscribe-Post headers (RFC 2369, RFC 8058) | P2 | 0.4 |
| FR-52 | `In-Reply-To` and `References` for threading | P1 | 0.3 |
| FR-53 | Sign raw RFC 5322 bytes not built by smtp-net (DKIM over arbitrary input with budgets) | P2 | 0.5 |
| FR-54 | Send raw RFC 5322 bytes not built by smtp-net, after validation (CRLF only, line lengths, header block present) | P1 | 0.3 |
| FR-55 | VERP-style return path helper (`bounces+token@domain`) for mapping bounces to messages | P3 | after 1.0 allowed |
| FR-56 | LMTP mode (RFC 2033): LHLO and per-recipient replies after end of data | P3 | after 1.0 allowed |
| FR-57 | REQUIRETLS (RFC 8689) | P3 | after 1.0 allowed |
| FR-58 | OAUTHBEARER (RFC 7628) and SCRAM-SHA-256-PLUS (RFC 9266 `tls-exporter`) | P3 | after 1.0 allowed |
| FR-59 | BINARYMIME (RFC 3030) | P3 | after 1.0 allowed |
| FR-60 | Streaming attachments from a reader without holding them in memory | P2 | 0.5 |

### 5.2 Non-functional requirements

| Id | Requirement | Measure |
|---|---|---|
| NFR-1 | No panics in library code | clippy `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` denied in library code; fuzzing finds none |
| NFR-2 | Hot paths allocate nothing: reply parsing, command formatting, dot-stuffing, base64 and quoted-printable encoding into a caller buffer, DKIM canonicalization, serialization into a `Sink` | counting-allocator tests |
| NFR-3 | Memory per session bounded by configuration, never by server input | budget tests with hostile servers; default session memory at most 16 KiB **[est.]** |
| NFR-4 | Linear time in input size for every parser and encoder | property tests on inputs up to 64 MiB with timing ratio checks; no nested rescans |
| NFR-5 | At least 20% faster than lettre 0.11 sync `SmtpTransport` for sending 1,000 messages over one connection to a loopback server at 0, 1, and 10 ms simulated round-trip time, at equal or stronger security | criterion, published in `docs/PERFORMANCE.md` |
| NFR-6 | Message build plus serialization of a typical verification email (text and HTML, about 2 KiB) at most 5 µs **[est.]** and at least 20% faster than lettre's builder and mail-builder | criterion |
| NFR-7 | Zero CPU when idle: no timers or threads when nothing is being sent; the pool's idle expiry is checked lazily on checkout | code review, `strace` and Process Monitor spot checks |
| NFR-8 | No secret in `Debug`, `Display`, errors, logs, or transcripts; AUTH lines redacted in transcripts | tests that format every type holding a secret |
| NFR-9 | Deterministic output: the same message, clock value, and random bytes give the same bytes on every platform | golden-file tests on Linux, macOS, Windows |
| NFR-10 | Builds on Linux, macOS, Windows, stable and 1.85; core (`proto`, `message`, `dkim` canonicalization) builds `no_std` with `alloc` | CI matrix |
| NFR-11 | Zero third-party runtime dependencies outside crypt-io's audited cryptography and tls-net's rustls | `cargo tree -e normal` check in CI |
| NFR-12 | Every error variant actionable: says what was refused and what to do | doc review; one test per variant |
| NFR-13 | Interoperates with Exim (cPanel), Postfix, Microsoft 365, Gmail submission, and Mailpit | interop CI and the 0.8 field test |
| NFR-14 | 24-hour soak (one message per 10 ms to the loopback server, reused connections, injected faults) with no memory growth and no leaked sockets | soak job before 0.8 |

---


## 6. Standards

The portfolio standard is [`../REPS.md`](../REPS.md) with the engineering law in [`DIRECTIVES.md`](./DIRECTIVES.md). This section records only where smtp-net applies it in a specific way.

- **How "faster" is measured.** For an SMTP client the network round trip dominates, so the comparison has two parts: CPU cost per message (build, sign, serialize, encode) measured in isolation, and wall time per message over loopback with simulated round-trip times, where the gain comes from pipelining, CHUNKING, and connection reuse. Both are published; neither alone is claimed as "the" speed. The bar is at least 20% faster than the best Rust competitor at equal or stronger security.
- **Which paths are hot.** The hot paths are listed in NFR-2. The message builder owns its header values and parts (`String`, `Vec<u8>`) because a message outlives the call that builds it and crosses into a job store; it allocates a bounded number of times per message (target at most 8 allocations for a text plus HTML message **[est.]**), and that number is held by a counting-allocator test rather than claimed to be zero.
- **Efficiency.** One `write` system call per pipelined command group, body chunks written in buffers of at least 16 KiB (configurable), and connection reuse so a batch pays for one TCP and TLS handshake.
- **Persisted state.** smtp-net persists nothing itself. `PreparedMessage` is the only byte form meant for storage (by task-io); it carries a version byte and a CRC-32C checksum so a corrupt job payload is refused instead of sent, and task-io's store provides crash safety.
- **Concurrency.** `Session` and `Client` are `Send` and not `Sync` (one connection, one owner). `Message`, `PreparedMessage`, `DkimSigner`, `Server`, and `HourlyLimit` are `Send + Sync`. `Pool` and `HourlyLimit` are the only shared mutable state; both use atomics, and both have `loom` models.
- **Cross-platform.** smtp-net has no `cfg(unix)` code; the OS is reached only through net-io, the TLS engine, `std::time`, and mod-rand. The modules `proto`, `message` (without `std` conveniences), `address`, and `dkim::canon` build with `no_std` plus `alloc`; time and randomness are passed in. FreeBSD is not in CI because smtp-net touches no OS event mechanism.
- **Dependencies.** No third-party runtime dependency. The accepted exceptions are audited cryptography reached through crypt-io, and rustls reached through tls-net. Independent verification of DKIM signatures and MIME output, and the competitor benchmarks, live in a separate repository (D-035), so reference implementations never enter smtp-net's dependency graph, not even as dev-dependencies.
- **Unsafe.** `#![forbid(unsafe_code)]`. Wiping secrets uses crypt-io's `Zeroizing`, not hand-written volatile writes.
- **Names.** Protocol names that are themselves the standard's words keep their spelling (`Ehlo`, `Rcpt`, `Bdat`, `Dkim`, `Smtputf8` in enum variants that mirror RFC keywords), because a reader of the RFC looks for those exact words. Everything else uses plain words (`Disposition`, `possibly_delivered`, `Envelope`).
- **Documents.** Besides the standard set, smtp-net ships `docs/DELIVERABILITY.md` (SPF, DKIM, DMARC, PTR, cPanel limits, bounces), because a correct client still fails if the operator's DNS is wrong.
- **CI additions.** A `no_std` build job for the core modules, an interop job on Linux that runs Mailpit and Exim containers (12.8), and a job in the comparison repository that verifies DKIM signatures and MIME output with reference implementations.
- **Versions.** 0.1 scaffold, 0.2 design lock, 0.3 core, 0.4 extended, 0.5 feature complete, 0.6 optimisation, 0.7 hardening, 0.8 alpha, 0.9 beta with the pre-1.0 polish pass, 1.0 stable. No series is skipped. An MSRV raise is a major change after 1.0.

## 7. Design and architecture

### 7.1 Module map

```
src/
  lib.rs              crate docs, Tier-1 functions (send, send_local, send_prepared), re-exports, VERSION
  error.rs            Error, ErrorKind, Disposition, Stage, nested error enums
  address.rs          Address, Mailbox, Domain; validation on parse-net's grammar
  encode/
    base64.rs         base64 with 76-character lines (private until encode-lib, D-015)
    qp.rs             quoted-printable with the dot and "From " rules (private until encode-lib)
    crc32c.rs         CRC-32C for PreparedMessage (private, D-028)
    scan.rs           SWAR scans for CR, LF, NUL, '.', and non-ASCII
  message/
    mod.rs            Message, MessageBuilder, Tier-1 constructors
    header.rs         HeaderName, Headers, folding and RFC 2047 words (through parse-net), injection checks
    part.rs           Part, Body, Attachment, Inline, Multipart kinds, ContentType
    transfer.rs       transfer-encoding choice
    serialize.rs      Sink trait, streaming serializer, boundary generation and checks
    id.rs             MessageId generation and validation
    prepared.rs       Envelope, PreparedMessage, job codec (version + CRC-32C)
  dkim/               feature "dkim"
    canon.rs          simple and relaxed canonicalization, streaming, no_std
    signer.rs         DkimSigner, DkimKey, tag list, header selection, oversigning
    record.rs         DNS TXT record generation
  proto/
    reply.rs          ReplyParser, Reply, ReplyCode, EnhancedCode
    capability.rs     Capabilities from EHLO
    command.rs        command formatting, xtext, final CR/LF scan
    stuff.rs          DotStuffer (streaming)
    sasl.rs           Plain, Login, XOAuth2, ScramSha256 (+ OAuthBearer later), Mechanism trait
    session.rs        Session state machine, events, deadlines
    classify.rs       reply and error to Disposition rules
    timeouts.rs       Timeouts, Millis
  gate.rs             SendGate trait, Admission, HourlyLimit
  client/             feature "client"
    server.rs         Server, ServerBuilder, Security, Credentials
    tls.rs            TlsConnector seam over net-io's TlsSession (D-026)
    connection.rs     net-io connect, loopback check, TLS record layer
    client.rs         Client (blocking driver), Report
    pool.rs           Pool
  testing/            feature "testing"
    script.rs         ScriptedServer (sans-IO), Transcript
    server.rs         TestServer (blocking loopback, fault injection)
```

### 7.2 Features

| Feature | Default | Enables | Pulls |
|---|---|---|---|
| `std` | yes | OS random source, wall clock, `std::error::Error`, `IoSink`, generated `Date` and `Message-ID` | mod-rand |
| `client` | yes | blocking driver, `send`, `send_local`, `send_prepared`, `Client`, `Pool`, the STARTTLS and implicit TLS paths through the `TlsConnector` seam | net-io, `std` |
| `tls` | no until tls-net is published, then yes (D-025) | tls-net's verified client connector as the default for `Server::starttls` and `Server::implicit_tls` | tls-net (rustls), `client` |
| `dkim` | no | DKIM signing | crypt-io (`hash-sha2`, `sign-ed25519`, `sign-rsa`) |
| `scram` | no | SCRAM-SHA-256 | crypt-io (`hash-sha2`, `mac-hmac`, `kdf-pbkdf2`) |
| `key-vault` | no | accept key-vault handles for credentials and DKIM keys | key-vault |
| `testing` | no | `ScriptedServer`, `TestServer`, transcripts | `std` |

### 7.3 Data flow

```
 caller ──▶ MessageBuilder ──▶ Message (owned, validated)
                                   │ serialize (Sink, streaming, deterministic)
                                   ▼
                            message bytes ──▶ DkimSigner::sign ──▶ DKIM-Signature header prepended
                                   │
                                   ▼
                    PreparedMessage { envelope, bytes, flags } ──▶ (task-io payload) ──▶ worker
                                   │
 Client::send ──▶ SendGate::admit ──▶ connect (net-io) ──▶ [TLS] ──▶ Session
                                                                     │ events, bytes
          driver loop: transmit() ──▶ socket ──▶ receive() ──▶ poll_event()
                                   │
                                   ▼
                    Report { message_id, recipients, final reply }  or  Error { disposition, ... }
```

The message is serialized and signed **once**, before it enters the job store. Retries send the same bytes with the same `Message-ID`, so a receiver that saw a duplicate (after an ambiguous failure, 7.7) can recognise it, and the DKIM signature stays valid.

### 7.4 The sans-IO session

The session owns no socket, reads no clock, and draws no random numbers. The driver gives it bytes and the current monotonic time in milliseconds; it gives back bytes to write, events, and the next deadline.

```
 driver                                    Session
   │ receive(input, now) ─────────────────▶ parse replies, advance state
   │ ◀──────────────────── consumed count
   │ transmit() ◀────────── pending output (&[u8])
   │ transmitted(n) ───────────────────────▶ drop n bytes from output
   │ poll_event() ◀──────── Event (Ready, StartTls, RecipientRejected, Delivered, ...)
   │ deadline() ◀────────── Option<Millis>
   │ on_timeout(now) ──────────────────────▶ Error::Timeout { stage } if expired
   │ tls_established() ────────────────────▶ after the driver finished the handshake
   │ begin(envelope) / body(chunk) / end_body() / reset() / quit()
```

**States.**

```
 AwaitGreeting ──220──▶ SendEhlo ──▶ AwaitEhlo ──250──▶ Capable
       │ 554/421              │ 500/502 (loopback plaintext only)
       ▼                      ▼
     Closed              SendHelo ──▶ AwaitHelo ──250──▶ Capable (no extensions)

 Capable
   ├─ TLS required, not yet TLS ──▶ SendStartTls ──▶ AwaitStartTls ──220, buffer empty──▶ NeedTls (Event::StartTls)
   │        ──tls_established()──▶ SendEhlo (capabilities discarded) ──▶ AwaitEhlo ──▶ Capable (TLS)
   ├─ credentials configured, not yet authenticated ──▶ SendAuth ──▶ AwaitAuth ⇄ (334 challenge, response)
   │        ──235──▶ Ready
   └─ otherwise ──▶ Ready

 Ready ──begin(envelope)──▶ SendMail ──▶ SendRcpt × n ──▶ SendData | SendBdatLast
         (one group when PIPELINING; one command per round trip otherwise)
       ──▶ AwaitMail ──▶ AwaitRcpt × n ──▶ AwaitData(354) ──▶ Body ──end_body()──▶ AwaitDataEnd ──250──▶ Ready
                                                         (BDAT: AwaitBdat ──250──▶ Ready)
 Ready ──quit()──▶ SendQuit ──▶ AwaitQuit ──221──▶ Closed
 any state ──421, EOF, timeout, protocol error──▶ Closed (with the error and its disposition)
```

**Rules the state machine enforces.**

1. A command is formatted into the output buffer only in a state that allows it; any other call returns `Error::Usage` (a caller bug, permanent).
2. Replies are matched to commands by count, in order (RFC 2920 3.1). A reply that arrives when no command is outstanding is a protocol error (`Error::Protocol(UnexpectedReply)`), except a 421 which always closes.
3. STARTTLS is never pipelined with anything after it. After the 220 reply to STARTTLS, the receive buffer must be empty: any further byte already received in plaintext is the response-injection attack described by the NO STARTTLS study (Poddebniak, Ising, Böck, Schinzel, USENIX Security 2021), and the session ends with `Error::StartTlsInjection`. The driver must not read more plaintext after the 220; `receive` returns a consumed count that stops at the end of that reply so the driver can check.
4. After TLS, every capability learned before TLS is discarded (RFC 3207 4.2: the client "MUST discard any knowledge obtained from the server") and EHLO is sent again. RFC 3207 says SHOULD for the new EHLO; smtp-net always sends it, because extensions advertised in plaintext could have been altered.
5. After a SASL mechanism that negotiates a security layer (none of the built-in ones does), capabilities are discarded and EHLO is sent again (RFC 4954).
6. AUTH is refused by the session unless `tls_established()` was called or the configuration says `PlaintextLoopback` and the driver confirmed the peer is loopback (`peer_is_loopback(true)`).
7. A body byte is accepted only in `Body` state. Dot-stuffing (DATA) or chunk framing (BDAT) is applied by the session, never by the caller.
8. Every command line is checked after formatting: it must contain no CR or LF before its terminating CRLF and must be at most 512 octets (RFC 5321 4.5.3.1.4), except AUTH lines, which may reach 12,288 octets (RFC 4954 says that length "is considered to be a sufficient line length limit"); an AUTH initial response that would exceed the limit is sent after a 334 instead (RFC 4954).

### 7.5 Reply parsing

```
reply-line = 3DIGIT ( "-" / SP ) [ enhanced-code SP ] text CRLF
           / 3DIGIT CRLF                                   (code alone, accepted)
```

- The first digit must be 2, 3, 4, or 5; the second 0 to 5; the third 0 to 9. Anything else is `Protocol(MalformedReply)`.
- Every line of a multi-line reply must carry the same code; a mismatch is `Protocol(InconsistentReply)`.
- An enhanced status code (`class "." subject "." detail`, class 2, 4, or 5, subject and detail 0 to 999) is parsed only when ENHANCEDSTATUSCODES was advertised; its class must equal the reply's first digit, otherwise it is ignored (kept as text) and the reply's own code decides.
- Budgets (defaults, configurable): at most 1,000 octets per line including CRLF (RFC 5321 says 512; the budget is generous for real servers whose greetings run long, see O-15), at most 64 lines per reply, at most 8 KiB per reply in total. Exceeding a budget is `Protocol(ReplyTooLong)` and the session closes.
- Bare LF as a line ending in a reply is refused (`Protocol(BareLineFeed)`); NUL is refused.
- Text is kept in a bounded buffer for the report (first 1 KiB). `Display` replaces every byte outside printable ASCII and space with `?`, so a hostile server cannot write terminal escape sequences into logs.

### 7.6 Pipelining, chunking, and round trips

Round trips per message on a reused connection (after the session is `Ready`):

| Server offers | Commands | Round trips |
|---|---|---|
| nothing | MAIL; RCPT; DATA; body and `.` | 4 (with one recipient) |
| PIPELINING | MAIL + RCPT + DATA in one group; body and `.` | 2 |
| PIPELINING + CHUNKING | MAIL + RCPT + `BDAT n LAST` + body in one write | 1 |

This is the main source of the 20% target (NFR-5): lettre's `Extension` enum lists no PIPELINING or CHUNKING keyword (docs.rs, lettre 0.11.23), so it is assumed to pay four round trips per message; the 0.6 benchmark confirms or corrects this.

Deadlock rule (RFC 2920 section 3.1, window): the blocking driver writes a pipelined group with a single non-blocking-safe write only when the group is at most 4 KiB **[RFC 2920 "usually 4K octets"]**; a larger group (many recipients) is split into groups of at most 4 KiB, each followed by reading the replies it produced. With BDAT, the body is written after the command group's replies are drained when the body exceeds the socket send buffer, so the client never blocks writing while the server blocks writing replies.

When every RCPT in a pipelined group was rejected and the server still answers DATA with 354, the session sends a lone `.` (RFC 2920 section 3.1) and reports `Error::AllRecipientsRejected` with every per-recipient reply. A failed BDAT ends the transaction; the session sends RSET before the next one (RFC 3030: the state after a failure is indeterminate).

### 7.7 Failure classification

Every error carries a `Disposition`. task-io maps `Temporary` to `Fail::retry` and `Permanent` to `Fail::permanent`.

| Condition | Disposition | `possibly_delivered` | Notes |
|---|---|---|---|
| Local validation error (address, header, budget, file name, key) | Permanent | false | retrying cannot change the input |
| `SendGate` refused | Temporary | false | `retry_after` set to the gate's next free time |
| DNS resolution of the configured host failed, connect refused, network unreachable, connect timeout | Temporary | false | |
| Greeting 421 | Temporary | false | server busy or shutting down |
| Greeting 554 | Permanent | false | RFC 5321 3.1: no SMTP service here; usually configuration |
| EHLO and HELO refused (5yz) | Permanent | false | |
| STARTTLS not advertised when required | Temporary | false | `security_event = true`; could be a stripping attacker on the path; repeated failures end in the dead-letter queue |
| STARTTLS reply 454 | Temporary | false | RFC 3207 |
| STARTTLS reply 501 or other 5yz | Permanent | false | |
| Plaintext bytes after the STARTTLS 220 | Temporary | false | `security_event = true` |
| TLS handshake I/O error or timeout | Temporary | false | |
| Certificate verification failed, name mismatch, protocol version refused | Permanent | false | configuration; retrying the same server cannot pass |
| AUTH 454 (4.7.0) | Temporary | false | |
| AUTH 432 (4.7.12, password transition needed) | Permanent | false | an operator must act |
| AUTH 535 (5.7.8), 534 (5.7.9), 530 (5.7.0), 538 | Permanent | false | credentials or policy |
| No acceptable AUTH mechanism offered | Permanent | false | |
| MAIL 4yz | Temporary | false | |
| MAIL 5yz | Permanent | false | |
| RCPT 4yz | Temporary for that recipient | false | |
| RCPT 452 or 552 with `x.5.3` (too many recipients) | Temporary for the remaining recipients | false | FR-42 sends them in a further transaction |
| RCPT 5yz otherwise | Permanent for that recipient | false | |
| All recipients rejected | Temporary if any rejection was 4yz, else Permanent | false | |
| DATA or BDAT 4yz before any body byte | Temporary | false | |
| Message larger than the advertised SIZE (local check) | Permanent | false | |
| End-of-data reply 4yz | Temporary | false | the server said it did not take the message |
| End-of-data reply 5yz | Permanent | false | content rejected |
| EOF, reset, or timeout **after** the end-of-data sequence (or BDAT LAST) was written and **before** its reply was read | Temporary | **true** | RFC 1047 duplicate-message problem; the same `Message-ID` is reused on retry |
| EOF, reset, or timeout at any earlier point | Temporary | false | |
| 421 at any point | Temporary | true only if after end-of-data | connection closes |
| Malformed reply or reply budget exceeded | Temporary | true only if after end-of-data | `security_event = true` |
| SMTPUTF8 or 8BITMIME needed and not advertised | Permanent | false | no downgrade |
| DSN `Required` and not advertised | Permanent | false | |

The default timeouts follow RFC 5321 4.5.3.2 (7.8) precisely because a short end-of-data timeout turns slow content scanning into `possibly_delivered` duplicates.

### 7.8 Timeouts

| Stage | Default | Source |
|---|---|---|
| connect | 30 s | design choice **[est.]**; not in RFC 5321 |
| initial 220 greeting | 5 min | RFC 5321 4.5.3.2.1 |
| EHLO, HELO, STARTTLS, AUTH, RSET, NOOP, QUIT replies | 5 min | RFC 5321 4.5.3.2 lists MAIL and RCPT at 5 min; smtp-net applies the same value to these commands |
| TLS handshake | 60 s | design choice **[est.]**; longer than net-io's 10 s inbound handshake deadline because a remote relay under load can be slow, and an outbound client is not a slowloris risk to anyone but itself |
| MAIL reply | 5 min | 4.5.3.2.2 |
| RCPT reply | 5 min | 4.5.3.2.3 |
| DATA initiation (354) | 2 min | 4.5.3.2.4 |
| each data block write | 3 min | 4.5.3.2.5 |
| end-of-data reply | 10 min | 4.5.3.2.6 |
| BDAT reply | 10 min for LAST, 3 min otherwise | derived from 4.5.3.2.5 and 4.5.3.2.6 |
| total per message | none by default | the job's own deadline in task-io bounds the whole send |
| pooled connection idle | 60 s | below the 5 min server timeout of 4.5.3.2.7, so the client closes first |

`Timeouts::rfc5321()` is the default. `Timeouts::local()` (connect 2 s, replies 30 s, end-of-data 120 s **[est.]**) exists for loopback submission to a local MTA, documented as shorter than RFC 5321 recommends, with the duplicate risk stated.

### 7.9 Message model

- `Message` holds a header list (validated, owned) and a body tree (`Part`), plus flags computed at build time: `needs_smtputf8`, `has_8bit`, `size_hint`.
- **Encoding choice (O-7).** Default output is 7-bit clean: text parts become `7bit` when every line is ASCII and at most 998 octets, otherwise quoted-printable when at least 80% of bytes are printable ASCII **[est. threshold, measured at 0.6]**, otherwise base64. Binary attachments are always base64. RFC 6376 section 5.3 says signers SHOULD convert to quoted-printable or base64 before signing, because a relay that converts 8bit to 7bit later breaks the signature; producing 7-bit output by default makes DKIM signatures survive. `MessageBuilder::allow_8bit(true)` allows `8bit` for UTF-8 text when the caller knows the path supports it.
- **Quoted-printable** (RFC 2045 6.7): encoded lines at most 76 characters with soft breaks `=` CRLF; `=` encoded; trailing space and tab before a line break encoded; a line beginning with `.` is encoded as `=2E` and a line beginning with `From ` as `=46rom ` (defence against dot and mbox mangling); CRLF in text becomes a hard line break.
- **Base64** (RFC 2045 6.8): lines of exactly 76 characters except the last.
- **Headers.** Structured headers (From, To, Cc, Reply-To, Sender) are written from validated `Mailbox` values; display names that need quoting are quoted (`quoted-string`) when ASCII, encoded (RFC 2047 `B` or `Q`, whichever is shorter) when not. Unstructured headers (Subject, custom) are encoded when they contain non-ASCII, or when they contain a substring that matches the encoded-word syntax `=?...?=` (so user text shows literally instead of being decoded by readers, threat T-23). Folding happens only at whitespace between encoded words or atoms.
- **Message-ID.** `<` + 26 base32 characters of 128 random bits + `@` + the domain of the From address (or a configured domain) + `>`. Not the host name (threat T-14), not a timestamp-based id. id-forge's UUIDv7 and ULID embed a timestamp, which `Date` already discloses, but they also order messages and reveal volume; plain random is preferred. Random bits come from `mod_rand::tier3::fill_bytes` (OS CSPRNG); its `io::Error` maps to `Error::Random`, classified temporary because the OS source can recover (8.12).
- **Boundaries.** `=_` + 32 base32 characters (160 random bits). `=_` cannot appear in quoted-printable output (an `=` is always followed by two hex digits or a line break) and `_` is not in the base64 alphabet, so encoded parts can never contain the boundary; 7bit and 8bit parts are scanned once for `--` + boundary at a line start, and a new boundary is drawn if found (probability about 2^-160 for random content).
- **Date.** `Tue, 21 Oct 2026 14:03:05 +0000` from Unix seconds (civil-from-days algorithm, no time zone tables); a caller-supplied time zone offset is supported in Tier 2.
- **Required headers.** RFC 5322 requires `Date` and `From`; smtp-net also always writes `Message-ID` and `MIME-Version: 1.0`. Header order on output: `Date`, `From`, `Sender`, `Reply-To`, `To`, `Cc`, `Subject`, `Message-ID`, `In-Reply-To`, `References`, then custom headers in insertion order, then `MIME-Version` and the `Content-*` headers. The order is fixed so DKIM's `h=` list and golden tests are stable.

### 7.10 DKIM signing

- **Input:** the serialized message bytes (CRLF line endings, as they will be sent before dot-stuffing).
- **Body hash:** stream the body through the canonicalizer (simple: remove trailing empty lines, empty body becomes CRLF; relaxed: drop trailing whitespace on each line, compress runs of whitespace to one space, remove trailing empty lines) into SHA-256. Known vectors: an empty body hashes to `frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=` under simple and `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=` under relaxed (the SHA-256 of CRLF and of the empty string; both checked in tests).
- **Header selection:** `h=` lists `from:to:cc:subject:date:message-id:reply-to:in-reply-to:references:mime-version:content-type:content-transfer-encoding:list-unsubscribe:list-unsubscribe-post` for the headers present, then repeats `from`, `to`, `cc`, `subject`, `date`, `reply-to`, `message-id` once more (oversigning, RFC 6376 5.4.2: a listed instance that does not exist is hashed as a null string, so a header added later breaks the signature). From is always signed (RFC 6376 5.4: "The From header field MUST be signed").
- **Never emitted:** `l=` (body length; it lets content be appended under a valid signature, RFC 6376 8.2), `rsa-sha1` (RFC 8301 3.1: "MUST NOT be used for signing or verifying"), `z=`.
- **Emitted:** `v=1; a=; c=; d=; s=; t=; bh=; h=; b=`, and `x=` and `i=` when configured.
- **Signature:** the `DKIM-Signature` header with `b=` empty is canonicalized and hashed last, without its trailing CRLF (RFC 6376 3.7). RSA-SHA256: PKCS#1 v1.5 signature over the canonicalized header data with SHA-256. Ed25519-SHA256: the SHA-256 hash of the canonicalized header data, signed with PureEdDSA Ed25519 (RFC 8463 section 3: "It signs the hash with the PureEdDSA variant Ed25519").
- **Folding:** lines of the header are kept to 78 columns, folded with CRLF SP at tag boundaries, between `h=` names, and inside the `b=` value, which starts its own line (D-068); relaxed canonicalization at the verifier removes the folding, and under simple header canonicalization the exact folding is what was signed, so the signer serializes the header once and signs those bytes.
- **Several signatures:** each signer adds its own header; signatures are independent (RFC 8463 Appendix A) and are prepended in the order given.

### 7.11 Envelope and recipients

- Reverse-path: the explicit return path if set, else the `Sender` address if set, else the single `From` address. Multiple `From` mailboxes are refused in 1.0 (P3 to allow with `Sender`).
- Forward-paths: To, Cc, Bcc in that order, deduplicated by exact local part and lowercase ASCII domain. At most 100 recipients per message by default (RFC 5321 4.5.3.1.8 requires servers to buffer at least 100); more is a local permanent error unless raised.
- An empty recipient list is a local permanent error.
- Null reverse-path `<>` is allowed only through `Envelope::null_sender` (bounces and auto-replies), never derived.

### 7.12 Connection policy and the blocking driver

`Security` has three values and no "opportunistic" one, because submission carries credentials and private content:

| `Security` | Port default | Behaviour |
|---|---|---|
| `PlaintextLoopback` | 25 | the configured host must be `127.0.0.0/8`, `::1`, or `localhost`, **and** the connected peer address reported by net-io must be loopback; otherwise `Error::PlaintextRefused` before any byte is sent |
| `StartTls` | 587 | plaintext greeting and EHLO, then STARTTLS required (FR-28, FR-29) |
| `ImplicitTls` | 465 | TLS from the first byte (RFC 8314), certificate verified against the configured host name |

The driver loop is a plain blocking loop over net-io's connection: write `transmit()`, read into a fixed buffer, `receive`, drain `poll_event`, apply `deadline()` as the socket read timeout. No thread is spawned per message. The driver resolves the host with net-io (which uses `std::net::ToSocketAddrs` until dns-net exists), tries addresses in order, and applies the connect timeout per address within the overall stage budget.

**Connection reuse.** `Client` keeps the session open after a message. Before a new transaction on a connection that has been idle, the driver does not send NOOP (one round trip saved); if the server closed the connection, the MAIL write or its reply fails with EOF before any reply was accepted, which is safe to retry once on a new connection inside the same `send` call (nothing was accepted), and the driver does so. Limits: 100 messages per connection **[est.]**, 60 s idle.

### 7.13 Pacing for host limits

cPanel's "Max hourly emails per domain" defaults to Unlimited, but hosts commonly set a value; it is enforced only on remote deliveries, and messages over the limit are **accepted at SMTP time** and then handled by the setting "The percentage of email messages (above the account's hourly maximum) to queue and retry for delivery" (cPanel docs, "How to Set Email Send Limits"). So smtp-net receives `250` for a message the host will hold or drop. Pacing therefore has to happen before submission, in the client. `HourlyLimit` counts in one-minute buckets over a rolling hour and refuses with `retry_after` when the next message would exceed the limit; the unit is messages or recipients (O-21: which one cPanel counts is not confirmed).

### 7.14 Memory strategy

| Object | Memory | Bound |
|---|---|---|
| `Session` | one output buffer (default 4 KiB commands, grows only for AUTH up to 12,288 octets), one reply buffer (default 8 KiB), capabilities (fixed fields plus up to 32 unknown keywords of up to 64 octets) | configuration |
| body path | no buffering in the session beyond the output buffer; `body(chunk)` returns how much it accepted | output buffer size |
| `Client` read buffer | 16 KiB **[est.]** | configuration |
| `Message` | owned headers and parts; total encoded size checked against `max_message_size` (default 25 MiB) before encoding begins | configuration |
| `DkimSigner` | header hash input buffered (header block at most 64 KiB by budget); body hashed streaming | configuration |
| `HourlyLimit` | 60 atomic counters | fixed |
| `Pool` | at most `max_connections` sessions | configuration |

### 7.15 Logging and observability

smtp-net does not log. It exposes an optional `Observer` trait (Tier 3, P2) called with structured events (connected, TLS established with its version, reply codes, transaction outcome, timings; D-076). Transcripts (for tests and debugging) record commands and replies with AUTH payloads replaced by `<redacted N octets>`, and with message bodies omitted unless explicitly enabled.

---


## 8. API

The public API (every type, trait, function, error, grade, tier, version, and cost target) is written in [`../docs/API.md`](../docs/API.md). That file is the design lock: a change to it after 0.2.0 is a decision and goes into section 19.

## 9. Parity matrix

Sources were checked on 2026-10-21 (links in section 18). "Not stated" means the checked documentation does not say; it is not a claim that the feature is missing. lettre, mail-send plus mail-builder, and async-smtp are the Rust competitors; Python `smtplib` and `email` and .NET MailKit are references for what mature libraries offer.

| Capability | smtp-net 1.0 (grade) | lettre 0.11.23 | mail-send 0.6.2 + mail-builder 1.0.0 | async-smtp 0.10.2 | Python smtplib + email | MailKit (.NET) |
|---|---|---|---|---|---|---|
| Blocking API without an async runtime | yes (P0) | yes (sync transport) | no: "Full async (requires Tokio)" | no (tokio or async-std) | yes | not checked |
| Sans-IO protocol core | yes (P0) | not stated | not stated | not stated | no | not checked |
| `no_std` core | yes (P1, NFR-10) | not stated | not stated | not stated | n/a | n/a |
| STARTTLS | yes (P0) | yes (`Extension::StartTls`) | yes (RFC 3207 listed) | yes | yes (`starttls()`) | yes |
| STARTTLS response-injection defence (buffer must be empty) | yes (P0) | not stated | not stated | not stated | not stated | not stated |
| Implicit TLS (465) | yes (P0) | not stated on the pages checked | yes (`implicit_tls` in examples) | not stated | yes (`SMTP_SSL`) | not checked |
| Plaintext only to a verified loopback peer | yes (P0) | not stated | not stated | not stated | not stated | not stated |
| PIPELINING | yes (P1) | not in its `Extension` enum | not stated | yes | not stated | yes |
| CHUNKING / BDAT | yes (P2) | not in its `Extension` enum | not stated | not stated | not stated | yes |
| SIZE declared on MAIL and checked before sending | yes (P1) | not stated | not stated | not stated | not stated | yes (SIZE listed) |
| 8BITMIME | yes (P1) | yes | not stated | yes | yes (`BODY=8BITMIME` in `send_message`) | yes |
| SMTPUTF8 / EAI | yes (P2) | yes | not stated | yes | yes (3.5 and later) | yes |
| DSN (RFC 3461) | yes (P2) | not stated | not stated | not stated | raw `mail_options` and `rcpt_options` strings | yes |
| ENHANCEDSTATUSCODES parsed | yes (P0) | not stated | not stated | not stated | not stated (code and text attributes) | not stated |
| AUTH PLAIN | yes (P0) | yes | yes | yes | yes | yes |
| AUTH LOGIN | yes (P1) | yes | yes | yes | yes | yes |
| XOAUTH2 | yes (P2) | yes | yes | yes | through custom `auth()` | yes |
| OAUTHBEARER | P3 | no (not in `Mechanism`) | not listed | not listed | through custom `auth()` | yes |
| SCRAM-SHA-256 | yes (P2) | no (not in `Mechanism`) | not listed | not listed | through custom `auth()` | yes (and -PLUS) |
| CRAM-MD5, DIGEST-MD5 | refused by design | no (not in `Mechanism`) | yes (both) | not listed | CRAM-MD5 yes | yes |
| Mechanism choice | caller allowlist order | caller-set list | automatic, "from most secure to least secure" | not stated | fixed order (CRAM-MD5, PLAIN, LOGIN) filtered by what the server advertises | not checked |
| Temporary vs permanent classification | every error, plus `possibly_delivered` (P0) | `is_transient`, `is_permanent` | not stated | not stated | exception classes by stage, with codes | not checked |
| Per-recipient outcomes | yes (P0) | not stated | not stated | not stated | yes (`SMTPRecipientsRefused.recipients`) | not checked |
| Timeouts per RFC 5321 stage | yes (P0) | one `timeout(Option<Duration>)` | not stated | not stated | one socket `timeout` | not checked |
| Connection reuse | yes (P1) | yes (`pool` feature) | not stated | not stated | yes (one `SMTP` object, many sends) | not checked |
| Connection pool | yes (P2) | yes (`PoolConfig`) | not stated | not stated | not stated | not checked |
| Pacing hook for host limits | yes (P1) | not stated | not stated | not stated | not stated | not stated |
| Job payload form (versioned, checksummed) | yes (P1) | not stated | not stated | not stated | not stated | not stated |
| MIME builder | yes (P0) | yes (`builder` feature) | yes (mail-builder) | not stated | yes (`email`) | yes (MimeKit) |
| multipart alternative, mixed, related | yes (P0) | not stated on the pages checked | yes (nested example) | n/a | not checked | not checked |
| Inline images (`cid:`) | yes (P0) | not stated on the pages checked | yes (`inline`, `cid:` example) | n/a | not checked | not checked |
| RFC 2047 encoded words | yes (P0) | not stated on the pages checked | not stated (examples use non-ASCII) | n/a | not checked | not checked |
| RFC 2231 file names | yes (P0) | not stated | not stated | n/a | not checked | not checked |
| Header injection refused (CR/LF is an error, never stripped) | yes (P0) | not stated | not stated | n/a | `verify_generated_headers` (3.13, default on) raises instead of writing a header that would parse as several; CVE-2024-6923 fixed | not stated |
| Dot-stuffing correct across chunk boundaries, proven by split tests | yes (P0) | fixed in 0.9.6 and 0.10.0-rc.3 (RUSTSEC-2021-0069) | not stated | not stated | not stated | not stated |
| DKIM RSA-SHA256 | yes (P0) | yes (`DkimSigningAlgorithm::Rsa`) | yes | not stated | no (third-party dkimpy) | through MimeKit.Cryptography (details not checked) |
| DKIM Ed25519-SHA256 | yes (P0) | yes (`DkimSigningAlgorithm::Ed25519`) | yes | not stated | no | not checked |
| DKIM RSA-SHA1 | refused (RFC 8301) | not stated | yes | not stated | no | not checked |
| DKIM oversigning, no `l=` by construction | yes (P0) | not stated | not stated | n/a | n/a | not checked |
| DKIM DNS record generation | yes (P2) | not stated | not stated | n/a | n/a | not checked |
| Test server with fault injection | yes (P1) | not stated | not stated | not stated | not in the standard library | not stated |
| LMTP | P3 | not stated | not stated | not stated | yes (`LMTP`) | not checked |
| sendmail binary transport | refused by design | yes (`sendmail-transport`; RUSTSEC-2020-0069 history) | not stated | not stated | no | not checked |
| Minimum Rust | 1.85 | 1.74 | not checked | not checked | n/a | n/a |

---

## 10. Security

### 10.1 Threat table

Costs are per message unless stated, **[est.]** until measured at 0.6 and 0.7. Every row has an attack test that must fail to get through (standard 2.4).

| Id | Threat | Defence | Attack test | Cost |
|---|---|---|---|---|
| T-1 | Header injection: a user's name or subject carrying `\r\nBcc: victim@x` adds recipients or headers | every setter calls `check_header_value`; CR, LF, NUL (and C0/C1 controls except TAB in unstructured text) are errors naming the field and position; nothing is stripped | for every field (From name, To name, Subject, custom value, file name, Content-ID, Message-ID, References, List-Unsubscribe): inputs with `\r`, `\n`, `\r\n`, `\0`, `\u{85}`, `\u{2028}` are refused; property test: no builder output has more header lines than the builder was given | 1 scan of each value, about 0.3 ns per byte **[est.]** |
| T-2 | Envelope command injection: an address with CRLF or `>` turns `RCPT TO:<a>` into extra commands | addresses validated by grammar (no CR, LF, `<`, `>`, unquoted spaces); every formatted command is re-scanned for CR or LF before its final CRLF (defence in depth); xtext encoding for DSN values | addresses such as `a@b>\r\nRCPT TO:<c@d`, `"a\r\n"@b`, `a@b\0c` refused; command formatter fuzzed with arbitrary `Address` bytes forced through the Tier 3 path | 1 scan per command, under 10 ns |
| T-3 | Dot-stuffing failure ends DATA early and smuggles commands (RUSTSEC-2021-0069: a period after `CRLF CRLF` was missed) | streaming `DotStuffer` keeps line-start state across chunks; tests at every split point; BDAT avoids stuffing entirely | bodies containing `\r\n.\r\n`, `\r\n\r\n.\r\n`, `.` at body start, `..`, lines of only `.`, all split at every byte; the `TestServer` must receive exactly the original body | none beyond the scan |
| T-4 | SMTP smuggling: bare LF or CR sequences (`\n.\n`, `\r.\r`) that a server treats as end-of-data (CVE-2023-51764, 51765, 51766) | the builder emits CRLF only; `body()` and `PreparedMessage::from_raw` refuse bare CR and bare LF; the client therefore never sends an ambiguous end-of-data candidate | messages with `\n.\n`, `\r.\r`, `\r\n.\n`, `\n.\r\n` refused before any byte is written | 1 scan |
| T-5 | STARTTLS stripping: a path attacker removes `250-STARTTLS` | `Security::StartTls` requires the extension; absence ends the session, no fallback; classified temporary with `security_event` | `Fault::OmitStartTls`: no AUTH and no MAIL is ever sent; the error is `StartTlsUnavailable` | none |
| T-6 | STARTTLS response injection: plaintext replies queued after `220` are read as if they came over TLS (NO STARTTLS, USENIX Security 2021) | `receive` stops after the 220; the driver checks the buffer is empty and that no further plaintext byte is pending before the handshake; capabilities discarded and EHLO resent after TLS | `Fault::InjectAfterStartTls(b"250-AUTH PLAIN\r\n250 OK\r\n")` causes `StartTlsInjection`; no injected capability is ever used | none |
| T-7 | STARTTLS command injection on our side (pipelining a command after STARTTLS that would be executed in plaintext) | STARTTLS is always the last command of its group; nothing is queued until `tls_established` | state-machine test: no output after STARTTLS until `tls_established` | none |
| T-8 | Credentials sent in plaintext | session refuses AUTH unless secure or loopback-plaintext opt-in with a verified loopback peer | `Security::StartTls` with a server that never offers STARTTLS: no AUTH line; `PlaintextLoopback` to a non-loopback peer (DNS answer for `localhost` pointing elsewhere, simulated) is refused before connect completes | none |
| T-9 | Credential leakage through `Debug`, errors, transcripts, logs | `Secret` redacts; AUTH payloads redacted in transcripts; errors carry no reply bytes from AUTH exchanges except the code | format every type holding a secret with `{:?}` and `{}` and search the output for the secret; transcript tests | none |
| T-10 | Authentication downgrade: server or attacker offers only a weaker mechanism | caller allowlist; no automatic fallback outside it; under TLS an attacker cannot alter the list | server offering only LOGIN when the allowlist is `[ScramSha256]` gives `AuthUnavailable` | none |
| T-11 | Certificate validation bypass or wrong name | tls-net verification on by default; server name is the configured host, never the EHLO greeting; disabling verification is a `dangerous_` method refused for non-loopback hosts in release builds (O-19) | self-signed and wrong-name fixture certificates fail with `Tls(CertificateRejected)`, permanent | handshake cost only |
| T-12 | Hostile server reply flood (endless continuation lines, huge lines) exhausts memory | `ReplyLimits` checked per byte before storing; the session closes on excess | `Fault::OversizedReply`, a 10 MiB line, 100,000 continuation lines: memory stays under the configured budget (counting allocator) | none |
| T-13 | Slow server (slow drip of reply bytes) ties up a worker forever | per-stage deadlines measured from the command, not reset per byte; optional total deadline | `Fault::SlowDrip { bytes_per_second: 1 }` ends in `Timeout` at the stage deadline | none |
| T-14 | Desynchronised replies (extra replies, replies before commands) mislead the client in pipelining | replies matched by count and by class: a reply with no command outstanding, or one whose class cannot answer its command (250 to DATA, 354 to MAIL or to the end of data, any 1yz), is `Protocol(UnexpectedReply)` and closes the session (D-096) | `Fault::ExtraReply` at EHLO, MAIL, RCPT, DATA, and the end of data: the session closes; no message is reported delivered that the server did not take; transcripts for 250 to DATA and 354 to MAIL and to the end of data | one comparison per reply |
| T-15 | MIME boundary collision lets attachment content forge parts | boundaries start with `=_` (impossible in QP and base64 output) plus 160 random bits; 7bit and 8bit parts scanned and the boundary redrawn on a hit | property test with adversarial text containing likely boundaries; injected collision with a fixed random source forces a redraw | 1 scan of 7bit/8bit parts |
| T-16 | Predictable Message-ID or boundary enables forging replies or parts | OS CSPRNG (`mod_rand::tier3`); failure of the source is an error, never a fallback to weaker randomness | random-source failure injected through `build_with`: build fails with `Random` | 1 system call per message for 36 bytes, about 1 µs **[est.]** |
| T-17 | Host name and internal topology leaked in Message-ID or EHLO | Message-ID uses the From domain; EHLO uses a configured name or the local socket's address literal, never the machine name | golden tests: no output contains the machine host name | none |
| T-18 | Duplicate delivery after an ambiguous failure (RFC 1047) | `possibly_delivered` flag; the same bytes and Message-ID on retry; RFC 5321 end-of-data timeout (10 min) by default | `Fault::CloseAfterDataEnd`: error is temporary with `possibly_delivered`; a retry sends identical bytes | none |
| T-19 | DKIM content appended under a valid signature (`l=`) | `l=` never emitted | signature header parsed in tests: no `l=` tag ever | none |
| T-20 | DKIM header addition (a second From or Subject added later passes verification) | oversigning of From, To, Cc, Subject, Date, Reply-To, Message-ID | verify with the reference verifier after adding a second Subject: verification fails | about 7 extra header-name hashes, under 1 µs |
| T-21 | Weak DKIM keys or algorithms | RSA under 2048 refused always (D-066); `rsa-sha1` never produced; Ed25519 offered | key-size tests at 1023, 1024, 2047, 2048, 4096, 4098 bits (OpenSSL cannot make 4097, D-071) | none |
| T-22 | DKIM private key exposure | keys held in crypt-io types that wipe on drop; optional key-vault handles; `Debug` redacts; keys never in errors | format tests; drop test with a key built from a known seed (checked through crypt-io's own tests) | none |
| T-23 | Encoded-word injection: user text such as `=?utf-8?b?...?=` in a Subject is decoded by readers into something else | unstructured text containing encoded-word syntax is itself encoded, so readers show it literally | a Subject of `=?utf-8?q?Bank_alert?=` round-trips through a reference parser to the same literal text | 1 scan |
| T-24 | Attachment file name path traversal or control characters (`../../.bashrc`, `\x1b[...`) | file names refused if they contain `/`, `\`, control characters, or are empty; length at most 255 octets | traversal and control-character names refused | 1 scan |
| T-25 | Display-name spoofing in From (`"support@bank.com" <evil@x>`) when display names come from users | `MessageBuilder::refuse_address_like_display_names`: a display name with `@` in From, Sender, Reply-To, To, or Cc is refused (off by default, D-097); documented: never put untrusted text in From display names | the policy refuses each field and is off by default | 1 scan |
| T-26 | Resource exhaustion by huge or many attachments, deep nesting | `MessageLimits` checked before allocation and encoding; `encoded_len` computed first | 1 GiB attachment, 10,000 parts, depth 100: refused before encoding, memory under budget | none |
| T-27 | Spam cannon: user-controlled recipient lists turn the service into a relay | recipients per message capped (100); `SendGate` caps per hour; documented that applications must not accept arbitrary recipient lists from users | 101 recipients refused; gate refuses beyond the limit under 64 threads (loom and stress) | 30 ns per admission **[est.]** |
| T-28 | Bcc disclosure | Bcc never serialized; envelope only | golden test: no `Bcc` header in any output | none |
| T-29 | Timing leak in SCRAM server-signature check | constant-time comparison (crypt-io `hmac_sha256_check`) | both paths exercised; dudect-style timing check of the comparison, Welch's t under 4.5 on Linux and Windows (D-099) | none |
| T-30 | Terminal or log injection through server reply text | `text_lossy` replaces non-printable bytes; `Observer` receives codes only | reply text with ESC sequences and CR shows as `?` | 1 scan of kept text |
| T-31 | RSA signing timing side channel (the `rsa` crate's RUSTSEC-2023-0071, "no patched versions") | crypt-io's RSA signing backend chosen to be constant-time with blinding (`aws-lc-rs`, O-1); DKIM signing also happens off the request path, so timing is not observable per request | `cargo audit` and `cargo deny` must pass without an ignore for RUSTSEC-2023-0071 | none at runtime |
| T-32 | Downgrade from implicit TLS or STARTTLS to plaintext by configuration mistake (`PlaintextLoopback` aimed at a remote relay) | plaintext requires both a loopback host literal or `localhost` **and** a loopback peer address | `PlaintextLoopback` with host `mail.example.com` refused at `build`; with `localhost` resolving to a non-loopback address refused at connect | none |
| T-33 | Corrupted or tampered job payload sends a different message | `PreparedMessage` CRC-32C, version, and budgets checked before use; task-io's `Sealer` encrypts payloads at rest (password-reset links are secrets) | flip every bit of a sample payload: every flip is refused | CRC at about 8 GB/s **[est.]** |
| T-34 | Password-reset links and tokens exposed in transcripts or the dead-letter queue | transcripts omit bodies by default; docs require task-io's encryption at rest for mail jobs | transcript test: body absent unless enabled | none |
| T-35 | Unicode tricks in Subject and display names (bidirectional overrides) | U+202A to U+202E and U+2066 to U+2069 refused in the Subject and display names unless `MessageBuilder::allow_bidi_controls` (on by default, D-097); right-to-left text and the RLM and LRM marks pass | every override and isolate refused in Subject and Cc; allowed with the option; Hebrew text, RLM, and LRM pass | 1 scan |
| T-36 | Over-long header lines split or truncated by receivers, creating a different header set | hard 998 limit; folding only at whitespace; refusal when impossible | 2,000-octet unbreakable value refused | none |

### 10.2 Defences that make classes of failure impossible

- **One gate for header values.** Every setter goes through `check_header_value`; there is no other path into the header list, so a new header type cannot forget the check.
- **Owned, validated types.** `Address`, `Mailbox`, `HeaderName`, `ContentType` can only be constructed through validating functions; the serializer accepts only these types.
- **Commands from types.** Commands are formatted from validated types into a buffer that is scanned before sending; no `format!` with caller strings anywhere in `proto`.
- **No plaintext AUTH by construction.** The session's AUTH state is unreachable unless secure or loopback-confirmed.
- **No fallback paths.** There is no code that sends after a TLS failure.

### 10.3 Defence ideas per version (hypothesis, method, expected cost)

| Version | Idea | Hypothesis | Method | Expected cost |
|---|---|---|---|---|
| 0.3 | Command shadow check | a formatter bug that emits two commands is caught before the socket | count CRLF in each output group and compare with the number of commands queued | under 10 ns per group |
| 0.4 | Pinned relay identity | an operator can pin the relay's certificate public key in addition to normal verification | tls-net option, checked after verification (never instead of it, RFC 8314) | one hash per handshake |
| 0.5 | Self-verifying DKIM | a signing bug (wrong canonicalization) is caught before the message leaves | verify our own signature with an internal verifier in debug and test builds, and optionally in production for one message in N | about 1 hash pass per checked message |
| 0.6 | Duplicate-suppression hint | receivers dedupe on Message-ID; a stable id per idempotency key makes this work across job retries even when the payload is rebuilt | `message_id_from_key(key, domain)`: keyed BLAKE3 of the idempotency key | one hash |
| 0.7 | Outbound content budget per recipient domain (done: `DomainLimit`, D-098) | a compromised account sending to one domain is noticed early | a recipient budget per domain in a bounded table, combined with `HourlyLimit` as a gate pair | one lock and one hash per admission **[est.]** |
| 0.8 | Reply anomaly score | a man in the middle changes reply timing and text | record greeting banner and capability set per server; a change raises a security event | one comparison per connect |

---

## 11. Performance

### 11.1 Targets

| Operation | Target | Competitor baseline to beat by 20% | Method |
|---|---|---|---|
| Build and serialize a verification email (text plus HTML, about 2 KiB) | at most 5 µs, at most 8 allocations **[est.]** | lettre `Message::builder` + `formatted()`, mail-builder `MessageBuilder::write_to_vec` | criterion, counting allocator |
| Serialize a message with a 1 MiB attachment | at least 1.5 GB/s of attachment input **[est.]** | lettre, mail-builder | criterion |
| base64 encoding (76-character lines) | at least 2 GB/s **[est.]** | mail-builder's base64 ("12-bit lookup table") | criterion |
| quoted-printable encoding | at least 800 MB/s **[est.]** | lettre, mail-builder | criterion |
| Header value check (`check_header_value`) | at least 4 GB/s **[est.]** | none (no competitor exposes it) | criterion |
| Reply parsing, single line | at most 50 ns, 0 alloc **[est.]** | lettre's response parser, async-smtp's | criterion |
| EHLO parsing, 10 lines | at most 400 ns **[est.]** | as above | criterion |
| Dot-stuffing | at least 4 GB/s on typical text **[est.]** | lettre `ClientCodec` | criterion |
| DKIM relaxed body canonicalization (before hashing) | at least 2 GB/s **[est.]** | lettre `dkim`, mail-auth | criterion |
| DKIM Ed25519 signature, 10 KiB message | at most 40 µs **[est.]** | lettre `dkim_sign`, mail-auth | criterion |
| DKIM RSA-2048 signature, 10 KiB message | at most 1.6 ms **[est.]** | as above | criterion |
| 1,000 messages over one connection, loopback, 0 ms added RTT | at least 20% less wall time than lettre sync `SmtpTransport` (NFR-5) | lettre | criterion with the `TestServer` |
| same at 1 ms and 10 ms simulated RTT | at least 20% less (expected about 50% with PIPELINING and about 75% with CHUNKING **[est.]**) | lettre | `TestServer` with `Fault::DelayAt` on every reply |
| Session memory | at most 16 KiB **[est.]** | lettre (measured, not claimed) | counting allocator |
| `HourlyLimit::admit` uncontended | at most 30 ns **[est.]** | throttle-net `Throttle::try_acquire` (reference only) | criterion |

### 11.2 Benchmarks

`benches/` holds: `build.rs` (message build and serialize, three message shapes), `encode.rs` (base64, QP, header check, encoded words), `proto.rs` (reply parsing, command formatting, dot-stuffing), `dkim.rs` (canonicalization, hashing, both signatures), `send.rs` (end-to-end over loopback at 0, 1, 10 ms RTT, with and without PIPELINING and CHUNKING), `gate.rs`. Competitor benchmarks live in the `smtp-net-bench` repository (D-035), with the competitor versions pinned and recorded in `docs/PERFORMANCE.md` alongside hardware, OS, Rust version, and the date. Baselines are committed; a regression over 5% blocks the change.

### 11.3 How the 20% is achieved

1. Round trips (7.6): PIPELINING halves them; CHUNKING plus PIPELINING quarters them for single-recipient mail.
2. One write per command group and large body writes (6.3).
3. Serialization straight into the socket buffer from the message tree, without an intermediate formatted copy, when no DKIM signer is configured (signing needs the bytes first, so signed mail is serialized once into the `PreparedMessage`). (smtp-net's `send` of an unprepared message uses `write_to` straight into the session's body path; whether lettre formats into an intermediate buffer first is to be confirmed by profiling at 0.6).
4. SWAR scanning (eight bytes at a time with `u64` arithmetic, no `unsafe`, no third-party crate) for CR, LF, `.`, and non-ASCII detection.
5. Connection reuse and the pool, so batches pay one handshake.

If a target is missed, the 0.6 roadmap entry records the measured number and the reason, and the change that fixes it carries the benchmark.

---

## 12. Testing plan

### 12.1 Unit tests

Every function, every `Ok` and `Err` path, at the bottom of each file, named `test_<subject>_<condition>_<expected>` (for example `test_reply_parser_mismatched_continuation_code_refused`, `test_dot_stuffer_dot_after_double_crlf_split_at_every_byte_stuffed`).

### 12.2 Conversation transcripts

`tests/transcripts/*.txt`, each a full conversation run by `ScriptedServer`, whole and split at every byte of both directions. Required set: plain loopback send; EHLO refused then HELO; STARTTLS then EHLO; implicit TLS; AUTH PLAIN success, 535, 454, 432, 534, 538; AUTH LOGIN; XOAUTH2 success and JSON failure; SCRAM success, wrong server signature, server nonce not extending ours, iteration count 4,095 and 1,000,001; PIPELINING with one recipient accepted and one rejected; all rejected with DATA 354 (lone dot); all rejected with DATA 503; RCPT 452 too many recipients and the deferred transaction; SIZE exceeded locally; 8BITMIME needed and absent; SMTPUTF8 needed and absent; DSN `IfSupported` and `Required`; BDAT success; BDAT failure then RSET; 421 at greeting, after EHLO, after MAIL, after DATA, after end-of-data; end-of-data 451, 554; QUIT with 221 and with EOF; connection reuse with three messages; reuse after the server closed the idle connection.

### 12.3 Property tests (proptest)

- Builder output parsed by the reference MIME parser (in `smtp-net-bench` (D-035)) gives back the same headers (decoded), parts, and bytes, for arbitrary Unicode text, binary attachments, and part trees within limits.
- No builder output contains a bare CR or bare LF, a line over 998 octets, or a `Bcc` header.
- Dot-stuffing then unstuffing returns the original body for every input and every split.
- Reply parser never panics, never exceeds its budget, and gives the same result for every split.
- `encode_word` output decodes to the input; every word is at most 75 characters.
- QP and base64 round-trip; QP lines at most 76.
- `PreparedMessage` encode then decode is the identity; any single-byte change is refused.
- `HourlyLimit` never admits more than its limit in any 60-minute window under arbitrary interleavings (with a manual clock).
- DKIM: signatures from smtp-net verify with the reference verifier for arbitrary messages; canonicalization is the same for every split.

### 12.4 Fuzz targets (cargo-fuzz, corpus outside the repository)

`fuzz_reply` (ReplyParser), `fuzz_ehlo` (Capabilities), `fuzz_session_server_bytes` (arbitrary server bytes against a session in each starting state), `fuzz_address` (Address and Mailbox parse), `fuzz_content_type`, `fuzz_header_value` (check and encode), `fuzz_raw_message` (`PreparedMessage::from_raw`), `fuzz_prepared_decode`, `fuzz_dkim_canon` (header and body canonicalizers), `fuzz_sasl_challenges` (SCRAM server-first and server-final, XOAUTH2 error JSON), `fuzz_transcript` (the test transcript parser). Each runs at least 1 hour per release from 0.7, and 24 hours before 1.0.

### 12.5 Conformance vectors

- RFC 6376 Appendix A example and the empty-body hashes of 7.10.
- RFC 8463 Appendix A (Ed25519 and RSA signed example).
- RFC 2047 and RFC 2231 examples.
- RFC 4616 and RFC 7677 section 3 (SCRAM-SHA-256 example exchange) as SASL vectors.
- Google's XOAUTH2 documented example string.
- Independent verification: every DKIM test message is verified in CI by two independent verifiers in `smtp-net-bench` (D-035) (one Rust, one Python dkimpy) so a shared misreading of the RFC by smtp-net and one verifier is caught.

### 12.6 Counting-allocator tests

Reply parsing, command formatting, dot-stuffing, base64, QP, header checks, `write_to` into a pre-sized buffer, DKIM canonicalization, `HourlyLimit::admit`, and a full `Session` transaction after `new` (zero allocations on the session side).

### 12.7 loom

`HourlyLimit` (bucket roll-over and admission race), `Pool` (checkout, return, drop of a failed client, idle expiry on checkout).

### 12.8 Interop and integration

- `tests/` integration tests against `TestServer` (plaintext, STARTTLS, implicit TLS with fixture certificates).
- CI interop job on Linux with containers: Mailpit (catcher), Postfix with Dovecot SASL (offers SCRAM-SHA-256 **[est.: depends on the Dovecot configuration chosen]**), Exim 4.97.1 or later (cPanel's MTA family). Each run sends every message shape through every security mode the server supports and checks the received bytes.
- Field tests at 0.8: the cPanel host's Exim on `127.0.0.1`, Microsoft 365 submission (XOAUTH2 when basic authentication is gone), Gmail submission (app password and XOAUTH2); DKIM results checked in the receiving mailbox's `Authentication-Results` header.

### 12.9 Soak

24 hours, one message every 10 ms through a pool of 4 connections to `TestServer` with faults injected at a 1% rate; checks: resident memory flat after warm-up, no file descriptor or handle growth, every message either delivered or reported with the right disposition.

### 12.10 Edge cases (exhaustive list)

**Replies**
1. Empty input to `receive`.
2. One byte at a time for every transcript.
3. Reply code alone with CRLF (`250\r\n`).
4. Reply code with space and empty text (`250 \r\n`).
5. Code `199`, `600`, `2a0`, `25`, `2500`.
6. Continuation with a different code (`250-a\r\n251 b\r\n`).
7. Continuation then EOF.
8. Line of exactly 1,000 octets (limit) and 1,001 (refused); custom limit 512 and 513.
9. 64 lines (limit) and 65 (refused).
10. Total 8,192 octets and 8,193.
11. Bare LF line ending; bare CR inside text; NUL inside text.
12. Enhanced code present but not advertised (kept as text).
13. Enhanced code class not matching reply class (`250 5.0.0 ok`): ignored.
14. Enhanced code with four-digit subject (`5.1000.1`): ignored.
15. Reply arriving with no outstanding command.
16. Two replies in one read after a pipelined group; replies split across reads in every position.
17. UTF-8 and binary bytes in reply text.
18. 421 in the middle of a pipelined group.

**Greeting and EHLO**
19. Greeting 554; greeting 421; greeting delayed to one millisecond before the deadline and one after.
20. Multi-line greeting.
21. EHLO 500 or 502 on loopback (HELO fallback) and on TLS-required sessions (refused).
22. EHLO with no extensions.
23. Duplicate keywords; lowercase keywords; unknown keywords with parameters; 33 unknown keywords (beyond the kept 32: counted, not kept).
24. `SIZE` without value, `SIZE 0`, `SIZE 18446744073709551615`, `SIZE -1`, `SIZE 1e9`.
25. AUTH with no mechanisms; AUTH with 50 mechanisms; `AUTH=PLAIN` legacy form (accepted as an alias **[est.: old servers]**).

**STARTTLS and TLS**
26. STARTTLS advertised, reply 220 with trailing bytes in the same read (injection).
27. Reply 220 split across reads with nothing after it (valid).
28. Reply 454, 501, 500.
29. STARTTLS advertised before TLS but the second EHLO also advertises STARTTLS (ignored, never sent twice).
30. Second EHLO removes AUTH (no AUTH possible: `AuthUnavailable`).
31. TLS handshake EOF; certificate expired; wrong name; self-signed; TLS 1.1 offered only.
32. Implicit TLS to a plaintext server (handshake garbage): permanent `Tls(ProtocolMismatch)`, with an error message that suggests port 587.
33. STARTTLS to an implicit TLS port (server never sends a greeting): greeting timeout, message suggests port 465.

**AUTH**
34. PLAIN initial response that would exceed 12,288 octets: sent after 334.
35. Empty password; password with NUL (refused for PLAIN); user with non-ASCII (UTF-8 allowed for PLAIN).
36. 334 with invalid base64 challenge; 334 with an empty challenge (`334 ` with a trailing space, RFC 4954).
37. Server sends 235 before the exchange is complete (protocol error).
38. Server sends 334 forever (bounded number of steps: 8 for built-ins).
39. XOAUTH2 failure JSON over 1 KiB, invalid JSON, non-UTF-8.
40. SCRAM: server nonce equal to ours, shorter, not starting with ours; salt invalid base64; `i=0`; `i=4096`; `i=1000001`; server-final with `e=` error; server signature one bit off.

**Transactions**
41. One recipient; 100 recipients; 101 (refused locally); 0 (refused).
42. Duplicate recipients in To and Bcc (deduplicated); same local part with different domain case.
43. MAIL 4yz, 5yz; RCPT mixed 2yz, 4yz, 5yz with `RecipientPolicy::Any` and `All`.
44. All RCPT rejected, DATA 354 (lone dot), DATA 503, DATA 554.
45. DATA 354 then connection close before body.
46. Close after the final `.` and before the reply (`possibly_delivered`).
47. End-of-data reply arriving one millisecond before and after the 10-minute deadline (simulated clock).
48. Message exactly at the advertised SIZE; one byte over.
49. Body empty; body of one byte; body without final CRLF; body ending in `.`; body of only `.\r\n`; body with 1,000-octet lines (limit including CRLF) and 1,001.
50. BDAT with body sizes 0, 1, exactly the chunk size, chunk size plus one; BDAT 5yz mid-message then RSET.
51. RCPT 452 after 50 recipients: remaining 50 sent in a second transaction; second transaction partially fails.
52. Reuse: second message after 59 s and 61 s idle; server closed the connection silently (EOF on MAIL); server replies 421 to MAIL.
53. 100th and 101st message on one connection (reconnect).
54. `begin` called twice; `body` before `begin`; `end_body` twice (usage errors).

**Addresses**
55. Local part 64 and 65 octets; domain 255 and 256; path 256 and 257.
56. Quoted local parts with spaces, backslash escapes, `@` inside quotes.
57. Dots: leading, trailing, consecutive (refused unquoted).
58. Domain label 63 and 64 octets; label with leading or trailing hyphen; numeric TLD; trailing dot.
59. Address literals `[192.0.2.1]`, `[IPv6:2001:db8::1]` (refused by default, accepted when enabled).
60. Non-ASCII local part (SMTPUTF8 only); non-ASCII domain with and without SMTPUTF8 (O-11).
61. Display names with quotes, commas, semicolons, `@`, non-ASCII, empty string, only spaces.
62. Comments `(x)` and obsolete route syntax `<@a:b@c>` (refused).

**Headers and encoding**
63. Subject empty; 998 octets of ASCII without spaces (cannot fold: refused if over limit with the name); 10,000 octets with spaces (folded); non-ASCII of every UTF-8 length (1 to 4 octets) at every word-split position.
64. Text that looks like an encoded word.
65. Custom header names: empty, 76 and 77 octets, containing `:`, space, non-ASCII, reserved names in every case variant.
66. 100 and 101 custom headers.
67. References with 50 and 51 ids.
68. Message-ID supplied with and without angle brackets, with spaces, with a literal right side.
69. Date at Unix 0, at 2038-01-19T03:14:08Z, at 9999-12-31T23:59:59Z, offsets -1439, +1439, 1440 (refused).

**MIME**
70. Text only, HTML only, both, both plus attachments, both plus inline, inline without HTML (refused), inline with duplicate Content-ID (refused).
71. Attachment of 0 bytes; exactly at the size limit; one byte over (refused before encoding).
72. File names with spaces, quotes, non-ASCII, 255 and 256 octets, `/`, `\`, `..`, NUL, ESC.
73. Content types invalid (`text`, `text/`, `/plain`, parameters with CR).
74. Depth 8 and 9; parts 100 and 101.
75. Text with only CR line endings (refused), mixed LF and CRLF (normalized), trailing spaces before line breaks (QP encodes them).
76. Text lines of exactly 76, 77, 998, 999 octets in QP and 7bit decisions.
77. Text whose lines start with `.` and `From ` in QP.
78. Random source returning the same boundary as content (forced through `build_with`).

**DKIM**
79. Empty body under simple and relaxed (known hashes).
80. Body of only CRLFs; body without final CRLF; whitespace-only lines.
81. Header with folded value; header names in mixed case; duplicate headers (bottom-up selection).
82. Message without From (refused); header block over 64 KiB (refused).
83. Key sizes 1023, 1024 (with and without allow), 2048, 4096, 4097 bits; malformed PEM; encrypted PKCS#8 (refused, with a message telling the operator to decrypt it into key-vault).
84. Selector with dots; domain with uppercase; `i=` outside the domain.
85. Two signers (Ed25519 and RSA) on one message, both verified independently.

**Gate, pool, driver, payload**
86. Gate at limit minus one, limit, limit plus one; bucket roll-over at the minute boundary; clock going backwards (treated as no time passing).
87. Pool with 1 connection and 64 threads; a failing connection removed; idle expiry.
88. Connect to an address list where the first address refuses and the second accepts.
89. `localhost` resolving to `::1` only, to `127.0.0.1` only, and (simulated) to a public address.
90. `PreparedMessage::decode` with empty input, wrong magic, unknown version, truncated at every byte, oversized length fields, flipped bits.
91. Clock jump during a send (monotonic clock required; wall clock used only for headers).
92. Drop of a `Client` in every state (QUIT attempted within 1 s, never blocks longer).

---


## 13. Documentation deliverables

### 13.1 Files

| File | Content | By |
|---|---|---|
| `README.md` | per `README_TEMPLATE.md`; quick start shows `Message::text` with `send_local`, then `Message::html` with `Server::starttls(...).login(...)`, then the task-io handler; feature table; status | every version |
| `docs/API.md` | every public item in the metrics-lib format, several examples per use case (local submission, remote relay, DKIM, job payloads, pacing, custom SASL, sans-IO driver) | 0.2 (design lock), kept current |
| `docs/ARCHITECTURE.md` | 7.1 to 7.15 of this file, kept true to the code | 0.5 |
| `docs/PERFORMANCE.md` | measured numbers, hardware, competitor versions, method | 0.6 |
| `docs/SECURITY.md` | threat model (section 10), each defence with its cost and test | 0.7 |
| `docs/PLATFORM-NOTES.md` | Windows, macOS, Linux notes (certificate stores through tls-net, loopback address behaviour, `localhost` resolution) | 0.8 |
| `docs/DELIVERABILITY.md` | the operator guide of 13.3 | 0.5 |
| `docs/STABILITY-1.0.md` | the 1.0 audit record | 1.0 |
| `CHANGELOG.md` | Keep a Changelog 1.1.0 | every change |
| `docs/release/vX.Y.Z.md` | release notes, past tense | every version |
| `examples/` | `send_local.rs`, `send_starttls.rs`, `send_with_dkim.rs`, `prepared_job.rs`, `sans_io_driver.rs`, `hourly_limit.rs`, `dkim_dns_record.rs` | as features land |

### 13.2 Rustdoc

Crate docs start with Tier 1. Every public item has a runnable example; examples that need a server use `TestServer` (feature `testing`, enabled for docs.rs) so they run in `cargo test --doc`.

### 13.3 Operator guide content (`docs/DELIVERABILITY.md`)

A correct client still lands in spam if DNS is wrong. The guide covers:

1. **What a 250 means.** The submission server accepted the message; it has not been delivered. On cPanel, mail over the hourly limit is accepted and then queued or dropped (7.13), so pacing must happen in the client.
2. **SPF** (RFC 7208): a TXT record at the sending domain listing the hosts that send for it, for example `v=spf1 a mx ip4:203.0.113.10 -all` (`~all` while testing). One SPF record per domain; at most 10 DNS-querying mechanisms.
3. **DKIM** (RFC 6376, 8463): TXT at `<selector>._domainkey.<domain>` from `DkimKey::dns_record()`. Ed25519 and RSA under different selectors (RFC 8463 section 6: one key record per selector). RSA 2048-bit records exceed 255 octets and must be split into several strings inside one TXT record. Gmail requires at least 1024-bit keys and recommends 2048. Key rotation: publish the new selector, switch the signer, keep the old record for a week **[est.]**, then remove it.
4. **cPanel's own DKIM.** cPanel's Email Deliverability tool can create DKIM keys and Exim can sign outgoing mail itself **[unverified for the target host]**. If Exim signs, smtp-net signing is optional for the local path (O-8).
5. **DMARC** (RFC 7489): TXT at `_dmarc.<domain>`, start with `v=DMARC1; p=none; rua=mailto:dmarc@<domain>`, move to `quarantine` then `reject` once reports show SPF or DKIM alignment for all legitimate mail. Alignment means the From domain matches the DKIM `d=` (or the SPF domain).
6. **PTR** (forward-confirmed reverse DNS) for the sending IP, required by Gmail for all senders.
7. **Bulk sender rules** (Gmail, since 2024-02-01, more than 5,000 messages a day to Gmail): SPF and DKIM and DMARC, alignment, one-click unsubscribe (RFC 8058) for subscribed and marketing mail, spam rate below 0.3% (recommended below 0.1%). Transactional mail (verification, reset) does not need List-Unsubscribe, but alerts and newsletters do.
8. **Bounce handling basics.** A synchronous refusal comes back as an smtp-net error; most delivery failures arrive later as a bounce message (a DSN, RFC 3464) sent to the envelope return path. Use a dedicated return path mailbox (`Envelope::return_path`), consider VERP-style addresses (`bounces+<token>@domain`, FR-55) so a bounce identifies the message, treat `5.1.1` (bad mailbox) as permanent and stop sending to that address (a suppression list in the application's users core), and never retry a permanent failure. Reading the bounce mailbox is out of scope (4.2).
9. **Rate limits.** Configure `HourlyLimit` below the host's cap, counting the same unit the host counts (O-21), with headroom for operator mail.
10. **MTA-STS, TLS-RPT, DANE, BIMI**: receiving-side or brand features; listed for completeness, not needed for submission.

---


## 14. Version roadmap, release routine, definition of done

- The version roadmap, with each version's content, exit criteria, and dependencies, is [`ROADMAP.md`](./ROADMAP.md).
- The release routine: finish the version (every roadmap item, version bumped everywhere, `CHANGELOG.md` rolled, `docs/release/vX.Y.Z.md` written); the local gate on Windows and Linux, stable and 1.85; a feature branch and a pull request; green CI on every platform; squash-merge; tag `vX.Y.Z`; `gh release create vX.Y.Z --title "vX.Y.Z - <Title>" --notes-file docs/release/vX.Y.Z.md`, pre-release for 0.x; `cargo doc` with default and all features under `RUSTDOCFLAGS=-D warnings`; `cargo publish`; check crates.io and docs.rs. From 0.3 the crate depends on published first-party crates, so a release waits for every dependency it needs to be on crates.io rather than switching to `path` dependencies.
- The definition of done is [`DIRECTIVES.md`](./DIRECTIVES.md) section 3, plus: every API item the roadmap assigns to the version exists with rustdoc, a runnable example, and tests for every `Ok` and `Err` path; transcripts run whole and split at every byte; property tests for every invariant in 12.3 that the version touches; a fuzz target for every new parser; every threat row assigned to the version has a passing attack test; counting-allocator tests for every "0 alloc" cost the version ships; benchmarks for every new hot path; `cargo tree -e normal` shows no third-party crate outside crypt-io's and tls-net's accepted dependencies; and the decision log is updated for every decision made during the work.

## 17. Open decisions and their answers

Every question open at the design lock, with the answer adopted in 0.2.0 and the decision that records it. None is still open. A row marked **revisit** is checked again at the version named.

| Id | Question | Answer | Decision |
|---|---|---|---|
| O-1 | Where and with what backend does DKIM get Ed25519 and RSA signing? | a crypt-io `sign` module behind features `sign-ed25519` and `sign-rsa`, over aws-lc-rs (the library tls-net uses, so a binary carries one C crypto library); decided by James on 2026-10-21 | D-006 |
| O-2 | XOAUTH2 in 1.0? | yes, P2 in 0.5 | D-007 |
| O-3 | Publish to claim the name? | yes: 0.2.0 is the first crates.io release | D-008 |
| O-4 | First-run path on the cPanel host | both: `Server::local()` (port 25, no AUTH) and port 587 with AUTH over verified-loopback plaintext; the host check itself is run with James at the 0.8 field test | D-009, D-033 |
| O-5 | Default timeouts | RFC 5321 values; `Timeouts::local()` for `Server::local()` | D-010 |
| O-6 | Default EHLO name | the local socket's address literal; an FQDN through `client_name`; never the machine host name | D-011 |
| O-7 | Default transfer encoding | 7-bit; `allow_8bit(true)` opts in | D-012 |
| O-8 | Who DKIM-signs on the cPanel host | Exim when the host already signs; smtp-net signing ships at 0.5 regardless | D-013 |
| O-9 | Where the RFC 5322, 2045, 2047, 2231 grammar lives | parse-net 0.9 (published); no private grammar module | D-014 |
| O-10 | Where base64 and quoted-printable come from | private in smtp-net until encode-lib publishes; then re-exports. RFC 2047 words in the Q form through parse-net (**revisit** at 0.9 for the B form) | D-015 |
| O-11 | Internationalized domains without SMTPUTF8 | refused until unicode-lang offers IDNA; A-labels accepted | D-016 |
| O-12 | SCRAM credentials with non-ASCII characters | ASCII only until SASLprep or OpaqueString exists | D-017 |
| O-13 | Own gate or throttle-net | own `SendGate` and `HourlyLimit` | D-018 |
| O-14 | Default recipient policy | `RecipientPolicy::Any` | D-019 |
| O-15 | Reply line budget | 1,000 octets by default, configurable | D-020 |
| O-16 | A `sendmail` transport | never | D-021 |
| O-17 | An async driver | not in this crate | D-022 |
| O-18 | `testing` under semantic versioning | yes from 1.0 | D-023 |
| O-19 | Disabling certificate verification | loopback hosts only, or with a second explicit flag; the same rule in every build profile | D-024 |
| O-20 | Default features | `std` and `client` now; `tls` joins the defaults in the release that adds tls-net | D-025 |
| O-21 | What cPanel counts toward the hourly cap | configurable `CountUnit`, default `Recipients`; per process (**revisit** at the 0.8 field test) | D-027 |
| O-22 | CRC-32C private or shared | private for 0.4 | D-028 |
| O-23 | Does `send` sign automatically | yes, unless the message is already a `PreparedMessage` | D-029 |
| O-24 | `Auto-Submitted` in Tier 1 by default | no; a builder option (**revisit** after the 0.8 field test) | D-030 |

## 18. References

### 18.1 RFCs and specifications

- RFC 5321, Simple Mail Transfer Protocol (4.2.1 reply classes, 4.5.2 transparency, 4.5.3.1 size limits, 4.5.3.2 timeouts): https://www.rfc-editor.org/rfc/rfc5321.html
- RFC 5322, Internet Message Format: https://www.rfc-editor.org/rfc/rfc5322.html
- RFC 6409, Message Submission for Mail: https://www.rfc-editor.org/rfc/rfc6409.html
- RFC 8314, Cleartext Considered Obsolete (implicit TLS for submission): https://www.rfc-editor.org/rfc/rfc8314.html
- RFC 3207, SMTP Service Extension for Secure SMTP over TLS: https://www.rfc-editor.org/rfc/rfc3207.html
- RFC 2920, SMTP Service Extension for Command Pipelining: https://www.rfc-editor.org/rfc/rfc2920.html
- RFC 3030, SMTP Service Extensions for Transmission of Large and Binary MIME Messages (CHUNKING, BINARYMIME): https://www.rfc-editor.org/rfc/rfc3030.html
- RFC 1870, SMTP Service Extension for Message Size Declaration: https://www.rfc-editor.org/rfc/rfc1870.html
- RFC 6152, SMTP Service Extension for 8-bit MIME Transport: https://www.rfc-editor.org/rfc/rfc6152.html
- RFC 6531, SMTP Extension for Internationalized Email: https://www.rfc-editor.org/rfc/rfc6531.html
- RFC 6532, Internationalized Email Headers: https://www.rfc-editor.org/rfc/rfc6532.html
- RFC 3461, SMTP Service Extension for Delivery Status Notifications: https://www.rfc-editor.org/rfc/rfc3461.html
- RFC 3464, An Extensible Message Format for Delivery Status Notifications: https://www.rfc-editor.org/rfc/rfc3464.html
- RFC 2034, SMTP Service Extension for Returning Enhanced Error Codes: https://www.rfc-editor.org/rfc/rfc2034.html
- RFC 3463, Enhanced Mail System Status Codes: https://www.rfc-editor.org/rfc/rfc3463.html
- RFC 5248, A Registry for SMTP Enhanced Mail System Status Codes: https://www.rfc-editor.org/rfc/rfc5248.html
- RFC 8689, SMTP Require TLS Option: https://www.rfc-editor.org/rfc/rfc8689.html
- RFC 2033, Local Mail Transfer Protocol: https://www.rfc-editor.org/rfc/rfc2033.html
- RFC 1047, Duplicate Messages and SMTP: https://www.rfc-editor.org/rfc/rfc1047.html
- RFC 4954, SMTP Service Extension for Authentication: https://www.rfc-editor.org/rfc/rfc4954.html
- RFC 4616, The PLAIN SASL Mechanism: https://www.rfc-editor.org/rfc/rfc4616.html
- LOGIN mechanism, draft-murchison-sasl-login-00: https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00
- Google XOAUTH2 protocol: https://developers.google.com/workspace/gmail/imap/xoauth2-protocol
- RFC 7628, SASL Mechanisms for OAuth (OAUTHBEARER): https://www.rfc-editor.org/rfc/rfc7628.html
- RFC 5802, SCRAM: https://www.rfc-editor.org/rfc/rfc5802.html
- RFC 7677, SCRAM-SHA-256 and SCRAM-SHA-256-PLUS: https://www.rfc-editor.org/rfc/rfc7677.html
- RFC 9266, Channel Bindings for TLS 1.3 (`tls-exporter`): https://www.rfc-editor.org/rfc/rfc9266.html
- RFC 4013, SASLprep; RFC 8265, PRECIS usernames and passwords: https://www.rfc-editor.org/rfc/rfc4013.html, https://www.rfc-editor.org/rfc/rfc8265.html
- RFC 2195 (CRAM-MD5) and RFC 6331 (DIGEST-MD5 moved to Historic): https://www.rfc-editor.org/rfc/rfc2195.html, https://www.rfc-editor.org/rfc/rfc6331.html
- RFC 2045, 2046, 2047, 2049, MIME: https://www.rfc-editor.org/rfc/rfc2045.html, https://www.rfc-editor.org/rfc/rfc2046.html, https://www.rfc-editor.org/rfc/rfc2047.html, https://www.rfc-editor.org/rfc/rfc2049.html
- RFC 2231, MIME Parameter Value and Encoded Word Extensions: https://www.rfc-editor.org/rfc/rfc2231.html
- RFC 2183, Content-Disposition: https://www.rfc-editor.org/rfc/rfc2183.html
- RFC 2387, multipart/related: https://www.rfc-editor.org/rfc/rfc2387.html
- RFC 2392, Content-ID and Message-ID URLs: https://www.rfc-editor.org/rfc/rfc2392.html
- RFC 2369 (List-* headers) and RFC 8058 (one-click unsubscribe): https://www.rfc-editor.org/rfc/rfc2369.html, https://www.rfc-editor.org/rfc/rfc8058.html
- RFC 3834, Recommendations for Automatic Responses to Electronic Mail: https://www.rfc-editor.org/rfc/rfc3834.html
- RFC 6376, DomainKeys Identified Mail Signatures: https://www.rfc-editor.org/rfc/rfc6376.html
- RFC 8463, A New Cryptographic Signature Method for DKIM (Ed25519-SHA256): https://www.rfc-editor.org/rfc/rfc8463.html
- RFC 8301, Cryptographic Algorithm and Key Usage Update to DKIM: https://www.rfc-editor.org/rfc/rfc8301.html
- RFC 7208 (SPF) and RFC 7489 (DMARC): https://www.rfc-editor.org/rfc/rfc7208.html, https://www.rfc-editor.org/rfc/rfc7489.html
- RFC 5890 to 5893 (IDNA2008), RFC 3492 (Punycode), Unicode UTS 46: https://www.rfc-editor.org/rfc/rfc5890.html, https://www.rfc-editor.org/rfc/rfc3492.html, https://www.unicode.org/reports/tr46/
- RFC 7817, Updated TLS Server Identity Check Procedure for Email-Related Protocols: https://www.rfc-editor.org/rfc/rfc7817.html

### 18.2 Security research and advisories

- NO STARTTLS (Poddebniak, Ising, Böck, Schinzel, USENIX Security 2021): https://nostarttls.secvuln.info/
- RUSTSEC-2021-0069, lettre SMTP command injection in body (dot-stuffing after double CRLF): https://rustsec.org/advisories/RUSTSEC-2021-0069.html
- RUSTSEC-2020-0069, lettre sendmail transport argument injection: https://osv.dev/vulnerability/RUSTSEC-2020-0069
- SMTP smuggling (CVE-2023-51764, 51765, 51766), Exim advisory discussion: https://seclists.org/oss-sec/2023/q4/348
- CVE-2024-6923, CPython email header injection on serialization: https://access.redhat.com/security/cve/CVE-2024-6923
- RUSTSEC-2023-0071, `rsa` crate Marvin timing side channel: https://rustsec.org/advisories/RUSTSEC-2023-0071.html
- RUSTSEC-2025-0007, `ring` maintenance advisory (withdrawn): https://rustsec.org/advisories/RUSTSEC-2025-0007

### 18.3 Competitors and reference implementations

- lettre 0.11.23 crate docs (features, MSRV 1.74): https://docs.rs/lettre/latest/lettre/
- lettre `Mechanism` (PLAIN, LOGIN, XOAUTH2): https://docs.rs/lettre/latest/lettre/transport/smtp/authentication/enum.Mechanism.html
- lettre `Extension` (8BITMIME, SMTPUTF8, STARTTLS, AUTH): https://docs.rs/lettre/latest/lettre/transport/smtp/extension/enum.Extension.html
- lettre SMTP `Error` (`is_transient`, `is_permanent`): https://docs.rs/lettre/latest/lettre/transport/smtp/struct.Error.html
- lettre `DkimSigningAlgorithm` (Rsa, Ed25519): https://docs.rs/lettre/latest/lettre/message/dkim/enum.DkimSigningAlgorithm.html
- mail-send 0.6.2: https://docs.rs/mail-send/latest/mail_send/
- mail-builder 1.0.0: https://docs.rs/mail-builder/latest/mail_builder/
- async-smtp 0.10.2: https://docs.rs/async-smtp/latest/async_smtp/
- Python `smtplib`: https://docs.python.org/3/library/smtplib.html
- Python `email.policy` (`verify_generated_headers`, line length 78): https://docs.python.org/3/library/email.policy.html
- Python `email.utils` (`make_msgid`, `formatdate`, strict address parsing): https://docs.python.org/3/library/email.utils.html
- MailKit (SASL mechanisms and SMTP extensions): https://github.com/jstedfast/MailKit
- aws-lc-rs `signature` module (RSA PKCS#1 SHA-256 and Ed25519 signing; the backend chosen in O-1, X-1): https://docs.rs/aws-lc-rs/latest/aws_lc_rs/signature/index.html
- ring 0.17 `signature` module (the same API shape; the earlier recommendation): https://docs.rs/ring/latest/ring/signature/index.html

### 18.4 Operations

- Gmail email sender guidelines: https://support.google.com/a/answer/81126
- cPanel, How to Set Email Send Limits: https://docs.cpanel.net/knowledge-base/email/how-to-set-email-send-limits/
- cPanel, How to Prevent Email Abuse (default Unlimited): https://docs.cpanel.net/knowledge-base/email/how-to-prevent-email-abuse/
- cPanel, Tweak Settings, Mail: https://docs.cpanel.net/whm/server-configuration/tweak-settings/mail/
- Exchange Online basic-authentication retirement for SMTP AUTH (secondary notice, dates to be checked against Microsoft): https://learn.microsoft.com/en-us/answers/questions/5645009/exchange-online-to-retire-basic-auth-for-client-su

---

## 19. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Client only; no mail server | services send mail; receiving is a different product |
| D-002 | 2026-10-13 | Sans-IO core | testable without a server; same core over any transport |
| D-003 | 2026-10-13 | TLS required by default; plaintext only to localhost by explicit configuration | no silent downgrade |
| D-004 | 2026-10-13 | Retries belong to the job system | smtp-net stays a sender, not a queue |
| D-005 | 2026-11-04 | The full specification (requirements, threat model, API, test plan) replaces the scaffold plan, and the roadmap follows the standard version table: 0.3 core, 0.4 extended, 0.5 feature complete, 0.6 optimisation, 0.7 hardening, 0.8 alpha, 0.9 beta, 1.0 stable. The scaffold's mapping (0.3 submission, 0.4 DKIM) is retired. | one table for every crate in the stack; DKIM needs a crypt-io release, so it belongs with the other crypt-io items in 0.5 |
| D-006 | 2026-11-04 | DKIM signatures (Ed25519-SHA256, RSA-SHA256) and SCRAM's PBKDF2 come from crypt-io (`sign-ed25519`, `sign-rsa`, `kdf-pbkdf2`) over aws-lc-rs; smtp-net calls crypt-io only. 0.5 waits for that crypt-io release. | James's decision of 2026-10-21 (O-1); constant-time RSA with blinding (the RustCrypto `rsa` crate has RUSTSEC-2023-0071 with no fixed version); one C crypto library per binary, shared with tls-net |
| D-007 | 2026-11-04 | XOAUTH2 is P2 and ships in 0.5 (the scaffold plan had it after 1.0) | Microsoft is retiring basic authentication for SMTP client submission in Exchange Online and Gmail relays favour OAuth; the mechanism is small, and token acquisition stays in oauth-net |
| D-008 | 2026-11-04 | The crate name is claimed by publishing 0.2.0 (the design lock). 0.1.0 is tagged in git but not published. | the scaffold was never published; publishing the design lock claims the name with a crate whose docs state its status |
| D-009 | 2026-11-04 | Both first-run paths on a cPanel host: `Server::local()` submits to `127.0.0.1:25` without AUTH; port 587 with AUTH PLAIN over plaintext is allowed only because the peer is verified loopback (`Server::builder("127.0.0.1", Security::PlaintextLoopback).port(587).login(..)`) | whether the host's Exim relays unauthenticated mail from loopback is not known; both stay on the machine and neither crosses the network |
| D-010 | 2026-11-04 | RFC 5321 section 4.5.3.2 timeouts are the default (`Timeouts::rfc5321()`); `Server::local()` uses `Timeouts::local()` | a short end-of-data timeout turns slow content scanning into `possibly_delivered` duplicates (T-18); the job's own deadline bounds the whole send |
| D-011 | 2026-11-04 | The default EHLO argument is the address literal of the local socket (`[127.0.0.1]`, `[IPv6:...]`); `ServerBuilder::client_name` sets an FQDN; the machine host name is never used | RFC 5321 4.1.4 allows a literal; it is always true and discloses nothing the server cannot see (T-17) |
| D-012 | 2026-11-04 | Output is 7-bit clean by default; `MessageBuilder::allow_8bit(true)` permits `8bit` UTF-8 text | the message is built before the server's capabilities are known, and RFC 6376 5.3 recommends 7-bit for signed mail so a relay's 8-to-7 conversion cannot break the signature |
| D-013 | 2026-11-04 | On a cPanel host that already signs with Exim, smtp-net signing is optional for the local path; smtp-net DKIM still ships in 0.5 | two signatures under different selectors are valid but wasteful; the first site will not stay on one host |
| D-014 | 2026-11-04 | The mail grammar comes from parse-net 0.9 (`default-features = false`, plus `alloc`): `mail::parse_addr_spec`, `parse_mailbox`, `check_header_value`, `is_field_name`, `fold`, `encode_words`, `write_mime_param`, `write_msg_id`, `parse_msg_id`, `media`, `MailDate`. smtp-net adds only the RFC 5321 path rules on top (domain literals off by default, LDH labels of at most 63 octets, no trailing dot, path at most 256 octets). No private grammar module. | parse-net is published with this layer; one grammar for the stack; two implementations of the same grammar would disagree somewhere |
| D-015 | 2026-11-04 | base64 and quoted-printable are private modules in smtp-net, exposed as `base64_encode_lines` and `quoted_printable_encode`; they become re-exports when encode-lib publishes, so the API does not change. RFC 2047 words used parse-net's Q form until parse-net 0.9.1 shipped the B form without encode-lib; since smtp-net 0.5.1 the form is chosen per header (D-082). The choice changes length only, never meaning. | encode-lib does not exist; MIME bodies cannot wait for it; the B form is an optimisation, and reimplementing encoded words here would split the grammar |
| D-016 | 2026-11-04 | A non-ASCII domain is refused without SMTPUTF8 (`AddressError::InternationalDomainUnsupported`); U-labels are accepted only for SMTPUTF8 sends; A-labels (`xn--`) are always accepted | a partial IDNA would map names differently from other software ("input two implementations could interpret differently is refused") |
| D-017 | 2026-11-04 | SCRAM-SHA-256 accepts ASCII credentials only; a non-ASCII credential skips SCRAM and the next mechanism in the allowlist is tried | SASLprep (RFC 4013) or OpaqueString (RFC 8265) does not exist in the portfolio; PLAIN carries UTF-8 as it is |
| D-018 | 2026-11-04 | smtp-net defines the one-method `SendGate` trait and ships a lock-free `HourlyLimit`; throttle-net is not a dependency | throttle-net's `std` feature pulls third-party crates and an async waiting surface (3.5) |
| D-019 | 2026-11-04 | `RecipientPolicy::Any` is the default: the message goes to the accepted recipients and the report lists each rejected one with its disposition | service mail almost always has one recipient; for multi-recipient alerts partial delivery is better than none |
| D-020 | 2026-11-04 | Reply lines may be 1,000 octets (configurable); 64 lines and 8 KiB per reply | long reply lines are not ambiguous, and RFC 5321's 512 would fail against servers a user cannot fix; memory stays bounded |
| D-021 | 2026-11-04 | No `sendmail` binary transport, ever | spawning a program with user-influenced arguments caused RUSTSEC-2020-0069; loopback SMTP does the same job without a process boundary |
| D-022 | 2026-11-04 | No async driver in this crate | the sans-IO core works with any driver; an async adapter can live elsewhere |
| D-023 | 2026-11-04 | The `testing` module is covered by semantic versioning from 1.0 | other crates' tests will use `TestServer` |
| D-024 | 2026-11-04 | `ServerBuilder::dangerous_disable_certificate_verification()` is accepted only when the host is a loopback literal or `localhost`; for any other host `build` also needs `allow_insecure_remote(true)`, otherwise `Config(InsecureNotAllowed)`. The rule is the same in debug and release builds. | RFC 8314: a connection whose certificate cannot be validated is not confidential. The specification's `cfg(debug_assertions)` exception is dropped because behaviour must not change between build profiles (NFR-9) |
| D-025 | 2026-11-04 | Default features are `std` and `client`. The STARTTLS and implicit TLS paths are part of `client` and run through the `TlsConnector` seam (D-026); feature `tls` adds tls-net's verified connector and joins the defaults in the release that adds it. A `StartTls` or `ImplicitTls` server without a connector fails at `build` with `Config(TlsConnectorMissing)`; there is no plaintext fallback. | tls-net is not published, and a feature that cannot be built cannot be a default; the TLS logic (state machine, injection check, re-EHLO) does not depend on which engine runs the handshake |
| D-026 | 2026-11-04 | TLS is reached through a `TlsConnector` trait: `fn session(&self, server_name: &str) -> Result<Box<dyn net_io::TlsSession>, TlsSetupError>`. The driver runs the handshake and record layer over net-io's sans-IO `TlsSession` (the seam tls-net already implements for servers), so a client engine needs no second interface. | one seam for the stack; the driver stays independent of rustls; tests can run the whole STARTTLS path with a test engine |
| D-027 | 2026-11-04 | `HourlyLimit` counts `CountUnit::Recipients` by default and is per process | the safer assumption never under-counts; which unit cPanel counts is unconfirmed and is checked at the 0.8 field test |
| D-028 | 2026-11-04 | CRC-32C (Castagnoli, table-driven) is private for 0.4; it moves to a shared crate if one is published first | task-io needs the same function; a shared crate does not exist yet |
| D-029 | 2026-11-04 | `send` signs with the server's DKIM signers when the message is not already prepared; a `PreparedMessage` is never re-signed | a job payload is signed once, before it enters the store, so retries send identical bytes |
| D-030 | 2026-11-04 | Tier 1 constructors do not add `Auto-Submitted`; `MessageBuilder::auto_submitted` does | its effect on filtering at major receivers is not measured; decided again after the field test |
| D-031 | 2026-11-04 | Time comes from `std::time`: `SystemTime` for `Date` and the DKIM `t=` tag, `Instant` for driver deadlines; clock-lib is not a dependency | the standard library gives both clocks; one fewer dependency |
| D-032 | 2026-11-04 | smtp-net has its own `Sink` trait (`write(&mut self, &[u8]) -> Result<(), SinkError>`, `SinkError::{Full, Io(kind)}`), adapted internally to parse-net's `Sink` for parse-net's writers. `Sink for Vec<u8>` never refuses; the message size budget is checked against `encoded_len` before writing. | a serializer that writes to sockets and files must carry the I/O error kind out; parse-net's `Full` cannot |
| D-033 | 2026-11-04 | 0.3's exit check on the cPanel host's Exim moves to the 0.8 field test, because it needs James's host; 0.3 instead sends every message shape through Exim and Mailpit containers in a CI interop job and checks the received bytes | the move is recorded (anti-deferral rule); a container Exim is the same MTA family the host runs |
| D-034 | 2026-11-04 | `Error` keeps its details in one heap allocation (`Box`), so `Result<T, Error>` stays pointer-sized on hot paths; errors are created only on failure | a large error type slows every successful call that returns `Result` |
| D-035 | 2026-11-04 | Competitor benchmarks and the independent DKIM and MIME verifiers live in a separate public repository, `smtp-net-bench`, with its own lockfile and pinned versions (as http-net-bench and cookie-net-bench do), replacing the in-repository `compare/` crate of the specification | reference implementations never enter smtp-net's dependency graph, and the comparison can be rerun by anyone |
| D-036 | 2026-11-04 | The roadmap has a pre-1.0 polish milestone, 0.9.x, before any release candidate: every accepted gap and deferred item revisited, performance re-tuned against lettre and mail-builder, the security and edge-case review re-run, and a 1.0 readiness note written. 1.0.0 needs James's explicit go. | the same pass the other crates of the stack run before 1.0 |
| D-037 | 2026-11-04 | The session's TLS states ship in 0.3: STARTTLS sent only when advertised, the stop after its `220`, the response-injection check, `tls_established`, capabilities discarded and EHLO sent again, and the implicit TLS start. The driver's TLS engine and AUTH stay in 0.4. | the state machine is sans-IO and needs no TLS engine; T-5, T-6, and T-7 are tested at the session in the same version as the rest of the state machine |
| D-038 | 2026-11-04 | `Session::connection_lost(cause) -> Error` is added (Tier 3): a driver reports EOF or a transport failure, and the session closes and returns the classified error, `possibly_delivered` included | every driver, the built-in one and a caller's, gets the same RFC 1047 rule from one place |
| D-039 | 2026-11-04 | `Address::parse_allowing_literal` is added for domain literals (`[192.0.2.1]`, `[IPv6:...]`); `Address::parse` refuses them | the specification asks for literals "refused unless enabled" without naming the switch; a separate function keeps the default strict |
| D-040 | 2026-11-04 | Attachment `name=` and `filename=` parameters are both written by parse-net's `write_mime_param` (RFC 2231 for non-ASCII or long values); RFC 2047 words are not put inside parameters | RFC 2047 section 5 does not allow encoded words in a quoted parameter; current readers read RFC 2231. Revisited at 0.9 with interop evidence from old readers |
| D-041 | 2026-11-04 | An EHLO keyword outside the RFC 5321 grammar (Exim's `X_PIPE_CONNECT`, a lone `-X`) is counted and kept as an unknown keyword, not refused; only a known keyword with a bad parameter (a SIZE that is not a number up to 2^53) is `MalformedCapability` | the client never acts on an unknown keyword, so two readings of it cannot change what is sent; refusing it would fail against servers a user cannot fix |
| D-042 | 2026-11-04 | `Message::prepare`, the `PreparedMessage` accessors, `MessageBuilder::allow_8bit`, and `Session::noop` ship in 0.3 (the API listed 0.4) | `Client::send_prepared` is 0.3 and needs them; the others are small and complete |
| D-043 | 2026-11-04 | With `RecipientPolicy::All`, DATA is not pipelined: it waits for every RCPT reply and is not sent after a refusal | after a `354` the only way not to deliver is to drop the connection mid-data; waiting one round trip is the cost of the policy |
| D-044 | 2026-11-04 | After a failed transaction the session sends RSET and reports `TransactionFailed` once RSET is answered, so the session is ready when the driver sees the event | after refused recipients or a refused DATA the server may still hold the MAIL state; RSET makes the next transaction start clean |
| D-045 | 2026-11-04 | An empty body is sent as a lone `.` line (no blank line before it) | the end-of-data sequence is CRLF `.` CRLF and the CRLF after DATA's reply is already there; a blank line would add a line to the message |
| D-046 | 2026-11-04 | net-io is used at `0.6` | 0.5.0 was yanked (a reactor slowloris fix; the blocking connection smtp-net uses was not affected); 0.6 is the published floor |
| D-047 | 2026-11-04 | Allocation counts measured at 0.3.0 and moved to 0.6 with the numbers: a text plus HTML build allocates 97 times (target at most 8); `Session::begin` copies the envelope (one allocation per address plus one) and `Event::Delivered` carries an owned reply (one). Zero today, held by `tests/alloc.rs`: the body path, replies before the end of data, base64, quoted-printable, the header gate, and `write_to` into a sized buffer. | the anti-deferral rule: the 0.6 optimisation milestone owns allocation targets, and the numbers are recorded now so 0.6 starts from a measurement |
| D-048 | 2026-11-04 | The scripted test driver (`ScriptedServer`) finishes a server burst before it simulates the TLS handshake, so plaintext queued behind the STARTTLS `220` meets the session's `NeedTls` check whatever the read boundaries | the byte-at-a-time transcript run found that the simulation let a split injection through as TLS data; a real driver hands the socket to the TLS engine, where such bytes fail the handshake |
| D-049 | 2026-11-04 | Until 0.4, `ServerBuilder::build` refuses `Security::StartTls` and `Security::ImplicitTls` with `Config(TlsConnectorMissing)` | no plaintext fallback exists, so a TLS server without an engine must fail before anything is sent |
| D-050 | 2026-11-04 | `Secret` and the AUTH buffers use crypt-io's `Zeroizing` (crypt-io 1.3 with only the `zeroize` feature, which pulls `zeroize` and `subtle`) | wiping needs volatile writes, which `forbid(unsafe_code)` rules out here; crypt-io is the accepted cryptography exception |
| D-051 | 2026-11-04 | Feature `tls` (tls-net 0.3, rustls with aws-lc-rs and the Mozilla roots) is on by default, as D-025 planned. `Server::starttls` and `Server::implicit_tls` use one shared tls-net client (sessions can be resumed); `ServerBuilder::tls(TlsClient)` sets another, for example one that trusts a private CA. tls-net has no way to turn verification off, so with it `dangerous_disable_certificate_verification` fails the connection with `Tls(Setup)`: a test relay is trusted through its own CA instead. | tls-net 0.3 published a client session on net-io's seam; the default build needs a C compiler for aws-lc-rs (it built on Windows here without NASM) **[cost: about +16 s debug, +24 s release on 32 cores, crypt-io's measurement]**; `default-features = false, features = ["client"]` keeps the cPanel path free of rustls |
| D-052 | 2026-11-04 | The tls-net connector classifies tls-net's error codes: 35 (no common version or suite), 37 to 40 (certificate invalid, required, revoked, pin mismatch) are `CertificateRejected`, permanent; 31 (not TLS) is `ProtocolMismatch`; the rest stay `Handshake`, temporary | tls-net reports certificate problems by code with no alert on the client side; the classification of PLAN 7.7 needs to tell them apart |
| D-053 | 2026-11-04 | The driver reads from the socket only when a TLS step neither consumed nor wrote anything, and gives the engine at least 32 KiB of output room | found with real rustls: a `NeedInput` after a consumed record does not mean "read now", and rustls refuses output below 18,437 octets |
| D-054 | 2026-11-04 | With CHUNKING the message goes as `BDAT n` with all its bytes, then `BDAT 0 LAST` (or `BDAT 2 LAST` and CRLF when the bytes do not end in CRLF), all pipelined; a message over 64 KiB waits for the MAIL and RCPT replies before its chunk **[est. limit]**; after a failed BDAT, RSET | the same message as DATA delivers, still one round trip; the wait keeps the client from blocking on a full socket while the server blocks writing replies (RFC 3030 leaves the state after a failure undefined) |
| D-055 | 2026-11-04 | `Event::Deferred` carries the deferred recipients' indices (`Vec<usize>`) rather than a `Range`; `Client` sends them in further transactions (at most 10) with the same bytes and merges the report | a server may defer recipients that are not contiguous; the same bytes keep the `Message-ID` and any signature |
| D-056 | 2026-11-04 | A recipient is deferred as one too many only on `452` or `552` with the enhanced code `x.5.3`; `452` without it (for example `4.2.2`, mailbox full) is a temporary refusal | only `x.5.3` says "too many recipients"; anything else would be guessing |
| D-057 | 2026-11-04 | Job payload format 1: `SMTPNET1`, version, flags (null sender, DSN), length-prefixed envelope and DSN fields, the message bytes, CRC-32C. `decode` checks magic, version, checksum, then each length against its budget (message 64 MiB, address 256 octets) before allocating, then validates through `from_raw`, so the `Message-ID` and the flags are recomputed, never trusted from the payload | one validation path for raw bytes and payloads; a corrupt or forged payload cannot carry a flag the bytes contradict |
| D-058 | 2026-11-04 | `HourlyLimit` admits with a compare-and-swap on the window total after retiring expired one-minute buckets (each retired once, by the thread whose swap takes it); a refund returns only counts still in the current minute; a clock that goes backwards counts as no time passing | the total is the only gate, so no interleaving over-admits (64-thread test, two loom models); refusing a little early after a clock step is the safe side |
| D-059 | 2026-11-04 | `TestServer` gains AUTH (PLAIN, LOGIN, redacted transcript), BDAT, DSN parameter capture, `TestTls` (a framing-only stand-in that refuses a wrong name, for tests without a TLS library), and `tls_engine` (any server-side net-io `TlsSession`, used with tls-net and the fixture certificates in `tests/fixtures/`) | the driver's TLS paths run end to end both without and with a real TLS stack, on every CI platform |
| D-060 | 2026-11-04 | `Part` is public with validated constructors (`text`, `binary`, `multipart`, `from_attachment`, `from_inline`, `transfer_encoding`); the `Body` enum stays internal | a public enum would let a caller build a part no validation saw; the constructors give the same tree |
| D-061 | 2026-11-04 | `List-Unsubscribe` takes 1 to 8 `https:` or `mailto:` targets; one-click needs an `https:` target (RFC 8058). `List-Unsubscribe`, `List-Unsubscribe-Post`, and `Auto-Submitted` are reserved names for `MessageBuilder::header` | other schemes (`javascript:`) have no place in the header; a reserved name cannot be set twice |
| D-062 | 2026-11-04 | Fixed two 0.3.0 bugs: `Address` equality compared only the domain (`b@x == d@x`), found by the deferral test; `MessageBuilder::date_unix` was ignored and the build time was stamped instead | `Address` now compares the whole address; the date regression test checks a fixed time |
| D-063 | 2026-11-04 | The session's output is overwritten once an AUTH response in it has been transmitted (best effort without unsafe code); the responses are built in `Zeroizing` buffers | T-9: the password's base64 does not linger in the output buffer's spare capacity |
| D-064 | 2026-11-04 | The 0.4 check "delivery through an external relay on 587 and 465 with verification" runs in CI against Mailpit with real TLS (STARTTLS and implicit TLS, the fixture certificate, verified against the fixture CA); a public relay (Gmail, Microsoft 365) needs James's credentials and is part of the 0.8 field test | a real third-party TLS server, every push; credentials for public relays are James's |
| D-065 | 2026-11-04 | task-io is not published: the 0.4 job-contract test runs against a stub of its handler contract (`tests/extended.rs`: temporary to retry, permanent to dead letter); it is re-run against task-io when task-io publishes | the roadmap allowed this; the contract is two mappings |
| D-066 | 2026-11-04 | No `allow_rsa_1024`: RSA keys of 2048 to 4096 bits only. Shorter keys get `KeyTooSmall { bits, minimum: 2048 }` (measured from the key's DER before the backend sees it); longer ones `KeyTooLarge` | crypt-io refuses RSA under 2048 bits in every configuration, so the switch would have nothing to switch; RFC 8301 3.2 lets signers use 1024 but says they SHOULD use 2048, and verifiers only must handle up to 4096 |
| D-067 | 2026-11-04 | The DKIM canonicalizers (`BodyCanonicalizer`, `HeaderCanonicalizer`, `Canonicalization`) are always built and `no_std`; keys and `DkimSigner` need the `dkim` feature, off by default | the signer needs AWS-LC (C and assembly) through crypt-io; a build that does not sign should not compile it |
| D-068 | 2026-11-04 | The `DKIM-Signature` header: tags in the order `v a c d i s t x h bh b`; lines kept to 78 columns, folded at tag boundaries and between `h=` names; `b=` starts its own line; the signed form is the header through `b=`, canonicalized like the others and without its CRLF. Several signers each sign the original message independently, and their headers go in front in the order given; the body hash is computed once per body canonicalization | one serialization is both what is sent and what is signed, so simple header canonicalization cannot drift; independent signatures are what RFC 8463 section 6 asks for |
| D-069 | 2026-11-04 | `h=` lists each default header once per instance present, then the oversign list once each whether present or not; `headers()` keeps From and removes duplicates; `oversign(&[])` turns oversigning off | a listed name with no instance is hashed as empty, which is what stops a header added in transit (T-20) |
| D-070 | 2026-11-04 | Independent DKIM verification runs in this repository's CI with dkimpy (Python): `tests/dkim.rs` writes a corpus (Ed25519, RSA 2048 and 4096, PKCS#8 and PKCS#1, every canonicalization pair, a multipart message, two signatures on one message, and tampered copies) and `.github/scripts/dkim_verify.py` checks every `pass-` file verifies and every `fail-` file does not. This replaces the DKIM half of D-035; smtp-net-bench keeps benchmarks and the MIME comparison. The 0.5 check "DKIM passes at Gmail and Outlook.com" needs a domain whose DNS publishes the keys and is part of the 0.8 field test | a verifier in another language shares no code or crate with smtp-net and runs on every push; a public receiver needs James's domain and DNS |
| D-071 | 2026-11-04 | The T-21 key-size test uses 4098 bits for "just over 4096": OpenSSL rounds odd sizes above 4096 down to even ones (a 4097-bit request gives 4096); 1023, 1024, and 2047 are as specified. The fixture keys in `tests/fixtures/dkim/` are test-only | the test still crosses the limit by the smallest step the generator allows |
| D-072 | 2026-11-04 | `Credentials` has three kinds, each fitting its own mechanisms: `Password` (SCRAM-SHA-256, PLAIN, LOGIN), `OAuth2` (XOAUTH2), `Custom` (its mechanism). The default allowlist is `[ScramSha256 (with the scram feature), Plain, Login, XOAuth2, Other]`, and the choice skips mechanisms the credentials do not fit | one default list serves every credential kind; a token never goes to PLAIN and a password never to XOAUTH2 |
| D-073 | 2026-11-04 | SCRAM-SHA-256: a 24-byte nonce from the OS (`std`) or `Auth::scram_nonce` (16 to 64 printable characters, required without `std`); iterations 4096 to 1,000,000; the server-final message must come in a `334` (RFC 4954 carries no data with success), and a `235` before the server signature checked out is refused as `ServerSignatureMismatch`, a security event; the signature check is crypt-io's constant-time `hmac_sha256_check` (T-29). Credentials outside printable ASCII skip SCRAM (O-12) and `NonAsciiCredential` is returned when nothing else fits | mutual authentication is the point of SCRAM: a server that cannot prove it holds the key is not trusted with the message |
| D-074 | 2026-11-04 | XOAUTH2 sends its initial response on the AUTH line unless the line would pass 12,288 octets. On failure the server's error document (at most 1 KiB) is read only for its `status`, which `Error::auth_detail` returns; nothing else of it is kept | the status tells a job to refresh the token; the rest of the document is server text with no use and some risk |
| D-075 | 2026-11-04 | Custom mechanisms implement `Mechanism`; `CustomMechanism` is a factory (a fresh mechanism per session) whose name is checked as 1 to 20 of `A-Z 0-9 - _`. A client-side SASL error closes the connection instead of sending `*` | the name goes on the AUTH line, so it cannot carry CR or LF; there is no fallback after a failed AUTH (T-10), so cancelling and continuing has no use |
| D-076 | 2026-11-04 | `Observer` and `ObservedEvent` (connected, TLS up, reply codes, delivered, failed, security event); reply events are opt-in in the session (`SessionConfig::reply_events`) and the driver turns them on only when an observer is set. Events carry codes, never reply text, secrets, or bodies | T-30; a session without an observer queues nothing extra |
| D-077 | 2026-11-04 | `Pool`: 1 to 64 slots; checkout claims a slot in an atomic bitmap (preferring slots with an open connection) and takes that slot's uncontended mutex; a waiter sleeps on a condition variable with a release counter, up to the wait limit (10 s by default), then gets `PoolExhausted` (temporary). A failed connection is dropped; idle expiry is the client's own check on use. loom models the bitmaps | the bitmap is the lock-free part of "a lock-free stack of idle clients"; moving a client through an atomic would need unsafe code |
| D-078 | 2026-11-04 | `Attachment::from_source` needs `std`: the single-use source sits behind `Arc<Mutex>` so a `Message` stays `Send + Sync` and `Clone`; its declared length is exact (`Build(LengthMismatch)` either way) and a second serialization fails with `Source(Consumed)`. `BodySource::read` returns `SourceError`, and `ReadSource` adapts `std::io::Read` instead of a blanket impl. `send` still holds the encoded message in memory; `Message::write_to` streams end to end | interior mutability without unsafe code needs std's mutex; callers cannot construct `Error`, so the source has its own error type; a blanket impl would collide with a caller type that is both a reader and a source; retries and recipient deferral need the bytes again |
| D-079 | 2026-11-04 | Two CI flakes fixed: the interop job polls for Exim deliveries still in progress (up to 30 s) instead of sleeping 3 s, and the hourly-limit refund test fails a send at MAIL against a test server instead of connecting to a released port a parallel test could take | both failed on timing, not on smtp-net |
| D-080 | 2026-11-04 | Fuzz targets `dkim` (canonicalization split invariance; signing never panics and always gives a well-formed header) and `sasl` (arbitrary server bytes during SCRAM, XOAUTH2, PLAIN, LOGIN; SCRAM never ends authenticated without the server's proof). The fuzz crate builds AWS-LC | the spec's `fuzz_dkim_canon` and `fuzz_sasl_challenges`, with the signer added |
| D-081 | 2026-11-04 | tls-net 0.5 (was 0.3): no source change and every real-TLS test passes. The driver keeps `TlsClient::connect` after STARTTLS rather than tls-net's `start_after_plaintext`, and the session keeps its own response-injection check (T-6): the session hands the driver no leftover bytes to pass on, and the check works with any `TlsConnector`, not only tls-net's | the newer release carries tls-net's fixes and the same aws-lc-rs as crypt-io 1.3; a second injection check in tls-net costs nothing and the session's does not depend on it |
| D-082 | 2026-11-05 | RFC 2047 words (subjects, unstructured headers, display names, `encode_word`) use the B form when more than half of the text's octets are not ASCII and B comes out shorter; otherwise Q. Both lengths are counted with parse-net's `CountSink`, nothing is written twice. parse-net 0.9.1 is the minimum | B is about 40% shorter for Japanese or Russian text, which also means fewer folded lines; for mostly ASCII text such as `José`, B can save an octet but makes the header unreadable in raw form, so Q stays there |
| D-083 | 2026-11-06 | A text plus HTML build allocates 21 times (97 at 0.3.0): the block's header text is shared by every header instead of one string each, names the crate writes are `&'static str`, the builder's strings move into the message instead of being copied, and multipart boundaries are inline arrays. The PLAN 11.1 estimate of 8 is recorded as missed: five setters (`from`, `to`, `subject`, `text`, `html`) each store their input, and the message owns its head, header index, part list, body texts, and id | each remaining allocation is an owned value a `Message` must keep to be `Clone`, `Send`, reusable for retries, and independent of the caller's borrows; reaching 8 would need a borrowing builder, a second API for no measurable gain (the build is 3.5 µs, under its 5 µs target) |
| D-084 | 2026-11-06 | `Envelope` holds its sender, recipients, and DSN behind an `Arc`; `Session::begin` keeps a clone (a reference count) instead of copying the addresses, and allocates nothing. Changes go through `Arc::make_mut` | `begin` copied one string per address at 0.3 (D-047); sharing is safe because an envelope is immutable once handed to a session, and cloning stays cheap for retries and the pool |
| D-085 | 2026-11-06 | A ready session holding one transaction uses 19,176 bytes: the output buffer (`SessionConfig::output_capacity`, 16 KiB by default) plus about 3 KiB for the reply buffer, capabilities, and transaction. The PLAN 11.1 estimate of 16 KiB in total is recorded as missed; with a 4 KiB output buffer a session is 6,888 bytes. The default stays 16 KiB | one TLS record of body per write is the throughput choice (fewer writes, fewer records); a deployment holding many idle connections sets a smaller buffer, and `tests/alloc.rs` holds both numbers |
| D-086 | 2026-11-06 | Byte scans eight octets at a time with `u64` arithmetic, no `unsafe` (`src/scan.rs`): the line-end search for dot-stuffing and raw input, the ASCII and printable checks for the header gate and raw input, and the search for spaces and controls in relaxed body canonicalization. base64 encodes six octets per step through a 4,096-entry table of character pairs (8 KiB, static); quoted-printable classifies octets through a 256-entry table and copies literal runs mid-line. Each scan and encoder is checked against the plain loop it replaced at every offset and over a 3,000-case corpus | PLAN 11.3 item 4; the output is proven identical, so the security impact is none; the cost is 8.25 KiB of static tables |
| D-087 | 2026-11-06 | `Event::Delivered` keeps its owned reply (one allocation per message, after the end-of-data reply) | the `Report` gives callers the server's queue id and text, which a log needs; the allocation is off the body path and once per message, so removing it would cost API for no measured gain |
| D-088 | 2026-11-06 | Unsigned mail is serialized once into a `PreparedMessage` and not streamed from the message tree into the session's body path (PLAN 11.3 item 3 not taken) | retries, a 421 reconnect, and recipients deferred by a 452 send the same bytes again; serialization runs at 2.4 to 2.9 GB/s, so the copy costs about 1 µs for a 2 KiB message; `Message::write_to` still streams for a caller who wants it |
| D-089 | 2026-11-06 | `Fault::RoundTrip(Duration)` is a delay line: every byte the server writes (replies and TLS records, in order) reaches the client that long later through a writer thread, while the server goes on reading. A client pays it once each time it waits, however many commands it pipelined, which is how a network round trip costs it. A first version slept before each read that followed a reply, and charged a round trip whenever a pipelined group arrived in two segments; `Fault::DelayAt` delays each reply in turn and overstates pipelined groups. `TestServer::client_waits` counts the times new client bytes arrived after every queued reply had gone out: the round-trip test asserts those counts (3 with PIPELINING and CHUNKING, 4 with PIPELINING, 6 with neither) instead of elapsed time, because on the loaded build machine a 40 ms sleep took over 100 ms. `TestServer` sets `TCP_NODELAY`: without it Nagle's algorithm and delayed acknowledgements added about 40 ms per exchange | the end-to-end targets compare round trips, so the test server must model one round trip per turnaround; every client measured gets the same server |
| D-090 | 2026-11-06 | Benchmark method: the build machine is shared (load average 70 to 490 on 32 threads during 0.6), so each published number is the minimum over many short batches (`benches/examples/targets.rs`, the bench repository's `report`), next to criterion's distributions from `cargo bench`. Preemption only adds time, so the minimum is the cleanest estimate available here, and every number is an upper bound | a mean under that load measures other processes; the 0.9 re-tune republishes on a quiet machine |
| D-091 | 2026-11-06 | Where competitors are faster, the gap is recorded, not closed by lowering checks: mail-builder builds the verification email about 3 times faster because it does not validate addresses or header values, and serializes a 1 MiB attachment about 7 times faster through a SIMD base64 crate built on `unsafe` code; mail-auth's Ed25519 signature is about 10% faster. smtp-net keeps its checks and `#![forbid(unsafe_code)]`; SIMD encoding would come from a first-party encoding crate with its own audited `unsafe`, considered at the 0.9 re-tune | validation is a security requirement (header injection, smuggling), and the crate's no-unsafe rule is a DIRECTIVES rule; smtp-net is still 1.8 times faster than lettre to build and 3 times faster with an attachment |
| D-092 | 2026-11-06 | crypt-io stays at 1.3: 1.4 adds signature verification, and inbound DKIM verification is outside smtp-net's scope (it signs; receivers verify). Linux is the production target: crypt-io's Ed25519 is several times slower under Windows MSVC (64 µs against 20 µs for a 10 KiB message on the same machine; crypt-io reports up to about 10 times) | a dependency bump with no use is churn; the documented target platform tells deployers where the numbers hold |
| D-093 | 2026-11-06 | 0.6 closes with these PLAN 11.1 rows short under the release-day load (load average about 470 on 32 threads), recorded with their numbers in `docs/PERFORMANCE.md` and ROADMAP 0.6: quoted-printable (0.53 to 0.63 GB/s; 0.91 in a quieter run), single-line reply (61 to 94 ns; 50 in a quieter run), dot-stuffing (2.9 to 3.6 GB/s; about 6 in a quieter run), EHLO with capabilities (661 to 788 ns), relaxed body canonicalization (1.22 to 1.50 GB/s). The 0.9 pass re-measures them on a quiet machine and fixes any still short; the canonicalizer's next step is to pass already-canonical lines straight from the input instead of through its 512-octet run buffer | criterion's intervals under that load were wider than ten times the quiet result, so neither tool can separate code cost from contention for these rows today; every row that depends on them end to end (both DKIM signatures, the send, the build) meets its target with room, and holding the release for a quiet machine would block hardening on a condition outside the repository |
| D-094 | 2026-11-06 | Two pool tests fixed for loaded machines: the exhaustion test waits until the first send's connection is up instead of sleeping 200 ms, and the connection-limit test raises the per-connection message limit, because the pool fills the lowest free slot first and one connection could reach the 100-message reconnect, adding a fifth accepted connection while never more than four were open | both failed on timing or on correct reconnects, not on the pool; found by the gates under a load average near 480 |
| D-095 | 2026-11-07 | The NFR-14 soak is `tests/soak.rs` (ignored by default, `SMTP_NET_SOAK_SECS`): one message every 10 ms over a reused connection through `(HourlyLimit, DomainLimit)` with recipients at 1,000 domains, a two-slot `Pool` fed by two threads every 50 ms, and one send a second to a server with a fault, ten kinds in turn, each with its expected outcome. A counting allocator gives live heap bytes; `/proc/self` gives descriptors and threads. It fails when the highest heap of the last third passes the first third's by 1 MiB (after a tenth of the run as warm-up), when descriptors or threads grow by more than 4, when a fault ends another way, or when the server took fewer messages than were reported sent. `TestServerBuilder::record(false)` keeps the server's own memory flat | a leak of one allocation per message grows by about 8.6 million allocations a day, far above the slack; a fixed slack instead of a slope keeps allocator jitter from failing a clean run; the server must not grow, or it hides the client's numbers |
| D-096 | 2026-11-07 | A reply whose class cannot answer its command (RFC 5321 4.2.1 and 4.3.2: only DATA and AUTH have a 3yz, DATA has no 2yz, nothing has a 1yz) is `Protocol(UnexpectedReply)`, temporary, and closes the session; after the end of data it is possibly delivered. Found by the T-14 test: an extra reply under pipelining made a `250` answer DATA, which was reported as a permanent `Rejected` | a permanent refusal dead-letters the message although the server refused nothing; out-of-step replies mean no later reply can be trusted, so the session cannot go on |
| D-097 | 2026-11-07 | The display-name and bidi policies (P3 in the 0.2 plan) ship in 0.7 so every row of 10.1 has a defence: bidi overrides and isolates are refused by default (`allow_bidi_controls(true)` lets them through); address-like display names are refused only with `refuse_address_like_display_names(true)`. Both are checked at build over every displayed mailbox and the Subject | right-to-left text needs none of the overrides, and in subjects they are a known trick to disguise file names; `orders@shop.example` as a display name is used in good faith, so that check is the application's choice; one scan each |
| D-098 | 2026-11-07 | `DomainLimit` (feature `std`): per recipient domain, case-insensitive, at most `per_hour` recipients in any 60 minutes, kept in 13 five-minute buckets so a count is never dropped early (up to 5 minutes late); a `Mutex<HashMap>` of at most `max_domains` (default 1,024) that forgets the least recently used domain when full; all of a message's domains admitted or none. `SendGate` gains `admit_envelope` and `refund_envelope`, defaulting to the count-based methods; `(A, B)` is a gate that refunds the first when the second refuses | the 0.7 idea of 10.3 needs the addresses, which the count-based trait does not carry; default methods keep every existing gate working; a lock is simpler than a lock-free map for a per-message check and costs far less than the network round trip; forgetting the least recently used domain keeps memory bounded while a domain under steady mail keeps its count |
| D-099 | 2026-11-07 | The T-29 timing check times crypt-io's `hmac_sha256_check` on decoded signatures that differ from the right one in the first or the last octet: random interleaving, 200,000 samples of 8 checks per class, slowest 10% cropped, Welch's t under 4.5. It runs on request in release (`#[ignore]`). Linux: t 0.07, -1.76, -0.97; Windows: at most 1.19 | timing in CI is noise; timing the whole server-final step measured base64 decoding of characters the server chose (a steady 0.3 to 0.7 ns, t to -7.6), which leaks nothing; the comparison with the secret is the step that must be flat |
| D-100 | 2026-11-07 | Every row of 10.1 maps to named tests in `docs/SECURITY.md`; `tests/threats.rs` holds the attack tests no other test covered in full. Accepted differences from the 10.1 wording: T-2's formatter is checked by a randomized unit test (50,000 paths), not libFuzzer, because the line formatter is internal; T-6 accepts `StartTlsInjection` or a TLS failure, since injected bytes can reach the TLS engine first, and both refuse with no injected capability used; T-11's wrong name is tested with `TestTls`, since a real certificate test needs a second loopback address the test server does not bind, and a self-signed certificate is tested with rustls; T-22's "never in errors" holds by construction (error kinds are `Copy` codes); T-30's CR is refused rather than shown as `?` | each difference is as strict as the wording or stricter, and is recorded so the 1.0 audit does not mistake it for a gap |
| D-101 | 2026-11-07 | 0.7 fuzzing: one hour per target, all eleven at once in WSL, with libFuzzer's false timeout on a WSL clock step resumed only when its input replays clean. `prepared_decode` frames inputs with an odd first byte with the header and a valid CRC-32C (computed independently in the target): its first hour reached 52 coverage points because random input almost never passes the checksum. The targets the reply-class change touches (`session_server_bytes`, `transcript`) and the reframed `prepared_decode` got a further hour on the final code | the exit criterion is an hour per target with no finding; a target that cannot get past a checksum is not fuzzing what is behind it |
| D-102 | 2026-11-07 | CI runs the loom models (`HourlyLimit`, the pool slot bitmap) in a `loom` job with `--cfg smtp_net_loom`; until 0.7 they ran only by hand | a model nobody runs proves nothing about the code as it changes |
| D-103 | 2026-11-07 | parse-net 0.9.2 was not published when the 0.7 soak started; the soak was not held for it. If it lands before 0.7.0 it is adopted in the same release with the affected fuzz targets run another hour, and the soak result stands, because 0.9.2 changes address and header parsing, not the delivery loop the soak exercises | the soak takes a day; the parsing changes are covered by the fuzz targets and unit tests that exercise them |
| D-104 | 2026-11-08 | parse-net 0.9.2: Content-Type and Content-Disposition parameters go through `mail::write_mime_param_at`, told the room left on the line, in place of the local fold-before-parameter logic; `class::is_atext` (public since 0.5) replaces the local copy. `Mailbox::parse` keeps its own `unquote_phrase` and does not use the new `mail::decode_phrase`: on the sending side the input is application text, so RFC 2047 encoded-word syntax stays literal (T-23) and a comment is refused rather than silently dropped, while `decode_phrase` reads a received header (it decodes encoded words and drops comments). Output is byte for byte unchanged (golden tests); the `address` and `content_type` fuzz targets ran another hour | the folding and the predicate now live in one place, the parser crate; `decode_phrase` is right for a reader and wrong for a writer's input |
