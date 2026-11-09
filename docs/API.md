# smtp-net - API Reference

> The public API of `smtp-net`, written at the 0.2.0 design lock for every version up to 1.0. Each item names the version that ships it; until then it does not exist in the crate. Design and decisions: [`dev/PLAN.md`](../dev/PLAN.md). Schedule: [`dev/ROADMAP.md`](../dev/ROADMAP.md).

## Table of contents

- [8.1 Conventions](#81-conventions)
- [8.2 Tier 1: the 80% path](#82-tier-1-the-80-path)
- [8.3 Addresses](#83-addresses)
- [8.4 Building messages](#84-building-messages)
  - [8.4.1 Parts, attachments, budgets](#841-parts-attachments-budgets)
  - [8.4.2 Headers and encoding primitives (Tier 3)](#842-headers-and-encoding-primitives-tier-3)
  - [8.4.3 Serialization sinks](#843-serialization-sinks)
- [8.5 Envelope and prepared messages](#85-envelope-and-prepared-messages)
- [8.6 Protocol core (Tier 3, sans-IO)](#86-protocol-core-tier-3-sans-io)
  - [8.6.1 Replies and capabilities](#861-replies-and-capabilities)
  - [8.6.2 SASL](#862-sasl)
- [8.7 DKIM (feature `dkim`)](#87-dkim-feature-dkim)
- [8.8 Client driver (feature `client`)](#88-client-driver-feature-client)
  - [8.8.1 TLS seam](#881-tls-seam)
- [8.9 Pacing (send gate)](#89-pacing-send-gate)
- [8.10 Timeouts](#810-timeouts)
- [8.11 Observability (Tier 3)](#811-observability-tier-3)
- [8.12 Errors](#812-errors)
  - [8.12.1 Nested error enums](#8121-nested-error-enums)
- [8.13 Test support (feature `testing`)](#813-test-support-feature-testing)
- [8.14 Constants](#814-constants)
- [8.15 Examples by use case](#815-examples-by-use-case)
- [8.16 Changes since the design lock](#816-changes-since-the-design-lock)

### 8.1 Conventions

- Sections of this file are numbered 8.x because this is section 8 of the design in `dev/PLAN.md`. A reference to another number (7.7, 10.1, 12.2), to a requirement (FR-n, NFR-n), a threat (T-n), an open question (O-n), or a decision (D-n) points into `dev/PLAN.md`.
- **Grade** is P0 (must ship in its version) to P3 (allowed after 1.0). **Tier** is 1 (one call, no configuration, about 80% of uses), 2 (builders and configuration), or 3 (the full, generic, allocation-free surface). **Ver** is the smtp-net version that ships the item.
- **Cost** is the target on the reference machine named in `docs/PERFORMANCE.md` (0.6); every number marked **[est.]** is an estimate until 0.6 measures it. "0 alloc" means a counting-allocator test proves no heap allocation.
- Signatures are exact in name, parameters, and return type. Lifetimes and generic bounds shown are the intended ones; an implementation may tighten a bound only when this file is changed in the same pull request and the change is recorded in the decision log.
- Every public enum and every public struct with public fields is `#[non_exhaustive]`. Every function returning a value that must be checked is `#[must_use]`.
- Errors: every fallible function returns `Result<T, smtp_net::Error>` unless a narrower error is shown; each narrower error converts into `Error` with `From`, keeping its disposition (8.12).
- Features (PLAN 7.2): `std` and `client` are on by default; `tls`, `dkim`, `scram`, `key-vault`, and `testing` are off. Items in 8.7 need `dkim`; items in 8.8 need `client`; items in 8.13 need `testing`.

### 8.2 Tier 1: the 80% path

```rust
// Send a plain-text email through the local MTA (cPanel Exim on 127.0.0.1:25).
let msg = smtp_net::Message::text(
    "Example <no-reply@example.com>",
    "user@example.org",
    "Confirm your email address",
    "Open this link to confirm: https://example.com/confirm/abc123",
)?;
let report = smtp_net::send_local(&msg)?;
println!("accepted as {}", report.message_id());

// Send text plus HTML through a remote relay with STARTTLS on 587 and AUTH.
let msg = smtp_net::Message::html(
    "Example <no-reply@example.com>",
    "user@example.org",
    "Reset your password",
    "<p>Reset: <a href=\"https://example.com/r/xyz\">link</a></p>",
    "Reset: https://example.com/r/xyz",
)?;
let server = smtp_net::Server::starttls("mail.example.com")
    .login("no-reply@example.com", password);         // password: impl Into<Secret>
smtp_net::send(&server, &msg)?;

// In a task-io handler: classify and hand back.
fn send_email(job: &task_io::Job) -> Result<(), task_io::Fail> {
    let prepared = smtp_net::PreparedMessage::decode(job.payload()).map_err(task_io::Fail::permanent)?;
    match smtp_net::send_prepared(&SERVER, &prepared) {
        Ok(_) => Ok(()),
        Err(e) if e.is_temporary() => Err(task_io::Fail::retry(e)),
        Err(e) => Err(task_io::Fail::permanent(e)),
    }
}
```

| Item | Signature | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|---|
| `send` | `pub fn send(server: &Server, message: &Message) -> Result<Report, Error>` | prepares (derives the envelope, serializes, applies the server's DKIM signers if configured), applies the server's `SendGate`, connects, sends, sends QUIT, closes | every `Error` kind; see 8.12 | network-bound; CPU below 20 µs plus signing **[est.]** | P0 | 1 | 0.3 |
| `send_local` | `pub fn send_local(message: &Message) -> Result<Report, Error>` | `send(&Server::local(), message)` | as `send` | as `send` | P0 | 1 | 0.3 |
| `send_prepared` | `pub fn send_prepared(server: &Server, message: &PreparedMessage) -> Result<Report, Error>` | sends already prepared bytes (the job path); never re-serializes or re-signs | as `send` minus build errors | as `send` | P0 | 1 | 0.4 |
| `Message::text` | `pub fn text(from: &str, to: &str, subject: &str, body: &str) -> Result<Message, Error>` | parses `from` and `to` as mailboxes (display name optional), single `text/plain; charset=utf-8` part, generated `Date` and `Message-ID` | `Address`, `Header` (CR/LF), `Build` (budget) | 1.5 µs for a 1 KiB body, at most 6 alloc **[est.]** | P0 | 1 | 0.3 |
| `Message::html` | `pub fn html(from: &str, to: &str, subject: &str, html: &str, text: &str) -> Result<Message, Error>` | `multipart/alternative` with text first and HTML last (RFC 2046: the last part is the preferred one) | as `text` | 3 µs for 2 KiB total **[est.]** | P0 | 1 | 0.3 |
| `Server::local` | `pub fn local() -> Server` | `127.0.0.1:25`, `Security::PlaintextLoopback`, no AUTH, `Timeouts::local()`, EHLO name = address literal of the local socket address | none | none | P0 | 1 | 0.3 |
| `Server::starttls` | `pub fn starttls(host: &str) -> Server` | port 587, `Security::StartTls`, verification on, `Timeouts::rfc5321()`; the TLS engine is tls-net's with feature `tls`, otherwise the one set with `ServerBuilder::tls_connector` (D-025) | none at construction; the host is validated at connect (`Config`); no engine: `Config(TlsConnectorMissing)`, nothing sent | none | P0 | 1 | 0.4 |
| `Server::implicit_tls` | `pub fn implicit_tls(host: &str) -> Server` | port 465, `Security::ImplicitTls` | as above | none | P0 | 1 | 0.4 |
| `Server::login` | `pub fn login(self, user: &str, password: impl Into<Secret>) -> Server` | sets credentials; mechanism allowlist `[Plain, Login]` (SCRAM first when the `scram` feature is on) | none | none | P0 | 1 | 0.4 |
| `Report::message_id` | `pub fn message_id(&self) -> &str` | the `Message-ID` sent | none | 0 alloc | P0 | 1 | 0.3 |
| `Error::is_temporary` | `pub fn is_temporary(&self) -> bool` | `disposition() == Disposition::Temporary` | none | 0 alloc | P0 | 1 | 0.3 |

### 8.3 Addresses

```rust
pub struct Address { /* local part and domain, validated, owned */ }
pub struct Mailbox { /* optional display name and an Address */ }
pub struct Domain  { /* validated; ASCII (A-labels) or UTF-8 (U-labels, SMTPUTF8 only) */ }

impl Address {
    pub fn parse(input: &str) -> Result<Address, AddressError>;
    pub fn new(local_part: &str, domain: &str) -> Result<Address, AddressError>;
    pub fn local_part(&self) -> &str;
    pub fn domain(&self) -> &Domain;
    pub fn needs_smtputf8(&self) -> bool;
    pub fn as_str(&self) -> &str;                      // addr-spec as written on the wire
}
impl Mailbox {
    pub fn parse(input: &str) -> Result<Mailbox, AddressError>;   // "Name <a@b>" or "a@b"
    pub fn new(display_name: Option<&str>, address: Address) -> Result<Mailbox, AddressError>;
    pub fn display_name(&self) -> Option<&str>;
    pub fn address(&self) -> &Address;
}
impl Domain {
    pub fn parse(input: &str) -> Result<Domain, AddressError>;
    pub fn is_ascii(&self) -> bool;
    pub fn as_str(&self) -> &str;
}
impl core::str::FromStr for Address { type Err = AddressError; /* parse */ }
impl core::str::FromStr for Mailbox { type Err = AddressError; /* parse */ }
impl core::fmt::Display for Address { /* addr-spec */ }
impl core::fmt::Display for Mailbox { /* header form, display name quoted or encoded */ }

#[non_exhaustive]
pub enum AddressError {
    Empty, TooLong { part: AddressPart, length: usize, limit: usize },
    InvalidLocalPart { position: usize }, InvalidDomain { position: usize },
    LabelTooLong { label: usize }, AddressLiteralNotAllowed, MissingAt,
    ControlCharacter { position: usize },                 // includes CR, LF, NUL
    InternationalDomainUnsupported,                        // until IDNA exists (O-11)
    DisplayNameInvalid { position: usize },
}
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `Address::parse` | RFC 5322 `addr-spec` (via parse-net) restricted to what RFC 5321 accepts in a path: dot-atom or quoted-string local part, domain; no comments, no obsolete syntax, no folding whitespace; lengths per FR-8; a non-ASCII local part or domain is accepted and flagged `needs_smtputf8` | `AddressError` variants | 60 ns for 30 octets, 0 alloc to validate, 1 alloc to own **[est.]** | P0 | 2 | 0.3 |
| `Address::new` | builds from parts with the same checks | as `parse` | as `parse` | P1 | 2 | 0.3 |
| `Address::local_part`, `domain`, `as_str` | borrowed views | none | 0 alloc | P0 | 2 | 0.3 |
| `Address::needs_smtputf8` | true when either part has a non-ASCII octet | none | 0 alloc | P1 | 2 | 0.3 |
| `Mailbox::parse` | `display-name <addr-spec>` or bare `addr-spec`; display name as phrase or quoted-string; RFC 2047 words in the input are **not** decoded (the caller passes text) | `AddressError` | 120 ns **[est.]** | P0 | 2 | 0.3 |
| `Mailbox::new` | display name checked for control characters; stored as given; encoded only on output | `DisplayNameInvalid`, `ControlCharacter` | 1 alloc | P0 | 2 | 0.3 |
| `Domain::parse` | LDH labels, at most 63 octets each, total at most 255; trailing dot refused; address literal only when enabled (`[192.0.2.1]`, `[IPv6:...]`) | `AddressError` | 40 ns **[est.]** | P1 | 3 | 0.3 |
| IDNA conversion of U-label domains to A-labels | not provided until unicode-lang offers UTS 46 (O-11); U-labels accepted only for SMTPUTF8 sends | `InternationalDomainUnsupported` | none | P2 | 2 | 0.5 if the gap closes, else after 1.0 with the reason recorded |
| `Group` syntax (`undisclosed-recipients:;`) | written only as an output form for To when every recipient is Bcc | none | none | P3 | 2 | after 1.0 |

### 8.4 Building messages

```rust
pub struct Message { /* validated headers and body tree; Send + Sync */ }
pub struct MessageBuilder { /* accumulates; every setter validates immediately */ }

impl Message {
    pub fn builder() -> MessageBuilder;
    pub fn text(from: &str, to: &str, subject: &str, body: &str) -> Result<Message, Error>;
    pub fn html(from: &str, to: &str, subject: &str, html: &str, text: &str) -> Result<Message, Error>;
    pub fn message_id(&self) -> &str;
    pub fn headers(&self) -> &Headers;
    pub fn envelope(&self) -> Result<Envelope, Error>;      // derived per 7.11
    pub fn needs_smtputf8(&self) -> bool;
    pub fn has_8bit(&self) -> bool;
    pub fn encoded_len(&self) -> u64;                       // exact serialized length
    pub fn write_to<S: Sink>(&self, sink: &mut S) -> Result<(), Error>;
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error>;
    pub fn prepare(&self) -> Result<PreparedMessage, Error>;
    pub fn prepare_signed(&self, signers: &[DkimSigner], now_unix: u64) -> Result<PreparedMessage, Error>;
}

impl MessageBuilder {
    pub fn from(self, mailbox: impl TryInto<Mailbox>) -> Result<Self, Error>;
    pub fn sender(self, mailbox: impl TryInto<Mailbox>) -> Result<Self, Error>;
    pub fn reply_to(self, mailbox: impl TryInto<Mailbox>) -> Result<Self, Error>;
    pub fn to(self, mailbox: impl TryInto<Mailbox>) -> Result<Self, Error>;
    pub fn cc(self, mailbox: impl TryInto<Mailbox>) -> Result<Self, Error>;
    pub fn bcc(self, mailbox: impl TryInto<Mailbox>) -> Result<Self, Error>;
    pub fn subject(self, text: &str) -> Result<Self, Error>;
    pub fn text(self, body: &str) -> Result<Self, Error>;
    pub fn html(self, body: &str) -> Result<Self, Error>;
    pub fn attachment(self, attachment: Attachment) -> Result<Self, Error>;
    pub fn inline(self, inline: Inline) -> Result<Self, Error>;
    pub fn header(self, name: &str, value: &str) -> Result<Self, Error>;
    pub fn message_id(self, id: &str) -> Result<Self, Error>;
    pub fn message_id_domain(self, domain: &str) -> Result<Self, Error>;
    pub fn date_unix(self, seconds: u64) -> Self;
    pub fn date_unix_with_offset(self, seconds: u64, offset_minutes: i16) -> Result<Self, Error>;
    pub fn in_reply_to(self, id: &str) -> Result<Self, Error>;
    pub fn references(self, ids: &[&str]) -> Result<Self, Error>;
    pub fn list_unsubscribe(self, targets: &[&str], one_click: bool) -> Result<Self, Error>;
    pub fn auto_submitted(self, value: AutoSubmitted) -> Self;
    pub fn allow_8bit(self, allow: bool) -> Self;
    pub fn allow_bidi_controls(self, allow: bool) -> Self;                 // default false (T-35)
    pub fn refuse_address_like_display_names(self, refuse: bool) -> Self;  // default false (T-25)
    pub fn limits(self, limits: MessageLimits) -> Self;
    pub fn body(self, part: Part) -> Result<Self, Error>;  // full control of the MIME tree
    pub fn build(self) -> Result<Message, Error>;
    pub fn build_with(self, random: &mut dyn RandomSource, now_unix: u64) -> Result<Message, Error>; // no_std
}
pub trait RandomSource { fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>; }
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `Message::builder` | empty builder with default `MessageLimits` | none | 0 alloc | P0 | 2 | 0.3 |
| `MessageBuilder::from` | sets the single From mailbox; a second call replaces it | `Address` | 1 alloc | P0 | 2 | 0.3 |
| `MessageBuilder::sender` | RFC 5322 Sender; used as reverse-path when set and no explicit return path exists | `Address` | 1 alloc | P2 | 2 | 0.3 |
| `MessageBuilder::reply_to` | adds a Reply-To mailbox (repeatable, at most `limits.max_recipients`) | `Address`, `Build(TooMany)` | 1 alloc | P1 | 2 | 0.3 |
| `MessageBuilder::to`, `cc`, `bcc` | add recipients; Bcc is never serialized (FR-11) | `Address`, `Build(TooManyRecipients)` | 1 alloc each | P0 | 2 | 0.3 |
| `MessageBuilder::subject` | stores text; refuses CR, LF, NUL, and C0 or C1 controls other than TAB; encoded on output per 7.9 | `Header(ControlCharacter { field: "Subject", position })` | 1 alloc | P0 | 2 | 0.3 |
| `MessageBuilder::text`, `html` | sets the text or HTML body; line endings normalized to CRLF at serialization (LF and CRLF accepted on input, bare CR refused) | `Build(BareCarriageReturn)`, `Build(TooLarge)` | 1 alloc (body copied once) | P0 | 2 | 0.3 |
| `MessageBuilder::attachment` | adds to `multipart/mixed` | `Build(TooManyParts)`, `Build(TooLarge)` | 0 alloc beyond the attachment's own | P0 | 2 | 0.3 |
| `MessageBuilder::inline` | adds to `multipart/related` beside the HTML part; refused at `build` when there is no HTML body | `Build(InlineWithoutHtml)`, `Build(DuplicateContentId)` | as above | P0 | 2 | 0.3 |
| `MessageBuilder::header` | custom header; name checked against RFC 5322 `ftext` (printable ASCII 33 to 126 except `:`), at most 76 octets; value checked for CR, LF, NUL; reserved names refused (From, Sender, Reply-To, To, Cc, Bcc, Subject, Date, Message-ID, MIME-Version, Content-*, DKIM-Signature, Return-Path, Received) | `Header(InvalidName)`, `Header(Reserved)`, `Header(ControlCharacter)`, `Build(TooManyHeaders)` | 2 alloc | P0 | 2 | 0.3 |
| `MessageBuilder::message_id` | caller-supplied id in `id-left@id-right` form (angle brackets added); validated per RFC 5322 `msg-id` (dot-atom-text on both sides; the `no-fold-literal` right side is refused) | `Header(InvalidMessageId)` | 1 alloc | P1 | 2 | 0.3 |
| `MessageBuilder::message_id_domain` | domain for generated ids instead of the From domain | `Address` | 1 alloc | P1 | 2 | 0.3 |
| `MessageBuilder::date_unix` | fixes the Date header time (tests, scheduled sends) | none | 0 alloc | P1 | 2 | 0.3 |
| `MessageBuilder::date_unix_with_offset` | numeric zone offset, -1439 to +1439 minutes | `Header(InvalidDate)` | 0 alloc | P3 | 2 | 0.4 |
| `MessageBuilder::in_reply_to`, `references` | threading headers; each id validated; References at most 50 ids **[est. budget]** | `Header(InvalidMessageId)`, `Build(TooMany)` | 1 alloc each | P1 | 2 | 0.3 |
| `MessageBuilder::list_unsubscribe` | `List-Unsubscribe: <https://...>, <mailto:...>`; with `one_click` also `List-Unsubscribe-Post: List-Unsubscribe=One-Click` (RFC 8058, which requires an HTTPS target); targets checked for `<`, `>`, `,`, whitespace, and control characters | `Header(InvalidUnsubscribe)` | 2 alloc | P2 | 2 | 0.4 |
| `MessageBuilder::auto_submitted` | `Auto-Submitted: auto-generated` or `auto-replied` (RFC 3834); suppresses vacation replies to service mail (O-24) | none | 0 alloc | P2 | 2 | 0.4 |
| `MessageBuilder::allow_8bit` | permits `8bit` for UTF-8 text parts (O-7) | none | 0 alloc | P2 | 2 | 0.4 |
| `MessageBuilder::allow_bidi_controls` | lets bidirectional overrides and isolates (U+202A to U+202E, U+2066 to U+2069) into the Subject and display names; refused at `build` by default (T-35, D-097); right-to-left text and the RLM and LRM marks always pass | `Header(BidiControl { field, position })` without it | one scan per value | P1 | 2 | 0.7 |
| `MessageBuilder::refuse_address_like_display_names` | refuses at `build` a display name containing `@` in From, Sender, Reply-To, To, or Cc (T-25, D-097); off by default | `Header(AddressLikeDisplayName { field })` | one scan per name | P1 | 2 | 0.7 |
| `MessageBuilder::limits` | replaces budgets (8.4.1) | none | 0 alloc | P1 | 2 | 0.3 |
| `MessageBuilder::body` | sets a caller-built `Part` tree instead of text, html, attachment, inline | `Build(DepthExceeded)`, `Build(TooManyParts)` | 0 alloc | P2 | 3 | 0.4 |
| `MessageBuilder::build` | checks From present, at least one recipient, budgets, inline-without-HTML; draws Message-ID and boundaries from the OS CSPRNG; stamps Date from the wall clock (`std`) | `Build(MissingFrom)`, `Build(NoRecipients)`, every budget, `Random` | 2 µs for text plus HTML **[est.]** | P0 | 2 | 0.3 |
| `MessageBuilder::build_with`, `RandomSource` | the same with caller-supplied randomness and time; available without `std` | as `build` | as `build` | P1 | 3 | 0.3 |
| `Message::envelope` | per 7.11 | `Build(NoRecipients)`, `Build(MultipleFrom)` | 1 alloc per recipient | P0 | 2 | 0.3 |
| `Message::encoded_len` | exact byte length of `write_to` output, computed without encoding (base64 and QP lengths computed arithmetically or by one scan) | none | one scan of text parts at about 4 GB/s **[est.]** | P1 | 3 | 0.3 |
| `Message::write_to` | streaming serialization into any `Sink`; deterministic | `Sink(...)` | 0 alloc; base64 at least 2 GB/s, QP at least 800 MB/s **[est.]** | P0 | 3 | 0.3 |
| `Message::to_bytes` | `write_to` a `Vec` sized by `encoded_len` | as `write_to` | 1 alloc | P0 | 2 | 0.3 |
| `Message::prepare` | envelope plus bytes plus flags as a `PreparedMessage` | as `envelope` and `write_to` | 2 alloc **[est.]** | P0 | 2 | 0.4 |
| `Message::prepare_signed` | as `prepare`, then each signer adds its DKIM-Signature header | plus `Dkim(...)` | plus signing cost (8.7) | P0 | 2 | 0.5 |

#### 8.4.1 Parts, attachments, budgets

```rust
pub struct Part { /* content type, headers, body, children */ }
pub enum Body { Text(String), Bytes(Vec<u8>), Multipart(Multipart, Vec<Part>), Source(Box<dyn BodySource>) }
#[non_exhaustive] pub enum Multipart { Mixed, Alternative, Related }
pub struct ContentType { /* type/subtype + parameters, validated token grammar */ }
pub struct Attachment { /* file name, content type, bytes or source */ }
pub struct Inline { /* content id, content type, bytes, optional file name */ }
#[non_exhaustive] pub enum TransferEncoding { SevenBit, EightBit, QuotedPrintable, Base64 }
#[non_exhaustive] pub enum AutoSubmitted { AutoGenerated, AutoReplied }

impl Attachment {
    pub fn new(file_name: &str, content_type: &str, bytes: Vec<u8>) -> Result<Attachment, Error>;
    pub fn from_source(file_name: &str, content_type: &str, len: u64, source: Box<dyn BodySource>) -> Result<Attachment, Error>;
}
impl Inline {
    pub fn new(content_id: &str, content_type: &str, bytes: Vec<u8>) -> Result<Inline, Error>;
}
impl ContentType {
    pub fn parse(input: &str) -> Result<ContentType, HeaderError>;
    pub fn with_parameter(self, name: &str, value: &str) -> Result<ContentType, HeaderError>;
}
pub trait BodySource: Send { fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error>; }

#[non_exhaustive]
pub struct MessageLimits {
    pub max_message_size: u64,     // 25 MiB encoded
    pub max_parts: u16,            // 100
    pub max_depth: u8,             // 8
    pub max_headers: u16,          // 100 custom headers
    pub max_header_value: u32,     // 16 KiB before encoding
    pub max_recipients: u16,       // 100 (To + Cc + Bcc)
    pub max_line_octets: u16,      // 998 (RFC 5322 2.1.1 hard limit)
}
impl Default for MessageLimits { /* values above */ }
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `Attachment::new` | `Content-Disposition: attachment; filename*=utf-8''...` (RFC 2231) when non-ASCII, plain `filename="..."` when ASCII; `name=` parameter on Content-Type for old readers (RFC 2047 encoded when non-ASCII); content type validated as `type/subtype` tokens; base64 always | `Header(InvalidFileName)` (empty, `/`, `\`, control characters, longer than 255 octets), `Header(InvalidContentType)` | 1 alloc for the name | P0 | 2 | 0.3 |
| `Attachment::from_source` | streams from a `BodySource`; `len` is the declared raw length, enforced exactly (short or long reads are errors) | `Build(LengthMismatch)`, `Build(TooLarge)`, source errors | 0 alloc per chunk | P2 | 3 | 0.5 |
| `Inline::new` | `Content-ID: <id>` validated as `msg-id`; `Content-Disposition: inline`; the HTML refers to it as `cid:id` (RFC 2392) | `Header(InvalidContentId)` | 1 alloc | P0 | 2 | 0.3 |
| `ContentType::parse`, `with_parameter` | RFC 2045 token and quoted-string grammar (via parse-net); RFC 2231 encoding for non-ASCII parameter values | `HeaderError` | 80 ns **[est.]** | P1 | 3 | 0.3 |
| `Part`, `Body`, `Multipart` | the MIME tree for Tier 3 callers; validated at `build` (depth, count, size) | `Build(...)` at build | none | P2 | 3 | 0.4 |
| `TransferEncoding` | chosen per 7.9; `Part::transfer_encoding(enc)` forces one (refused when the content does not fit, for example `SevenBit` with non-ASCII) | `Build(EncodingMismatch)` | none | P2 | 3 | 0.4 |
| `BodySource` | pull-based source trait so `no_std` callers can stream without `std::io::Read`; a blanket adapter for `std::io::Read` under `std` | source errors map to `Error::Body` | none | P2 | 3 | 0.5 |
| `MessageLimits` | budgets checked before allocation or encoding | `Build(...)` variants naming the limit and the value | none | P0 | 2 | 0.3 |

#### 8.4.2 Headers and encoding primitives (Tier 3)

```rust
pub struct Headers { /* ordered list of (HeaderName, value) */ }
pub struct HeaderName(/* validated ftext */);
impl Headers {
    pub fn get(&self, name: &str) -> Option<&str>;            // first instance, case-insensitive
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &str)>;
}
pub fn encode_word(text: &str, out: &mut String) -> Result<(), HeaderError>;   // RFC 2047, Q or B (D-082)
pub fn fold_header(name: &str, value: &str, out: &mut Vec<u8>) -> Result<(), HeaderError>;
pub fn base64_encode_lines(input: &[u8], out: &mut [u8]) -> Result<usize, Error>;   // 76-char lines
pub fn quoted_printable_encode(input: &[u8], out: &mut [u8], state: &mut QpState) -> Result<usize, Error>;
pub fn check_header_value(field: &str, value: &str) -> Result<(), HeaderError>;    // CR, LF, NUL, controls
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `Headers::get`, `iter` | read access for callers and for DKIM header selection | none | 0 alloc | P1 | 3 | 0.3 |
| `encode_word` | RFC 2047 encoded words, `UTF-8` charset, at most 75 characters each, split only between UTF-8 scalar values; B when most octets are not ASCII and B is shorter, otherwise Q (D-082) | `HeaderError::ControlCharacter` | 0 alloc when `out` has capacity | P1 | 3 | 0.3 |
| `fold_header` | folds at whitespace to 78 where possible; refuses if any line would exceed 998 | `HeaderError::LineTooLong` | 0 alloc with capacity | P1 | 3 | 0.3 |
| `base64_encode_lines` | standard alphabet, padding, CRLF every 76 characters; streaming with a 3-byte carry in the serializer | `Error::BufferTooSmall` | at least 2 GB/s **[est.]**, 0 alloc | P1 | 3 | 0.3 |
| `quoted_printable_encode`, `QpState` | RFC 2045 6.7 with the extra `.` and `From ` rules (7.9); streaming state across chunks | `Error::BufferTooSmall` | at least 800 MB/s **[est.]**, 0 alloc | P1 | 3 | 0.3 |
| `check_header_value` | the single injection gate every setter uses; exposed so other crates (form-net, web-net contact forms) can check user input early | `HeaderError::ControlCharacter { field, position }` | at least 4 GB/s (SWAR scan) **[est.]** | P0 | 3 | 0.3 |

The base64 and quoted-printable encoders move to encode-lib when it publishes (D-015); the functions above then become re-exports so the API does not change. `encode_word` and `fold_header` are thin wrappers over parse-net's `mail::encode_words` and `mail::fold` (D-014); `encode_word` writes the Q form until parse-net offers the B form without encode-lib (D-015). `check_header_value` adds the field name to parse-net's `mail::check_header_value` result, and refuses C1 controls and U+2028 and U+2029 in unstructured text (T-1).

#### 8.4.3 Serialization sinks

```rust
pub trait Sink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError>;
}
#[non_exhaustive] pub enum SinkError { Full, Io(IoKind) }      // IoKind: std::io::ErrorKind with std, a unit type without
impl Sink for Vec<u8> { /* push; never refuses (D-032) */ }
#[cfg(feature = "std")] pub struct IoSink<W: std::io::Write>(pub W);
#[cfg(feature = "std")] impl<W: std::io::Write> Sink for IoSink<W> { /* write_all */ }
pub struct CountingSink { pub bytes: u64 }               // exact sizes without storing
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `Sink` | output abstraction usable without `std` | `SinkError::Full`, `SinkError::Io(kind)` | none | P1 | 3 | 0.3 |
| `IoSink` | adapter over `std::io::Write` | `SinkError::Io` | none | P1 | 3 | 0.3 |
| `CountingSink` | counts without storing | none | 0 alloc | P2 | 3 | 0.3 |

### 8.5 Envelope and prepared messages

```rust
pub struct Envelope { /* reverse-path, forward-paths, DSN parameters */ }
impl Envelope {
    pub fn new(from: Address, to: &[Address]) -> Result<Envelope, Error>;
    pub fn null_sender(to: &[Address]) -> Result<Envelope, Error>;
    pub fn from(&self) -> Option<&Address>;
    pub fn recipients(&self) -> &[Address];
    pub fn return_path(self, address: Address) -> Self;
    pub fn dsn(self, dsn: Dsn) -> Self;
}
#[non_exhaustive]
pub struct Dsn { pub ret: Option<DsnReturn>, pub envelope_id: Option<String>, pub notify: DsnNotify, pub policy: DsnPolicy }
#[non_exhaustive] pub enum DsnReturn { Full, Headers }
pub struct DsnNotify { /* NEVER, or any of SUCCESS, FAILURE, DELAY */ }
#[non_exhaustive] pub enum DsnPolicy { IfSupported, Required }

pub struct PreparedMessage { /* envelope, message bytes, message id, flags */ }
impl PreparedMessage {
    pub fn from_raw(envelope: Envelope, rfc5322: Vec<u8>) -> Result<PreparedMessage, Error>;
    pub fn envelope(&self) -> &Envelope;
    pub fn bytes(&self) -> &[u8];
    pub fn message_id(&self) -> Option<&str>;
    pub fn needs_smtputf8(&self) -> bool;
    pub fn has_8bit(&self) -> bool;
    pub fn encode(&self) -> Vec<u8>;                       // job payload
    pub fn decode(payload: &[u8]) -> Result<PreparedMessage, Error>;
}
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `Envelope::new` | explicit envelope; recipients deduplicated; at most `max_recipients` | `Build(NoRecipients)`, `Build(TooManyRecipients)` | 1 alloc | P0 | 2 | 0.3 |
| `Envelope::null_sender` | `MAIL FROM:<>` for bounces and auto-replies | as `new` | 1 alloc | P2 | 2 | 0.4 |
| `Envelope::from`, `recipients` | inspection | none | 0 alloc | P0 | 2 | 0.3 |
| `Envelope::return_path` | bounce address distinct from From (bounce handling, 13.3 item 8) | none | 0 alloc | P1 | 2 | 0.3 |
| `Envelope::dsn`, `Dsn`, `DsnReturn`, `DsnNotify`, `DsnPolicy` | RFC 3461 parameters; ENVID and ORCPT xtext-encoded (`+XX` for `+`, `=`, and octets outside 33 to 126); ENVID at most 100 characters (RFC 3461 4.4) | `Build(InvalidDsn)` | 0 alloc on send | P2 | 2 | 0.4 |
| `PreparedMessage::from_raw` | wraps caller bytes after checking: CRLF only (no bare CR or LF), every line at most 998 octets, a header block ending in an empty line, a From header present; flags computed by one scan | `Build(BareLineFeed)`, `Build(BareCarriageReturn)`, `Build(LineTooLong)`, `Build(NoHeaderBlock)`, `Build(MissingFrom)` | one scan at about 4 GB/s **[est.]** | P1 | 2 | 0.3 |
| `PreparedMessage::envelope`, `bytes`, `message_id`, `needs_smtputf8`, `has_8bit` | inspection | none | 0 alloc | P0 | 2 | 0.4 |
| `PreparedMessage::encode` | `b"SMTPNET1"` magic, version byte, flags, length-prefixed envelope fields, message bytes, CRC-32C trailer; deterministic | none | 1 alloc; CRC at about 8 GB/s **[est.]** | P1 | 2 | 0.4 |
| `PreparedMessage::decode` | verifies magic, version, and every length against budgets before allocation, then the CRC-32C, then re-validates addresses; an unknown version is refused | `Error::Payload(Corrupt)`, `Payload(UnknownVersion)`, `Payload(TooLarge)`, address errors | 1 alloc | P1 | 2 | 0.4 |

CRC-32C is implemented in smtp-net in about 40 lines (table-driven) unless a first-party crate offers it by 0.4; task-io plans its own (task-io `PLAN.md` 5.10), and a shared crate is a candidate (O-22).

### 8.6 Protocol core (Tier 3, sans-IO)

```rust
pub struct Session { /* state machine; Send, not Sync */ }
#[derive(Clone, Copy)] pub struct Millis(pub u64);       // the caller's monotonic clock

#[non_exhaustive]
pub struct SessionConfig {
    pub client_name: ClientName,                // EHLO argument
    pub security: SessionSecurity,              // Plaintext, StartTlsRequired, ImplicitTls
    pub auth: Option<Auth>,                     // credentials and mechanism allowlist
    pub timeouts: Timeouts,
    pub pipelining: bool,                       // use when offered (default true)
    pub chunking: bool,                         // use BDAT when offered (default true)
    pub recipient_policy: RecipientPolicy,      // Any (default) or All
    pub reply_limits: ReplyLimits,
    pub output_capacity: usize,                 // default 4 KiB
}
#[non_exhaustive] pub enum ClientName { Domain(Domain), AddressLiteral(core::net::IpAddr) }
#[non_exhaustive] pub enum SessionSecurity { Plaintext { peer_is_loopback: bool }, StartTlsRequired, ImplicitTls }
#[non_exhaustive] pub enum RecipientPolicy { Any, All }

impl Session {
    pub fn new(config: SessionConfig, now: Millis) -> Result<Session, Error>;
    pub fn receive(&mut self, input: &[u8], now: Millis) -> Result<usize, Error>;
    pub fn transmit(&self) -> &[u8];
    pub fn transmitted(&mut self, n: usize);
    pub fn poll_event(&mut self) -> Option<Event>;
    pub fn deadline(&self) -> Option<Millis>;
    pub fn on_timeout(&mut self, now: Millis) -> Result<(), Error>;
    pub fn tls_established(&mut self, info: TlsInfo, now: Millis) -> Result<(), Error>;
    pub fn begin(&mut self, envelope: &Envelope, flags: BodyFlags, size: u64, now: Millis) -> Result<(), Error>;
    pub fn body(&mut self, chunk: &[u8], now: Millis) -> Result<usize, Error>;
    pub fn end_body(&mut self, now: Millis) -> Result<(), Error>;
    pub fn reset(&mut self, now: Millis) -> Result<(), Error>;
    pub fn noop(&mut self, now: Millis) -> Result<(), Error>;
    pub fn quit(&mut self, now: Millis) -> Result<(), Error>;
    pub fn state(&self) -> SessionState;
    pub fn capabilities(&self) -> Option<&Capabilities>;
    pub fn is_secure(&self) -> bool;
    pub fn wants_read(&self) -> bool;          // a reply is outstanding
}

#[non_exhaustive]
pub enum Event {
    Greeting(Reply),
    Ready { secure: bool, authenticated: bool },
    StartTls,                                   // driver: run the TLS handshake now, then tls_established()
    Authenticated { mechanism: MechanismName },
    RecipientAccepted { index: usize },
    RecipientRejected { index: usize, reply: Reply, disposition: Disposition },
    BodyWanted,                                 // driver: call body() until done, then end_body()
    Delivered { reply: Reply, accepted: usize, rejected: usize, deferred: usize },
    Deferred { recipients: core::ops::Range<usize> },   // too many recipients; the driver starts a new transaction
    TransactionFailed(Error),
    Closed { error: Option<Error> },
}
#[non_exhaustive] pub enum SessionState { AwaitGreeting, Negotiating, NeedTls, Authenticating, Ready, InTransaction, Body, AwaitDataEnd, Closing, Closed }
#[non_exhaustive] pub struct TlsInfo { pub protocol: TlsProtocol, pub exporter: Option<[u8; 32]> }
#[non_exhaustive] pub struct BodyFlags { pub eight_bit: bool, pub smtputf8: bool }
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `Session::new` | allocates the output and reply buffers once; state `AwaitGreeting` (with `ImplicitTls`, the driver calls `tls_established` before the first `receive`) | `Config(...)` for an impossible combination (for example AUTH with `Plaintext { peer_is_loopback: false }`) | 2 alloc, then none | P0 | 3 | 0.3 |
| `Session::receive` | parses as many complete reply lines as `input` holds, advances state, queues events and output; returns bytes consumed; stops right after the STARTTLS 220 reply so the driver can verify that nothing follows | `Protocol(...)`; server refusals become events, and the error that closes the session is also returned | 50 ns per single-line reply, 400 ns for a 10-line EHLO, 0 alloc **[est.]** | P0 | 3 | 0.3 |
| `Session::transmit`, `transmitted` | pending output and its acknowledgement | none (`transmitted` saturates at the pending length) | 0 alloc | P0 | 3 | 0.3 |
| `Session::poll_event` | FIFO of at most 4 plus the recipient count; bounded by `max_recipients` | none | 0 alloc after `new` | P0 | 3 | 0.3 |
| `Session::deadline`, `on_timeout` | the stage deadline; `on_timeout` closes the session with `Timeout { stage }` when `now` is past it, otherwise does nothing | `Timeout` | 0 alloc | P0 | 3 | 0.3 |
| `Session::tls_established` | valid only in `NeedTls` (STARTTLS) or at start (implicit TLS); discards capabilities; queues EHLO | `Usage(WrongState)` | 0 alloc | P0 | 3 | 0.4 |
| `Session::begin` | validates the envelope against capabilities (SIZE, SMTPUTF8, 8BITMIME, DSN), then queues MAIL, RCPT, and DATA or BDAT per 7.6 | `MessageTooLarge`, `ExtensionRequired(...)`, `Usage(WrongState)` | 40 ns per command, 0 alloc **[est.]** | P0 | 3 | 0.3 |
| `Session::body` | accepts up to the free output capacity, dot-stuffing (DATA) or framing (BDAT); refuses bare CR or LF | `Build(BareLineFeed)` and `Build(BareCarriageReturn)` (permanent), `Usage(WrongState)` | at least 4 GB/s on lines without a leading dot **[est.]**, 0 alloc | P0 | 3 | 0.3 |
| `Session::end_body` | writes `CRLF . CRLF` (the first CRLF only if the body did not end in CRLF) or `BDAT 0 LAST` when needed; marks the `possibly_delivered` point | `Usage(WrongState)` | 0 alloc | P0 | 3 | 0.3 |
| `Session::reset` | RSET (after a failed BDAT, or to abandon a transaction) | `Usage(WrongState)` | 0 alloc | P0 | 3 | 0.3 |
| `Session::noop` | NOOP, for drivers that want a liveness probe | `Usage(WrongState)` | 0 alloc | P2 | 3 | 0.4 |
| `Session::quit` | QUIT; `Closed` after 221 or EOF | none | 0 alloc | P0 | 3 | 0.3 |
| `Session::state`, `capabilities`, `is_secure`, `wants_read` | inspection | none | 0 alloc | P1 | 3 | 0.3 |
| `Event` | as listed; `Deferred` carries the indices left for a further transaction (FR-42) | none | none | P0 | 3 | 0.3 |
| `SessionConfig`, `ClientName`, `SessionSecurity`, `RecipientPolicy`, `BodyFlags`, `SessionState` | configuration and state; `Default` gives `ClientName::AddressLiteral(127.0.0.1)`, `StartTlsRequired`, RFC timeouts | none | none | P0 | 3 | 0.3 |
| `TlsInfo::exporter` | 32 bytes of `tls-exporter` (RFC 9266) for SCRAM-PLUS; `None` when not available | none | none | P3 | 3 | after 1.0 |
| LMTP mode (`SessionConfig::lmtp`) | LHLO, per-recipient replies after end-of-data (RFC 2033) | as session | as session | P3 | 3 | after 1.0 |

#### 8.6.1 Replies and capabilities

```rust
#[derive(Clone, Copy, PartialEq, Eq)] pub struct ReplyCode(u16);          // validated
#[derive(Clone, Copy, PartialEq, Eq)] pub struct EnhancedCode { pub class: u8, pub subject: u16, pub detail: u16 }
pub struct Reply { /* code, enhanced, bounded text, line count, truncated flag */ }
impl ReplyCode {
    pub fn new(code: u16) -> Option<ReplyCode>;
    pub fn get(self) -> u16;
    pub fn is_positive(self) -> bool;          // 2yz or 3yz
    pub fn is_transient(self) -> bool;         // 4yz
    pub fn is_permanent(self) -> bool;         // 5yz
}
impl Reply {
    pub fn code(&self) -> ReplyCode;
    pub fn enhanced(&self) -> Option<EnhancedCode>;
    pub fn lines(&self) -> impl Iterator<Item = &[u8]>;
    pub fn text_lossy(&self) -> impl core::fmt::Display + '_;    // sanitized
    pub fn is_truncated(&self) -> bool;
}
pub struct ReplyParser { /* streaming, budgets */ }
impl ReplyParser {
    pub fn new(limits: ReplyLimits, enhanced: bool) -> ReplyParser;
    pub fn push(&mut self, input: &[u8]) -> Result<(usize, Option<Reply>), ProtocolError>;
}
#[non_exhaustive] pub struct ReplyLimits { pub max_line: u16, pub max_lines: u16, pub max_total: u32 }   // 1000, 64, 8192

pub struct Capabilities { /* parsed EHLO */ }
impl Capabilities {
    pub fn parse(ehlo: &Reply) -> Result<Capabilities, ProtocolError>;
    pub fn has(&self, extension: Extension) -> bool;
    pub fn size_limit(&self) -> Option<u64>;            // None: not advertised; Some(0): no fixed limit
    pub fn auth_mechanisms(&self) -> impl Iterator<Item = MechanismName> + '_;
    pub fn unknown(&self) -> impl Iterator<Item = &[u8]> + '_;
}
#[non_exhaustive]
pub enum Extension { Pipelining, Size, EightBitMime, Smtputf8, Chunking, BinaryMime, Dsn, EnhancedStatusCodes, StartTls, Auth, RequireTls }
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `ReplyCode` | validated three-digit code (first digit 2 to 5, second 0 to 5) | `None` from `new` | 0 alloc | P0 | 3 | 0.3 |
| `EnhancedCode` | class 2, 4, or 5; subject and detail 0 to 999 (the RFC 3463 grammar allows up to three digits) | a parse failure leaves it `None` | 0 alloc | P0 | 3 | 0.3 |
| `Reply` | owned copy of at most `max_total` octets of text | none | 1 alloc per reply kept in a report; none inside the session | P0 | 3 | 0.3 |
| `Reply::text_lossy` | bytes outside printable ASCII shown as `?` (threat T-30) | none | 0 alloc | P0 | 3 | 0.3 |
| `ReplyParser::push` | streaming parser; returns consumed bytes and a reply when complete; correct when input is split at every byte | `ProtocolError::{MalformedReply, InconsistentReply, ReplyTooLong, BareLineFeed, Nul}` | as `receive` | P0 | 3 | 0.3 |
| `Capabilities::parse` | the first line is the server's domain and greeting; each further line one keyword with parameters; keywords case-insensitive; the `SIZE` value parsed with checked arithmetic (refused above 2^53; 0 means no fixed limit); the AUTH list parsed into known names, unknown names kept | `ProtocolError::MalformedCapability` | 300 ns for 10 lines **[est.]** | P0 | 3 | 0.3 |
| `Capabilities::has`, `size_limit`, `auth_mechanisms`, `unknown` | inspection | none | 0 alloc | P0 | 3 | 0.3 |
| `Extension` | the keywords smtp-net acts on | none | none | P0 | 3 | 0.3 |

#### 8.6.2 SASL

```rust
pub struct Auth { pub credentials: Credentials, pub mechanisms: MechanismList }
#[non_exhaustive] pub enum Credentials {
    Password { user: String, password: Secret },
    OAuth2 { user: String, token: Secret },
}
impl Credentials {
    pub fn password(user: &str, password: impl Into<Secret>) -> Credentials;
    pub fn oauth2(user: &str, token: impl Into<Secret>) -> Credentials;
}
#[non_exhaustive] pub enum MechanismName { Plain, Login, XOAuth2, OAuthBearer, ScramSha256, ScramSha256Plus, Other }
pub struct MechanismList { /* ordered, at most 8 */ }
pub struct Secret { /* Zeroizing<Vec<u8>>; Debug prints "Secret(<redacted>)" */ }

pub trait Mechanism: Send {
    fn name(&self) -> &'static str;
    fn initial_response(&mut self, out: &mut Vec<u8>) -> Result<bool, SaslError>;   // false: none
    fn step(&mut self, challenge: &[u8], out: &mut Vec<u8>) -> Result<Step, SaslError>;
    fn verify_success(&mut self, final_data: Option<&[u8]>) -> Result<(), SaslError>;
}
#[non_exhaustive] pub enum Step { Continue, Done }
```

| Mechanism or item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| PLAIN (RFC 4616) | `AUTH PLAIN <base64(authzid NUL authcid NUL passwd)>` with an empty authzid; initial response unless the line would exceed the limit; user and password checked for NUL | `SaslError::InvalidCredential` (NUL), `AuthFailed(reply)` | 200 ns plus one round trip **[est.]** | P0 | 2 | 0.4 |
| LOGIN (draft-murchison-sasl-login-00) | `AUTH LOGIN`, then user and password, each as a base64 reply to a 334; the server's challenge text is ignored (it is informational) | as PLAIN | three round trips | P1 | 2 | 0.4 |
| XOAUTH2 (Google) | initial response `base64("user=" user 0x01 "auth=Bearer " token 0x01 0x01)`; on a 334 error challenge, keeps the decoded JSON for the report (bounded to 1 KiB, parsed only for `status`), sends an empty line, expects 535 | `AuthFailed { reply, detail }` | one round trip | P2 | 2 | 0.5 |
| SCRAM-SHA-256 (RFC 7677, RFC 5802) | client-first with a 24-byte random nonce (base64); verifies that the server nonce extends ours; PBKDF2 with the server's salt and iteration count (refused below 4,096, the RFC 7677 minimum the server should use, and above 1,000,000 by budget **[est. ceiling]**); sends the client proof; verifies the server signature in constant time; user and password ASCII-only until SASLprep exists (O-12) | `SaslError::{ServerNonceMismatch, IterationsOutOfRange, ServerSignatureMismatch, NonAsciiCredential}`, `AuthFailed` | PBKDF2: about 4,096 HMAC-SHA-256 iterations at about 1 µs each, so about 4 ms **[est.]**; two round trips | P2 | 2 | 0.5 |
| SCRAM-SHA-256-PLUS (RFC 9266) | as SCRAM with `p=tls-exporter` channel binding from `TlsInfo::exporter` | as SCRAM, `ChannelBindingUnavailable` | as SCRAM | P3 | 2 | after 1.0 |
| OAUTHBEARER (RFC 7628) | GS2 header and the `auth=Bearer` key-value form | as XOAUTH2 | one round trip | P3 | 2 | after 1.0 |
| CRAM-MD5 (RFC 2195), DIGEST-MD5 (Historic, RFC 6331), NTLM, GSSAPI | **not implemented**: CRAM-MD5 and DIGEST-MD5 rest on MD5 and require the server to store reversible secrets; NTLM is proprietary and deprecated; GSSAPI needs a Kerberos stack. Callers with a real need implement `Mechanism` | n/a | n/a | refused by design (not graded) | n/a | n/a |
| `Mechanism` trait | custom SASL mechanisms; the session base64-encodes and decodes, enforces line limits, and handles `*` cancellation (RFC 4954: a cancelled exchange gets 501) | `SaslError::Custom` | none | P2 | 3 | 0.5 |
| `Secret` | zeroized on drop (crypt-io `Zeroizing`); `Debug` and `Display` redacted; `From<String>`, `From<&str>`, `From<Vec<u8>>`; with feature `key-vault`, `Secret::from_handle` | none | 1 alloc | P0 | 2 | 0.4 |
| `Auth`, `Credentials`, `MechanismName`, `MechanismList`, `Step` | configuration types | `Config(TooManyMechanisms)` above 8 | none | P0 | 2 | 0.4 |

**Selection rule (FR-35).** The client walks its own `MechanismList` in order and picks the first one the server advertises. Default list: `[ScramSha256 (with the feature), Plain, Login]`. If none matches: `Error::AuthUnavailable { offered }`, permanent. The server's order is ignored. PLAIN and LOGIN are equally weak once TLS is up (both send the password); SCRAM never sends it.

### 8.7 DKIM (feature `dkim`)

```rust
pub struct DkimSigner { /* domain, selector, key, canonicalization, headers, expiry, identity */ }
pub struct DkimKey { /* crypt-io signing key; zeroized */ }
#[non_exhaustive] pub enum Canonicalization { Simple, Relaxed }
#[non_exhaustive] pub enum DkimAlgorithm { Ed25519Sha256, RsaSha256 }

impl DkimKey {
    pub fn ed25519_from_pkcs8_pem(pem: &str) -> Result<DkimKey, DkimError>;
    pub fn ed25519_from_pkcs8_der(der: &[u8]) -> Result<DkimKey, DkimError>;
    pub fn ed25519_from_seed(seed: &[u8; 32]) -> Result<DkimKey, DkimError>;
    pub fn rsa_from_pem(pem: &str) -> Result<DkimKey, DkimError>;            // PKCS#8 or PKCS#1
    pub fn rsa_from_der(der: &[u8]) -> Result<DkimKey, DkimError>;
    pub fn algorithm(&self) -> DkimAlgorithm;
    pub fn dns_record(&self) -> String;                                      // "v=DKIM1; k=...; p=..."
}
impl DkimSigner {
    pub fn new(domain: &str, selector: &str, key: DkimKey) -> Result<DkimSigner, DkimError>;
    pub fn canonicalization(self, header: Canonicalization, body: Canonicalization) -> Self;
    pub fn headers(self, names: &[&str]) -> Result<Self, DkimError>;        // replaces the default list
    pub fn oversign(self, names: &[&str]) -> Result<Self, DkimError>;
    pub fn expiry(self, seconds: u32) -> Self;                              // x = t + seconds
    pub fn identity(self, address: &Address) -> Result<Self, DkimError>;     // i=, inside d= or a subdomain
    pub fn sign(&self, message: &[u8], now_unix: u64) -> Result<String, DkimError>;   // the header line
    pub fn sign_into(&self, message: &[u8], now_unix: u64, out: &mut Vec<u8>) -> Result<(), DkimError>;
}
pub struct BodyCanonicalizer { /* streaming, no_std */ }
pub struct HeaderCanonicalizer;
#[non_exhaustive]
pub enum DkimError {
    InvalidDomain, InvalidSelector, InvalidHeaderName, KeyFormat, KeyTooSmall { bits: u32, minimum: u32 },
    KeyTooLarge { bits: u32 }, MissingFrom, HeaderBlockTooLarge, MalformedMessage { line: usize },
    IdentityOutsideDomain, Signing,
}
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `DkimKey::ed25519_*` | loads through crypt-io `sign-ed25519`; the seed form serves keys stored in key-vault | `KeyFormat` | 20 µs to load **[est.]** | P0 | 2 | 0.5 |
| `DkimKey::rsa_from_pem`, `rsa_from_der` | PKCS#8 or PKCS#1; modulus 2048 bits or more (RFC 8301 3.2 SHOULD; D-066), at most 4096 (RFC 8301: verifiers must handle 1024 to 4096); encrypted PKCS#8 refused | `KeyFormat`, `KeyTooSmall`, `KeyTooLarge` | 100 µs to load **[est.]** | P0 | 2 | 0.5 |
| `DkimKey::algorithm` | which `a=` value the key produces | none | 0 alloc | P1 | 2 | 0.5 |
| `DkimKey::dns_record` | Ed25519: `v=DKIM1; k=ed25519; p=<44 base64 characters>` (RFC 8463 4.2); RSA: `v=DKIM1; k=rsa; p=<base64 SubjectPublicKeyInfo>`; the docs say RSA records above 255 octets are published as several TXT strings | none | 1 alloc | P2 | 2 | 0.5 |
| `DkimSigner::new` | domain validated as a `Domain`; selector as dot-separated LDH labels; defaults: relaxed/relaxed, the 7.10 header and oversign lists, no `x=`, no `i=` | `InvalidDomain`, `InvalidSelector` | 2 alloc | P0 | 2 | 0.5 |
| `DkimSigner::canonicalization` | header and body each simple or relaxed | none | 0 alloc | P1 | 2 | 0.5 |
| `DkimSigner::headers`, `oversign` | replace the lists; `from` always kept even if omitted; names validated | `InvalidHeaderName` | 1 alloc | P2 | 2 | 0.5 |
| `DkimSigner::expiry` | adds `x=` | none | 0 alloc | P2 | 2 | 0.5 |
| `DkimSigner::identity` | adds `i=`; refused outside `d=` (RFC 6376 3.5) | `IdentityOutsideDomain` | 1 alloc | P3 | 2 | 0.5 |
| `DkimSigner::sign` | parses the header block (bounded at 64 KiB); streams the body through the body canonicalizer into SHA-256; builds `h=` from present headers plus oversigned names; hashes the selected headers bottom-up per RFC 6376 5.4.2, then the signature header with empty `b=`; signs; folds; returns the complete header line with CRLF | `MissingFrom`, `HeaderBlockTooLarge`, `MalformedMessage`, `Signing` | Ed25519: 25 µs plus hashing; RSA-2048: 1.5 ms plus hashing **[est.]**; body hashing at SHA-256 speed (about 1.5 GB/s with SHA-NI **[est.]**) | P0 | 2 | 0.5 |
| `DkimSigner::sign_into` | appends to a caller buffer | as `sign` | 0 alloc with capacity | P2 | 3 | 0.5 |
| `BodyCanonicalizer`, `HeaderCanonicalizer` | streaming canonicalizers, correct at every split point; `no_std` | none | relaxed body at least 2 GB/s before hashing **[est.]** | P1 | 3 | 0.5 |
| DKIM over raw bytes (FR-53) | `sign` works on any RFC 5322 bytes that pass the `PreparedMessage::from_raw` checks | as `sign` | as `sign` | P2 | 2 | 0.5 |

### 8.8 Client driver (feature `client`)

```rust
pub struct Server { /* host, port, security, credentials, timeouts, EHLO name, TLS options, signers, gate */ }
pub struct ServerBuilder { /* every option */ }
#[non_exhaustive] pub enum Security { PlaintextLoopback, StartTls, ImplicitTls }

impl Server {
    pub fn local() -> Server;
    pub fn starttls(host: &str) -> Server;
    pub fn implicit_tls(host: &str) -> Server;
    pub fn login(self, user: &str, password: impl Into<Secret>) -> Server;
    pub fn builder(host: &str, security: Security) -> ServerBuilder;
}
impl ServerBuilder {
    pub fn port(self, port: u16) -> Self;
    pub fn credentials(self, credentials: Credentials) -> Self;
    pub fn mechanisms(self, list: &[MechanismName]) -> Result<Self, Error>;
    pub fn client_name(self, name: ClientName) -> Self;
    pub fn timeouts(self, timeouts: Timeouts) -> Self;
    pub fn tls_connector(self, connector: impl TlsConnector + 'static) -> Self;   // 8.8.1
    #[cfg(feature = "tls")] pub fn tls(self, config: tls_net::ClientConfig) -> Self; // when tls-net publishes (D-025)
    pub fn dangerous_disable_certificate_verification(self) -> Self; // FR-31, D-024
    pub fn allow_insecure_remote(self, allow: bool) -> Self;         // second flag of D-024
    pub fn dkim(self, signer: DkimSigner) -> Self;                   // feature "dkim"; repeatable
    pub fn gate(self, gate: impl SendGate + 'static) -> Self;
    pub fn pipelining(self, use_it: bool) -> Self;
    pub fn chunking(self, use_it: bool) -> Self;
    pub fn recipient_policy(self, policy: RecipientPolicy) -> Self;
    pub fn max_messages_per_connection(self, n: u32) -> Self;
    pub fn observer(self, observer: impl Observer + 'static) -> Self;
    pub fn build(self) -> Result<Server, Error>;
}

pub struct Client { /* one connection and its Session; Send */ }
impl Client {
    pub fn connect(server: &Server) -> Result<Client, Error>;
    pub fn send(&mut self, message: &Message) -> Result<Report, Error>;
    pub fn send_prepared(&mut self, message: &PreparedMessage) -> Result<Report, Error>;
    pub fn noop(&mut self) -> Result<(), Error>;
    pub fn is_open(&self) -> bool;
    pub fn capabilities(&self) -> &Capabilities;
    pub fn close(self) -> Result<(), Error>;                         // QUIT; Drop also attempts QUIT, bounded by 1 s
}

pub struct Pool { /* bounded set of Clients for one Server; Send + Sync */ }
impl Pool {
    pub fn new(server: Server, max_connections: usize) -> Result<Pool, Error>;
    pub fn send(&self, message: &Message) -> Result<Report, Error>;
    pub fn send_prepared(&self, message: &PreparedMessage) -> Result<Report, Error>;
    pub fn idle(&self) -> usize;
}

pub struct Report { /* message id, per-recipient outcomes, final reply, timings, security */ }
impl Report {
    pub fn message_id(&self) -> &str;
    pub fn accepted(&self) -> impl Iterator<Item = &Address>;
    pub fn rejected(&self) -> impl Iterator<Item = (&Address, &Reply, Disposition)>;
    pub fn final_reply(&self) -> &Reply;
    pub fn was_secure(&self) -> bool;
    pub fn tls_protocol(&self) -> Option<TlsProtocol>;
    pub fn elapsed(&self) -> core::time::Duration;
}
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `Server::builder`, `ServerBuilder::build` | every option of 7.12; `build` checks that credentials with `PlaintextLoopback` are used only when the host is a loopback literal or `localhost`; port 0 refused; at most 8 mechanisms; at most 4 DKIM signers | `Config(...)` naming the option | none | P1 | 2 | 0.4 (0.3 for the plaintext subset) |
| `ServerBuilder::port` | overrides the default port | none | none | P0 | 2 | 0.3 |
| `ServerBuilder::credentials`, `mechanisms` | credentials and the allowlist of FR-35 | `Config(TooManyMechanisms)` | none | P1 | 2 | 0.4 |
| `ServerBuilder::client_name` | EHLO argument (O-6) | none | none | P1 | 2 | 0.3 |
| `ServerBuilder::timeouts` | per 8.10 | none | none | P1 | 2 | 0.3 |
| `ServerBuilder::tls_connector` | the TLS engine for STARTTLS and implicit TLS (8.8.1); the server name given to it is always the configured host, never the EHLO greeting | none | none | P0 | 2 | 0.4 |
| `ServerBuilder::tls` | feature `tls`: tls-net's verified client connector built from a tls-net client configuration (roots, minimum version); the default connector when the feature is on | none | none | P1 | 2 | the release after tls-net publishes (D-025) |
| `ServerBuilder::dangerous_disable_certificate_verification`, `allow_insecure_remote` | for test relays only: accepted for a loopback host; any other host also needs `allow_insecure_remote(true)`; the same rule in every build profile (D-024); passed to the connector, which must honour it | `Config(InsecureNotAllowed)` | none | P3 | 2 | 0.4 |
| `ServerBuilder::dkim` | signers applied by `send` when the message is not already prepared (O-23) | none | none | P1 | 2 | 0.5 |
| `ServerBuilder::gate` | pacing (8.9) | none | none | P1 | 2 | 0.4 |
| `ServerBuilder::pipelining`, `chunking`, `recipient_policy`, `max_messages_per_connection` | behaviour switches with the defaults of 8.6 and 7.12 | none | none | P2 | 2 | 0.4 |
| `ServerBuilder::observer` | structured events (7.15) | none | none | P2 | 3 | 0.5 |
| `Client::connect` | resolves, connects within the connect timeout, checks loopback for plaintext, runs implicit TLS if configured, drives the session to `Ready` | `Connect`, `PlaintextRefused`, `Tls(...)`, `StartTlsUnavailable`, `StartTlsInjection`, `AuthUnavailable`, `AuthFailed`, `Timeout`, `Rejected` | 1 RTT plaintext; plus the TLS handshake (1 RTT with TLS 1.3) and 2 RTT for STARTTLS and the second EHLO; plus AUTH | P1 | 2 | 0.3 |
| `Client::send`, `send_prepared` | gate, then a transaction per 7.6; reconnects once if the server had closed an idle connection before accepting anything (7.12); handles `Deferred` with further transactions | every send error | the round trips of 7.6; CPU about 10 µs per message beyond encoding **[est.]** | P1 | 2 | 0.3 |
| `Client::noop`, `is_open`, `capabilities` | liveness and inspection | `Timeout`, `Rejected` | 1 RTT for `noop` | P2 | 2 | 0.4 |
| `Client::close` | QUIT and close | as `noop` | 1 RTT | P1 | 2 | 0.3 |
| `Pool` | at most `max_connections` clients; checkout is a lock-free stack of idle clients (atomics) with a bounded wait; idle clients older than the idle limit are closed on checkout (no timer thread, NFR-7); a failed client is dropped, not returned | `PoolExhausted` (temporary) when every connection stays busy past the wait bound | checkout 50 ns uncontended **[est.]** | P2 | 2 | 0.5 |
| `Report` and its methods | per-recipient outcomes, final reply, TLS facts, timings | none | 1 alloc per rejected recipient | P0 | 1 and 2 | 0.3 |

#### 8.8.1 TLS seam

```rust
pub trait TlsConnector: Send + Sync {
    /// A new client session for `server_name` (the configured host). The engine verifies the
    /// server's certificate against that name unless `insecure` is set (D-024).
    fn session(&self, server_name: &str, insecure: bool) -> Result<Box<dyn net_io::TlsSession>, TlsSetupError>;
}
#[non_exhaustive] pub struct TlsSetupError { pub kind: TlsFailure }
#[non_exhaustive] pub enum TlsProtocol { Tls12, Tls13, Other(u16) }
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `TlsConnector` | the engine for STARTTLS and implicit TLS. The driver runs the handshake and the record layer over net-io's sans-IO `TlsSession` (`step`, `encrypt`, `close`), the same seam tls-net implements for servers (D-026). `insecure` is true only after `ServerBuilder` accepted `dangerous_disable_certificate_verification` under the rule of D-024 | `TlsSetupError` becomes `Error` with kind `Tls(..)`, permanent | one session per connection | P0 | 3 | 0.4 |
| `TlsProtocol` | the negotiated version as reported by the engine, in `Report::tls_protocol` and `Observer` events | none | none | P1 | 2 | 0.4 |
| tls-net connector | with feature `tls`: `Server::starttls` and `Server::implicit_tls` use tls-net's verified connector by default; without it, `ServerBuilder::tls_connector` must be called, or `build` fails with `Config(TlsConnectorMissing)` | as above | as above | P0 | 1 | the release after tls-net publishes a client session (D-025) |

### 8.9 Pacing (send gate)

```rust
pub trait SendGate: Send + Sync {
    fn admit(&self, recipients: u32, now_unix_ms: u64) -> Admission;
    fn refund(&self, recipients: u32, now_unix_ms: u64) {}      // admitted message not sent
    fn admit_envelope(&self, envelope: &Envelope, now_unix_ms: u64) -> Admission { /* admit(count) */ }
    fn refund_envelope(&self, envelope: &Envelope, now_unix_ms: u64) { /* refund(count) */ }
}
impl<A: SendGate, B: SendGate> SendGate for (A, B) { /* both must admit */ }
#[non_exhaustive] pub enum Admission { Admit, RetryAfter(core::time::Duration) }

pub struct HourlyLimit { /* 60 one-minute buckets, atomics */ }
#[non_exhaustive] pub enum CountUnit { Messages, Recipients }
impl HourlyLimit {
    pub fn messages(per_hour: u32) -> HourlyLimit;
    pub fn recipients(per_hour: u32) -> HourlyLimit;
    pub fn remaining(&self, now_unix_ms: u64) -> u32;
}
impl SendGate for HourlyLimit { /* ... */ }

#[cfg(feature = "std")] pub struct DomainLimit { /* per recipient domain, bounded table */ }
impl DomainLimit {
    pub fn per_domain(per_hour: u32) -> DomainLimit;
    pub fn max_domains(self, n: usize) -> DomainLimit;          // default 1,024
    pub fn remaining(&self, domain: &str, now_unix_ms: u64) -> u32;
}
impl SendGate for DomainLimit { /* admit_envelope */ }
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `SendGate`, `Admission` | called before connecting and before each transaction; `RetryAfter` becomes `Error::Throttled` with `retry_after` (temporary); `refund` is called when an admitted message is then not sent (connection failure before MAIL was accepted) | none | none | P1 | 2 | 0.4 |
| `HourlyLimit::messages`, `recipients`, `CountUnit` | rolling 60-minute window of one-minute buckets; admission is a CAS loop on the current bucket after subtracting expired buckets; never over-admits under any thread count (loom-tested); `retry_after` is the time until enough of the oldest bucket expires; per process (several processes share nothing; documented, O-21) | none | 30 ns uncontended **[est.]**, 0 alloc | P1 | 2 | 0.4 |
| `HourlyLimit::remaining` | inspection | none | 0 alloc | P2 | 2 | 0.4 |
| `SendGate::admit_envelope`, `refund_envelope` | what the client calls; they default to `admit` and `refund` with the recipient count, so a count-based gate needs nothing more | none | none | P1 | 2 | 0.7 |
| `(A, B)` as a `SendGate` | admits only what both admit; when the second refuses, the first is refunded | none | the two gates' costs | P1 | 2 | 0.7 |
| `DomainLimit::per_domain`, `max_domains`, `remaining` | at most `per_hour` recipients per recipient domain (ASCII case ignored) in any 60 minutes, in 13 five-minute buckets (a count may be kept up to 5 minutes late, never dropped early); a message is admitted for all its domains or none; the table holds `max_domains` domains and forgets the least recently used (PLAN 10.3, D-098) | none | one lock and one hash per domain of the message **[est.]**; about 250 octets per domain | P1 | 2 | 0.7 |
| throttle-net adapter | documented example in `docs/API.md`, not a dependency (3.5) | n/a | n/a | P3 | docs | 0.5 |

### 8.10 Timeouts

```rust
#[non_exhaustive]
pub struct Timeouts {
    pub connect: Duration, pub greeting: Duration, pub command: Duration, pub tls_handshake: Duration,
    pub mail: Duration, pub rcpt: Duration, pub data_init: Duration, pub data_block: Duration,
    pub data_end: Duration, pub idle: Duration, pub total: Option<Duration>,
}
impl Timeouts { pub fn rfc5321() -> Timeouts; pub fn local() -> Timeouts; }
impl Default for Timeouts { /* rfc5321() */ }
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `Timeouts::rfc5321` | the values of 7.8 | none | none | P0 | 2 | 0.3 |
| `Timeouts::local` | shorter values for loopback submission, documented as below RFC 5321 | none | none | P1 | 2 | 0.3 |
| `Timeouts.total` | whole-send bound; on expiry the error is `Timeout` with stage `Total` | `Timeout` | none | P1 | 2 | 0.3 |

### 8.11 Observability (Tier 3)

```rust
pub trait Observer: Send + Sync { fn event(&self, event: &ObservedEvent<'_>); }
#[non_exhaustive] pub enum ObservedEvent<'a> {
    Connected { peer: core::net::SocketAddr }, Secure { protocol: TlsProtocol },
    Reply { stage: Stage, code: ReplyCode, enhanced: Option<EnhancedCode> },
    Delivered { message_id: &'a str, accepted: usize, rejected: usize, elapsed: Duration },
    Failed { stage: Option<Stage>, disposition: Disposition, possibly_delivered: bool },
    SecurityEvent { kind: SecurityEventKind },
}
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Ver |
|---|---|---|---|---|---|---|
| `Observer`, `ObservedEvent` | never receives secrets or bodies; reply text excluded (codes only) | none | one virtual call per event | P2 | 3 | 0.5 |
| `SecurityEventKind` | `StartTlsMissing`, `StartTlsInjection`, `CertificateRejected`, `MalformedReply`, `ReplyBudgetExceeded`, `AuthExchange`, `PlaintextRefused`, `Other`, for bouncer-io or the error core | none | none | P2 | 3 | 0.5 |

### 8.12 Errors

```rust
#[non_exhaustive]
pub struct Error { /* kind, stage, reply, disposition, possibly_delivered, retry_after, security_event */ }
impl Error {
    pub fn kind(&self) -> &ErrorKind;
    pub fn stage(&self) -> Option<Stage>;
    pub fn reply(&self) -> Option<&Reply>;
    pub fn disposition(&self) -> Disposition;
    pub fn is_temporary(&self) -> bool;
    pub fn is_permanent(&self) -> bool;
    pub fn possibly_delivered(&self) -> bool;
    pub fn retry_after(&self) -> Option<Duration>;
    pub fn is_security_event(&self) -> bool;
    pub fn recipients(&self) -> &[(Address, Reply, Disposition)];   // per-recipient detail when relevant
}
#[non_exhaustive] pub enum Disposition { Temporary, Permanent }
#[non_exhaustive] pub enum Stage { Connect, Greeting, Ehlo, Helo, StartTls, TlsHandshake, Auth, Mail, Rcpt, Data, Body, DataEnd, Bdat, Rset, Noop, Quit, Total }
#[non_exhaustive]
pub enum ErrorKind {
    Address(AddressError), Header(HeaderError), Build(BuildError), Dkim(DkimError), Payload(PayloadError),
    Config(ConfigError), Usage(UsageError), Random, Body,
    Connect(std::io::ErrorKind), Io(std::io::ErrorKind), Tls(TlsFailure), Timeout,
    PlaintextRefused, StartTlsUnavailable, StartTlsInjection,
    AuthUnavailable, AuthFailed, Sasl(SaslError),
    Protocol(ProtocolError), Rejected,                     // the server refused; see reply()
    AllRecipientsRejected, MessageTooLarge { size: u64, limit: u64 },
    ExtensionRequired(Extension), Throttled, PoolExhausted, ConnectionClosed, BufferTooSmall,
}
```

`ErrorKind::Connect` and `ErrorKind::Io` carry `std::io::ErrorKind` only with the `std` feature; without it the core never produces them (the core does no I/O). The `Error` value keeps its details in one allocation, so `Result<T, Error>` is pointer-sized (D-034).

| Item | Behaviour | Grade | Tier | Ver |
|---|---|---|---|---|
| `Error` | one struct with a kind enum, so the classification fields are uniform; `Display` says what was refused and what to do (for example: "the server does not offer STARTTLS; TLS is required for this server, so nothing was sent. Check the port (587 for STARTTLS, 465 for implicit TLS) or the server's TLS configuration."); never contains credentials, message bodies, or reply bytes outside printable ASCII | P0 | 1 to 3 | 0.3 |
| `Error::disposition`, `is_temporary`, `is_permanent`, `possibly_delivered`, `retry_after`, `is_security_event` | per 7.7; `possibly_delivered` is true only after the end-of-data sequence was written | P0 | 1 | 0.3 |
| `Error::kind`, `stage`, `reply` | inspection | P0 | 2 | 0.3 |
| `Error::recipients` | per-recipient replies for `AllRecipientsRejected` and for partial failures under `RecipientPolicy::All` | P0 | 2 | 0.3 |
| `Disposition`, `Stage` | as listed | P0 | 2 | 0.3 |
| `ErrorKind` and the nested error enums | each variant documented with cause and remedy, one test each (NFR-12) | P0 | 2 | 0.3 |
| `std::error::Error` impl, `source()` chained to nested errors | under `std` | P0 | 2 | 0.3 |
| `ErrorKind::Random` | the OS random source failed; temporary | P0 | 2 | 0.3 |

#### 8.12.1 Nested error enums

Each enum is `#[non_exhaustive]`, implements `Display` (what was refused and what to do) and, with `std`, `std::error::Error`, and converts into `Error` with the disposition shown. Positions are byte offsets into the input that was refused.

```rust
#[non_exhaustive] pub enum HeaderError {                                  // Permanent
    ControlCharacter { field: &'static str, position: usize },          // CR, LF, NUL, C0/C1, U+2028, U+2029
    InvalidName, Reserved, LineTooLong, InvalidMessageId, InvalidDate,
    InvalidUnsubscribe, InvalidFileName, InvalidContentType, InvalidContentId,
    BidiControl { field: &'static str, position: usize },              // T-35, 0.7
    AddressLikeDisplayName { field: &'static str },                    // T-25, 0.7
}
#[non_exhaustive] pub enum BuildError {                                   // Permanent
    MissingFrom, MultipleFrom, NoRecipients, TooManyRecipients { limit: u16 },
    TooMany { what: &'static str, limit: u32 }, TooManyParts, TooManyHeaders,
    TooLarge { size: u64, limit: u64 }, DepthExceeded, InlineWithoutHtml, DuplicateContentId,
    BareCarriageReturn { position: u64 }, BareLineFeed { position: u64 }, LineTooLong { line: u64 },
    NoHeaderBlock, LengthMismatch { declared: u64, actual: u64 }, EncodingMismatch, InvalidDsn,
}
#[non_exhaustive] pub enum ConfigError {                                  // Permanent
    PortZero, InvalidHost, PlaintextHostNotLoopback, CredentialsWithoutSecurity,
    TooManyMechanisms, TooManySigners, InsecureNotAllowed, TlsConnectorMissing,
    AuthWithPlaintextRemote,
}
#[non_exhaustive] pub enum UsageError { WrongState { state: SessionState }, BodyAfterEnd, Closed }   // Permanent (a caller bug)
#[non_exhaustive] pub enum ProtocolError {                                // Temporary, security_event
    MalformedReply, InconsistentReply, ReplyTooLong, BareLineFeed, Nul, UnexpectedReply,
    MalformedCapability, MalformedChallenge, TooManySteps,
}
#[non_exhaustive] pub enum PayloadError { Corrupt, UnknownVersion { version: u8 }, TooLarge, Truncated }   // Permanent
#[non_exhaustive] pub enum SaslError {                                    // Permanent unless noted
    InvalidCredential, NonAsciiCredential, InvalidChallenge, ServerNonceMismatch,
    IterationsOutOfRange { iterations: u32 }, ServerSignatureMismatch, ChannelBindingUnavailable,
    Custom(&'static str),
}
#[non_exhaustive] pub enum TlsFailure {
    CertificateRejected,    // Permanent: verification failed, wrong name, version refused
    ProtocolMismatch,       // Permanent: the peer does not speak TLS (implicit TLS to a plaintext port)
    Handshake,              // Temporary: I/O failure or timeout during the handshake
    Closed,                 // Temporary: the peer closed the TLS stream without close_notify
    Setup,                  // Permanent: the connector could not build a session
}
#[non_exhaustive] pub enum SinkError { Full, Io(IoKind) }               // Permanent for Full, Temporary for Io
```

| Item | Behaviour | Grade | Tier | Ver |
|---|---|---|---|---|
| `HeaderError`, `BuildError`, `UsageError`, `ProtocolError`, `SinkError` | as listed; each variant has a test that produces it (NFR-12) | P0 | 2 | 0.3 |
| `ConfigError` | variants for options added in 0.4 appear in 0.4 | P0 | 2 | 0.3 |
| `PayloadError` | `PreparedMessage::decode` | P1 | 2 | 0.4 |
| `SaslError`, `TlsFailure`, `TlsSetupError` | AUTH and TLS | P0 | 2 | 0.4 |
| `DkimError` | 8.7 | P0 | 2 | 0.5 |

### 8.13 Test support (feature `testing`)

```rust
pub struct ScriptedServer { /* sans-IO peer driven by a Transcript */ }
pub struct Transcript { /* ordered expected client lines and server replies */ }
impl Transcript {
    pub fn parse(text: &str) -> Result<Transcript, Error>;   // "C: EHLO ..." / "S: 250-..." lines
}
impl ScriptedServer {
    pub fn new(transcript: Transcript) -> ScriptedServer;
    pub fn run(&mut self, session: &mut Session) -> Result<(), ScriptMismatch>;   // pumps bytes both ways
    pub fn run_split(&mut self, session: &mut Session, split: usize) -> Result<(), ScriptMismatch>;
}

pub struct TestServer { /* blocking loopback SMTP server on 127.0.0.1:0 */ }
impl TestServer {
    pub fn start() -> Result<TestServer, Error>;
    pub fn builder() -> TestServerBuilder;
    pub fn port(&self) -> u16;
    pub fn server(&self) -> Server;                           // a Server pointing at it
    pub fn received(&self) -> Vec<ReceivedMessage>;          // envelope + bytes as received
    pub fn transcript(&self) -> String;                      // AUTH redacted
    pub fn client_waits(&self) -> usize;                     // with Fault::RoundTrip: round trips the client waited
    pub fn messages(&self) -> usize;                         // accepted, counted with or without record
}
impl TestServerBuilder {
    pub fn record(self, keep: bool) -> Self;                 // false: keep no messages or transcript (a soak)
}
pub struct TestServerBuilder { /* extensions offered, AUTH, TLS certificate, faults */ }
#[non_exhaustive] pub enum Fault {
    ReplyAt { stage: Stage, reply: &'static str }, CloseAt(Stage), CloseAfterDataEnd, DelayAt { stage: Stage, by: Duration },
    InjectAfterStartTls(&'static [u8]), OmitStartTls, MalformedReply(Stage), OversizedReply(Stage),
    ExtraReply(Stage), RejectRecipient(usize), TooManyRecipientsAfter(usize), SlowDrip { bytes_per_second: u32 },
    RoundTrip(Duration),
}
```

| Item | Behaviour | Grade | Tier | Ver |
|---|---|---|---|---|
| `Transcript`, `ScriptedServer`, `ScriptMismatch` | conversation transcripts as data (one file per scenario in `tests/transcripts/`), run whole and split at every byte | P1 | 3 | 0.3 |
| `TestServer`, `TestServerBuilder` | a real listener (std `TcpListener`, test-only) that speaks enough SMTP to accept, record, and misbehave on command; extensions and AUTH mechanisms configurable; TLS with fixture certificates in `tests/fixtures/` (feature `tls`) | P1 | 2 | 0.3 (TLS at 0.4) |
| `Fault` | fault injection for every threat test in section 10 | P1 | 2 | 0.3 |
| `ReceivedMessage` | envelope, bytes after dot-unstuffing, the extensions used | P1 | 2 | 0.3 |

### 8.14 Constants

| Constant | Value | Grade | Tier | Ver |
|---|---|---|---|---|
| `VERSION` | `env!("CARGO_PKG_VERSION")` | P0 | 1 | 0.1 (exists) |
| `PORT_SUBMISSION` | 587 (RFC 6409) | P1 | 2 | 0.3 |
| `PORT_SUBMISSIONS` | 465 (RFC 8314) | P1 | 2 | 0.3 |
| `PORT_SMTP` | 25 | P1 | 2 | 0.3 |
| `MAX_COMMAND_LINE` | 512 (RFC 5321 4.5.3.1.4) | P1 | 3 | 0.3 |
| `MAX_AUTH_LINE` | 12,288 (RFC 4954) | P1 | 3 | 0.4 |
| `MAX_TEXT_LINE` | 1,000 including CRLF (RFC 5321 4.5.3.1.6) | P1 | 3 | 0.3 |
| `MAX_HEADER_LINE` | 998 excluding CRLF (RFC 5322 2.1.1) | P1 | 3 | 0.3 |
| `RECOMMENDED_HEADER_LINE` | 78 (RFC 5322 2.1.1) | P1 | 3 | 0.3 |
| `MAX_LOCAL_PART` | 64 | P1 | 3 | 0.3 |
| `MAX_DOMAIN` | 255 | P1 | 3 | 0.3 |
| `MAX_PATH` | 256 | P1 | 3 | 0.3 |
| `MAX_ENCODED_WORD` | 75 (RFC 2047 section 2) | P1 | 3 | 0.3 |
| `MIME_LINE_LENGTH` | 76 (RFC 2045 6.7 and 6.8) | P1 | 3 | 0.3 |


### 8.15 Examples by use case

These examples are the design-lock contract for the README and the rustdoc. Each one becomes a doctest in the version that ships it; the examples that need a server run against `TestServer`.

**Local submission (cPanel Exim on loopback, 0.3).**

```rust
let msg = smtp_net::Message::text(
    "Example <no-reply@example.com>",
    "user@example.org",
    "Confirm your email address",
    "Open this link to confirm: https://example.com/confirm/abc123",
)?;
let report = smtp_net::send_local(&msg)?;
println!("accepted as {}", report.message_id());
```

**Local submission on port 587 with AUTH over verified loopback (0.4).**

```rust
let server = smtp_net::Server::builder("127.0.0.1", smtp_net::Security::PlaintextLoopback)
    .port(587)
    .credentials(smtp_net::Credentials::password("no-reply@example.com", password))
    .build()?;
smtp_net::send(&server, &msg)?;
```

**Remote relay with STARTTLS (0.4; the engine from feature `tls` or `tls_connector`).**

```rust
let server = smtp_net::Server::starttls("mail.example.com").login("no-reply@example.com", password);
let report = smtp_net::send(&server, &msg)?;
assert!(report.was_secure());
```

**Several messages on one connection (0.3).**

```rust
let mut client = smtp_net::Client::connect(&smtp_net::Server::local())?;
for msg in &batch {
    match client.send(msg) {
        Ok(report) => println!("{} accepted", report.message_id()),
        Err(e) if e.is_temporary() => requeue(msg, e.retry_after()),
        Err(e) => dead_letter(msg, e),
    }
}
client.close()?;
```

**Job payloads (0.4).** Build and sign once, store the bytes, send them from the worker; retries send identical bytes with the same `Message-ID`.

```rust
let payload = msg.prepare()?.encode();                         // in the request handler
// ... stored by the job system, read back by a worker ...
let prepared = smtp_net::PreparedMessage::decode(&payload)?;   // refuses a corrupt payload
match smtp_net::send_prepared(&server, &prepared) {
    Ok(_) => {}
    Err(e) if e.possibly_delivered() => log_possible_duplicate(&e),
    Err(e) if e.is_temporary() => retry_later(e.retry_after()),
    Err(e) => dead_letter(e),
}
```

**DKIM (0.5).**

```rust
let key = smtp_net::DkimKey::ed25519_from_pkcs8_pem(&pem)?;
println!("publish at s1._domainkey.example.com: {}", key.dns_record());
let signer = smtp_net::DkimSigner::new("example.com", "s1", key)?;
let prepared = msg.prepare_signed(&[signer], now_unix)?;
```

**Pacing below a host's hourly cap (0.4).**

```rust
let server = smtp_net::Server::builder("127.0.0.1", smtp_net::Security::PlaintextLoopback)
    .gate(smtp_net::HourlyLimit::recipients(450))
    .build()?;
match smtp_net::send(&server, &msg) {
    Err(e) if matches!(e.kind(), smtp_net::ErrorKind::Throttled) => delay_job(e.retry_after()),
    other => handle(other),
}
```

**A custom SASL mechanism (0.5).** Implement `Mechanism`; the session base64-encodes and decodes, enforces line limits, and cancels with `*` on error.

**A sans-IO driver (0.3).** Any transport can drive a `Session`:

```rust
let mut session = smtp_net::Session::new(config, now())?;
loop {
    let out = session.transmit();
    if !out.is_empty() { let n = socket.write(out)?; session.transmitted(n); }
    while let Some(event) = session.poll_event() {
        match event {
            smtp_net::Event::Ready { .. } => session.begin(&envelope, flags, size, now())?,
            smtp_net::Event::BodyWanted => { /* call body() until the message is written, then end_body() */ }
            smtp_net::Event::Delivered { .. } => session.quit(now())?,
            smtp_net::Event::Closed { error } => return error.map_or(Ok(()), Err),
            _ => {}
        }
    }
    if session.wants_read() {
        let n = socket.read_until(session.deadline(), &mut buf)?;
        let consumed = session.receive(&buf[..n], now())?;
        // a partial consume happens only right after a STARTTLS 220: any byte left over is an injection (T-6)
    }
}
```

### 8.16 Changes since the design lock

Each change is recorded in `dev/PLAN.md` section 19.

| Version | Change | Decision |
|---|---|---|
| 0.3.0 | `Session::tls_established`, `TlsInfo`, `TlsProtocol`, and the session's STARTTLS and implicit TLS states ship in 0.3 (listed 0.4); the driver's TLS stays 0.4 | D-037 |
| 0.3.0 | New: `Session::connection_lost(&mut self, cause: ErrorKind) -> Error` (Tier 3, P0): the driver reports EOF or a transport failure; the session closes and returns the classified error | D-038 |
| 0.3.0 | New: `Address::parse_allowing_literal(input: &str) -> Result<Address, AddressError>` (Tier 2, P3); `Domain::is_literal`, `Address::same_mailbox`, `Capabilities::auth_mechanism_names`, `Capabilities::unknown_count`, `Reply::line_count`, `Session::tls_protocol`, `Headers::len`, `Headers::is_empty`, `ContentType::essence`, `ContentType::parameter`, `Attachment::file_name`, `Attachment::bytes`, `Inline::content_id`, `Envelope::needs_smtputf8`, `Server::host`, `Server::port`, `Server::security`, `Server::timeouts`, `BodyFlags::new`, `TlsInfo::new`, `TlsProtocol::from_wire`, `Millis::after`, `Stage::name`, `Extension::keyword` (inspection helpers) | D-039 |
| 0.3.0 | `encode_word` returns `Result<(), HeaderError>` (a control character is refused) | D-015 |
| 0.3.0 | `Message::prepare`, the `PreparedMessage` accessors, `MessageBuilder::allow_8bit`, `Session::noop` ship in 0.3 | D-042 |
| 0.3.0 | Attachment `name=` uses RFC 2231 like `filename=` | D-040 |
| 0.3.0 | Out-of-grammar EHLO keywords are kept as unknown, not `MalformedCapability` | D-041 |
| 0.3.0 | `ConfigError::TlsConnectorMissing` and `ConfigError::BufferTooSmall` are listed; `UsageError` is `WrongState { state }` or `Closed`; `ErrorKind::StartTlsUnavailable` and `StartTlsInjection` ship with the session's TLS states | D-037, D-049 |
| 0.3.0 | `Part`, `Body`, `Multipart` stay internal until `MessageBuilder::body` (0.4); `Multipart` is public as a name only | none (on schedule) |
| 0.3.0 | Test support: `ScriptedServer::run(&self, session, messages: &[PreparedMessage]) -> Result<ScriptOutcome, ScriptMismatch>` (and `run_split`) drives the transactions itself; `ScriptOutcome`, `TestServer::connections`, `TestServerBuilder::{extensions, fault, refuse_ehlo, start}`, `Fault::CloseAfterMessages(n)` | D-048 |
| 0.4.0 | `Security::{StartTls, ImplicitTls}` work through `TlsConnector`; feature `tls` (default) uses tls-net's `TlsClient`; `ServerBuilder::tls(tls_net::TlsClient)` replaces the sketched `tls(tls_net::ClientConfig)`; with tls-net, `dangerous_disable_certificate_verification` fails with `Tls(Setup)` | D-051, D-052 |
| 0.4.0 | `Event::Deferred { recipients: Vec<usize> }` (was a `Range`); `Event::Authenticated`; `Session::is_authenticated`; `SessionConfig::{auth, chunking}` | D-055 |
| 0.4.0 | BDAT as `BDAT n` then `BDAT 0 LAST` (or `BDAT 2 LAST` and CRLF); with CHUNKING, `begin`'s `size` must be exact (`Build(LengthMismatch)` otherwise) | D-054 |
| 0.4.0 | New: `send_prepared` (Tier 1), `Server::to_builder`, `ServerBuilder::{credentials, mechanisms, tls_connector, tls, allow_insecure_remote, gate, chunking}`, `Credentials::{password, user}`, `Secret::{new, len, is_empty}`, `MechanismName::as_str`, `MechanismList::{new, iter}`, `Auth::{new, mechanisms}`, `SaslError`, `MAX_AUTH_LINE`, `TlsFailure`, `TlsSetupError::new`, `PayloadError`, `Dsn::{new, ret, envelope_id, required, return_content, envelope_id_value, notify, policy}`, `DsnNotify::{NEVER, SUCCESS, FAILURE, DELAY}`, `Envelope::{null_sender, dsn, dsn_parameters}`, `PreparedMessage::{encode, decode}`, `SendGate`, `Admission`, `HourlyLimit::{messages, recipients, remaining, unit}`, `CountUnit`, `MessageBuilder::{date_unix_with_offset, list_unsubscribe, auto_submitted, body}`, `AutoSubmitted`, `Part::{text, binary, multipart, from_attachment, from_inline, transfer_encoding}` | D-057, D-058, D-060, D-061 |
| 0.4.0 | `ErrorKind::{Tls, Throttled, AuthUnavailable, AuthFailed, Sasl, Payload}`; `ConfigError::{TooManyMechanisms, InsecureNotAllowed}` | none |
| 0.4.0 | Test support: `TestTls`, `TestServerBuilder::{starttls, implicit_tls, tls_name, tls_engine, auth}`, `TestServer::server_builder`, `ReceivedMessage::{rcpt_parameters, secure, chunked, user}`, `Fault::RejectCertificate`, transcripts take `C: <RAW n>` | D-059 |
| 0.4.0 | Fixed: `Address` equality compares the whole address; `MessageBuilder::date_unix` is honoured | D-062 |
| 0.5.0 | No `DkimSigner::allow_rsa_1024`: crypt-io refuses RSA under 2048 bits; `KeyTooSmall` reports the size. New: `DkimKey::rsa_bits`, `DkimSigner::{domain, selector, key}`, `DKIM_RSA_MIN_BITS`, `DKIM_RSA_MAX_BITS`, `Canonicalization::name`, `DkimAlgorithm::name`; `identity` takes `&Address` | D-066 |
| 0.5.0 | The canonicalizers build without the `dkim` feature (`no_std`); `HeaderCanonicalizer::new(mode)` and `canonicalize(field, &mut Vec<u8>)`; `BodyCanonicalizer::{new, update, finish}` with an output closure | D-067 |
| 0.5.0 | New: `PreparedMessage::sign(self, signers, now_unix)` signs raw input (FR-53); `Message::prepare_signed` is `prepare` then `sign`; `ServerBuilder::dkim` (at most 4, `Config(TooManyDkimSigners)`) | D-068 |
| 0.5.0 | `Credentials::{OAuth2, Custom}`, `Credentials::oauth2`; `MechanismName::{XOAuth2, ScramSha256, Other}`; the default allowlist is `[ScramSha256 (feature scram), Plain, Login, XOAuth2, Other]` filtered by credential kind; `Auth::scram_nonce`; `SaslError::{InvalidServerMessage, ServerNonceMismatch, IterationsOutOfRange, ServerSignatureMismatch, ServerError, NonAsciiCredential, NonceMissing, ResponseTooLong, InvalidMechanismName, Custom}` | D-072, D-073 |
| 0.5.0 | `Error::auth_detail` gives the XOAUTH2 error status (the sketched `AuthFailed { reply, detail }` is `AuthFailed` with `Error::reply` and `Error::auth_detail`) | D-074 |
| 0.5.0 | `Mechanism`, `Step`, and `CustomMechanism::{new, name}` (a factory; names checked) for `Credentials::Custom`; `verify_success` gets `None` (SMTP carries no success data) | D-075 |
| 0.5.0 | `ServerBuilder::observer`; `Event::Reply` and `SessionConfig::reply_events` (opt-in); `ObservedEvent::Failed.stage` is `Option<Stage>`; `SecurityEventKind::{AuthExchange, PlaintextRefused, Other}` | D-076 |
| 0.5.0 | `Pool::{new, wait_limit, send, send_prepared, idle, server}`; `ErrorKind::PoolExhausted`; `ConfigError::PoolSize` | D-077 |
| 0.5.0 | `Attachment::from_source` (feature `std`), `Attachment::{len, is_empty, is_streamed}`, `BodySource` returning `SourceError`, `ReadSource`; `ErrorKind::Source(SourceError)` | D-078 |
| 0.5.0 | Test support: `TestServerBuilder::oauth2`, SCRAM-SHA-256 in `TestServer` with the `scram` feature, `Fault::BadScramSignature`, transcripts take `C: <EMPTY>` | none |
| 0.5.1 | RFC 2047 words choose Q or B per header; parse-net 0.9.1 | D-082 |
| 0.6.0 | `Envelope` shares its addresses behind an `Arc` (clone is a reference count; `Session::begin` allocates nothing); `Session` memory is `SessionConfig::output_capacity` plus about 3 KiB | D-084, D-085 |
| 0.6.0 | Test support: `Fault::RoundTrip(Duration)` (every byte to the client arrives that much later; a client pays it once per wait), `TestServer::client_waits`; `TestServer` sets `TCP_NODELAY` | D-089 |
| 0.7.0 | New: `MessageBuilder::{allow_bidi_controls, refuse_address_like_display_names}`, `HeaderError::{BidiControl, AddressLikeDisplayName}`; bidi overrides and isolates in the Subject and display names are refused by default | D-097 |
| 0.7.0 | New: `DomainLimit` (feature `std`), `SendGate::{admit_envelope, refund_envelope}` (default methods), `(A, B)` as a gate; the client asks through `admit_envelope` | D-098 |
| 0.7.0 | `ProtocolError::UnexpectedReply` also covers a reply whose class cannot answer its command (250 to DATA, 354 to MAIL): temporary, the session closes (was a permanent `Rejected`) | D-096 |
| 0.7.0 | Test support: `TestServerBuilder::record`, `TestServer::messages` | D-095 |
