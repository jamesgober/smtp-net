<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>smtp-net</b><br>
    <sub><sup>API REFERENCE</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>API</span>
        <span>&nbsp;│&nbsp;</span>
        <a href="./ARCHITECTURE.md" title="Architecture"><b>ARCHITECTURE</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./SECURITY.md" title="Security"><b>SECURITY</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./DELIVERABILITY.md" title="Deliverability"><b>DELIVERABILITY</b></a>
    </sup>
</div>
<br>

A task-oriented tour of the 0.8 API, covering every public item. The
rustdoc on [docs.rs](https://docs.rs/smtp-net) has the same items with more
detail; every Rust block here is compiled as a doctest with all features
enabled, and run unless it is marked `no_run` (those reach a real relay).
Examples that send use the crate's own `TestServer`, so they run without a
mail server.

- [Setup](#setup)
- [Sending one message](#sending-one-message)
- [Messages](#messages)
  - [Tier 1 constructors](#tier-1-constructors)
  - [The builder](#the-builder)
  - [Attachments and inline images](#attachments-and-inline-images)
  - [Reading a built message](#reading-a-built-message)
  - [Budgets](#budgets)
- [Addresses](#addresses)
- [Servers](#servers)
  - [Constructors](#constructors)
  - [The server builder](#the-server-builder)
  - [Credentials and AUTH](#credentials-and-auth)
  - [Timeouts](#timeouts)
  - [TLS](#tls)
- [Connections](#connections)
  - [Client: one connection](#client-one-connection)
  - [Pool: shared connections](#pool-shared-connections)
  - [Report](#report)
- [Errors](#errors)
  - [Error](#error)
  - [ErrorKind and the nested enums](#errorkind-and-the-nested-enums)
  - [Replies](#replies)
- [Job payloads](#job-payloads)
  - [PreparedMessage](#preparedmessage)
  - [Envelope](#envelope)
  - [DSN](#dsn)
- [DKIM](#dkim)
- [Pacing](#pacing)
- [Observability](#observability)
- [The `protocol` module: the sans-IO session](#the-protocol-module-the-sans-io-session)
  - [Session](#session)
  - [Events and states](#events-and-states)
  - [Reply parsing and capabilities](#reply-parsing-and-capabilities)
  - [SASL](#sasl)
- [The `mime` module](#the-mime-module)
  - [Parts](#parts)
  - [Headers](#headers)
  - [Encoders](#encoders)
  - [Sinks and randomness](#sinks-and-randomness)
- [The `dkim` module](#the-dkim-module)
- [The `testing` module](#the-testing-module)
- [Constants](#constants)
- [Migrating from 0.7](#migrating-from-07)
- [Changes since the design lock](#changes-since-the-design-lock)

## Setup

```toml
[dependencies]
smtp-net = "0.8"
# local submission only, without building rustls:
# smtp-net = { version = "0.8", default-features = false, features = ["client"] }
# with DKIM signing and SCRAM-SHA-256:
# smtp-net = { version = "0.8", features = ["dkim", "scram"] }
```

| Feature | Default | Adds |
|---|---|---|
| `std` | yes | the OS random source (`mime::OsRandom`), the system clock in `MessageBuilder::build`, `std::error::Error`, `mime::IoSink`, `mime::ReadSource`, `DomainLimit` |
| `client` | yes | the blocking driver over net-io: `send`, `send_local`, `send_prepared`, `Client`, `Pool`, `Server` |
| `tls` | yes | STARTTLS and implicit TLS with tls-net (rustls, Mozilla roots) as the default engine |
| `dkim` | no | `DkimKey`, `DkimSigner`, `PreparedMessage::sign`, `ServerBuilder::dkim` (crypt-io over AWS-LC; needs a C compiler) |
| `scram` | no | SCRAM-SHA-256, first in the default mechanism list (pure Rust) |
| `testing` | no | the `testing` module |

Without default features, addresses, messages, the session, and the DKIM
canonicalizers build `no_std` with `alloc`.

The crate root holds what an application uses. Three modules hold the
surface for drivers, custom bodies, and other libraries: `protocol`,
`mime`, and `dkim`. `testing` is the fourth.

## Sending one message

`send_local` submits to the mail server on this machine (`127.0.0.1:25`,
plaintext only to a verified loopback peer). `send` submits to any
[`Server`](#servers). Both build the envelope from the message, connect,
send, say QUIT, and close. Plain `?` works into `Box<dyn Error>`:

```rust,no_run
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let msg = smtp_net::Message::text(
        "Example <no-reply@example.com>",
        "user@example.org",
        "Confirm your email address",
        "Open this link to confirm: https://example.com/confirm/abc123",
    )?;
    smtp_net::send_local(&msg)?;

    let relay = smtp_net::Server::starttls("smtp.example.com").login("no-reply@example.com", "app-password");
    smtp_net::send(&relay, &msg)?;
    Ok(())
}
```

The same against the crate's test server, which runs here:

```rust
use smtp_net::testing::TestServer;

let server = TestServer::start()?;
let msg = smtp_net::Message::text("no-reply@example.com", "user@example.org", "Hi", "Hello")?;
let report = smtp_net::send(&server.server(), &msg)?;
assert_eq!(report.accepted().len(), 1);
assert_eq!(server.received()[0].recipients, ["user@example.org"]);
# Ok::<(), smtp_net::Error>(())
```

| Function | Does | Errors |
|---|---|---|
| `send(server: &Server, message: &Message) -> Result<Report, Error>` | signs with the server's DKIM signers, asks its gate, connects, sends, closes | every `ErrorKind` |
| `send_local(message: &Message) -> Result<Report, Error>` | `send(&Server::local(), message)` | as `send` |
| `send_prepared(server: &Server, message: &PreparedMessage) -> Result<Report, Error>` | sends stored bytes as they are, never re-signs (the job path) | as `send`, without the build errors |

Decide what to do with a failure from the error itself:

```rust,no_run
# let msg = smtp_net::Message::text("no-reply@example.com", "user@example.org", "Hi", "Hello")?;
match smtp_net::send_local(&msg) {
    Ok(report) => println!("accepted as {}", report.message_id()),
    Err(e) if e.possibly_delivered() => eprintln!("the server may have it: {e}"),
    Err(e) if e.is_temporary() => eprintln!("retry later: {e}"),
    Err(e) => eprintln!("do not retry: {e}"),
}
# Ok::<(), smtp_net::Error>(())
```

## Messages

A `Message` is a built RFC 5322 message: headers, a MIME body, a generated
`Message-ID` and `Date`, and the envelope recipients (including Bcc, which
is never written into the message). It is `Send + Sync` and immutable.

### Tier 1 constructors

| Constructor | Builds |
|---|---|
| `Message::text(from: &str, to: &str, subject: &str, body: &str) -> Result<Message, Error>` | one `text/plain; charset=utf-8` part |
| `Message::html(from: &str, to: &str, subject: &str, html: &str, text: &str) -> Result<Message, Error>` | `multipart/alternative`, text first, HTML last |

Errors: `Address` for a mailbox that does not parse, `Header` for a control
character in the subject, `Build` for a budget, `Random` if the OS random
source failed. Both need feature `std` (clock and random source).

```rust
let msg = smtp_net::Message::html(
    "Example <no-reply@example.com>",
    "user@example.org",
    "Reset your password",
    "<p>Open <a href=\"https://example.com/reset/abc\">this link</a>.</p>",
    "Open this link: https://example.com/reset/abc",
)?;
assert_eq!(msg.headers().get("Subject"), Some("Reset your password"));
# Ok::<(), smtp_net::Error>(())
```

### The builder

`Message::builder() -> MessageBuilder`. Every setter that takes text
validates it and returns `Result<Self, Error>`: CR, LF, and other control
characters are refused, never stripped. The address setters take anything
that converts into a `Mailbox` (`&str`, `Mailbox`, `Address`).

```rust
let msg = smtp_net::Message::builder()
    .from("Billing <billing@example.com>")?
    .reply_to("support@example.com")?
    .to("customer@example.org")?
    .cc("accounts@example.org")?
    .bcc("archive@example.com")?          // envelope only
    .subject("Your receipt")?
    .text("Thank you for your order.")?
    .html("<p>Thank you for your order.</p>")?
    .header("X-Order", "1234")?
    .auto_submitted(smtp_net::AutoSubmitted::AutoGenerated)
    .build()?;
assert_eq!(msg.envelope()?.recipients().len(), 3);
assert!(!String::from_utf8_lossy(&msg.to_bytes()?).contains("archive@example.com"));
# Ok::<(), smtp_net::Error>(())
```

| Method | Sets | Errors |
|---|---|---|
| `from(mailbox)`, `sender(mailbox)`, `reply_to(mailbox)` | `From`, `Sender`, `Reply-To` | `Address`, `Header` |
| `to(mailbox)`, `cc(mailbox)`, `bcc(mailbox)` | a recipient; call again for more | `Address`, `Build(TooManyRecipients)` |
| `subject(text: &str)` | `Subject`, RFC 2047 encoded when not ASCII | `Header` |
| `text(body: &str)`, `html(body: &str)` | the text and HTML bodies | `Build` |
| `attachment(Attachment)`, `inline(Inline)` | a file part, an inline image (needs `html`) | `Build` |
| `header(name: &str, value: &str)` | a custom header (reserved names refused) | `Header(InvalidName / Reserved / ControlCharacter)` |
| `message_id(id: &str)`, `message_id_domain(domain: &str)` | the `Message-ID`, or only its domain | `Header(InvalidMessageId)` |
| `date_unix(seconds: u64)`, `date_unix_with_offset(seconds: u64, offset_minutes: i16)` | the `Date` | `Header(InvalidDate)` for the second |
| `in_reply_to(id: &str)`, `references(ids: &[&str])` | threading headers | `Header`, `Build(TooMany)` |
| `list_unsubscribe(targets: &[&str], one_click: bool)` | `List-Unsubscribe` and, with `one_click`, RFC 8058 `List-Unsubscribe-Post` | `Header(InvalidUnsubscribe)` |
| `auto_submitted(AutoSubmitted)` | `Auto-Submitted` (RFC 3834) | none |
| `body(Part)` | a whole body tree in place of text, HTML, and attachments | none |
| `allow_8bit(bool)` | send 8-bit text unencoded when the server offers 8BITMIME | none |
| `allow_bidi_controls(bool)` | accept bidi overrides and isolates in the Subject and display names (refused by default) | none |
| `refuse_address_like_display_names(bool)` | refuse a display name that looks like another address | none |
| `limits(MessageLimits)` | the budgets below | none |
| `build() -> Result<Message, Error>` | the message, with the OS clock and random source (`std`) | `Build(MissingFrom / NoRecipients / ...)`, `Random` |
| `build_with(random: &mut dyn RandomSource, now_unix: u64)` | the same with caller-supplied randomness and time (`no_std`, deterministic tests) | as `build` |

```rust
let msg = smtp_net::Message::builder()
    .from("Alerts <alerts@example.com>")?
    .to("ops@example.org")?
    .subject("Disk 91% full on db-2")?
    .text("db-2 /var is 91% full.")?
    .list_unsubscribe(&["https://example.com/unsubscribe/abc"], true)?
    .message_id_domain("example.com")?
    .date_unix(1_700_000_000)
    .build()?;
assert!(msg.message_id().ends_with("@example.com"));
assert!(msg.headers().get("List-Unsubscribe-Post").is_some());
# Ok::<(), smtp_net::Error>(())
```

`AutoSubmitted` is `AutoGenerated` or `AutoReplied`.

### Attachments and inline images

| Item | Does | Errors |
|---|---|---|
| `Attachment::new(file_name: &str, content_type: &str, bytes: Vec<u8>)` | a file part, base64 | `Header(InvalidFileName / InvalidContentType)` |
| `Attachment::from_source(file_name: &str, content_type: &str, len: u64, source: Box<dyn BodySource>)` | a part read while sending, never held in memory | as `new`; `Source(..)` while sending |
| `Attachment::{len, is_empty, is_streamed, file_name, bytes}` | inspection (`bytes` is empty for a streamed one) | none |
| `Inline::new(content_id: &str, content_type: &str, bytes: Vec<u8>)` | an image referenced as `cid:` from the HTML | `Header(InvalidContentId / InvalidContentType)` |
| `Inline::content_id` | the id | none |

```rust
use smtp_net::{Attachment, Inline, Message};
let logo = Inline::new("logo@example.com", "image/png", vec![0x89, b'P', b'N', b'G'])?;
let msg = Message::builder()
    .from("no-reply@example.com")?
    .to("user@example.org")?
    .subject("Welcome")?
    .text("Welcome.")?
    .html("<img src=\"cid:logo@example.com\"> Welcome.")?
    .inline(logo)?
    .attachment(Attachment::new("terms.txt", "text/plain", b"Terms.".to_vec())?)?
    .build()?;
assert!(msg.headers().get("Content-Type").unwrap().starts_with("multipart/mixed"));
# Ok::<(), smtp_net::Error>(())
```

A large file, streamed from disk (`mime::ReadSource` wraps any `std::io::Read`):

```rust,no_run
use smtp_net::{Attachment, mime::ReadSource};
let file = std::fs::File::open("report.pdf")?;
let len = file.metadata()?.len();
let part = Attachment::from_source("report.pdf", "application/pdf", len, Box::new(ReadSource::new(file)))?;
assert!(part.is_streamed());
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Reading a built message

| Method | Returns |
|---|---|
| `message_id(&self) -> &str` | the `Message-ID`, without angle brackets |
| `headers(&self) -> &mime::Headers` | the top-level headers |
| `envelope(&self) -> Result<Envelope, Error>` | `MAIL FROM` (the From or Sender address) and every recipient |
| `needs_smtputf8(&self) -> bool`, `has_8bit(&self) -> bool` | what the server must offer |
| `encoded_len(&self) -> u64` | the serialized size |
| `write_to<S: mime::Sink>(&self, sink: &mut S) -> Result<(), Error>` | serializes without allocating |
| `to_bytes(&self) -> Result<Vec<u8>, Error>` | serializes into a new buffer |
| `prepare(&self) -> Result<PreparedMessage, Error>` | the envelope and bytes as they will be sent (see [Job payloads](#job-payloads)) |

```rust
let msg = smtp_net::Message::text("no-reply@example.com", "user@example.org", "Hi", "Hello")?;
let bytes = msg.to_bytes()?;
assert_eq!(bytes.len() as u64, msg.encoded_len());
let mut count = smtp_net::mime::CountingSink::default();
msg.write_to(&mut count)?;
assert_eq!(count.bytes, msg.encoded_len());
# Ok::<(), smtp_net::Error>(())
```

### Budgets

`MessageLimits` bounds what one message may hold; a builder over a budget
fails with a `Build` error instead of allocating without limit. Public
fields (the type is `#[non_exhaustive]`, so start from `default()`):
`max_message_size: u64` (25 MiB), `max_parts: u16`, `max_depth: u8`,
`max_headers: u16`, `max_header_value: u32`, `max_recipients: u16`,
`max_references: u16`.

```rust
let mut limits = smtp_net::MessageLimits::default();
limits.max_recipients = 1;
let err = smtp_net::Message::builder()
    .limits(limits)
    .from("no-reply@example.com")?
    .to("a@example.org")?
    .to("b@example.org")
    .unwrap_err();
assert!(matches!(err.kind(), smtp_net::ErrorKind::Build(smtp_net::BuildError::TooManyRecipients { .. })));
# Ok::<(), smtp_net::Error>(())
```

## Addresses

| Item | Does | Errors |
|---|---|---|
| `Address::parse(input: &str)` | an RFC 5321 address, `local@domain` | `AddressError` |
| `Address::parse_allowing_literal(input: &str)` | also `user@[192.0.2.1]` | `AddressError` |
| `Address::new(local_part: &str, domain: &str)` | from parts | `AddressError` |
| `Address::{local_part, domain, as_str, needs_smtputf8, same_mailbox}` | inspection; `same_mailbox` compares the domain without case | none |
| `Mailbox::parse(input: &str)` | `Display Name <local@domain>` or a bare address | `AddressError` |
| `Mailbox::new(display_name: Option<&str>, address: Address)` | from parts | `AddressError::DisplayNameInvalid` |
| `Mailbox::{display_name, address}` | inspection | none |
| `Domain::parse(input: &str)` | a domain name (no literal) | `AddressError` |
| `Domain::{as_str, is_ascii, is_literal, eq_ignore_case}` | inspection | none |

`Address` and `Mailbox` also implement `TryFrom<&str>` and `Display`.
Equality on `Address` compares the whole address; the local part is case
sensitive (RFC 5321), the domain is not.

```rust
use smtp_net::{Address, Mailbox};
let a = Address::parse("Jane.Doe@Example.COM")?;
assert_eq!(a.local_part(), "Jane.Doe");
assert!(a.same_mailbox(&Address::parse("Jane.Doe@example.com")?));
let m = Mailbox::parse("\"Doe, Jane\" <jane@example.com>")?;
assert_eq!(m.display_name(), Some("Doe, Jane"));
assert!(Address::parse("jane@example.com\r\nBcc: x@evil.example").is_err());
# Ok::<(), smtp_net::AddressError>(())
```

## Servers

A `Server` says where and how to submit. It is `Send + Sync` and cheap to
clone; build one and share it.

### Constructors

| Constructor | Port | Security | Timeouts |
|---|---|---|---|
| `Server::local()` | 25 on `127.0.0.1` | plaintext, peer must be loopback | `Timeouts::local()` |
| `Server::starttls(host: &str)` | 587 | STARTTLS, required | `Timeouts::rfc5321()` |
| `Server::implicit_tls(host: &str)` | 465 | TLS from the first byte | `Timeouts::rfc5321()` |
| `Server::builder(host: &str, security: Security) -> ServerBuilder` | by security | as given | by security |
| `server.login(user: &str, password: impl Into<Secret>) -> Server` | | adds a password (SCRAM-SHA-256 when offered and built, else PLAIN, then LOGIN) | |
| `server.to_builder() -> ServerBuilder` | | starts a builder from this server | |

Accessors: `host()`, `port()`, `security()`, `timeouts()`.

`Security` is `PlaintextLoopback`, `StartTls`, or `ImplicitTls`. There is no
opportunistic mode: TLS is required whenever the host is not loopback.

```rust
use smtp_net::{Security, Server};
let relay = Server::starttls("smtp.example.com").login("no-reply@example.com", "app-password");
assert_eq!((relay.port(), relay.security()), (587, Security::StartTls));
assert_eq!(Server::implicit_tls("smtp.example.com").port(), 465);
assert!(Server::builder("smtp.example.com", Security::PlaintextLoopback).build().is_err());
```

### The server builder

Every `ServerBuilder` method returns `Self`; `build()` checks the whole
configuration once.

| Method | Sets (default) |
|---|---|
| `port(u16)` | the port (25, 587, or 465 by security) |
| `credentials(Credentials)` | AUTH credentials, sent only over TLS or to a verified loopback peer |
| `mechanisms(&[MechanismName])` | the AUTH allowlist, in order of preference (by credential kind) |
| `client_name(&str)` | the EHLO name: a domain or an IP address (the local socket's address as a literal) |
| `timeouts(Timeouts)` | every stage timeout |
| `tls(impl TlsConnector)` | the TLS engine (tls-net with the Mozilla roots) |
| `dangerous_disable_certificate_verification()` | no certificate check: loopback hosts only, unless `allow_insecure_remote(true)` too |
| `allow_insecure_remote(bool)` | the second flag for the line above (false) |
| `observer(impl Observer)` | structured events (none) |
| `gate(impl SendGate)` | pacing (none) |
| `pipelining(bool)`, `chunking(bool)` | use PIPELINING and CHUNKING when offered (true) |
| `recipient_policy(RecipientPolicy)` | `Any`: send when one recipient is accepted; `All`: send only when all are (`Any`) |
| `dkim(DkimSigner)` | a signer for every message `send` builds; repeat for up to 4 (feature `dkim`) |
| `max_messages_per_connection(u32)` | reconnect after this many messages (100) |
| `build() -> Result<Server, Error>` | |

`build` errors, all `Config(..)`: `PortZero`, `InvalidHost`,
`PlaintextHostNotLoopback`, `TlsConnectorMissing`, `InsecureNotAllowed`,
`TooManyMechanisms`, `InvalidClientName`, `TooManyDkimSigners`.

```rust
use smtp_net::{Credentials, MechanismName, RecipientPolicy, Security, Server, Timeouts};
let server = Server::builder("smtp.example.com", Security::StartTls)
    .port(2587)
    .credentials(Credentials::password("no-reply@example.com", "app-password"))
    .mechanisms(&[MechanismName::ScramSha256, MechanismName::Plain])
    .client_name("app-1.example.com")
    .timeouts(Timeouts::rfc5321())
    .recipient_policy(RecipientPolicy::All)
    .build()?;
assert_eq!(server.port(), 2587);
let bad = Server::builder("smtp.example.com", Security::StartTls).client_name("not a name").build();
assert!(matches!(bad.unwrap_err().kind(), smtp_net::ErrorKind::Config(smtp_net::ConfigError::InvalidClientName)));
# Ok::<(), smtp_net::Error>(())
```

### Credentials and AUTH

| Item | Does |
|---|---|
| `Credentials::password(user: &str, password: impl Into<Secret>)` | SCRAM-SHA-256, PLAIN, LOGIN |
| `Credentials::oauth2(user: &str, token: impl Into<Secret>)` | XOAUTH2 (Gmail, Microsoft 365); refreshing the token is the caller's job |
| `Credentials::Custom(protocol::CustomMechanism)` | a mechanism this crate does not implement |
| `Credentials::user(&self) -> &str` | the user name (empty for a custom mechanism) |
| `Secret::new(Vec<u8>)`, `From<&str>`, `From<String>`, `From<Vec<u8>>`; `len`, `is_empty` | a value wiped on drop, shown as `<redacted>` |
| `MechanismName` | `Plain`, `Login`, `XOAuth2`, `ScramSha256`, `Other` (a custom mechanism); `as_str()` |

The default allowlist depends on the credential kind: a password tries
`ScramSha256` (feature `scram`), then `Plain`, then `Login`; a token tries
`XOAuth2`. A server that offers none of the allowlist fails with
`AuthUnavailable` before anything is sent.

```rust
use smtp_net::{Credentials, Security, Server};
# let access_token = String::from("ya29.token");
let gmail = Server::builder("smtp.gmail.com", Security::StartTls)
    .credentials(Credentials::oauth2("no-reply@example.com", access_token))
    .build()?;
# let _ = gmail;
# Ok::<(), smtp_net::Error>(())
```

When XOAUTH2 fails, `Error::auth_detail()` gives the server's status, for
example `"401"` for an expired token: the cue to refresh it and retry.

### Timeouts

`Timeouts` holds one `Duration` per stage (public fields; the type is
`#[non_exhaustive]`): `connect`, `greeting`, `command`, `tls_handshake`,
`mail`, `rcpt`, `data_init`, `data_block`, `data_end`, `idle`, and
`total: Option<Duration>`.

| Constructor | Values |
|---|---|
| `Timeouts::rfc5321()` | RFC 5321 4.5.3.2: 5 minutes for the greeting, commands, MAIL, and RCPT; 2 for DATA, 3 per data block, 10 for the end of the data; connect 30 s, TLS handshake 60 s, idle 60 s |
| `Timeouts::local()` | for a mail server on the same machine: connect 2 s, TLS handshake 10 s, the other stages 30 s, the end of the data 2 minutes |

```rust
let mut t = smtp_net::Timeouts::rfc5321();
t.total = Some(std::time::Duration::from_secs(120));
let server = smtp_net::Server::starttls("smtp.example.com").to_builder().timeouts(t).build()?;
assert_eq!(server.timeouts().total, Some(std::time::Duration::from_secs(120)));
# Ok::<(), smtp_net::Error>(())
```

### TLS

The default engine (feature `tls`) is tls-net with the Mozilla root
bundle. Certificate verification cannot be turned off except for test
relays (two explicit flags for a remote host). Another engine implements
`TlsConnector`:

```rust,ignore
pub trait TlsConnector: Send + Sync {
    fn session(&self, server_name: &str, insecure: bool)
        -> Result<Box<dyn net_io::TlsSession>, TlsSetupError>;
}
```

`TlsSetupError::new(kind: TlsFailure)` reports a setup failure; it becomes
`ErrorKind::Tls(kind)`. `TlsProtocol` is `Tls12`, `Tls13`, or `Other(u16)`
(`TlsProtocol::from_wire(u16)`).

A relay signed by a private CA:

```rust,no_run
let ca = std::fs::read("internal-ca.pem")?;
let server = smtp_net::Server::builder("mail.internal.example", smtp_net::Security::StartTls)
    .tls(tls_net::client_with_ca_pem(&ca)?)
    .build()?;
# let _ = server;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Connections

### Client: one connection

`Client` is one connection and its session; `Send`, not `Sync`. Use it to
send several messages over one connection. It reconnects by itself after
`max_messages_per_connection`, after the idle timeout, and once after a
reused connection fails before anything was accepted.

| Method | Does | Errors |
|---|---|---|
| `Client::connect(server: &Server) -> Result<Client, Error>` | connects, greets, negotiates TLS and AUTH | `Connect`, `PlaintextRefused`, `Tls`, `StartTlsUnavailable`, `StartTlsInjection`, `AuthUnavailable`, `AuthFailed`, `Timeout`, `Protocol` |
| `send(&mut self, &Message) -> Result<Report, Error>` | as the free `send`, on this connection | as `send` |
| `send_prepared(&mut self, &PreparedMessage) -> Result<Report, Error>` | as the free `send_prepared` | as `send_prepared` |
| `noop(&mut self) -> Result<(), Error>` | a NOOP, to check the connection | `Timeout`, `Rejected`, `Usage` |
| `is_open(&self) -> bool`, `capabilities(&self) -> Option<&Capabilities>` | inspection; `is_open` is true only when the session is ready with nothing queued and no reply outstanding, the one state in which `Client` and `Pool` reuse a connection | none |
| `close(self) -> Result<(), Error>` | QUIT and close (a dropped client tries QUIT for 1 s) | `Timeout`, `Io` |

```rust
use smtp_net::{Client, Message, testing::TestServer};
let server = TestServer::start()?;
let mut client = Client::connect(&server.server())?;
for to in ["a@example.org", "b@example.org"] {
    client.send(&Message::text("no-reply@example.com", to, "Hi", "Hello")?)?;
}
client.close()?;
assert_eq!((server.received().len(), server.connections()), (2, 1));
# Ok::<(), smtp_net::Error>(())
```

### Pool: shared connections

`Pool` shares 1 to 64 connections across threads (`Send + Sync`). A
checkout waits up to `wait_limit` for a free connection, then fails with
`PoolExhausted` (temporary, nothing sent).

| Method | Does | Errors |
|---|---|---|
| `Pool::new(server: Server, max_connections: usize) -> Result<Pool, Error>` | connects lazily | `Config(PoolSize)` |
| `wait_limit(self, wait: Duration) -> Pool` | how long a send waits for a connection (10 s) | none |
| `send(&self, &Message)`, `send_prepared(&self, &PreparedMessage)` | as `Client` | as `Client`, plus `PoolExhausted` |
| `idle(&self) -> usize`, `server(&self) -> &Server` | inspection | none |

```rust
use smtp_net::{Message, Pool, testing::TestServer};
use std::sync::Arc;
let server = TestServer::start()?;
let pool = Arc::new(Pool::new(server.server(), 2)?);
std::thread::scope(|s| {
    for i in 0..4 {
        let pool = Arc::clone(&pool);
        s.spawn(move || {
            let to = format!("user{i}@example.org");
            pool.send(&Message::text("no-reply@example.com", &to, "Hi", "Hello").unwrap()).unwrap();
        });
    }
});
assert_eq!(server.received().len(), 4);
assert!(server.connections() <= 2);
# Ok::<(), smtp_net::Error>(())
```

### Report

What the server said about a sent message.

| Method | Returns |
|---|---|
| `message_id(&self) -> &str` | the `Message-ID` sent (empty for raw bytes without one) |
| `accepted(&self) -> &[Address]` | recipients the server accepted |
| `rejected(&self) -> &[RejectedRecipient]` | recipients it refused while accepting others |
| `final_reply(&self) -> &Reply` | the reply to the end of the data |
| `was_secure(&self) -> bool`, `tls_protocol(&self) -> Option<TlsProtocol>` | whether the message went over TLS, and which version |
| `elapsed(&self) -> Duration` | time from the first transaction to the final reply |

`RejectedRecipient` has `address() -> &Address`, `reply() -> &Reply`,
`disposition() -> Disposition`, `is_temporary()`, and `is_permanent()`.

```rust
use smtp_net::{Message, testing::{Fault, TestServer}};
let server = TestServer::builder().fault(Fault::RejectRecipient(1)).start()?;
let msg = Message::builder()
    .from("no-reply@example.com")?
    .to("a@example.org")?
    .to("b@example.org")?
    .subject("Hi")?
    .text("Hello")?
    .build()?;
let report = smtp_net::send(&server.server(), &msg)?;
assert_eq!(report.accepted().len(), 1);
let refused = &report.rejected()[0];
assert_eq!(refused.address().as_str(), "b@example.org");
assert!(refused.is_permanent());
# Ok::<(), smtp_net::Error>(())
```

## Errors

### Error

Every fallible call returns `smtp_net::Error`: one pointer wide, `Send +
Sync + 'static`, `std::error::Error` with `std`, and a message that says
what to do.

| Method | Returns |
|---|---|
| `kind(&self) -> &ErrorKind` | what went wrong |
| `stage(&self) -> Option<Stage>` | where in the conversation |
| `reply(&self) -> Option<&Reply>` | the server's reply, for a refusal |
| `disposition(&self) -> Disposition` | `Temporary` or `Permanent` |
| `is_temporary(&self)`, `is_permanent(&self)` | the same as booleans |
| `possibly_delivered(&self) -> bool` | the end of the data was written and no reply read: a retry may duplicate (the same bytes and `Message-ID` go again) |
| `retry_after(&self) -> Option<Duration>` | for `Throttled`: when the gate admits again |
| `is_security_event(&self) -> bool` | may be an attack (stripped STARTTLS, injected bytes, a bad certificate, an oversized reply) |
| `auth_detail(&self) -> Option<&str>` | the XOAUTH2 error status |
| `rejected(&self) -> &[RejectedRecipient]` | refused recipients, for `AllRecipientsRejected` and partial failures under `RecipientPolicy::All` |

```rust
use smtp_net::{Message, testing::{Fault, TestServer}};
let server = TestServer::builder().fault(Fault::RejectRecipient(0)).start()?;
let msg = Message::text("no-reply@example.com", "gone@example.org", "Hi", "Hello")?;
let e = smtp_net::send(&server.server(), &msg).unwrap_err();
assert!(matches!(e.kind(), smtp_net::ErrorKind::AllRecipientsRejected));
assert!(e.is_permanent() && !e.possibly_delivered());
assert_eq!(e.rejected()[0].address().as_str(), "gone@example.org");
# Ok::<(), smtp_net::Error>(())
```

`Disposition` is `Temporary` or `Permanent`. `Stage` is `Connect`,
`Greeting`, `Ehlo`, `Helo`, `StartTls`, `TlsHandshake`, `Auth`, `Mail`,
`Rcpt`, `Data`, `Body`, `DataEnd`, `Bdat`, `Rset`, `Noop`, `Quit`, or
`Total`; `Stage::name()` gives its name.

### ErrorKind and the nested enums

All are `#[non_exhaustive]`; match with a `_` arm.

| `ErrorKind` | Meaning | Disposition |
|---|---|---|
| `Address(AddressError)` | an address or mailbox was refused | permanent |
| `Header(HeaderError)` | a header name or value was refused | permanent |
| `Build(BuildError)` | the message could not be built | permanent |
| `Config(ConfigError)` | the configuration cannot work | permanent |
| `Usage(UsageError)` | the session was used out of order | permanent |
| `Random` | the OS random source failed | temporary |
| `Sink(SinkError)` | a sink refused bytes | permanent for `Full`, temporary for `Io` |
| `Payload(PayloadError)` | a job payload could not be decoded | permanent |
| `Dkim(DkimError)` | DKIM signing or key loading failed | permanent |
| `Source(SourceError)` | a streamed attachment failed | temporary for `Io` |
| `Connect(io::ErrorKind)`, `Io(io::ErrorKind)` | the connection could not be opened, or failed | temporary |
| `Timeout` | a stage deadline passed | temporary |
| `PlaintextRefused` | plaintext to a peer that is not loopback | permanent, security event |
| `StartTlsUnavailable` | STARTTLS required and not offered; nothing sent | permanent, security event |
| `StartTlsInjection` | plaintext after the server's `220` to STARTTLS | temporary, security event |
| `Tls(TlsFailure)` | the handshake or stream failed | by failure |
| `Throttled` | a gate refused; see `retry_after` | temporary |
| `AuthUnavailable`, `AuthFailed`, `Sasl(SaslError)` | AUTH could not run, was refused, or was refused by the client | by reply |
| `Protocol(ProtocolError)` | the server broke the protocol | temporary, security event |
| `Rejected`, `AllRecipientsRejected` | the server refused; see `reply` and `rejected` | by reply |
| `MessageTooLarge { size, limit }` | over the server's SIZE | permanent |
| `ExtensionRequired(Extension)` | the message needs an extension the server lacks (no downgrade) | permanent |
| `ConnectionClosed`, `PoolExhausted`, `BufferTooSmall` | | temporary, temporary, permanent |

| Nested enum | Variants |
|---|---|
| `AddressError` | `Empty`, `TooLong { part: AddressPart, length, limit }`, `InvalidLocalPart { position }`, `InvalidDomain { position }`, `LabelTooLong { label }`, `AddressLiteralNotAllowed`, `MissingAt`, `ControlCharacter { position }`, `InternationalDomainUnsupported`, `DisplayNameInvalid { position }` |
| `AddressPart` | `LocalPart`, `Domain`, `Path` |
| `HeaderError` | `ControlCharacter`, `InvalidName`, `Reserved`, `LineTooLong`, `InvalidMessageId`, `InvalidDate`, `InvalidUnsubscribe`, `InvalidFileName`, `InvalidContentType`, `InvalidContentId`, `BidiControl`, `AddressLikeDisplayName` |
| `BuildError` | `MissingFrom`, `MultipleFrom`, `NoRecipients`, `TooManyRecipients { limit }`, `TooMany`, `TooManyParts`, `TooManyHeaders`, `TooLarge`, `DepthExceeded`, `InlineWithoutHtml`, `DuplicateContentId`, `BareCarriageReturn`, `BareLineFeed`, `LineTooLong`, `NoHeaderBlock`, `LengthMismatch`, `EncodingMismatch`, `InvalidDsn`, `CommandTooLong` (a MAIL or RCPT line over its limit; nothing of the transaction was queued), `CommandHasControl` (CR, LF, or NUL in a command line; the last check, T-2) |
| `ConfigError` | `PortZero`, `InvalidHost`, `PlaintextHostNotLoopback`, `BufferTooSmall`, `TlsConnectorMissing`, `TooManyMechanisms`, `InsecureNotAllowed`, `AuthWithPlaintextRemote`, `TooManyDkimSigners`, `PoolSize`, `InvalidClientName` |
| `UsageError` | `WrongState { state: SessionState }`, `Closed` |
| `ProtocolError` | `MalformedReply`, `InconsistentReply`, `ReplyTooLong`, `BareLineFeed`, `Nul`, `UnexpectedReply`, `MalformedCapability` |
| `TlsFailure` | `CertificateRejected`, `ProtocolMismatch`, `Handshake`, `Closed`, `Setup` |
| `PayloadError` | `Corrupt`, `UnknownVersion { version }`, `TooLarge`, `Truncated` |
| `DkimError` | `InvalidDomain`, `InvalidSelector`, `InvalidHeaderName`, `KeyFormat`, `KeyTooSmall`, `KeyTooLarge`, `MissingFrom`, `HeaderBlockTooLarge`, `MalformedMessage`, `IdentityOutsideDomain`, `Signing` |
| `SaslError` | `InvalidCredential`, `InvalidChallenge`, `TooManySteps`, `InvalidServerMessage`, `ServerNonceMismatch`, `IterationsOutOfRange`, `ServerSignatureMismatch`, `ServerError`, `NonAsciiCredential`, `NonceMissing`, `ResponseTooLong`, `InvalidMechanismName`, `Custom` |
| `SourceError` | `Failed`, `Io(kind)`, `Consumed` |
| `SinkError` | `Full`, `Io(kind)` |
| `Extension` | `Pipelining`, `Size`, `EightBitMime`, `Smtputf8`, `Chunking`, `BinaryMime`, `Dsn`, `EnhancedStatusCodes`, `StartTls`, `Auth`, `RequireTls`; `keyword()` gives the EHLO keyword |

```rust
use smtp_net::{AddressError, ErrorKind};
let e = smtp_net::Message::text("not an address", "user@example.org", "Hi", "Hello").unwrap_err();
match e.kind() {
    ErrorKind::Address(AddressError::MissingAt) => {}
    other => panic!("unexpected: {other:?}"),
}
assert!(e.to_string().contains("@"));
```

### Replies

| Item | Does |
|---|---|
| `Reply::code(&self) -> ReplyCode` | the three-digit code |
| `Reply::enhanced(&self) -> Option<EnhancedCode>` | the RFC 3463 code, when the server sent one |
| `Reply::lines(&self)`, `line_count(&self)`, `text_lossy(&self)`, `is_truncated(&self)` | the text: raw lines, their number, a `Display` with invalid UTF-8 replaced, whether the budget cut it |
| `ReplyCode::new(u16) -> Option<ReplyCode>`, `get(self) -> u16` | a valid code: first digit 2 to 5, second 0 to 5 |
| `ReplyCode::{is_positive, is_temporary, is_permanent}` | `2yz`/`3yz`, `4yz`, `5yz` |
| `EnhancedCode { class: u8, subject: u16, detail: u16 }` | for example `5.1.1`; `Display` writes it so |

```rust
let code = smtp_net::ReplyCode::new(451).unwrap();
assert!(code.is_temporary() && !code.is_permanent());
assert_eq!(code.get(), 451);
assert!(smtp_net::ReplyCode::new(99).is_none());
```

## Job payloads

### PreparedMessage

The envelope and the exact bytes to send. Build (and sign) once where the
message is made, store `encode()` with the job, and send the decoded
payload from the worker: a retry sends the same bytes and `Message-ID`.

| Method | Does | Errors |
|---|---|---|
| `Message::prepare(&self) -> Result<PreparedMessage, Error>` | from a built message | as `Message::envelope` and `to_bytes` |
| `PreparedMessage::from_raw(envelope: Envelope, rfc5322: Vec<u8>)` | from bytes built elsewhere (checked: CRLF lines, a header block, line lengths) | `Build(BareCarriageReturn / BareLineFeed / LineTooLong / NoHeaderBlock / TooLarge)` |
| `sign(self, signers: &[DkimSigner], now_unix: u64)` | adds a `DKIM-Signature` per signer (feature `dkim`) | `Dkim(..)` |
| `encode(&self) -> Vec<u8>` | the versioned payload with a CRC-32C | none |
| `PreparedMessage::decode(payload: &[u8])` | back from a payload; a damaged one is refused | `Payload(Corrupt / UnknownVersion / TooLarge / Truncated)` |
| `envelope`, `bytes`, `message_id`, `needs_smtputf8`, `has_8bit` | inspection | none |

```rust
use smtp_net::{Message, PreparedMessage, testing::TestServer};
let server = TestServer::start()?;
let payload = Message::text("no-reply@example.com", "user@example.org", "Hi", "Hello")?.prepare()?.encode();

// ... later, in the worker:
let prepared = PreparedMessage::decode(&payload)?;
match smtp_net::send_prepared(&server.server(), &prepared) {
    Ok(_) => {}
    Err(e) if e.is_temporary() => { /* keep the job; retry after a back-off */ }
    Err(e) => { /* dead-letter the job */ let _ = e; }
}
assert_eq!(server.received().len(), 1);
let mut damaged = payload.clone();
damaged[20] ^= 1;
assert!(PreparedMessage::decode(&damaged).is_err());
# Ok::<(), smtp_net::Error>(())
```

### Envelope

The SMTP envelope: the reverse-path and the forward-paths.

| Method | Does | Errors |
|---|---|---|
| `Envelope::new(from: Address, to: &[Address])` | an envelope | `Build(NoRecipients / TooManyRecipients)` |
| `Envelope::null_sender(to: &[Address])` | `MAIL FROM:<>`, for bounces and auto-replies | as `new` |
| `with_return_path(self, Address) -> Envelope` | where bounces go, distinct from the From | none |
| `return_path(&self) -> Option<&Address>` | the reverse-path (`None` for the null sender) | none |
| `recipients(&self) -> &[Address]` | the forward-paths, in order | none |
| `with_dsn(self, Dsn) -> Envelope`, `dsn(&self) -> Option<&Dsn>` | DSN parameters | none |
| `needs_smtputf8(&self) -> bool` | a non-ASCII address | none |

```rust
use smtp_net::{Address, Envelope, Message};
let msg = Message::text("Shop <orders@example.com>", "user@example.org", "Order 1234", "Shipped.")?;
let envelope = msg.envelope()?.with_return_path(Address::parse("bounces+1234@example.com")?);
assert_eq!(envelope.return_path().unwrap().as_str(), "bounces+1234@example.com");
let bounce = Envelope::null_sender(&[Address::parse("user@example.org")?])?;
assert!(bounce.return_path().is_none());
# Ok::<(), smtp_net::Error>(())
```

### DSN

RFC 3461 delivery status notification parameters.

| Item | Does |
|---|---|
| `Dsn::new(notify: DsnNotify) -> Dsn` | `NOTIFY` on every recipient, no `RET`, no `ENVID`, policy `IfSupported` |
| `with_return_content(self, DsnReturn)`, `return_content(&self)` | `RET`: `Full` or `Headers` |
| `with_envelope_id(self, &str) -> Result<Dsn, Error>`, `envelope_id(&self)` | `ENVID`: printable ASCII, at most 100 characters (`Build(InvalidDsn)`) |
| `with_policy(self, DsnPolicy)`, `policy(&self)` | `IfSupported` sends without DSN when the server lacks it; `Required` fails with `ExtensionRequired(Dsn)` |
| `notify(&self) -> DsnNotify` | |
| `DsnNotify::{NEVER, SUCCESS, FAILURE, DELAY}`, combined with `\|`; `success()`, `failure()`, `delay()` | |

```rust
use smtp_net::{Dsn, DsnNotify, DsnPolicy, DsnReturn};
let dsn = Dsn::new(DsnNotify::FAILURE | DsnNotify::DELAY)
    .with_return_content(DsnReturn::Headers)
    .with_envelope_id("order-1234")?
    .with_policy(DsnPolicy::Required);
assert_eq!(dsn.envelope_id(), Some("order-1234"));
assert!(dsn.notify().failure() && !dsn.notify().success());
let msg = smtp_net::Message::text("no-reply@example.com", "user@example.org", "Hi", "Hello")?;
let prepared = smtp_net::PreparedMessage::from_raw(msg.envelope()?.with_dsn(dsn), msg.to_bytes()?)?;
assert!(prepared.envelope().dsn().is_some());
# Ok::<(), smtp_net::Error>(())
```

## DKIM

Feature `dkim`. Sign with Ed25519-SHA256 (RFC 8463) and RSA-SHA256 (RFC
8301: 2048 to 4096 bits) under two selectors.

| Item | Does | Errors |
|---|---|---|
| `DkimKey::ed25519_from_pkcs8_pem(&str)`, `ed25519_from_pkcs8_der(&[u8])`, `ed25519_from_seed(&[u8; 32])` | an Ed25519 key | `DkimError::KeyFormat` |
| `DkimKey::rsa_from_pem(&str)`, `rsa_from_der(&[u8])` | an RSA key (PKCS#1 or PKCS#8) | `KeyFormat`, `KeyTooSmall`, `KeyTooLarge` |
| `DkimKey::{algorithm, rsa_bits}` | inspection | none |
| `DkimKey::dns_record(&self) -> String` | the TXT record to publish at `<selector>._domainkey.<domain>` | none |
| `DkimSigner::new(domain: &str, selector: &str, key: DkimKey)` | relaxed/relaxed, From and the usual headers signed and oversigned | `InvalidDomain`, `InvalidSelector` |
| `canonicalization(self, header: Canonicalization, body: Canonicalization)` | `Simple` or `Relaxed` | none |
| `headers(self, &[&str])`, `oversign(self, &[&str])` | the signed and oversigned header names | `InvalidHeaderName` |
| `expiry(self, seconds: u32)` | `x=` | none |
| `identity(self, &Address)` | `i=`, inside the signing domain | `IdentityOutsideDomain` |
| `domain`, `selector`, `key` | inspection | none |
| `sign(&self, message: &[u8], now_unix: u64) -> Result<String, DkimError>` | the `DKIM-Signature` header for raw bytes | `MissingFrom`, `MalformedMessage`, `HeaderBlockTooLarge`, `Signing` |
| `sign_into(&self, message: &[u8], now_unix: u64, out: &mut Vec<u8>)` | the same, appended to `out` | as `sign` |

`DkimAlgorithm` is `Ed25519Sha256` or `RsaSha256`; `Canonicalization` is
`Simple` or `Relaxed`; both have `name()`. `DKIM_RSA_MIN_BITS` is 2048 and
`DKIM_RSA_MAX_BITS` 4096.

Sign every message a server sends:

```rust
use smtp_net::{DkimKey, DkimSigner, Message, testing::TestServer};
let key = DkimKey::ed25519_from_seed(&[7; 32])?;
println!("publish at ed2026._domainkey.example.com: {}", key.dns_record());
let server = TestServer::start()?;
let signing = server.server_builder().dkim(DkimSigner::new("example.com", "ed2026", key)?).build()?;
smtp_net::send(&signing, &Message::text("no-reply@example.com", "user@example.org", "Hi", "Hello")?)?;
assert!(server.received()[0].data.starts_with(b"DKIM-Signature: v=1; a=ed25519-sha256;"));
# Ok::<(), smtp_net::Error>(())
```

Or sign a prepared message once, before it is stored:

```rust
use smtp_net::{DkimKey, DkimSigner, Message};
let signer = DkimSigner::new("example.com", "ed2026", DkimKey::ed25519_from_seed(&[7; 32])?)?;
let prepared = Message::text("no-reply@example.com", "user@example.org", "Hi", "Hello")?
    .prepare()?
    .sign(&[signer], 1_700_000_000)?;
assert!(prepared.bytes().starts_with(b"DKIM-Signature: "));
# Ok::<(), smtp_net::Error>(())
```

## Pacing

A `SendGate` is asked before connecting and before each transaction. A
refusal fails the send with `Throttled` (temporary, nothing sent) and
`Error::retry_after`.

```rust,ignore
pub trait SendGate: Send + Sync {
    fn admit(&self, envelope: &Envelope, now_unix_ms: u64) -> Admission;
    fn refund(&self, envelope: &Envelope, now_unix_ms: u64) { /* keeps the allowance */ }
}
```

`Admission` is `Admit` or `RetryAfter(Duration)`. A pair `(A, B)` is a gate
that admits only what both admit, and refunds the first when the second
refuses. `now_unix_ms` is the wall clock, because a host's hourly cap
counts on the host's clock.

| Item | Does |
|---|---|
| `HourlyLimit::messages(per_hour: u32)`, `HourlyLimit::recipients(per_hour: u32)` | a rolling 60-minute limit, lock-free; `unit() -> CountUnit` (`Messages` or `Recipients`) |
| `HourlyLimit::remaining(&self, now_unix_ms: u64) -> u32` | what is left in the window |
| `DomainLimit::recipients(per_hour: u32)` | at most `per_hour` recipients per recipient domain in any 60 minutes (feature `std`) |
| `DomainLimit::max_domains(self, n: usize)` | most domains remembered (1,024); the least recently used is forgotten |
| `DomainLimit::remaining(&self, domain: &str, now_unix_ms: u64) -> u32` | what `domain` has left |

```rust
use smtp_net::{Address, Admission, DomainLimit, Envelope, HourlyLimit, SendGate};
let gate = (HourlyLimit::recipients(450), DomainLimit::recipients(2));
let to = |a: &str| Envelope::new(Address::parse("no-reply@example.com").unwrap(), &[Address::parse(a).unwrap()]).unwrap();
let t = 1_700_000_000_000;
assert_eq!(gate.admit(&to("a@one.example"), t), Admission::Admit);
assert_eq!(gate.admit(&to("b@one.example"), t), Admission::Admit);
assert!(matches!(gate.admit(&to("c@ONE.example"), t), Admission::RetryAfter(_)));
assert_eq!(gate.admit(&to("c@two.example"), t), Admission::Admit);
assert_eq!(gate.0.remaining(t), 447);
```

On a server: `ServerBuilder::gate(gate)`. A gate kept elsewhere (a database
counter, a job runner's limiter) implements the two methods; a gate that
counts recipients reads `envelope.recipients().len()`.

## Observability

`ServerBuilder::observer(impl Observer)` receives structured events. An
observer never sees secrets, message bodies, or reply text.

```rust,ignore
pub trait Observer: Send + Sync {
    fn event(&self, event: &ObservedEvent<'_>);
}
```

| `ObservedEvent` | Fields |
|---|---|
| `Connected` | `peer: SocketAddr` |
| `Secure` | `protocol: TlsProtocol` |
| `Reply` | `stage: Stage`, `code: ReplyCode`, `enhanced: Option<EnhancedCode>` |
| `Delivered` | `message_id: &str`, `accepted: usize`, `rejected: usize`, `elapsed: Duration` |
| `Failed` | `stage: Option<Stage>`, `disposition: Disposition`, `possibly_delivered: bool` |
| `SecurityEvent` | `kind: SecurityEventKind`: `StartTlsMissing`, `StartTlsInjection`, `CertificateRejected`, `MalformedReply`, `ReplyBudgetExceeded`, `AuthExchange`, `PlaintextRefused`, `Other` |

```rust
use smtp_net::{Message, ObservedEvent, Observer, testing::TestServer};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Count(AtomicUsize);
impl Observer for Count {
    fn event(&self, event: &ObservedEvent<'_>) {
        if let ObservedEvent::Delivered { .. } = event {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

let server = TestServer::start()?;
let observed = server.server_builder().observer(Count(AtomicUsize::new(0))).build()?;
smtp_net::send(&observed, &Message::text("no-reply@example.com", "user@example.org", "Hi", "Hello")?)?;
# Ok::<(), smtp_net::Error>(())
```

## The `protocol` module: the sans-IO session

For a driver over another transport. The full loop over a `TcpStream` is
[`examples/sans_io_driver.rs`](../examples/sans_io_driver.rs).

### Session

`Session` does no I/O, reads no clock, and draws no random numbers. The
driver feeds it bytes and the time (`Millis`, the caller's monotonic clock
in milliseconds), writes out what it queues, and acts on its events.

| Method | Does |
|---|---|
| `Session::new(config: SessionConfig, now: Millis) -> Result<Session, Error>` | a session waiting for the greeting (`Config(..)` for a configuration that cannot work) |
| `receive(&mut self, input: &[u8], now: Millis) -> Result<usize, Error>` | feeds server bytes; returns how many it took (fewer only after a STARTTLS `220`: the rest is an injection) |
| `transmit(&self) -> &[u8]`, `transmitted(&mut self, n: usize)` | the bytes to write, and how many were written |
| `poll_event(&mut self) -> Option<Event>` | the next event |
| `deadline(&self) -> Option<Millis>`, `on_timeout(&mut self, now: Millis)` | when the current stage times out, and the call when it has |
| `connection_lost(&mut self, cause: ErrorKind) -> Error` | the transport closed or failed; returns the classified error |
| `tls_established(&mut self, info: TlsInfo, now: Millis)` | the TLS handshake finished |
| `begin(&mut self, envelope: &Envelope, flags: BodyFlags, size: u64, now: Millis)` | starts a transaction; every MAIL and RCPT line is measured before the first is queued, so a refusal leaves the session as it was (`MessageTooLarge`, `ExtensionRequired`, `Build(CommandTooLong)`, `Usage`) |
| `body(&mut self, chunk: &[u8], now: Millis) -> Result<usize, Error>`, `end_body(&mut self, now: Millis)` | the message bytes (dot-stuffed or chunked by the session) |
| `reset`, `noop`, `quit` (each `(&mut self, now: Millis)`) | RSET, NOOP, QUIT |
| `state`, `capabilities`, `is_secure`, `is_authenticated`, `tls_protocol`, `wants_read` | inspection |

`SessionConfig` (public fields, `Default`): `client_name: ClientName`,
`security: SessionSecurity`, `auth: Option<Auth>`, `timeouts: Timeouts`,
`pipelining: bool`, `chunking: bool`, `recipient_policy: RecipientPolicy`,
`reply_limits: ReplyLimits`, `output_capacity: usize`, `reply_events: bool`.

`SessionSecurity` is `Plaintext { peer_is_loopback: bool }`,
`StartTlsRequired`, or `ImplicitTls`. `ClientName` is `Domain(Domain)` or
`AddressLiteral(IpAddr)`; `ClientName::parse(&str)` reads either form.
`BodyFlags::new(eight_bit: bool, smtputf8: bool)`; `TlsInfo::new(protocol)`;
`Millis::after(self, Duration)`.

```rust
use smtp_net::protocol::{Event, Millis, Session, SessionConfig, SessionSecurity};
let mut config = SessionConfig::default();
config.security = SessionSecurity::Plaintext { peer_is_loopback: true };
let mut s = Session::new(config, Millis(0))?;
s.receive(b"220 mail.example.com ESMTP\r\n", Millis(1))?;
assert!(matches!(s.poll_event(), Some(Event::Greeting(_))));
assert!(s.transmit().starts_with(b"EHLO "));
let n = s.transmit().len();
s.transmitted(n);
s.receive(b"250-mail.example.com\r\n250 PIPELINING\r\n", Millis(2))?;
assert!(matches!(s.poll_event(), Some(Event::Ready { secure: false, authenticated: false })));
# Ok::<(), smtp_net::Error>(())
```

### Events and states

| `Event` | Means |
|---|---|
| `Greeting(Reply)` | the server's `220` |
| `Reply { stage, code, enhanced }` | every reply, when `reply_events` is on |
| `Ready { secure, authenticated }` | the session can start a transaction |
| `StartTls` | start the TLS handshake now, then call `tls_established` |
| `Authenticated { mechanism }` | AUTH succeeded |
| `RecipientAccepted { index }`, `RecipientRejected { index, reply, disposition }` | per recipient |
| `BodyWanted` | send the message bytes |
| `Delivered { reply, accepted, rejected, deferred }` | the end of the data was accepted |
| `Deferred { recipients }` | recipients the server deferred (452): send them in a further transaction |
| `TransactionFailed(Error)` | the transaction failed; the session may still be usable |
| `Closed { error }` | the session ended |

`SessionState` is `AwaitGreeting`, `Negotiating`, `NeedTls`,
`Authenticating`, `Ready`, `InTransaction`, `Body`, `AwaitDataEnd`,
`Closing`, or `Closed`.

### Reply parsing and capabilities

| Item | Does |
|---|---|
| `ReplyParser::new(limits: ReplyLimits, enhanced: bool)` | a streaming parser (`enhanced`: the server advertised ENHANCEDSTATUSCODES) |
| `ReplyParser::push(&mut self, input: &[u8]) -> Result<(usize, Option<Reply>), ProtocolError>`, `is_partial` | consumes input, returns a reply when one is complete |
| `ReplyLimits { max_line: u16, max_lines: u16, max_total: u32 }` | 1000, 64, 8192 by default |
| `TextLossy<'_>` | the `Display` from `Reply::text_lossy` |
| `Capabilities::parse(ehlo: &Reply)` (at the root) | the EHLO capabilities |
| `Capabilities::{has(Extension), size_limit, auth_mechanism_names, unknown, unknown_count}` | inspection |
| `MAX_COMMAND_LINE` (512), `MAX_TEXT_LINE` (1000), `MAX_AUTH_LINE` (12,288) | RFC limits, in octets with CRLF |

```rust
use smtp_net::{Capabilities, Extension, protocol::{ReplyLimits, ReplyParser}};
let mut p = ReplyParser::new(ReplyLimits::default(), false);
let (used, reply) = p.push(b"250-mail.example.com\r\n250-SIZE 10240000\r\n250 CHUNKING\r\n")?;
assert_eq!(used, 55);
let caps = Capabilities::parse(&reply.unwrap())?;
assert!(caps.has(Extension::Chunking));
assert_eq!(caps.size_limit(), Some(10_240_000));
# Ok::<(), smtp_net::ProtocolError>(())
```

### SASL

| Item | Does |
|---|---|
| `Auth::new(credentials: Credentials) -> Auth` | credentials with the default allowlist; public fields `credentials`, `mechanisms` |
| `Auth::mechanisms(self, MechanismList)` | replaces the allowlist |
| `Auth::scram_nonce(self, &str) -> Result<Auth, Error>` | a fixed SCRAM nonce (tests, `no_std`) |
| `MechanismList::new(&[MechanismName]) -> Result<MechanismList, Error>`, `iter` | 1 to 8 names (`Config(TooManyMechanisms)`) |
| `Mechanism` (trait) | `name`, `initial_response`, `step(challenge, out) -> Result<Step, SaslError>`, `verify_success` |
| `Step` | `Continue` or `Done` |
| `CustomMechanism::new(name: &'static str, make: impl Fn() -> Box<dyn Mechanism>)`, `name` | a factory: each session gets a fresh mechanism (`Sasl(InvalidMechanismName)`) |

```rust
use smtp_net::{Credentials, SaslError, protocol::{CustomMechanism, Mechanism, Step}};

struct Token(Vec<u8>);
impl Mechanism for Token {
    fn name(&self) -> &'static str { "X-TOKEN" }
    fn initial_response(&mut self, out: &mut Vec<u8>) -> Result<bool, SaslError> {
        out.extend_from_slice(&self.0);
        Ok(true)
    }
    fn step(&mut self, _challenge: &[u8], _out: &mut Vec<u8>) -> Result<Step, SaslError> {
        Err(SaslError::InvalidChallenge)
    }
    fn verify_success(&mut self, _final_data: Option<&[u8]>) -> Result<(), SaslError> { Ok(()) }
}

let custom = CustomMechanism::new("X-TOKEN", || Box::new(Token(b"secret".to_vec())))?;
let server = smtp_net::Server::starttls("smtp.example.com").to_builder()
    .credentials(Credentials::Custom(custom))
    .build()?;
# let _ = server;
# Ok::<(), smtp_net::Error>(())
```

## The `mime` module

What `MessageBuilder` uses inside, for a body tree it does not make, a
large streamed part, allocation-free serialization, or reuse of an encoder.

### Parts

| Item | Does | Errors |
|---|---|---|
| `Part::text(content_type: &str, text: &str)` | a `text/*` part (`charset=utf-8` added), encoded as the builder encodes text | `Header(InvalidContentType)`, `Build(BareCarriageReturn)` |
| `Part::binary(content_type: &str, bytes: Vec<u8>)` | a base64 part | `Header` |
| `Part::multipart(kind: Multipart, parts: Vec<Part>)` | a container: `Mixed`, `Alternative`, `Related` | none |
| `Part::from_attachment(Attachment)`, `Part::from_inline(Inline)` | as the builder would | none |
| `Part::transfer_encoding(self, TransferEncoding)` | forces `SevenBit`, `EightBit`, `QuotedPrintable`, or `Base64` | `Build(EncodingMismatch)` |
| `ContentType::parse(&str)`, `with_parameter(self, name, value)`, `essence`, `parameter` | a validated media type | `HeaderError::InvalidContentType` |
| `BodySource` (trait: `read(&mut self, buf: &mut [u8]) -> Result<usize, SourceError>`), `ReadSource::new(impl std::io::Read)` | a streamed part's bytes | |

```rust
use smtp_net::{Message, mime::{Multipart, Part}};
let calendar = Part::text("text/calendar; method=REQUEST", "BEGIN:VCALENDAR\r\nEND:VCALENDAR")?;
let body = Part::multipart(Multipart::Alternative, vec![Part::text("text/plain", "Meeting at 10.")?, calendar]);
let msg = Message::builder()
    .from("calendar@example.com")?
    .to("user@example.org")?
    .subject("Meeting")?
    .body(body)
    .build()?;
assert!(msg.headers().get("Content-Type").unwrap().starts_with("multipart/alternative"));
# Ok::<(), smtp_net::Error>(())
```

### Headers

| Item | Does | Errors |
|---|---|---|
| `Headers::{get(name), iter, len, is_empty}` | a built message's headers (`get` ignores case) | none |
| `HeaderName::new(&str)`, `as_str` | a validated field name | `HeaderError::InvalidName` |
| `check_header_value(field: &'static str, value: &str)` | refuses CR, LF, NUL, the other C0 controls except TAB, DEL, C1 controls, U+2028, and U+2029 | `HeaderError::ControlCharacter` |
| `encode_word(text: &str, out: &mut String)` | RFC 2047 encoded words (Q or B, whichever is shorter) | `HeaderError` |
| `fold_header(name: &str, value: &str, out: &mut Vec<u8>)` | a folded header line, CRLF included | `HeaderError` |
| `MAX_HEADER_LINE` (998), `RECOMMENDED_HEADER_LINE` (78), `MAX_ENCODED_WORD` (75) | RFC 5322 and 2047 limits | |

```rust
use smtp_net::mime::{check_header_value, encode_word, fold_header};
assert!(check_header_value("Subject", "Hello\r\nBcc: x@evil.example").is_err());
let mut word = String::new();
encode_word("Grüße", &mut word)?;
assert_eq!(word, "=?UTF-8?B?R3LDvMOfZQ==?=");
let mut line = Vec::new();
fold_header("Subject", &"word ".repeat(30), &mut line)?;
assert!(line.split(|&b| b == b'\n').all(|l| l.len() <= 79));
# Ok::<(), smtp_net::HeaderError>(())
```

### Encoders

| Item | Does | Errors |
|---|---|---|
| `base64_encoded_len(n: u64) -> u64` | the size of `n` octets as base64 in 76-column lines | none |
| `base64_encode_lines(input: &[u8], out: &mut [u8]) -> Result<usize, Error>` | base64 into `out`, in 76-column lines separated by CRLF | `BufferTooSmall` |
| `QuotedPrintableState::new()` | streaming state | |
| `quoted_printable_encode(input, out, state)`, `quoted_printable_finish(out, state)` | quoted-printable, in pieces | `BufferTooSmall` |
| `MIME_LINE_LENGTH` (76) | | |

```rust
use smtp_net::mime::{QuotedPrintableState, base64_encode_lines, base64_encoded_len, quoted_printable_encode, quoted_printable_finish};
let mut out = vec![0u8; base64_encoded_len(5) as usize];
let n = base64_encode_lines(b"hello", &mut out)?;
assert_eq!(&out[..n], b"aGVsbG8=");
let mut state = QuotedPrintableState::new();
let mut qp = [0u8; 64];
let mut n = quoted_printable_encode("café".as_bytes(), &mut qp, &mut state)?;
n += quoted_printable_finish(&mut qp[n..], &mut state)?;
assert_eq!(&qp[..n], b"caf=C3=A9");
# Ok::<(), smtp_net::Error>(())
```

### Sinks and randomness

| Item | Does |
|---|---|
| `Sink` (trait: `write(&mut self, bytes: &[u8]) -> Result<(), SinkError>`) | where `Message::write_to` writes; `Vec<u8>` is one |
| `CountingSink { bytes: u64 }` | counts, stores nothing |
| `IoSink<W: std::io::Write>(pub W)` | any writer (feature `std`) |
| `RandomSource` (trait: `fill(&mut self, buf: &mut [u8]) -> Result<(), Error>`) | the randomness for `Message-ID`s and boundaries |
| `OsRandom` | the OS CSPRNG (feature `std`) |

```rust
use smtp_net::{Error, Message, mime::RandomSource};
struct Fixed;
impl RandomSource for Fixed {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        buf.fill(7);
        Ok(())
    }
}
let build = || Message::builder().from("a@example.com")?.to("b@example.org")?.subject("Hi")?.text("Hello")?.build_with(&mut Fixed, 1_700_000_000);
assert_eq!(build()?.to_bytes()?, build()?.to_bytes()?);
# Ok::<(), Error>(())
```

## The `dkim` module

The canonicalizers (RFC 6376 section 3.4), for code that hashes or checks
DKIM itself. They build without the `dkim` feature and without `std`.

| Item | Does |
|---|---|
| `BodyCanonicalizer::new(mode: Canonicalization)` | streaming body canonicalization |
| `update(&mut self, input: &[u8], out: &mut impl FnMut(&[u8]))`, `finish(self, out)` | feeds bytes; `finish` writes what the trailing-line rules held back |
| `HeaderCanonicalizer::new(mode)`, `canonicalize(&self, field: &[u8], out: &mut Vec<u8>)` | one header field |

```rust
use smtp_net::{Canonicalization, dkim::{BodyCanonicalizer, HeaderCanonicalizer}};
let mut body = Vec::new();
let mut c = BodyCanonicalizer::new(Canonicalization::Relaxed);
c.update(b"Hello  world \r\n\r\n\r\n", &mut |b| body.extend_from_slice(b));
c.finish(&mut |b| body.extend_from_slice(b));
assert_eq!(body, b"Hello world\r\n");
let mut field = Vec::new();
HeaderCanonicalizer::new(Canonicalization::Relaxed).canonicalize(b"Subject:  Hi \r\n", &mut field);
assert_eq!(field, b"subject:Hi\r\n");
```

## The `testing` module

Feature `testing`.

| Item | Does |
|---|---|
| `TestServer::start()`, `TestServer::builder() -> TestServerBuilder` | a loopback SMTP server on a free port, in its own thread; like Postfix, it answers a MAIL inside an open transaction with `503 5.5.1` and keeps the transaction |
| `TestServer::{port, server, server_builder}` | where it listens; a `Server` (or builder) pointing at it |
| `TestServer::{received, transcript, messages, connections, client_waits}` | what it received and how |
| `TestServerBuilder::{extensions(&[&str]), fault(Fault), refuse_ehlo, starttls, implicit_tls, tls_name, tls_engine, auth(user, password), oauth2(user, token), record(bool), start}` | what it offers and how it misbehaves |
| `ReceivedMessage` | public fields `from`, `recipients`, `mail_parameters`, `rcpt_parameters`, `data`, `secure`, `chunked`, `user` |
| `Fault` | `ReplyAt { stage, reply }`, `CloseAt(Stage)`, `CloseAfterDataEnd`, `CloseAfterMessages(n)`, `DelayAt { stage, by }`, `InjectAfterStartTls(bytes)`, `OmitStartTls`, `RejectCertificate`, `MalformedReply(Stage)`, `OversizedReply(Stage)`, `ExtraReply(Stage)`, `RejectRecipient(i)`, `TooManyRecipientsAfter(n)`, `SlowDrip { bytes_per_second }`, `BadScramSignature`, `RoundTrip(Duration)` |
| `TestTls` | a TLS engine for the test server's STARTTLS and implicit TLS (no real cryptography) |
| `Transcript::parse(&str)`, `len`, `is_empty` | an `S:` / `C:` conversation |
| `ScriptedServer::new(Transcript)`, `run(&self, &mut Session, &[PreparedMessage])`, `run_split(.., split)` | plays a transcript against a session; `ScriptOutcome { messages, closed }` or `ScriptMismatch { line, expected, got }` |

```rust
use smtp_net::{Stage, testing::{Fault, TestServer}};
let server = TestServer::builder()
    .fault(Fault::ReplyAt { stage: Stage::Mail, reply: "451 4.3.0 try later" })
    .start()?;
let msg = smtp_net::Message::text("no-reply@example.com", "user@example.org", "Hi", "Hello")?;
let e = smtp_net::send(&server.server(), &msg).unwrap_err();
assert!(e.is_temporary());
assert_eq!(e.stage(), Some(Stage::Mail));
# Ok::<(), smtp_net::Error>(())
```

## Constants

| Constant | Value |
|---|---|
| `PORT_SMTP` | 25 |
| `PORT_STARTTLS` | 587 (RFC 6409) |
| `PORT_IMPLICIT_TLS` | 465 (RFC 8314) |
| `VERSION` | the crate version |
| `MAX_LOCAL_PART`, `MAX_DOMAIN`, `MAX_PATH` | 64, 255, 256 octets (RFC 5321 4.5.3.1) |

## Migrating from 0.7

| 0.7 | 0.8 |
|---|---|
| `smtp_net::{Session, SessionConfig, Event, Millis, ...}` (the sans-IO core) | `smtp_net::protocol::{...}` |
| `smtp_net::{Part, ContentType, Sink, RandomSource, base64_encode_lines, ...}` | `smtp_net::mime::{...}` |
| `smtp_net::{BodyCanonicalizer, HeaderCanonicalizer}` | `smtp_net::dkim::{...}` |
| `smtp_net::{TestServer, Fault, ...}` | `smtp_net::testing::{...}` |
| `QpState` | `mime::QuotedPrintableState` |
| `PORT_SUBMISSION`, `PORT_SUBMISSIONS` | `PORT_STARTTLS`, `PORT_IMPLICIT_TLS` |
| `ServerBuilder::tls_connector(c)`, `ServerBuilder::tls(client)` | `ServerBuilder::tls(c)` |
| `ServerBuilder::mechanisms(&[..])?` | `ServerBuilder::mechanisms(&[..])` (checked by `build`) |
| `ServerBuilder::client_name(ClientName::Domain(Domain::parse(n)?))` | `ServerBuilder::client_name(n)` (checked by `build`) |
| `message.prepare_signed(&signers, now)` | `message.prepare()?.sign(&signers, now)` |
| `report.rejected()` yielding `(&Address, &Reply, Disposition)` | `report.rejected()` giving `&[RejectedRecipient]` |
| `report.accepted()` (an iterator) | `report.accepted()` giving `&[Address]` |
| `error.recipients()`, `RecipientFailure` | `error.rejected()`, `RejectedRecipient` |
| `SendGate::{admit(n, now), refund(n, now), admit_envelope, refund_envelope}` | `SendGate::{admit(&envelope, now), refund(&envelope, now)}` |
| `DomainLimit::per_domain(n)` | `DomainLimit::recipients(n)` |
| `ReplyCode::is_transient` | `ReplyCode::is_temporary` |
| `Dsn::ret(r)`, `Dsn::envelope_id(id)`, `Dsn::required()` | `Dsn::with_return_content(r)`, `Dsn::with_envelope_id(id)`, `Dsn::with_policy(DsnPolicy::Required)` |
| `Dsn::envelope_id_value()` | `Dsn::envelope_id()` |
| `Envelope::return_path(a)`, `Envelope::dsn(d)` (setters) | `Envelope::with_return_path(a)`, `Envelope::with_dsn(d)` |
| `Envelope::from()`, `Envelope::dsn_parameters()` (getters) | `Envelope::return_path()`, `Envelope::dsn()` |

## Changes since the design lock


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
| 0.7.1 | Connects race the resolved addresses (250 ms, 100 ms for loopback); no API change | D-107 |
| 0.7.1 | `DomainLimit` keeps a newer bucket's count after a backward clock step; no API change | D-106 |
| 0.7.2 | A refused MAIL or RCPT line queues nothing; new `BuildError::{CommandTooLong, CommandHasControl}` (were `Usage(Closed)`); `Client::is_open` is false while commands or replies are outstanding; `TestServer` answers a nested MAIL with `503` and keeps the transaction | D-119 |
| 0.8.0 | The root keeps what an application uses; the sans-IO core moves to `protocol`, MIME parts, encoders, sinks, and randomness to `mime`, the canonicalizers to `dkim`, test support to `testing` | D-110 |
| 0.8.0 | `SendGate` is `admit(&Envelope, now)` and `refund(&Envelope, now)` only (the count pair and `admit_envelope`/`refund_envelope` are gone) | D-111 |
| 0.8.0 | `ServerBuilder::tls(impl TlsConnector)` replaces `tls(TlsClient)` and `tls_connector` | D-112 |
| 0.8.0 | `Message::prepare_signed` removed: `prepare()?.sign(..)` | D-113 |
| 0.8.0 | New: `RejectedRecipient`; `Report::rejected` and `Error::rejected` give `&[RejectedRecipient]`, `Report::accepted` gives `&[Address]`; `RecipientFailure` and `Error::recipients` removed | D-114 |
| 0.8.0 | `PORT_STARTTLS` and `PORT_IMPLICIT_TLS` replace `PORT_SUBMISSION` and `PORT_SUBMISSIONS` | D-115 |
| 0.8.0 | `Dsn::{with_return_content, with_envelope_id, with_policy, envelope_id}`, `Envelope::{with_return_path, return_path, with_dsn, dsn}` replace `ret`, `envelope_id` (setter), `required`, `envelope_id_value`, `return_path` (setter), `from`, `dsn` (setter), `dsn_parameters` | D-116 |
| 0.8.0 | `DomainLimit::recipients`, `ReplyCode::is_temporary`, `mime::QuotedPrintableState` replace `per_domain`, `is_transient`, `QpState` | D-117 |
| 0.8.0 | `ServerBuilder::mechanisms` and `client_name(&str)` return `Self`, checked by `build`; new `ClientName::parse`, `ConfigError::InvalidClientName` | D-118 |
