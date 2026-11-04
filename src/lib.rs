//! # smtp_net
//!
//! An SMTP submission client: MIME message building, a sans-IO protocol
//! core, and a blocking driver, with every failure classified as temporary
//! or permanent.
//!
//! ## Tier 1: one call
//!
//! ```no_run
//! # #[cfg(feature = "client")] {
//! let msg = smtp_net::Message::text(
//!     "Example <no-reply@example.com>",
//!     "user@example.org",
//!     "Confirm your email address",
//!     "Open this link to confirm: https://example.com/confirm/abc123",
//! )?;
//! match smtp_net::send_local(&msg) {
//!     Ok(report) => println!("accepted as {}", report.message_id()),
//!     Err(e) if e.possibly_delivered() => eprintln!("the server may have it: {e}"),
//!     Err(e) if e.is_temporary() => eprintln!("retry later: {e}"),
//!     Err(e) => eprintln!("do not retry: {e}"),
//! }
//! # }
//! # Ok::<(), smtp_net::Error>(())
//! ```
//!
//! ## Tier 2: builders
//!
//! [`Message::builder`] for text, HTML, attachments, inline images, and
//! custom headers; [`Server::builder`] for the port, EHLO name, timeouts,
//! and recipient policy; [`Client`] to send many messages on one connection.
//!
//! ## Tier 3: the sans-IO core
//!
//! [`Session`] is the SMTP state machine: feed it bytes and the time, write
//! out what it queues, and act on its [`Event`]s. It does no I/O, reads no
//! clock, and draws no random numbers, so it runs under any transport and
//! builds without `std` (with `alloc`).
//!
//! ## Status
//!
//! `0.4.0`: messages, the session, local submission, STARTTLS and implicit
//! TLS relays with AUTH, CHUNKING, DSN, pacing, and job payloads. DKIM,
//! XOAUTH2, and SCRAM arrive in `0.5.0` (`dev/ROADMAP.md` in the
//! [repository](https://github.com/jamesgober/smtp-net)).

#![doc(html_root_url = "https://docs.rs/smtp-net")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate alloc;

mod address;
#[cfg(feature = "client")]
mod client;
mod encode;
mod error;
mod gate;
mod message;
mod proto;
#[cfg(feature = "testing")]
mod testing;

pub use address::{Address, Domain, MAX_DOMAIN, MAX_LOCAL_PART, MAX_PATH, Mailbox};
pub use encode::{
    MIME_LINE_LENGTH, QpState, base64_encode_lines, base64_encoded_len, quoted_printable_encode,
    quoted_printable_finish,
};
pub use error::{
    AddressError, AddressPart, BuildError, ConfigError, Disposition, Error, ErrorKind, Extension,
    HeaderError, PayloadError, ProtocolError, RecipientFailure, SinkError, Stage, TlsFailure,
    UsageError,
};
pub use message::{
    AutoSubmitted, Message, MessageBuilder, MessageLimits,
    header::{
        HeaderName, Headers, MAX_ENCODED_WORD, MAX_HEADER_LINE, RECOMMENDED_HEADER_LINE,
        check_header_value, encode_word, fold_header,
    },
    id::RandomSource,
    part::{Attachment, ContentType, Inline, Multipart, Part, TransferEncoding},
    prepared::{Dsn, DsnNotify, DsnPolicy, DsnReturn, Envelope, PreparedMessage},
    sink::{CountingSink, Sink},
};
#[cfg(feature = "std")]
pub use message::{id::OsRandom, sink::IoSink};
pub use proto::{
    Auth, BodyFlags, Capabilities, ClientName, Credentials, EnhancedCode, Event, MAX_AUTH_LINE,
    MAX_COMMAND_LINE, MAX_TEXT_LINE, MechanismList, MechanismName, Millis, RecipientPolicy, Reply,
    ReplyCode, ReplyLimits, ReplyParser, SaslError, Secret, Session, SessionConfig,
    SessionSecurity, SessionState, TextLossy, Timeouts, TlsInfo, TlsProtocol,
};

#[cfg(feature = "client")]
pub use client::{
    Client, Report, Security, Server, ServerBuilder, TlsConnector, TlsSetupError, send, send_local,
    send_prepared,
};
#[cfg(target_has_atomic = "64")]
pub use gate::HourlyLimit;
pub use gate::{Admission, CountUnit, SendGate};

#[cfg(feature = "testing")]
pub use testing::{
    Fault, ReceivedMessage, ScriptMismatch, ScriptOutcome, ScriptedServer, TestServer,
    TestServerBuilder, TestTls, Transcript,
};

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The SMTP port (RFC 5321).
pub const PORT_SMTP: u16 = 25;
/// The message submission port, STARTTLS (RFC 6409).
pub const PORT_SUBMISSION: u16 = 587;
/// The message submission port, implicit TLS (RFC 8314).
pub const PORT_SUBMISSIONS: u16 = 465;

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
