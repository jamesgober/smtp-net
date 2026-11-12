//! # smtp_net
//!
//! An SMTP submission client: MIME message building, a sans-IO protocol
//! core, and a blocking driver, with every failure classified as temporary
//! or permanent.
//!
//! ## Tier 1: one call
//!
//! Through the mail server on this machine (for example cPanel's Exim on
//! `127.0.0.1:25`):
//!
//! ```no_run
//! # #[cfg(feature = "client")]
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let msg = smtp_net::Message::text(
//!         "Example <no-reply@example.com>",
//!         "user@example.org",
//!         "Confirm your email address",
//!         "Open this link to confirm: https://example.com/confirm/abc123",
//!     )?;
//!     smtp_net::send_local(&msg)?;
//!     Ok(())
//! }
//! # #[cfg(not(feature = "client"))] fn main() {}
//! ```
//!
//! Through a relay with STARTTLS on port 587 ([`Server::implicit_tls`] for
//! port 465); certificate verification is always on:
//!
//! ```no_run
//! # #[cfg(feature = "client")]
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let msg = smtp_net::Message::text("no-reply@example.com", "user@example.org", "Hello", "Sent through a relay.")?;
//!     let relay = smtp_net::Server::starttls("smtp.example.com").login("no-reply@example.com", "app-password");
//!     smtp_net::send(&relay, &msg)?;
//!     Ok(())
//! }
//! # #[cfg(not(feature = "client"))] fn main() {}
//! ```
//!
//! Every [`Error`] says whether to retry ([`Error::is_temporary`]) and
//! whether the server may already hold the message
//! ([`Error::possibly_delivered`]).
//!
//! ## Tier 2: builders
//!
//! [`Message::builder`] for text, HTML, attachments, inline images, and
//! custom headers; [`Server::builder`] for the port, EHLO name, timeouts,
//! credentials, DKIM signers, pacing, and recipient policy; [`Client`] to
//! send many messages on one connection, [`Pool`] to share a few
//! connections across threads; [`PreparedMessage`] for job payloads.
//!
//! ## Tier 3: modules
//!
//! - [`protocol`]: the sans-IO [`Session`](protocol::Session). Feed it
//!   bytes and the time, write out what it queues, and act on its events.
//!   It does no I/O, reads no clock, and draws no random numbers, so it
//!   runs under any transport and builds without `std` (with `alloc`).
//! - [`mime`]: MIME parts for a custom body tree, header encoding, the
//!   base64 and quoted-printable encoders, and serialization sinks.
//! - [`dkim`]: the DKIM canonicalizers.
//! - `testing` (feature `testing`): a loopback SMTP server with fault
//!   injection, and a scripted peer for the session.
//!
//! Every public item, with examples per task, is in `docs/API.md` in the
//! [repository](https://github.com/jamesgober/smtp-net).
//!
//! ## Status
//!
//! `0.8.0`, the alpha: feature complete, tuned, and hardened, with the API
//! simplified before the field test (`docs/release/v0.8.0.md` lists every
//! rename from 0.7). Measured numbers are in `docs/PERFORMANCE.md`, the
//! threat model and its tests in `docs/SECURITY.md`, platform differences
//! in `docs/PLATFORM-NOTES.md`.

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
pub mod dkim;
mod encode;
mod error;
mod gate;
mod message;
mod proto;
mod scan;
#[cfg(feature = "testing")]
pub mod testing;

pub use address::{Address, Domain, MAX_DOMAIN, MAX_LOCAL_PART, MAX_PATH, Mailbox};
pub use dkim::canon::Canonicalization;
#[cfg(feature = "dkim")]
pub use dkim::key::{DKIM_RSA_MAX_BITS, DKIM_RSA_MIN_BITS, DkimAlgorithm, DkimKey};
#[cfg(feature = "dkim")]
pub use dkim::signer::DkimSigner;
pub use error::{
    AddressError, AddressPart, BuildError, ConfigError, Disposition, DkimError, Error, ErrorKind,
    Extension, HeaderError, PayloadError, ProtocolError, RejectedRecipient, SinkError, SourceError,
    Stage, TlsFailure, UsageError,
};
pub use message::{
    AutoSubmitted, Message, MessageBuilder, MessageLimits,
    part::{Attachment, Inline},
    prepared::{Dsn, DsnNotify, DsnPolicy, DsnReturn, Envelope, PreparedMessage},
};
pub use proto::{
    Capabilities, Credentials, EnhancedCode, MechanismName, RecipientPolicy, Reply, ReplyCode,
    SaslError, Secret, Timeouts, TlsProtocol,
};

#[cfg(feature = "client")]
pub use client::{
    Client, ObservedEvent, Observer, Pool, Report, Security, SecurityEventKind, Server,
    ServerBuilder, TlsConnector, TlsSetupError, send, send_local, send_prepared,
};
#[cfg(feature = "std")]
pub use gate::DomainLimit;
#[cfg(target_has_atomic = "64")]
pub use gate::HourlyLimit;
pub use gate::{Admission, CountUnit, SendGate};

pub mod protocol {
    //! The sans-IO SMTP session (Tier 3): the state machine under
    //! [`Client`](crate::Client), for a driver over another transport (an
    //! async runtime, an event loop, a test harness).
    //!
    //! [`Session`] does no I/O, reads no clock, and draws no random numbers:
    //! feed it the bytes the server sent and the time, write out what it
    //! queues ([`Session::transmit`]), and act on its [`Event`]s. It builds
    //! without `std` (with `alloc`). The types a session shares with the
    //! blocking client ([`Credentials`](crate::Credentials),
    //! [`Timeouts`](crate::Timeouts), [`Reply`](crate::Reply),
    //! [`Capabilities`](crate::Capabilities)) are at the crate root.
    pub use crate::proto::{
        Auth, BodyFlags, ClientName, CustomMechanism, Event, MAX_AUTH_LINE, MAX_COMMAND_LINE,
        MAX_TEXT_LINE, Mechanism, MechanismList, Millis, ReplyLimits, ReplyParser, Session,
        SessionConfig, SessionSecurity, SessionState, Step, TextLossy, TlsInfo,
    };
}

pub mod mime {
    //! The parts of a message below [`MessageBuilder`](crate::MessageBuilder)
    //! (Tier 3): MIME parts for a custom body tree, header encoding, the
    //! base64 and quoted-printable encoders, serialization sinks, and the
    //! random source for `Message-ID`s and boundaries.
    //!
    //! [`MessageBuilder`](crate::MessageBuilder) uses all of these for you;
    //! reach for them to build a body tree it does not make
    //! ([`MessageBuilder::body`](crate::MessageBuilder::body)), to stream a
    //! large attachment ([`ReadSource`]), to serialize without allocating
    //! ([`Sink`]), or to reuse an encoder.
    pub use crate::encode::{
        MIME_LINE_LENGTH, QuotedPrintableState, base64_encode_lines, base64_encoded_len,
        quoted_printable_encode, quoted_printable_finish,
    };
    pub use crate::message::{
        header::{
            HeaderName, Headers, MAX_ENCODED_WORD, MAX_HEADER_LINE, RECOMMENDED_HEADER_LINE,
            check_header_value, encode_word, fold_header,
        },
        id::RandomSource,
        part::{BodySource, ContentType, Multipart, Part, TransferEncoding},
        sink::{CountingSink, Sink},
    };
    #[cfg(feature = "std")]
    pub use crate::message::{id::OsRandom, part::ReadSource, sink::IoSink};
}

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The SMTP port (RFC 5321).
pub const PORT_SMTP: u16 = 25;
/// The message submission port, STARTTLS (RFC 6409).
pub const PORT_STARTTLS: u16 = 587;
/// The message submission port, implicit TLS (RFC 8314).
pub const PORT_IMPLICIT_TLS: u16 = 465;

/// Every Rust block in the README and in `docs/API.md` is compiled (and,
/// unless marked `no_run`, run) as a doctest, so the documentation cannot
/// drift from the API.
#[cfg(all(
    doctest,
    feature = "client",
    feature = "tls",
    feature = "dkim",
    feature = "scram",
    feature = "testing"
))]
mod doc_tests {
    #[doc = include_str!("../README.md")]
    struct Readme;
    #[doc = include_str!("../docs/API.md")]
    struct ApiReference;
}

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
