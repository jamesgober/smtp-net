//! Errors, with the temporary or permanent disposition a job system acts on.
//!
//! Every fallible function in the crate returns [`Error`]. Its
//! [`disposition`](Error::disposition) says whether retrying can help, and
//! [`possibly_delivered`](Error::possibly_delivered) says whether the server
//! may already hold the message (the end of the data was written and no reply
//! was read), following the classification table in `dev/PLAN.md` 7.7.

use alloc::{boxed::Box, vec::Vec};
use core::{fmt, time::Duration};

use crate::{address::Address, proto::Reply};

/// Whether retrying the same operation later can succeed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Disposition {
    /// The failure may clear by itself (a busy server, a network fault, a
    /// `4yz` reply): retry later, with backoff.
    Temporary,
    /// Retrying the same input cannot succeed (an invalid address, a `5yz`
    /// reply, a configuration mistake): stop and report it.
    Permanent,
}

/// The step of the conversation an error happened in.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Resolving the host and opening the TCP connection.
    Connect,
    /// Waiting for the server's `220` greeting.
    Greeting,
    /// `EHLO`.
    Ehlo,
    /// `HELO` (the fallback after `EHLO` was refused).
    Helo,
    /// `STARTTLS`.
    StartTls,
    /// The TLS handshake.
    TlsHandshake,
    /// `AUTH`.
    Auth,
    /// `MAIL FROM`.
    Mail,
    /// `RCPT TO`.
    Rcpt,
    /// `DATA` (waiting for `354`).
    Data,
    /// Writing the message body.
    Body,
    /// Waiting for the reply to the end of the data.
    DataEnd,
    /// `BDAT`.
    Bdat,
    /// `RSET`.
    Rset,
    /// `NOOP`.
    Noop,
    /// `QUIT`.
    Quit,
    /// The whole send, bounded by `Timeouts::total`.
    Total,
}

impl Stage {
    /// The stage's name as it appears in messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Stage::Connect => "connect",
            Stage::Greeting => "greeting",
            Stage::Ehlo => "EHLO",
            Stage::Helo => "HELO",
            Stage::StartTls => "STARTTLS",
            Stage::TlsHandshake => "TLS handshake",
            Stage::Auth => "AUTH",
            Stage::Mail => "MAIL FROM",
            Stage::Rcpt => "RCPT TO",
            Stage::Data => "DATA",
            Stage::Body => "message body",
            Stage::DataEnd => "end of data",
            Stage::Bdat => "BDAT",
            Stage::Rset => "RSET",
            Stage::Noop => "NOOP",
            Stage::Quit => "QUIT",
            Stage::Total => "whole send",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Which part of an address a length error is about.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressPart {
    /// The local part, before the `@` (at most 64 octets).
    LocalPart,
    /// The domain (at most 255 octets).
    Domain,
    /// The whole address as an SMTP path (at most 256 octets with `<` and `>`).
    Path,
}

/// An address or mailbox was refused.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressError {
    /// The input is empty.
    Empty,
    /// A part is longer than RFC 5321 4.5.3.1 allows.
    TooLong {
        /// The part that is too long.
        part: AddressPart,
        /// Its length in octets.
        length: usize,
        /// The limit.
        limit: usize,
    },
    /// The local part is not a dot-atom or a quoted string.
    InvalidLocalPart {
        /// Byte offset of the problem in the input.
        position: usize,
    },
    /// The domain is not a sequence of valid labels.
    InvalidDomain {
        /// Byte offset of the problem in the input.
        position: usize,
    },
    /// A domain label is longer than 63 octets.
    LabelTooLong {
        /// Zero-based index of the label.
        label: usize,
    },
    /// A domain literal (`[192.0.2.1]`) where only names are accepted.
    AddressLiteralNotAllowed,
    /// There is no `@`.
    MissingAt,
    /// A control character (CR, LF, NUL, another C0 or C1 control, DEL).
    ControlCharacter {
        /// Byte offset of the character in the input.
        position: usize,
    },
    /// A non-ASCII domain where SMTPUTF8 is not in use (no IDNA yet, D-016).
    InternationalDomainUnsupported,
    /// The display name is not a phrase or quoted string.
    DisplayNameInvalid {
        /// Byte offset of the problem in the input.
        position: usize,
    },
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            AddressError::Empty => {
                f.write_str("the address is empty; give an address such as user@example.com")
            }
            AddressError::TooLong {
                part,
                length,
                limit,
            } => {
                let what = match part {
                    AddressPart::LocalPart => "the local part (before the @)",
                    AddressPart::Domain => "the domain",
                    AddressPart::Path => "the address",
                };
                write!(
                    f,
                    "{what} is {length} octets, longer than the limit of {limit}"
                )
            }
            AddressError::InvalidLocalPart { position } => write!(
                f,
                "the local part is not valid at byte {position}; use letters, digits, and dots without a leading, trailing, or doubled dot, or a quoted string"
            ),
            AddressError::InvalidDomain { position } => write!(
                f,
                "the domain is not valid at byte {position}; use labels of letters, digits, and hyphens separated by single dots"
            ),
            AddressError::LabelTooLong { label } => {
                write!(f, "domain label {label} is longer than 63 octets")
            }
            AddressError::AddressLiteralNotAllowed => f.write_str(
                "address literals such as [192.0.2.1] are not accepted here; use a domain name",
            ),
            AddressError::MissingAt => f.write_str("the address has no @"),
            AddressError::ControlCharacter { position } => write!(
                f,
                "the address contains a control character at byte {position} (CR, LF, NUL, or another control); it was refused, not stripped"
            ),
            AddressError::InternationalDomainUnsupported => f.write_str(
                "the domain is not ASCII; write it as an A-label (xn--...) or send with SMTPUTF8",
            ),
            AddressError::DisplayNameInvalid { position } => write!(
                f,
                "the display name is not valid at byte {position}; quote names that contain punctuation such as , ; : < > @ ( )"
            ),
        }
    }
}

/// A header value, header name, or encoded header part was refused.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeaderError {
    /// A control character in a header value: CR, LF, NUL, another C0 or C1
    /// control other than TAB, DEL, or U+2028 and U+2029 (T-1). Refused,
    /// never stripped.
    ControlCharacter {
        /// The header field the value was for.
        field: &'static str,
        /// Byte offset of the character in the value.
        position: usize,
    },
    /// A header name outside RFC 5322 `ftext`, empty, or longer than 76 octets.
    InvalidName,
    /// A header name the builder sets itself (From, Subject, Date, Content-Type, ...).
    Reserved,
    /// A value that cannot be folded into lines of at most 998 octets.
    LineTooLong,
    /// A `Message-ID`, `In-Reply-To`, or `References` id that is not `left@right`
    /// with dot-atom text on both sides.
    InvalidMessageId,
    /// A date outside the range the `Date` header can carry.
    InvalidDate,
    /// A `List-Unsubscribe` target with `<`, `>`, `,`, whitespace, or a control.
    InvalidUnsubscribe,
    /// An attachment file name that is empty, contains `/`, `\`, or a control,
    /// or is longer than 255 octets (T-24).
    InvalidFileName,
    /// A content type that is not `type/subtype` with token characters.
    InvalidContentType,
    /// A `Content-ID` that is not `left@right` with dot-atom text on both sides.
    InvalidContentId,
    /// A bidirectional override or isolate (U+202A to U+202E, U+2066 to
    /// U+2069) in the Subject or a display name, which can make a reader show
    /// the text in another order (T-35). Refused unless
    /// `MessageBuilder::allow_bidi_controls` is set.
    BidiControl {
        /// The header field the value was for.
        field: &'static str,
        /// Byte offset of the character in the value.
        position: usize,
    },
    /// A display name containing `@`, refused under
    /// `MessageBuilder::refuse_address_like_display_names` (T-25).
    AddressLikeDisplayName {
        /// The header field the mailbox was for.
        field: &'static str,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            HeaderError::ControlCharacter { field, position } => write!(
                f,
                "the {field} value contains a control character at byte {position} (CR, LF, NUL, or another control); it was refused, not stripped"
            ),
            HeaderError::InvalidName => f.write_str(
                "the header name must be 1 to 76 printable ASCII characters without spaces or a colon",
            ),
            HeaderError::Reserved => f.write_str(
                "this header is set by the builder; use the builder method for it (from, to, subject, ...)",
            ),
            HeaderError::LineTooLong => f.write_str(
                "the header value has a word longer than a 998-octet line; add spaces or shorten it",
            ),
            HeaderError::InvalidMessageId => {
                f.write_str("the message id must look like left@right, with dot-atom text on both sides")
            }
            HeaderError::InvalidDate => f.write_str("the date is outside the years 1 to 9999 or the offset is beyond 23:59"),
            HeaderError::InvalidUnsubscribe => f.write_str(
                "an unsubscribe target must be a URI without spaces, commas, angle brackets, or controls",
            ),
            HeaderError::InvalidFileName => f.write_str(
                "the file name must be 1 to 255 octets with no /, \\, or control characters",
            ),
            HeaderError::InvalidContentType => {
                f.write_str("the content type must be type/subtype, for example application/pdf")
            }
            HeaderError::InvalidContentId => {
                f.write_str("the content id must look like left@right, for example logo@example.com")
            }
            HeaderError::BidiControl { field, position } => write!(
                f,
                "the {field} value contains a bidirectional override or isolate at byte {position}; allow them with allow_bidi_controls"
            ),
            HeaderError::AddressLikeDisplayName { field } => write!(
                f,
                "a {field} display name contains @, so a reader could take it for the address"
            ),
        }
    }
}

/// A message could not be built or a raw message was refused.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BuildError {
    /// No From mailbox was set.
    MissingFrom,
    /// More than one From mailbox (not supported before 1.0).
    MultipleFrom,
    /// No recipient in To, Cc, or Bcc, and no explicit envelope.
    NoRecipients,
    /// More recipients than `MessageLimits::max_recipients` (T-27).
    TooManyRecipients {
        /// The limit.
        limit: u16,
    },
    /// More entries of one kind than the limit allows.
    TooMany {
        /// What there were too many of.
        what: &'static str,
        /// The limit.
        limit: u32,
    },
    /// More MIME parts than `MessageLimits::max_parts`.
    TooManyParts,
    /// More custom headers than `MessageLimits::max_headers`.
    TooManyHeaders,
    /// The message (encoded) or a value is larger than its limit.
    TooLarge {
        /// The size in octets.
        size: u64,
        /// The limit in octets.
        limit: u64,
    },
    /// The MIME tree is deeper than `MessageLimits::max_depth`.
    DepthExceeded,
    /// An inline part without an HTML body to refer to it.
    InlineWithoutHtml,
    /// Two inline parts with the same Content-ID.
    DuplicateContentId,
    /// A CR not followed by LF (T-4).
    BareCarriageReturn {
        /// Byte offset of the CR.
        position: u64,
    },
    /// An LF not preceded by CR, in bytes that must use CRLF (T-4).
    BareLineFeed {
        /// Byte offset of the LF.
        position: u64,
    },
    /// A line longer than 998 octets in a raw message.
    LineTooLong {
        /// One-based line number.
        line: u64,
    },
    /// A raw message without a header block ending in an empty line.
    NoHeaderBlock,
    /// A source delivered more or fewer bytes than it declared.
    LengthMismatch {
        /// The declared length.
        declared: u64,
        /// The length delivered.
        actual: u64,
    },
    /// A forced transfer encoding that does not fit the content.
    EncodingMismatch,
    /// An invalid DSN parameter.
    InvalidDsn,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            BuildError::MissingFrom => {
                f.write_str("the message has no From address; set one with from()")
            }
            BuildError::MultipleFrom => {
                f.write_str("the message has more than one From address; use one")
            }
            BuildError::NoRecipients => {
                f.write_str("the message has no recipients; add one with to(), cc(), or bcc()")
            }
            BuildError::TooManyRecipients { limit } => write!(
                f,
                "the message has more than {limit} recipients; split it or raise MessageLimits::max_recipients"
            ),
            BuildError::TooMany { what, limit } => write!(f, "more than {limit} {what}"),
            BuildError::TooManyParts => {
                f.write_str("the message has more MIME parts than MessageLimits::max_parts")
            }
            BuildError::TooManyHeaders => {
                f.write_str("the message has more custom headers than MessageLimits::max_headers")
            }
            BuildError::TooLarge { size, limit } => {
                write!(f, "{size} octets is larger than the limit of {limit}")
            }
            BuildError::DepthExceeded => {
                f.write_str("the MIME tree is deeper than MessageLimits::max_depth")
            }
            BuildError::InlineWithoutHtml => {
                f.write_str("inline parts need an HTML body that refers to them; add html()")
            }
            BuildError::DuplicateContentId => {
                f.write_str("two inline parts have the same Content-ID")
            }
            BuildError::BareCarriageReturn { position } => write!(
                f,
                "a CR without LF at byte {position}; use LF or CRLF line endings"
            ),
            BuildError::BareLineFeed { position } => write!(
                f,
                "an LF without CR at byte {position}; raw messages must use CRLF line endings"
            ),
            BuildError::LineTooLong { line } => write!(f, "line {line} is longer than 998 octets"),
            BuildError::NoHeaderBlock => {
                f.write_str("the raw message has no header block ending in an empty line")
            }
            BuildError::LengthMismatch { declared, actual } => write!(
                f,
                "the source declared {declared} octets and delivered {actual}"
            ),
            BuildError::EncodingMismatch => {
                f.write_str("the forced transfer encoding does not fit the content")
            }
            BuildError::InvalidDsn => f.write_str("a DSN parameter is not valid"),
        }
    }
}

/// A configuration that cannot work was refused before anything was sent.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigError {
    /// Port 0.
    PortZero,
    /// The host is empty or not a valid name or address.
    InvalidHost,
    /// `PlaintextLoopback` with a host that is not `127.0.0.0/8`, `::1`, or `localhost` (T-32).
    PlaintextHostNotLoopback,
    /// An output buffer smaller than the longest command line.
    BufferTooSmall,
    /// STARTTLS or implicit TLS without a TLS engine (D-025); nothing was sent.
    TlsConnectorMissing,
    /// A mechanism allowlist that is empty or longer than 8.
    TooManyMechanisms,
    /// Certificate verification turned off for a host that is not loopback,
    /// without `allow_insecure_remote(true)` (D-024).
    InsecureNotAllowed,
    /// A session configured to authenticate over plaintext to a peer not
    /// confirmed to be loopback (T-8).
    AuthWithPlaintextRemote,
    /// More than 4 DKIM signers on one server.
    TooManyDkimSigners,
    /// A pool size outside 1 to 64.
    PoolSize,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConfigError::PortZero => "port 0 is not a server port",
            ConfigError::InvalidHost => "the host is empty or not a valid host name or IP address",
            ConfigError::PlaintextHostNotLoopback => {
                "plaintext submission is allowed only to 127.0.0.0/8, ::1, or localhost; use STARTTLS (port 587) or implicit TLS (port 465) for other hosts"
            }
            ConfigError::BufferTooSmall => "the output buffer is smaller than the longest SMTP command (512 octets)",
            ConfigError::TooManyMechanisms => "the AUTH mechanism list must hold 1 to 8 mechanisms",
            ConfigError::InsecureNotAllowed => {
                "certificate verification can be turned off only for a loopback host, or with allow_insecure_remote(true)"
            }
            ConfigError::TlsConnectorMissing => {
                "STARTTLS and implicit TLS need a TLS engine, which this build does not have; nothing was sent"
            }
            ConfigError::AuthWithPlaintextRemote => {
                "credentials are sent only over TLS or to a peer confirmed to be loopback"
            }
            ConfigError::TooManyDkimSigners => "a server takes at most 4 DKIM signers",
            ConfigError::PoolSize => "a pool holds 1 to 64 connections",
        })
    }
}

/// The session was used in a way its state does not allow (a caller bug).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UsageError {
    /// The call is not valid in the session's current state.
    WrongState {
        /// The state the session was in.
        state: crate::proto::SessionState,
    },
    /// The session is closed.
    Closed,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageError::WrongState { state } => write!(
                f,
                "the call is not valid while the session is {state:?}; follow the events the session reports"
            ),
            UsageError::Closed => f.write_str("the session is closed; open a new connection"),
        }
    }
}

/// The server's bytes broke the SMTP grammar or a budget (a security event).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtocolError {
    /// A reply line that is not `3DIGIT ( "-" / SP ) text CRLF`.
    MalformedReply,
    /// A multi-line reply whose lines carry different codes.
    InconsistentReply,
    /// A reply line, line count, or total over `ReplyLimits`.
    ReplyTooLong,
    /// A reply line ending in LF without CR.
    BareLineFeed,
    /// A NUL byte in a reply.
    Nul,
    /// A reply when no command was outstanding (T-14).
    UnexpectedReply,
    /// An EHLO capability line that cannot be parsed.
    MalformedCapability,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProtocolError::MalformedReply => "the server sent a reply line that is not valid SMTP",
            ProtocolError::InconsistentReply => {
                "the server sent a multi-line reply with different codes"
            }
            ProtocolError::ReplyTooLong => "the server's reply is over the reply budget",
            ProtocolError::BareLineFeed => "the server ended a reply line with LF instead of CRLF",
            ProtocolError::Nul => "the server sent a NUL byte",
            ProtocolError::UnexpectedReply => {
                "the server sent a reply when no command was outstanding"
            }
            ProtocolError::MalformedCapability => {
                "the server's EHLO reply has a capability line that is not valid"
            }
        })
    }
}

/// How a TLS handshake or TLS stream failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsFailure {
    /// Certificate verification failed, the name did not match, or the
    /// version was refused (T-11): permanent, retrying cannot pass.
    CertificateRejected,
    /// The peer does not speak TLS (implicit TLS to a plaintext port): permanent.
    ProtocolMismatch,
    /// The handshake failed on I/O or timed out: temporary.
    Handshake,
    /// The peer ended the TLS stream without close_notify: temporary.
    Closed,
    /// The engine could not build a session: permanent.
    Setup,
}

impl fmt::Display for TlsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TlsFailure::CertificateRejected => {
                "the server's certificate was refused (verification failed, wrong name, or TLS version); nothing was sent"
            }
            TlsFailure::ProtocolMismatch => {
                "the server did not answer TLS; if it expects STARTTLS, use port 587 and Security::StartTls"
            }
            TlsFailure::Handshake => "the TLS handshake failed or timed out",
            TlsFailure::Closed => "the server ended the TLS stream without closing it",
            TlsFailure::Setup => "the TLS engine could not start a session",
        })
    }
}

/// A job payload could not be decoded (T-33).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PayloadError {
    /// The magic, a length, or the checksum is wrong: the payload was
    /// damaged or is not an smtp-net payload.
    Corrupt,
    /// The payload was written by a version of smtp-net this one cannot read.
    UnknownVersion {
        /// The version byte.
        version: u8,
    },
    /// A length field is over its budget.
    TooLarge,
    /// The payload ends before its fields do.
    Truncated,
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadError::Corrupt => {
                f.write_str("the job payload is damaged (checksum or structure); it was not sent")
            }
            PayloadError::UnknownVersion { version } => write!(
                f,
                "the job payload has format version {version}, which this smtp-net cannot read; upgrade the worker"
            ),
            PayloadError::TooLarge => {
                f.write_str("a length in the job payload is over its budget; it was not sent")
            }
            PayloadError::Truncated => f.write_str("the job payload is truncated; it was not sent"),
        }
    }
}

/// DKIM signing or key loading failed (API 8.7).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DkimError {
    /// The `d=` domain is not a valid ASCII domain name.
    InvalidDomain,
    /// The selector is not dot-separated letters, digits, and hyphens.
    InvalidSelector,
    /// A header name in the signed or oversigned list is not a field name.
    InvalidHeaderName,
    /// The key is not in a format this crate reads (PKCS#8 or PKCS#1, PEM
    /// or DER, unencrypted), or is not a key for the algorithm asked for.
    KeyFormat,
    /// The RSA modulus is shorter than the minimum.
    KeyTooSmall {
        /// The modulus length in bits.
        bits: u32,
        /// The smallest accepted length.
        minimum: u32,
    },
    /// The RSA modulus is longer than 4096 bits, the most every verifier
    /// must handle (RFC 8301 section 3.2).
    KeyTooLarge {
        /// The modulus length in bits.
        bits: u32,
    },
    /// The message has no From header, which DKIM must sign.
    MissingFrom,
    /// The header block is over its budget (64 KiB).
    HeaderBlockTooLarge,
    /// The message is not RFC 5322 text DKIM can sign.
    MalformedMessage {
        /// The 1-based line where the problem is.
        line: usize,
    },
    /// The `i=` identity is outside the `d=` domain (RFC 6376 section 3.5).
    IdentityOutsideDomain,
    /// The signing backend failed.
    Signing,
}

impl fmt::Display for DkimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DkimError::InvalidDomain => f.write_str("the DKIM domain (d=) is not a valid ASCII domain name"),
            DkimError::InvalidSelector => f.write_str(
                "the DKIM selector is not dot-separated labels of letters, digits, and hyphens",
            ),
            DkimError::InvalidHeaderName => f.write_str("a DKIM signed header name is not a valid field name"),
            DkimError::KeyFormat => f.write_str(
                "the DKIM key is not an unencrypted PKCS#8 or PKCS#1 key (PEM or DER) for this algorithm",
            ),
            DkimError::KeyTooSmall { bits, minimum } => write!(
                f,
                "the DKIM RSA key has {bits} bits; at least {minimum} are required"
            ),
            DkimError::KeyTooLarge { bits } => write!(
                f,
                "the DKIM RSA key has {bits} bits; receivers only must handle up to 4096"
            ),
            DkimError::MissingFrom => f.write_str("the message has no From header, which DKIM must sign"),
            DkimError::HeaderBlockTooLarge => f.write_str("the message header block is over 64 KiB"),
            DkimError::MalformedMessage { line } => write!(
                f,
                "the message cannot be DKIM signed: line {line} is not a header field"
            ),
            DkimError::IdentityOutsideDomain => {
                f.write_str("the DKIM identity (i=) is outside the signing domain (d=)")
            }
            DkimError::Signing => f.write_str("the DKIM signing backend failed"),
        }
    }
}

/// A [`BodySource`](crate::BodySource) failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceError {
    /// The source failed, with its reason.
    Failed(&'static str),
    /// Reading failed.
    #[cfg(feature = "std")]
    Io(std::io::ErrorKind),
    /// The source was read already: a message with a streamed attachment
    /// serializes once.
    Consumed,
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceError::Failed(reason) => write!(f, "the attachment source failed: {reason}"),
            #[cfg(feature = "std")]
            SourceError::Io(kind) => write!(f, "reading the attachment source failed ({kind})"),
            SourceError::Consumed => f.write_str(
                "the streamed attachment was read already; build the message again to resend it",
            ),
        }
    }
}

/// A serialization sink refused bytes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SinkError {
    /// The sink has no room.
    Full,
    /// The underlying writer failed.
    #[cfg(feature = "std")]
    Io(std::io::ErrorKind),
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SinkError::Full => f.write_str("the output has no room for the message"),
            #[cfg(feature = "std")]
            SinkError::Io(kind) => write!(f, "writing the message failed: {kind}"),
        }
    }
}

/// An SMTP extension the server must offer for this message.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Extension {
    /// RFC 2920 command pipelining.
    Pipelining,
    /// RFC 1870 message size declaration.
    Size,
    /// RFC 6152 8-bit MIME transport.
    EightBitMime,
    /// RFC 6531 internationalized email.
    Smtputf8,
    /// RFC 3030 `BDAT`.
    Chunking,
    /// RFC 3030 binary MIME.
    BinaryMime,
    /// RFC 3461 delivery status notifications.
    Dsn,
    /// RFC 2034 enhanced status codes.
    EnhancedStatusCodes,
    /// RFC 3207 `STARTTLS`.
    StartTls,
    /// RFC 4954 `AUTH`.
    Auth,
    /// RFC 8689 `REQUIRETLS`.
    RequireTls,
}

impl Extension {
    /// The EHLO keyword.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Extension::Pipelining => "PIPELINING",
            Extension::Size => "SIZE",
            Extension::EightBitMime => "8BITMIME",
            Extension::Smtputf8 => "SMTPUTF8",
            Extension::Chunking => "CHUNKING",
            Extension::BinaryMime => "BINARYMIME",
            Extension::Dsn => "DSN",
            Extension::EnhancedStatusCodes => "ENHANCEDSTATUSCODES",
            Extension::StartTls => "STARTTLS",
            Extension::Auth => "AUTH",
            Extension::RequireTls => "REQUIRETLS",
        }
    }
}

/// What went wrong.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// An address or mailbox was refused.
    Address(AddressError),
    /// A header value or name was refused.
    Header(HeaderError),
    /// The message could not be built.
    Build(BuildError),
    /// The configuration cannot work.
    Config(ConfigError),
    /// The session was used out of order (a caller bug).
    Usage(UsageError),
    /// The OS random source failed.
    Random,
    /// A serialization sink refused bytes.
    Sink(SinkError),
    /// A job payload could not be decoded.
    Payload(PayloadError),
    /// DKIM signing or key loading failed.
    Dkim(DkimError),
    /// A streamed attachment's source failed.
    Source(SourceError),
    /// The TCP connection could not be opened.
    #[cfg(feature = "std")]
    Connect(std::io::ErrorKind),
    /// Reading or writing the connection failed.
    #[cfg(feature = "std")]
    Io(std::io::ErrorKind),
    /// A stage deadline passed.
    Timeout,
    /// Plaintext was configured, but the peer is not a loopback address (T-8, T-32).
    PlaintextRefused,
    /// TLS is required and the server does not offer STARTTLS (T-5); nothing was sent.
    StartTlsUnavailable,
    /// Plaintext bytes followed the server's `220` to STARTTLS (T-6).
    StartTlsInjection,
    /// The TLS handshake or stream failed.
    Tls(TlsFailure),
    /// A pacing gate refused; see [`Error::retry_after`].
    Throttled,
    /// The server offers no mechanism from the allowlist (T-10); nothing was sent.
    AuthUnavailable,
    /// The server refused the credentials; see [`Error::reply`].
    AuthFailed,
    /// The SASL exchange was refused on the client side.
    Sasl(crate::proto::SaslError),
    /// The server broke the protocol.
    Protocol(ProtocolError),
    /// The server refused; see [`Error::reply`].
    Rejected,
    /// Every recipient was refused; see [`Error::recipients`].
    AllRecipientsRejected,
    /// The message is larger than the server's advertised SIZE.
    MessageTooLarge {
        /// The message size in octets.
        size: u64,
        /// The server's limit.
        limit: u64,
    },
    /// The message needs an extension the server does not offer (no downgrade).
    ExtensionRequired(Extension),
    /// The connection closed before the conversation ended.
    ConnectionClosed,
    /// Every connection of a [`Pool`](crate::Pool) stayed busy past its
    /// wait limit; nothing was sent.
    PoolExhausted,
    /// A caller buffer is too small.
    BufferTooSmall,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Address(e) => fmt::Display::fmt(e, f),
            ErrorKind::Header(e) => fmt::Display::fmt(e, f),
            ErrorKind::Build(e) => fmt::Display::fmt(e, f),
            ErrorKind::Config(e) => fmt::Display::fmt(e, f),
            ErrorKind::Usage(e) => fmt::Display::fmt(e, f),
            ErrorKind::Random => f.write_str("the operating system's random source failed; retry later"),
            ErrorKind::Sink(e) => fmt::Display::fmt(e, f),
            ErrorKind::Payload(e) => fmt::Display::fmt(e, f),
            ErrorKind::Dkim(e) => fmt::Display::fmt(e, f),
            ErrorKind::Source(e) => fmt::Display::fmt(e, f),
            #[cfg(feature = "std")]
            ErrorKind::Connect(kind) => write!(
                f,
                "could not connect to the mail server ({kind}); check the host, the port, and that the server is running"
            ),
            #[cfg(feature = "std")]
            ErrorKind::Io(kind) => write!(f, "the connection to the mail server failed ({kind})"),
            ErrorKind::Timeout => f.write_str("the mail server did not answer in time"),
            ErrorKind::PlaintextRefused => f.write_str(
                "plaintext submission was refused because the peer is not a loopback address; nothing was sent",
            ),
            ErrorKind::StartTlsUnavailable => f.write_str(
                "the server does not offer STARTTLS; TLS is required for this server, so nothing was sent. Check the port (587 for STARTTLS, 465 for implicit TLS) or the server's TLS configuration",
            ),
            ErrorKind::StartTlsInjection => f.write_str(
                "the server sent plaintext after agreeing to STARTTLS, which is how a response-injection attack looks; the connection was closed",
            ),
            ErrorKind::Tls(e) => fmt::Display::fmt(e, f),
            ErrorKind::Throttled => f.write_str("the send gate is at its limit; nothing was sent, retry after the given time"),
            ErrorKind::AuthUnavailable => f.write_str(
                "the server offers none of the allowed AUTH mechanisms; nothing was sent. Check the server's AUTH line or the allowlist",
            ),
            ErrorKind::AuthFailed => f.write_str("the server refused the credentials"),
            ErrorKind::Sasl(e) => fmt::Display::fmt(e, f),
            ErrorKind::Protocol(e) => fmt::Display::fmt(e, f),
            ErrorKind::Rejected => f.write_str("the mail server refused the command"),
            ErrorKind::AllRecipientsRejected => f.write_str("the mail server refused every recipient"),
            ErrorKind::MessageTooLarge { size, limit } => write!(
                f,
                "the message is {size} octets and the server accepts at most {limit}; nothing was sent"
            ),
            ErrorKind::ExtensionRequired(ext) => write!(
                f,
                "the message needs the {} extension and the server does not offer it; nothing was sent",
                ext.keyword()
            ),
            ErrorKind::ConnectionClosed => f.write_str("the mail server closed the connection"),
            ErrorKind::PoolExhausted => f.write_str(
                "every pooled connection stayed busy past the wait limit; nothing was sent, retry later",
            ),
            ErrorKind::BufferTooSmall => f.write_str("the output buffer is too small"),
        }
    }
}

/// A per-recipient failure: the address, the server's reply, and whether retrying can help.
pub type RecipientFailure = (Address, Reply, Disposition);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Inner {
    kind: ErrorKind,
    stage: Option<Stage>,
    reply: Option<Reply>,
    disposition: Disposition,
    possibly_delivered: bool,
    retry_after: Option<Duration>,
    security_event: bool,
    /// The server's XOAUTH2 error status, when it sent one.
    detail: Option<alloc::string::String>,
    recipients: Vec<RecipientFailure>,
}

/// An smtp-net error: what was refused, where, and whether retrying can help.
///
/// The details live in one allocation, so `Result<T, Error>` is one pointer
/// wide (D-034).
///
/// # Examples
///
/// ```
/// let err = smtp_net::Address::parse("not an address").map_err(smtp_net::Error::from).unwrap_err();
/// assert!(err.is_permanent());
/// assert!(!err.possibly_delivered());
/// assert!(err.to_string().contains("@"));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Error {
    inner: Box<Inner>,
}

impl Error {
    /// An error of `kind` with the default disposition for that kind.
    pub(crate) fn new(kind: ErrorKind) -> Error {
        let (disposition, security_event) = default_disposition(&kind);
        Error {
            inner: Box::new(Inner {
                kind,
                stage: None,
                reply: None,
                disposition,
                possibly_delivered: false,
                retry_after: None,
                security_event,
                detail: None,
                recipients: Vec::new(),
            }),
        }
    }

    pub(crate) fn at(mut self, stage: Stage) -> Error {
        self.inner.stage = Some(stage);
        self
    }

    pub(crate) fn with_reply(mut self, reply: Reply) -> Error {
        self.inner.reply = Some(reply);
        self
    }

    pub(crate) fn with_disposition(mut self, disposition: Disposition) -> Error {
        self.inner.disposition = disposition;
        self
    }

    pub(crate) fn delivered_maybe(mut self, possibly: bool) -> Error {
        self.inner.possibly_delivered = possibly;
        self
    }

    #[cfg_attr(not(feature = "client"), allow(dead_code))]
    pub(crate) fn with_retry_after(mut self, d: Duration) -> Error {
        self.inner.retry_after = Some(d);
        self
    }

    pub(crate) fn with_detail(mut self, detail: Option<&str>) -> Error {
        self.inner.detail = detail.map(alloc::string::String::from);
        self
    }

    pub(crate) fn with_recipients(mut self, recipients: Vec<RecipientFailure>) -> Error {
        self.inner.recipients = recipients;
        self
    }

    /// What went wrong.
    #[must_use]
    pub fn kind(&self) -> &ErrorKind {
        &self.inner.kind
    }

    /// The stage of the conversation, when the error came from one.
    #[must_use]
    pub fn stage(&self) -> Option<Stage> {
        self.inner.stage
    }

    /// The server's reply, when the error is a refusal.
    #[must_use]
    pub fn reply(&self) -> Option<&Reply> {
        self.inner.reply.as_ref()
    }

    /// Whether retrying later can succeed.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        self.inner.disposition
    }

    /// `disposition() == Disposition::Temporary`: retry later.
    #[must_use]
    pub fn is_temporary(&self) -> bool {
        self.inner.disposition == Disposition::Temporary
    }

    /// `disposition() == Disposition::Permanent`: do not retry.
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        self.inner.disposition == Disposition::Permanent
    }

    /// True when the end of the data was written and no reply was read: the
    /// server may hold the message, so a retry may deliver a duplicate (RFC
    /// 1047). Retries send the same bytes and `Message-ID`, so receivers can
    /// recognise the duplicate.
    #[must_use]
    pub fn possibly_delivered(&self) -> bool {
        self.inner.possibly_delivered
    }

    /// When a pacing gate refused, the time until it admits again.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        self.inner.retry_after
    }

    /// True for failures that may be an attack on the connection (a stripped
    /// STARTTLS, a malformed or oversized reply, plaintext to a remote peer).
    #[must_use]
    pub fn is_security_event(&self) -> bool {
        self.inner.security_event
    }

    /// For `AuthFailed` after XOAUTH2: the `status` of the server's error
    /// document (for example `"401"` for an expired token, the cue to
    /// refresh it). Nothing else of the document is kept.
    #[must_use]
    pub fn auth_detail(&self) -> Option<&str> {
        self.inner.detail.as_deref()
    }

    /// Per-recipient replies, for `AllRecipientsRejected` and for partial
    /// failures under `RecipientPolicy::All`.
    #[must_use]
    pub fn recipients(&self) -> &[RecipientFailure] {
        &self.inner.recipients
    }
}

fn default_disposition(kind: &ErrorKind) -> (Disposition, bool) {
    use Disposition::{Permanent, Temporary};
    match kind {
        ErrorKind::Random
        | ErrorKind::Timeout
        | ErrorKind::ConnectionClosed
        | ErrorKind::Throttled
        | ErrorKind::PoolExhausted => (Temporary, false),
        ErrorKind::Tls(TlsFailure::Handshake | TlsFailure::Closed) => (Temporary, false),
        ErrorKind::Tls(TlsFailure::CertificateRejected) => (Permanent, true),
        #[cfg(feature = "std")]
        ErrorKind::Connect(_) | ErrorKind::Io(_) => (Temporary, false),
        ErrorKind::Sink(SinkError::Full) => (Permanent, false),
        #[cfg(feature = "std")]
        ErrorKind::Source(SourceError::Io(_)) => (Temporary, false),
        #[cfg(feature = "std")]
        ErrorKind::Sink(SinkError::Io(_)) => (Temporary, false),
        ErrorKind::Protocol(_) => (Temporary, true),
        ErrorKind::PlaintextRefused => (Permanent, true),
        ErrorKind::StartTlsUnavailable | ErrorKind::StartTlsInjection => (Temporary, true),
        // A NUL in a credential is the caller's input; a bad challenge or an
        // endless exchange is the server's misbehaviour.
        ErrorKind::Sasl(
            crate::proto::SaslError::InvalidCredential
            | crate::proto::SaslError::NonAsciiCredential
            | crate::proto::SaslError::NonceMissing
            | crate::proto::SaslError::InvalidMechanismName
            | crate::proto::SaslError::ResponseTooLong
            | crate::proto::SaslError::ServerError,
        ) => (Permanent, false),
        ErrorKind::Sasl(_) => (Temporary, true),
        _ => (Permanent, false),
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let i = &self.inner;
        let mut d = f.debug_struct("Error");
        d.field("kind", &i.kind)
            .field("stage", &i.stage)
            .field("disposition", &i.disposition)
            .field("possibly_delivered", &i.possibly_delivered);
        if let Some(reply) = &i.reply {
            d.field("reply", &reply.code().get());
        }
        if i.security_event {
            d.field("security_event", &true);
        }
        if !i.recipients.is_empty() {
            d.field("recipients", &i.recipients.len());
        }
        d.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner.kind, f)?;
        if let Some(stage) = self.inner.stage {
            write!(f, " (at {stage})")?;
            if stage == Stage::Greeting && self.inner.kind == ErrorKind::Timeout {
                f.write_str("; if the server expects TLS from the first byte (port 465), use Security::ImplicitTls")?;
            }
        }
        if let Some(reply) = &self.inner.reply {
            write!(f, ": {}", reply.text_lossy())?;
        }
        if self.inner.possibly_delivered {
            f.write_str("; the server may already have the message")?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<crate::proto::SaslError> for Error {
    fn from(e: crate::proto::SaslError) -> Error {
        Error::new(ErrorKind::Sasl(e))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for crate::proto::SaslError {}

macro_rules! from_nested {
    ($($t:ident => $v:ident),*) => {$(
        impl From<$t> for Error {
            fn from(e: $t) -> Error {
                Error::new(ErrorKind::$v(e))
            }
        }
        #[cfg(feature = "std")]
        impl std::error::Error for $t {}
    )*};
}
from_nested!(
    AddressError => Address,
    HeaderError => Header,
    BuildError => Build,
    ConfigError => Config,
    UsageError => Usage,
    ProtocolError => Protocol,
    SinkError => Sink,
    PayloadError => Payload,
    DkimError => Dkim,
    SourceError => Source
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_size_is_one_pointer() {
        assert_eq!(core::mem::size_of::<Error>(), core::mem::size_of::<usize>());
        assert_eq!(
            core::mem::size_of::<Result<(), Error>>(),
            core::mem::size_of::<usize>()
        );
    }

    #[test]
    fn test_error_default_dispositions_follow_the_table() {
        assert!(Error::from(AddressError::Empty).is_permanent());
        assert!(Error::from(HeaderError::InvalidName).is_permanent());
        assert!(Error::from(BuildError::NoRecipients).is_permanent());
        assert!(Error::new(ErrorKind::Timeout).is_temporary());
        assert!(Error::new(ErrorKind::Random).is_temporary());
        assert!(Error::new(ErrorKind::ConnectionClosed).is_temporary());
        let p = Error::from(ProtocolError::MalformedReply);
        assert!(p.is_temporary() && p.is_security_event());
        let plain = Error::new(ErrorKind::PlaintextRefused);
        assert!(plain.is_permanent() && plain.is_security_event());
        assert!(Error::new(ErrorKind::ExtensionRequired(Extension::Smtputf8)).is_permanent());
    }

    #[test]
    fn test_error_display_names_stage_and_duplicate_risk() {
        let e = Error::new(ErrorKind::Timeout)
            .at(Stage::DataEnd)
            .delivered_maybe(true);
        let s = alloc::string::ToString::to_string(&e);
        assert!(s.contains("end of data"), "{s}");
        assert!(s.contains("may already have"), "{s}");
        assert!(e.possibly_delivered());
    }

    #[test]
    fn test_every_nested_variant_has_an_actionable_message() {
        use alloc::string::ToString;
        let samples: Vec<Error> = alloc::vec![
            AddressError::Empty.into(),
            AddressError::TooLong {
                part: AddressPart::LocalPart,
                length: 65,
                limit: 64
            }
            .into(),
            AddressError::InvalidLocalPart { position: 1 }.into(),
            AddressError::InvalidDomain { position: 1 }.into(),
            AddressError::LabelTooLong { label: 0 }.into(),
            AddressError::AddressLiteralNotAllowed.into(),
            AddressError::MissingAt.into(),
            AddressError::ControlCharacter { position: 0 }.into(),
            AddressError::InternationalDomainUnsupported.into(),
            AddressError::DisplayNameInvalid { position: 0 }.into(),
            HeaderError::ControlCharacter {
                field: "Subject",
                position: 3
            }
            .into(),
            HeaderError::Reserved.into(),
            HeaderError::LineTooLong.into(),
            HeaderError::InvalidMessageId.into(),
            HeaderError::InvalidDate.into(),
            HeaderError::InvalidUnsubscribe.into(),
            HeaderError::InvalidFileName.into(),
            HeaderError::InvalidContentType.into(),
            HeaderError::InvalidContentId.into(),
            BuildError::MissingFrom.into(),
            BuildError::MultipleFrom.into(),
            BuildError::TooManyRecipients { limit: 100 }.into(),
            BuildError::TooMany {
                what: "references",
                limit: 50
            }
            .into(),
            BuildError::TooManyParts.into(),
            BuildError::TooManyHeaders.into(),
            BuildError::TooLarge { size: 2, limit: 1 }.into(),
            BuildError::DepthExceeded.into(),
            BuildError::InlineWithoutHtml.into(),
            BuildError::DuplicateContentId.into(),
            BuildError::BareCarriageReturn { position: 4 }.into(),
            BuildError::BareLineFeed { position: 4 }.into(),
            BuildError::LineTooLong { line: 2 }.into(),
            BuildError::NoHeaderBlock.into(),
            BuildError::LengthMismatch {
                declared: 1,
                actual: 2
            }
            .into(),
            BuildError::EncodingMismatch.into(),
            BuildError::InvalidDsn.into(),
            ConfigError::PortZero.into(),
            ConfigError::InvalidHost.into(),
            ConfigError::PlaintextHostNotLoopback.into(),
            ConfigError::BufferTooSmall.into(),
            ConfigError::AuthWithPlaintextRemote.into(),
            UsageError::Closed.into(),
            UsageError::WrongState {
                state: crate::proto::SessionState::Ready
            }
            .into(),
            ProtocolError::InconsistentReply.into(),
            ProtocolError::ReplyTooLong.into(),
            ProtocolError::BareLineFeed.into(),
            ProtocolError::Nul.into(),
            ProtocolError::UnexpectedReply.into(),
            ProtocolError::MalformedCapability.into(),
            SinkError::Full.into(),
            Error::new(ErrorKind::Rejected),
            Error::new(ErrorKind::AllRecipientsRejected),
            Error::new(ErrorKind::MessageTooLarge { size: 2, limit: 1 }),
            Error::new(ErrorKind::BufferTooSmall),
        ];
        for e in samples {
            let s = e.to_string();
            assert!(s.len() > 12, "{s}");
            assert!(!s.contains('\u{2014}'));
        }
    }
}
