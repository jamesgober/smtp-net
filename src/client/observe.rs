//! Structured events for monitoring (API 8.11, Tier 3). smtp-net does not
//! log; an [`Observer`] sees what happened, never a secret, a message body,
//! or reply text (codes only, T-30).

use core::net::SocketAddr;
use std::time::Duration;

use crate::error::{Disposition, Error, ErrorKind, ProtocolError, Stage, TlsFailure};
use crate::proto::{EnhancedCode, ReplyCode, TlsProtocol};

/// Receives [`ObservedEvent`]s from every connection of a [`Server`](crate::Server).
///
/// Called on the sending thread: keep it short (count, enqueue, or log
/// without blocking).
///
/// # Examples
///
/// ```
/// use std::sync::atomic::{AtomicU64, Ordering};
/// use smtp_net::{ObservedEvent, Observer};
///
/// #[derive(Default)]
/// struct Delivered(AtomicU64);
/// impl Observer for Delivered {
///     fn event(&self, event: &ObservedEvent<'_>) {
///         if let ObservedEvent::Delivered { .. } = event {
///             self.0.fetch_add(1, Ordering::Relaxed);
///         }
///     }
/// }
/// let server = smtp_net::Server::local().to_builder().observer(Delivered::default()).build()?;
/// # let _ = server;
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub trait Observer: Send + Sync {
    /// One event.
    fn event(&self, event: &ObservedEvent<'_>);
}

/// What an [`Observer`] is told.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedEvent<'a> {
    /// The TCP connection is up.
    Connected {
        /// The server's address.
        peer: SocketAddr,
    },
    /// TLS is up.
    Secure {
        /// The negotiated version.
        protocol: TlsProtocol,
    },
    /// A reply arrived (codes only).
    Reply {
        /// The command it answers.
        stage: Stage,
        /// The reply code.
        code: ReplyCode,
        /// The enhanced status code, when the server sends them.
        enhanced: Option<EnhancedCode>,
    },
    /// A message was accepted.
    Delivered {
        /// Its `Message-ID` (empty for raw bytes without one).
        message_id: &'a str,
        /// Recipients accepted.
        accepted: usize,
        /// Recipients refused.
        rejected: usize,
        /// Time from the first transaction to the final reply.
        elapsed: Duration,
    },
    /// A send failed.
    Failed {
        /// Where, when known.
        stage: Option<Stage>,
        /// Whether retrying can help.
        disposition: Disposition,
        /// The server may have the message.
        possibly_delivered: bool,
    },
    /// Something that looks like an attack or a broken server, for
    /// bouncer-io or an alerting system. Follows the `Failed` event.
    SecurityEvent {
        /// What it was.
        kind: SecurityEventKind,
    },
}

/// The kind of a [`ObservedEvent::SecurityEvent`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SecurityEventKind {
    /// TLS was required and the server did not offer STARTTLS (T-5).
    StartTlsMissing,
    /// Plaintext followed the server's `220` to STARTTLS (T-6).
    StartTlsInjection,
    /// The server's certificate did not verify.
    CertificateRejected,
    /// A reply broke the grammar.
    MalformedReply,
    /// A reply went over its budget.
    ReplyBudgetExceeded,
    /// The server misbehaved during AUTH (a SCRAM server that could not
    /// prove it knows the password, a bad challenge).
    AuthExchange,
    /// Plaintext was configured and the peer is not loopback.
    PlaintextRefused,
    /// Another security-relevant failure.
    Other,
}

impl SecurityEventKind {
    /// The kind for an error flagged as a security event.
    pub(crate) fn of(e: &Error) -> Option<SecurityEventKind> {
        if !e.is_security_event() {
            return None;
        }
        Some(match e.kind() {
            ErrorKind::StartTlsUnavailable => SecurityEventKind::StartTlsMissing,
            ErrorKind::StartTlsInjection => SecurityEventKind::StartTlsInjection,
            ErrorKind::Tls(TlsFailure::CertificateRejected) => {
                SecurityEventKind::CertificateRejected
            }
            ErrorKind::Protocol(ProtocolError::ReplyTooLong) => {
                SecurityEventKind::ReplyBudgetExceeded
            }
            ErrorKind::Protocol(_) => SecurityEventKind::MalformedReply,
            ErrorKind::Sasl(_) => SecurityEventKind::AuthExchange,
            ErrorKind::PlaintextRefused => SecurityEventKind::PlaintextRefused,
            _ => SecurityEventKind::Other,
        })
    }
}
