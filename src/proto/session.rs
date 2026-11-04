//! The sans-IO client session (PLAN 7.4): bytes in, bytes out, events out,
//! deadlines out. No socket, no clock, no randomness.

use alloc::{collections::VecDeque, vec::Vec};
use core::fmt;

use super::{
    Capabilities, ClientName, Millis, Reply, ReplyLimits, ReplyParser, Timeouts,
    classify::{rejected_disposition, reply_error},
    command::Line,
    stuff::DotStuffer,
};
use crate::{
    error::{Disposition, Error, ErrorKind, Extension, Stage, UsageError},
    message::prepared::Envelope,
};

/// Largest pipelined command group written before its replies are read (RFC
/// 2920 3.1: "usually 4K octets").
const GROUP_LIMIT: usize = 4096;
/// Smallest output buffer: one command line plus a terminator.
const MIN_OUTPUT: usize = 1024;

/// How the transport is secured.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionSecurity {
    /// No TLS. `peer_is_loopback` is the driver's confirmation that the
    /// connected peer address is loopback; it permits the HELO fallback.
    Plaintext {
        /// The connected peer is a loopback address.
        peer_is_loopback: bool,
    },
    /// STARTTLS is required before any transaction (RFC 3207); no fallback (T-5).
    StartTlsRequired,
    /// TLS from the first byte (RFC 8314); the driver calls
    /// [`Session::tls_established`] before the first `receive`.
    ImplicitTls,
}

/// What happens when some recipients are refused.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RecipientPolicy {
    /// Send to the accepted recipients (D-019).
    #[default]
    Any,
    /// Send only if every recipient is accepted.
    All,
}

/// The negotiated TLS version, as reported by the TLS engine.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsProtocol {
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
    /// Another version, by its wire number.
    Other(u16),
}

impl TlsProtocol {
    /// From the wire version number (0x0303 is TLS 1.2, 0x0304 is TLS 1.3).
    #[must_use]
    pub const fn from_wire(v: u16) -> TlsProtocol {
        match v {
            0x0303 => TlsProtocol::Tls12,
            0x0304 => TlsProtocol::Tls13,
            other => TlsProtocol::Other(other),
        }
    }
}

/// Facts about an established TLS connection.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsInfo {
    /// The negotiated version.
    pub protocol: TlsProtocol,
}

impl TlsInfo {
    /// TLS facts for `protocol`.
    #[must_use]
    pub const fn new(protocol: TlsProtocol) -> TlsInfo {
        TlsInfo { protocol }
    }
}

/// Facts about a message body that decide the MAIL parameters.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BodyFlags {
    /// The body has 8-bit parts (needs 8BITMIME).
    pub eight_bit: bool,
    /// An address or header needs SMTPUTF8.
    pub smtputf8: bool,
}

impl BodyFlags {
    /// Flags from their two values.
    #[must_use]
    pub const fn new(eight_bit: bool, smtputf8: bool) -> BodyFlags {
        BodyFlags {
            eight_bit,
            smtputf8,
        }
    }
}

/// The session's configuration.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// The EHLO argument (default: `[127.0.0.1]`).
    pub client_name: ClientName,
    /// Transport security (default: `StartTlsRequired`).
    pub security: SessionSecurity,
    /// Stage timeouts (default: RFC 5321).
    pub timeouts: Timeouts,
    /// Use PIPELINING when offered (default true).
    pub pipelining: bool,
    /// Policy for refused recipients (default `Any`).
    pub recipient_policy: RecipientPolicy,
    /// Reply budgets.
    pub reply_limits: ReplyLimits,
    /// Output buffer size in octets (default 16 KiB; at least 1 KiB).
    pub output_capacity: usize,
}

impl Default for SessionConfig {
    fn default() -> SessionConfig {
        SessionConfig {
            client_name: ClientName::default(),
            security: SessionSecurity::StartTlsRequired,
            timeouts: Timeouts::rfc5321(),
            pipelining: true,
            recipient_policy: RecipientPolicy::Any,
            reply_limits: ReplyLimits::default(),
            output_capacity: 16 * 1024,
        }
    }
}

/// Where the session is in the conversation.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// Waiting for the `220` greeting.
    AwaitGreeting,
    /// EHLO, HELO, or STARTTLS in progress.
    Negotiating,
    /// The driver must run the TLS handshake, then call `tls_established`.
    NeedTls,
    /// AUTH in progress.
    Authenticating,
    /// Ready for `begin`.
    Ready,
    /// MAIL, RCPT, DATA, or RSET in progress.
    InTransaction,
    /// Accepting body bytes through `body`.
    Body,
    /// Waiting for the reply to the end of the data.
    AwaitDataEnd,
    /// QUIT sent.
    Closing,
    /// Closed.
    Closed,
}

/// What the session tells the driver.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The server's greeting.
    Greeting(Reply),
    /// Ready for a transaction.
    Ready {
        /// The connection is TLS.
        secure: bool,
        /// AUTH succeeded.
        authenticated: bool,
    },
    /// Run the TLS handshake now, then call `tls_established`.
    StartTls,
    /// A recipient was accepted.
    RecipientAccepted {
        /// Index in the envelope's recipients.
        index: usize,
    },
    /// A recipient was refused.
    RecipientRejected {
        /// Index in the envelope's recipients.
        index: usize,
        /// The server's reply.
        reply: Reply,
        /// Whether retrying that recipient can help.
        disposition: Disposition,
    },
    /// Call `body` until the message is written, then `end_body`.
    BodyWanted,
    /// The server accepted the message.
    Delivered {
        /// The reply to the end of the data.
        reply: Reply,
        /// Recipients accepted.
        accepted: usize,
        /// Recipients refused.
        rejected: usize,
        /// Recipients left for a further transaction.
        deferred: usize,
    },
    /// The transaction failed; the session is ready for another one.
    TransactionFailed(Error),
    /// The session closed; `error` is `None` after a clean QUIT.
    Closed {
        /// Why it closed.
        error: Option<Error>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Greeting,
    Ehlo,
    Helo,
    StartTls,
    Mail,
    Rcpt(usize),
    Data,
    DataEnd,
    /// The reply to a lone dot sent after an unwanted 354.
    Discard,
    Rset,
    Noop,
    Quit,
}

impl Expect {
    fn stage(self) -> Stage {
        match self {
            Expect::Greeting => Stage::Greeting,
            Expect::Ehlo => Stage::Ehlo,
            Expect::Helo => Stage::Helo,
            Expect::StartTls => Stage::StartTls,
            Expect::Mail => Stage::Mail,
            Expect::Rcpt(_) => Stage::Rcpt,
            Expect::Data => Stage::Data,
            Expect::DataEnd | Expect::Discard => Stage::DataEnd,
            Expect::Rset => Stage::Rset,
            Expect::Noop => Stage::Noop,
            Expect::Quit => Stage::Quit,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    what: Expect,
    deadline: Millis,
}

#[derive(Clone, Debug)]
struct Txn {
    envelope: Envelope,
    flags: BodyFlags,
    size: u64,
    pipelined: bool,
    mail_queued: bool,
    next_rcpt: usize,
    data_queued: bool,
    accepted: usize,
    rejected: Vec<(usize, Reply, Disposition)>,
    failed: Option<Error>,
    stuffer: DotStuffer,
    /// Bytes of output up to and including the end-of-data sequence not yet transmitted.
    end_unsent: Option<usize>,
}

/// The SMTP client state machine. `Send`, not `Sync`: one connection, one owner.
///
/// # Examples
///
/// Driving a session by hand against scripted replies:
///
/// ```
/// use smtp_net::{Event, Millis, Session, SessionConfig, SessionSecurity};
/// let mut config = SessionConfig::default();
/// config.security = SessionSecurity::Plaintext { peer_is_loopback: true };
/// let mut s = Session::new(config, Millis(0))?;
/// s.receive(b"220 mx.example.com ESMTP\r\n", Millis(1))?;
/// assert_eq!(s.transmit(), b"EHLO [127.0.0.1]\r\n");
/// s.transmitted(s.transmit().len());
/// s.receive(b"250-mx.example.com\r\n250 PIPELINING\r\n", Millis(2))?;
/// assert!(matches!(s.poll_event(), Some(Event::Greeting(_))));
/// assert!(matches!(s.poll_event(), Some(Event::Ready { secure: false, .. })));
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub struct Session {
    config: SessionConfig,
    state: SessionState,
    out: Vec<u8>,
    parser: ReplyParser,
    pending: VecDeque<Pending>,
    events: VecDeque<Event>,
    caps: Option<Capabilities>,
    secure: bool,
    tls_protocol: Option<TlsProtocol>,
    txn: Option<Txn>,
    body_deadline: Option<Millis>,
    /// Bytes counted into the current pipelined group.
    group: usize,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("state", &self.state)
            .field("secure", &self.secure)
            .field("pending", &self.pending.len())
            .field("output", &self.out.len())
            .finish()
    }
}

impl Session {
    /// A session waiting for the greeting (or, with `ImplicitTls`, for
    /// `tls_established`). Allocates its buffers once.
    ///
    /// # Errors
    ///
    /// `Config(BufferTooSmall)` for an output capacity below 1 KiB.
    pub fn new(config: SessionConfig, now: Millis) -> Result<Session, Error> {
        if config.output_capacity < MIN_OUTPUT {
            return Err(crate::error::ConfigError::BufferTooSmall.into());
        }
        let mut s = Session {
            state: SessionState::AwaitGreeting,
            out: Vec::with_capacity(config.output_capacity),
            parser: ReplyParser::new(config.reply_limits, false),
            pending: VecDeque::with_capacity(8),
            events: VecDeque::with_capacity(8),
            caps: None,
            secure: false,
            tls_protocol: None,
            txn: None,
            body_deadline: None,
            group: 0,
            config,
        };
        if s.config.security == SessionSecurity::ImplicitTls {
            s.state = SessionState::NeedTls;
        } else {
            s.expect(Expect::Greeting, now);
        }
        Ok(s)
    }

    fn expect(&mut self, what: Expect, now: Millis) {
        let t = &self.config.timeouts;
        let d = match what {
            Expect::Greeting => t.greeting,
            Expect::Mail => t.mail,
            Expect::Rcpt(_) => t.rcpt,
            Expect::Data => t.data_init,
            Expect::DataEnd | Expect::Discard => t.data_end,
            _ => t.command,
        };
        self.pending.push_back(Pending {
            what,
            deadline: now.after(d),
        });
    }

    fn wrong_state(&self) -> Error {
        Error::new(ErrorKind::Usage(UsageError::WrongState {
            state: self.state,
        }))
    }

    /// Closes the session with `error` and queues `Event::Closed`.
    fn close(&mut self, mut error: Error) -> Error {
        let possibly = matches!(
            self.pending.front(),
            Some(Pending {
                what: Expect::DataEnd,
                ..
            })
        ) && self.txn.as_ref().is_some_and(|t| t.end_unsent == Some(0));
        if possibly {
            error = error.delivered_maybe(true);
        }
        self.state = SessionState::Closed;
        self.pending.clear();
        self.out.clear();
        self.txn = None;
        self.body_deadline = None;
        self.events.push_back(Event::Closed {
            error: Some(error.clone()),
        });
        error
    }

    /// Feeds bytes received from the server. Parses complete replies, advances
    /// the state, and queues events and output. Returns the bytes consumed;
    /// it stops right after the reply to STARTTLS, and any byte after that
    /// reply in `input` ends the session with `StartTlsInjection` (T-6).
    ///
    /// # Errors
    ///
    /// The error that closed the session (also reported as `Event::Closed`):
    /// `Protocol(..)`, `Rejected`, `StartTlsInjection`, `StartTlsUnavailable`,
    /// and `Usage` when the session expects no input.
    pub fn receive(&mut self, input: &[u8], now: Millis) -> Result<usize, Error> {
        if matches!(self.state, SessionState::Closed | SessionState::NeedTls) {
            if input.is_empty() {
                return Ok(0);
            }
            if self.state == SessionState::NeedTls {
                let e = Error::new(ErrorKind::StartTlsInjection).at(Stage::StartTls);
                return Err(self.close(e));
            }
            return Err(Error::new(ErrorKind::Usage(UsageError::Closed)));
        }
        let mut used = 0usize;
        while used < input.len() {
            let rest = input.get(used..).unwrap_or(&[]);
            let (n, done) = match self.parser.push_view(rest) {
                Ok(r) => r,
                Err(p) => {
                    let stage = self
                        .pending
                        .front()
                        .map_or(Stage::Greeting, |p| p.what.stage());
                    return Err(self.close(Error::from(p).at(stage)));
                }
            };
            used += n;
            if !done {
                break;
            }
            self.on_reply(now)?;
            if self.state == SessionState::NeedTls {
                if used < input.len() {
                    let e = Error::new(ErrorKind::StartTlsInjection).at(Stage::StartTls);
                    return Err(self.close(e));
                }
                break;
            }
            if self.state == SessionState::Closed {
                break;
            }
        }
        Ok(used)
    }

    fn on_reply(&mut self, now: Millis) -> Result<(), Error> {
        let code = self.parser.code().unwrap_or(super::ReplyCode(500));
        let Some(p) = self.pending.pop_front() else {
            let e = if code.get() == 421 {
                Error::new(ErrorKind::Rejected)
                    .with_reply(self.parser.take())
                    .with_disposition(Disposition::Temporary)
            } else {
                Error::from(crate::error::ProtocolError::UnexpectedReply)
            };
            return Err(self.close(e));
        };
        let stage = p.what.stage();
        if code.get() == 421 {
            let after_end = p.what == Expect::DataEnd
                && self.txn.as_ref().is_some_and(|t| t.end_unsent == Some(0));
            let reply = self.parser.take();
            let e = Error::new(ErrorKind::Rejected)
                .with_reply(reply)
                .with_disposition(Disposition::Temporary)
                .at(stage)
                .delivered_maybe(after_end);
            self.pending.push_front(p);
            return Err(self.close(e));
        }
        match p.what {
            Expect::Greeting => {
                let reply = self.parser.take();
                if code.get() == 220 {
                    self.events.push_back(Event::Greeting(reply));
                    self.state = SessionState::Negotiating;
                    self.send_ehlo(now)
                } else if code.is_positive() {
                    Err(self
                        .close(Error::from(crate::error::ProtocolError::UnexpectedReply).at(stage)))
                } else {
                    Err(self.close(reply_error(stage, reply)))
                }
            }
            Expect::Ehlo => {
                if code.get() == 250 {
                    let caps = match Capabilities::from_text(self.parser.text()) {
                        Ok(c) => c,
                        Err(e) => return Err(self.close(Error::from(e).at(stage))),
                    };
                    self.parser
                        .set_enhanced(caps.has(Extension::EnhancedStatusCodes));
                    self.caps = Some(caps);
                    self.after_hello(now)
                } else if matches!(code.get(), 500 | 502)
                    && self.config.security
                        == (SessionSecurity::Plaintext {
                            peer_is_loopback: true,
                        })
                {
                    let mut l = Line::new(&mut self.out);
                    l.put(b"HELO ").client_name(&self.config.client_name);
                    l.end()?;
                    self.expect(Expect::Helo, now);
                    Ok(())
                } else {
                    let reply = self.parser.take();
                    Err(self.close(reply_error(stage, reply)))
                }
            }
            Expect::Helo => {
                if code.get() == 250 {
                    self.caps = Some(Capabilities::default());
                    self.after_hello(now)
                } else {
                    let reply = self.parser.take();
                    Err(self.close(reply_error(stage, reply)))
                }
            }
            Expect::StartTls => {
                if code.get() == 220 {
                    self.state = SessionState::NeedTls;
                    self.events.push_back(Event::StartTls);
                    Ok(())
                } else {
                    let reply = self.parser.take();
                    Err(self.close(reply_error(stage, reply)))
                }
            }
            Expect::Rset => {
                if code.is_positive() {
                    self.finish_transaction();
                    Ok(())
                } else {
                    let reply = self.parser.take();
                    Err(self.close(reply_error(stage, reply)))
                }
            }
            Expect::Noop => {
                if code.is_positive() {
                    Ok(())
                } else {
                    let reply = self.parser.take();
                    Err(self.close(reply_error(stage, reply)))
                }
            }
            Expect::Quit => {
                self.state = SessionState::Closed;
                self.pending.clear();
                self.events.push_back(Event::Closed { error: None });
                Ok(())
            }
            Expect::Mail | Expect::Rcpt(_) | Expect::Data | Expect::DataEnd | Expect::Discard => {
                self.on_txn_reply(p.what, code, now)
            }
        }
    }

    fn send_ehlo(&mut self, now: Millis) -> Result<(), Error> {
        let mut l = Line::new(&mut self.out);
        l.put(b"EHLO ").client_name(&self.config.client_name);
        l.end()?;
        self.expect(Expect::Ehlo, now);
        Ok(())
    }

    fn after_hello(&mut self, now: Millis) -> Result<(), Error> {
        if self.config.security == SessionSecurity::StartTlsRequired && !self.secure {
            if self
                .caps
                .as_ref()
                .is_some_and(|c| c.has(Extension::StartTls))
            {
                push_command(&mut self.out, b"STARTTLS");
                self.expect(Expect::StartTls, now);
                return Ok(());
            }
            let e = Error::new(ErrorKind::StartTlsUnavailable).at(Stage::Ehlo);
            return Err(self.close(e));
        }
        self.state = SessionState::Ready;
        self.events.push_back(Event::Ready {
            secure: self.secure,
            authenticated: false,
        });
        Ok(())
    }

    fn on_txn_reply(
        &mut self,
        what: Expect,
        code: super::ReplyCode,
        now: Millis,
    ) -> Result<(), Error> {
        let Some(txn) = self.txn.as_mut() else {
            return Err(self.close(Error::from(crate::error::ProtocolError::UnexpectedReply)));
        };
        match what {
            Expect::Mail if !code.is_positive() => {
                let reply = self.parser.take();
                txn.failed = Some(reply_error(Stage::Mail, reply));
            }
            Expect::Rcpt(i) if txn.failed.is_none() => {
                if matches!(code.get(), 250 | 251) {
                    txn.accepted += 1;
                    self.events.push_back(Event::RecipientAccepted { index: i });
                } else {
                    let reply = self.parser.take();
                    let disposition = rejected_disposition(code);
                    txn.rejected.push((i, reply.clone(), disposition));
                    self.events.push_back(Event::RecipientRejected {
                        index: i,
                        reply,
                        disposition,
                    });
                }
            }
            Expect::Data => {
                if code.get() == 354 {
                    if txn.failed.is_some() || txn.accepted == 0 || self.policy_refuses() {
                        // RFC 2920 3.1: end the unwanted data with a lone dot.
                        self.fail_recipients_if_needed();
                        self.out.extend_from_slice(b".\r\n");
                        self.expect(Expect::Discard, now);
                    } else {
                        self.state = SessionState::Body;
                        self.body_deadline = Some(now.after(self.config.timeouts.data_block));
                        self.events.push_back(Event::BodyWanted);
                    }
                } else if txn.failed.is_none() {
                    if txn.accepted == 0 {
                        self.fail_recipients_if_needed();
                    } else {
                        let reply = self.parser.take();
                        if let Some(t) = self.txn.as_mut() {
                            t.failed = Some(reply_error(Stage::Data, reply));
                        }
                    }
                }
            }
            Expect::DataEnd => {
                let reply = self.parser.take();
                if code.is_positive() {
                    let (accepted, rejected) = (txn.accepted, txn.rejected.len());
                    self.events.push_back(Event::Delivered {
                        reply,
                        accepted,
                        rejected,
                        deferred: 0,
                    });
                    self.txn = None;
                    self.state = SessionState::Ready;
                    return Ok(());
                }
                txn.failed = Some(reply_error(Stage::DataEnd, reply));
                // The server ends the transaction after the end-of-data reply.
                let e = txn
                    .failed
                    .take()
                    .unwrap_or_else(|| Error::new(ErrorKind::Rejected));
                self.txn = None;
                self.state = SessionState::Ready;
                self.events.push_back(Event::TransactionFailed(e));
                return Ok(());
            }
            Expect::Discard => {}
            _ => {}
        }
        if self.pending.is_empty() && self.state == SessionState::InTransaction {
            self.advance(now)?;
        }
        Ok(())
    }

    fn policy_refuses(&self) -> bool {
        self.config.recipient_policy == RecipientPolicy::All
            && self.txn.as_ref().is_some_and(|t| !t.rejected.is_empty())
    }

    /// Sets the transaction's failure from its refused recipients, when it has none yet.
    fn fail_recipients_if_needed(&mut self) {
        let Some(txn) = self.txn.as_mut() else { return };
        if txn.failed.is_some() {
            return;
        }
        let temporary = txn
            .rejected
            .iter()
            .any(|(_, _, d)| *d == Disposition::Temporary);
        let kind = if txn.accepted == 0 {
            ErrorKind::AllRecipientsRejected
        } else {
            ErrorKind::Rejected
        };
        let recipients = txn
            .rejected
            .iter()
            .filter_map(|(i, r, d)| {
                txn.envelope
                    .recipients()
                    .get(*i)
                    .map(|a| (a.clone(), r.clone(), *d))
            })
            .collect();
        let e = Error::new(kind)
            .at(Stage::Rcpt)
            .with_disposition(if temporary {
                Disposition::Temporary
            } else {
                Disposition::Permanent
            })
            .with_recipients(recipients);
        txn.failed = Some(e);
    }

    /// Queues the next group of transaction commands, or ends a failed transaction.
    fn advance(&mut self, now: Millis) -> Result<(), Error> {
        let Some(txn) = self.txn.as_ref() else {
            return Ok(());
        };
        if txn.failed.is_some() {
            push_command(&mut self.out, b"RSET");
            self.expect(Expect::Rset, now);
            return Ok(());
        }
        let n = txn.envelope.recipients().len();
        let pipelined = txn.pipelined;
        self.group = 0;
        if !txn.mail_queued {
            self.queue_mail(now)?;
            if !pipelined {
                return Ok(());
            }
        }
        loop {
            let Some(txn) = self.txn.as_ref() else {
                return Ok(());
            };
            let i = txn.next_rcpt;
            if i >= n {
                break;
            }
            if pipelined && i > 0 && self.group >= GROUP_LIMIT && !self.pending.is_empty() {
                return Ok(());
            }
            self.queue_rcpt(i, now)?;
            if !pipelined {
                return Ok(());
            }
        }
        let Some(txn) = self.txn.as_ref() else {
            return Ok(());
        };
        if txn.data_queued {
            return Ok(());
        }
        let waiting = !self.pending.is_empty();
        if waiting && (!pipelined || self.config.recipient_policy == RecipientPolicy::All) {
            return Ok(());
        }
        if !waiting {
            // Every recipient reply is in.
            if txn.accepted == 0 || self.policy_refuses() {
                self.fail_recipients_if_needed();
                return self.advance(now);
            }
        }
        push_command(&mut self.out, b"DATA");
        self.expect(Expect::Data, now);
        if let Some(t) = self.txn.as_mut() {
            t.data_queued = true;
        }
        Ok(())
    }

    fn queue_mail(&mut self, now: Millis) -> Result<(), Error> {
        let caps_size = self.caps.as_ref().is_some_and(|c| c.has(Extension::Size));
        let start = self.out.len();
        let Some(txn) = self.txn.as_mut() else {
            return Ok(());
        };
        let mut l = Line::new(&mut self.out);
        l.put(b"MAIL FROM:").path(txn.envelope.from());
        if caps_size && txn.size > 0 {
            l.put(b" SIZE=").decimal(txn.size);
        }
        if txn.flags.eight_bit {
            l.put(b" BODY=8BITMIME");
        }
        if txn.flags.smtputf8 {
            l.put(b" SMTPUTF8");
        }
        l.end()?;
        txn.mail_queued = true;
        self.group += self.out.len() - start;
        self.expect(Expect::Mail, now);
        Ok(())
    }

    fn queue_rcpt(&mut self, i: usize, now: Millis) -> Result<(), Error> {
        let start = self.out.len();
        let Some(txn) = self.txn.as_mut() else {
            return Ok(());
        };
        let mut l = Line::new(&mut self.out);
        l.put(b"RCPT TO:").path(txn.envelope.recipients().get(i));
        l.end()?;
        txn.next_rcpt = i + 1;
        self.group += self.out.len() - start;
        self.expect(Expect::Rcpt(i), now);
        Ok(())
    }

    fn finish_transaction(&mut self) {
        let failed = self.txn.take().and_then(|mut t| t.failed.take());
        self.state = SessionState::Ready;
        if let Some(e) = failed {
            self.events.push_back(Event::TransactionFailed(e));
        }
    }

    /// The bytes waiting to be written to the server.
    #[must_use]
    pub fn transmit(&self) -> &[u8] {
        &self.out
    }

    /// Acknowledges that the first `n` bytes of [`transmit`](Session::transmit)
    /// were written (saturating at the pending length).
    pub fn transmitted(&mut self, n: usize) {
        let n = n.min(self.out.len());
        self.out.drain(..n);
        if let Some(t) = self.txn.as_mut() {
            if let Some(left) = t.end_unsent.as_mut() {
                *left = left.saturating_sub(n);
            }
        }
    }

    /// The next event, in order.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// The deadline of the oldest outstanding reply, or of the next body write.
    #[must_use]
    pub fn deadline(&self) -> Option<Millis> {
        match self.state {
            SessionState::Body => self.body_deadline,
            _ => self.pending.front().map(|p| p.deadline),
        }
    }

    /// Closes the session with `Timeout` when `now` is past the deadline;
    /// otherwise does nothing.
    ///
    /// # Errors
    ///
    /// `Timeout` with the stage, temporary, `possibly_delivered` after the end
    /// of the data was written.
    pub fn on_timeout(&mut self, now: Millis) -> Result<(), Error> {
        match self.deadline() {
            Some(d) if now >= d => {
                let stage = if self.state == SessionState::Body {
                    Stage::Body
                } else {
                    self.pending
                        .front()
                        .map_or(Stage::Total, |p| p.what.stage())
                };
                Err(self.close(Error::new(ErrorKind::Timeout).at(stage)))
            }
            _ => Ok(()),
        }
    }

    /// The transport closed or failed (EOF, reset, I/O error). Closes the
    /// session and returns the classified error: temporary, with
    /// `possibly_delivered` when the end of the data was written and its reply
    /// not read (RFC 1047, T-18). After a clean QUIT it returns the
    /// `ConnectionClosed` error without changing anything.
    pub fn connection_lost(&mut self, cause: ErrorKind) -> Error {
        let stage = match self.state {
            SessionState::Body => Stage::Body,
            _ => self
                .pending
                .front()
                .map_or(Stage::Greeting, |p| p.what.stage()),
        };
        if self.state == SessionState::Closed {
            return Error::new(cause).at(stage);
        }
        if self.state == SessionState::Closing {
            self.state = SessionState::Closed;
            self.pending.clear();
            self.events.push_back(Event::Closed { error: None });
            return Error::new(cause).at(Stage::Quit);
        }
        let e = Error::new(cause)
            .at(stage)
            .with_disposition(Disposition::Temporary);
        self.close(e)
    }

    /// Valid after `Event::StartTls` (or at the start with `ImplicitTls`): the
    /// driver finished the handshake. Capabilities learned before TLS are
    /// discarded (RFC 3207 4.2) and EHLO is sent again.
    ///
    /// # Errors
    ///
    /// `Usage(WrongState)`.
    pub fn tls_established(&mut self, info: TlsInfo, now: Millis) -> Result<(), Error> {
        if self.state != SessionState::NeedTls {
            return Err(self.wrong_state());
        }
        self.secure = true;
        self.tls_protocol = Some(info.protocol);
        self.caps = None;
        self.parser = ReplyParser::new(self.config.reply_limits, false);
        if self.config.security == SessionSecurity::ImplicitTls {
            self.state = SessionState::AwaitGreeting;
            self.expect(Expect::Greeting, now);
            return Ok(());
        }
        self.state = SessionState::Negotiating;
        self.send_ehlo(now)
    }

    /// Starts a transaction: checks the envelope against the server's
    /// capabilities (SIZE, SMTPUTF8, 8BITMIME), then queues MAIL, RCPT, and
    /// DATA, as one group when PIPELINING is offered (PLAN 7.6).
    ///
    /// # Errors
    ///
    /// `MessageTooLarge`, `ExtensionRequired(..)` (permanent, nothing sent),
    /// `Usage(WrongState)`.
    pub fn begin(
        &mut self,
        envelope: &Envelope,
        flags: BodyFlags,
        size: u64,
        now: Millis,
    ) -> Result<(), Error> {
        if self.state != SessionState::Ready {
            return Err(self.wrong_state());
        }
        let caps = self.caps.as_ref();
        let smtputf8 = flags.smtputf8 || envelope.needs_smtputf8();
        if smtputf8 && !caps.is_some_and(|c| c.has(Extension::Smtputf8)) {
            return Err(
                Error::new(ErrorKind::ExtensionRequired(Extension::Smtputf8)).at(Stage::Mail),
            );
        }
        if flags.eight_bit && !caps.is_some_and(|c| c.has(Extension::EightBitMime)) {
            return Err(
                Error::new(ErrorKind::ExtensionRequired(Extension::EightBitMime)).at(Stage::Mail),
            );
        }
        if let Some(limit) = caps.and_then(Capabilities::size_limit) {
            if limit > 0 && size > limit {
                return Err(Error::new(ErrorKind::MessageTooLarge { size, limit }).at(Stage::Mail));
            }
        }
        let pipelined =
            self.config.pipelining && caps.is_some_and(|c| c.has(Extension::Pipelining));
        self.txn = Some(Txn {
            envelope: envelope.clone(),
            flags: BodyFlags {
                eight_bit: flags.eight_bit,
                smtputf8,
            },
            size,
            pipelined,
            mail_queued: false,
            next_rcpt: 0,
            data_queued: false,
            accepted: 0,
            rejected: Vec::new(),
            failed: None,
            stuffer: DotStuffer::new(),
            end_unsent: None,
        });
        self.state = SessionState::InTransaction;
        if let Err(e) = self.advance(now) {
            self.txn = None;
            self.state = SessionState::Ready;
            return Err(e);
        }
        Ok(())
    }

    /// Accepts body bytes (the serialized message) up to the free output
    /// capacity, dot-stuffing them; returns how many were taken. Flush
    /// [`transmit`](Session::transmit) and call again with the rest.
    ///
    /// # Errors
    ///
    /// `Build(BareLineFeed)`, `Build(BareCarriageReturn)` (permanent: the
    /// session closes, since the server holds a partial message);
    /// `Usage(WrongState)`.
    pub fn body(&mut self, chunk: &[u8], now: Millis) -> Result<usize, Error> {
        if self.state != SessionState::Body {
            return Err(self.wrong_state());
        }
        let cap = self.config.output_capacity;
        let Some(txn) = self.txn.as_mut() else {
            return Err(self.wrong_state());
        };
        match txn.stuffer.push(chunk, &mut self.out, cap) {
            Ok(n) => {
                self.body_deadline = Some(now.after(self.config.timeouts.data_block));
                Ok(n)
            }
            Err(b) => {
                let e = Error::from(b).at(Stage::Body);
                Err(self.close(e).with_disposition(Disposition::Permanent))
            }
        }
    }

    /// Ends the body: writes the end-of-data sequence and waits for its reply.
    /// From the moment those bytes are transmitted, a lost connection is
    /// `possibly_delivered`.
    ///
    /// # Errors
    ///
    /// `Build(BareCarriageReturn)` for a body ending in CR, `Usage(WrongState)`.
    pub fn end_body(&mut self, now: Millis) -> Result<(), Error> {
        if self.state != SessionState::Body {
            return Err(self.wrong_state());
        }
        let Some(txn) = self.txn.as_mut() else {
            return Err(self.wrong_state());
        };
        if let Err(b) = txn.stuffer.finish(&mut self.out) {
            let e = Error::from(b).at(Stage::Body);
            return Err(self.close(e).with_disposition(Disposition::Permanent));
        }
        txn.end_unsent = Some(self.out.len());
        self.state = SessionState::AwaitDataEnd;
        self.body_deadline = None;
        self.expect(Expect::DataEnd, now);
        Ok(())
    }

    /// Sends RSET (to abandon a transaction, or after a failure).
    ///
    /// # Errors
    ///
    /// `Usage(WrongState)` outside `Ready` and `InTransaction`.
    pub fn reset(&mut self, now: Millis) -> Result<(), Error> {
        if !matches!(self.state, SessionState::Ready) {
            return Err(self.wrong_state());
        }
        push_command(&mut self.out, b"RSET");
        self.state = SessionState::InTransaction;
        self.expect(Expect::Rset, now);
        Ok(())
    }

    /// Sends NOOP, a liveness probe.
    ///
    /// # Errors
    ///
    /// `Usage(WrongState)` outside `Ready`.
    pub fn noop(&mut self, now: Millis) -> Result<(), Error> {
        if self.state != SessionState::Ready {
            return Err(self.wrong_state());
        }
        push_command(&mut self.out, b"NOOP");
        self.expect(Expect::Noop, now);
        Ok(())
    }

    /// Sends QUIT; the session is `Closed` after `221` or EOF. Does nothing
    /// when already closing or closed.
    ///
    /// # Errors
    ///
    /// None in practice; the `Result` keeps the signature uniform.
    pub fn quit(&mut self, now: Millis) -> Result<(), Error> {
        if matches!(self.state, SessionState::Closed | SessionState::Closing) {
            return Ok(());
        }
        if matches!(self.state, SessionState::Body) {
            // The data cannot be ended without delivering it: close instead.
            let e = Error::new(ErrorKind::ConnectionClosed).at(Stage::Body);
            self.close(e);
            return Ok(());
        }
        push_command(&mut self.out, b"QUIT");
        self.state = SessionState::Closing;
        self.expect(Expect::Quit, now);
        Ok(())
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// The capabilities of the latest EHLO (none before it, and none right after TLS).
    #[must_use]
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.caps.as_ref()
    }

    /// True after `tls_established`.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        self.secure
    }

    /// The TLS version, after `tls_established`.
    #[must_use]
    pub fn tls_protocol(&self) -> Option<TlsProtocol> {
        self.tls_protocol
    }

    /// True when a reply is outstanding and the driver should read.
    #[must_use]
    pub fn wants_read(&self) -> bool {
        !self.pending.is_empty()
            && !matches!(
                self.state,
                SessionState::Body | SessionState::NeedTls | SessionState::Closed
            )
    }
}

/// Appends a constant command line.
fn push_command(out: &mut Vec<u8>, command: &[u8]) {
    out.extend_from_slice(command);
    out.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests;
