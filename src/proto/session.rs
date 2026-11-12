//! The sans-IO client session (PLAN 7.4): bytes in, bytes out, events out,
//! deadlines out. No socket, no clock, no randomness.

use alloc::{collections::VecDeque, string::String, vec::Vec};
use core::fmt;

use super::{
    Capabilities, ClientName, Millis, Reply, ReplyLimits, ReplyParser, Timeouts,
    classify::{auth_error, rejected_disposition, reply_error},
    command::Line,
    sasl::{Auth, Exchange, MAX_AUTH_LINE, MechanismName},
    stuff::DotStuffer,
};
use crate::{
    error::{
        BuildError, ConfigError, Disposition, Error, ErrorKind, Extension, ProtocolError,
        RejectedRecipient, Stage, UsageError,
    },
    message::prepared::{DsnPolicy, DsnReturn, Envelope},
};

/// Largest pipelined command group written before its replies are read (RFC
/// 2920 3.1: "usually 4K octets").
const GROUP_LIMIT: usize = 4096;
/// Smallest output buffer: one command line plus a terminator.
const MIN_OUTPUT: usize = 1024;
/// A BDAT body larger than this is written only after the MAIL and RCPT
/// replies are in, so the client never blocks writing while the server
/// blocks writing replies (PLAN 7.6) **[est.]**.
const BDAT_PIPELINE_LIMIT: u64 = 64 * 1024;

/// How the transport is secured.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionSecurity {
    /// No TLS. `peer_is_loopback` is the driver's confirmation that the
    /// connected peer address is loopback; it permits the HELO fallback and
    /// AUTH over plaintext.
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
    /// Credentials and mechanism allowlist; `None` sends no AUTH.
    pub auth: Option<Auth>,
    /// Stage timeouts (default: RFC 5321).
    pub timeouts: Timeouts,
    /// Use PIPELINING when offered (default true).
    pub pipelining: bool,
    /// Use CHUNKING (BDAT) when offered (default true).
    pub chunking: bool,
    /// Policy for refused recipients (default `Any`).
    pub recipient_policy: RecipientPolicy,
    /// Reply budgets.
    pub reply_limits: ReplyLimits,
    /// Output buffer size in octets (default 16 KiB; at least 1 KiB).
    pub output_capacity: usize,
    /// Queue an [`Event::Reply`] for every reply (default false).
    pub reply_events: bool,
}

impl Default for SessionConfig {
    fn default() -> SessionConfig {
        SessionConfig {
            client_name: ClientName::default(),
            security: SessionSecurity::StartTlsRequired,
            auth: None,
            timeouts: Timeouts::rfc5321(),
            pipelining: true,
            chunking: true,
            recipient_policy: RecipientPolicy::Any,
            reply_limits: ReplyLimits::default(),
            output_capacity: 16 * 1024,
            reply_events: false,
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
    /// MAIL, RCPT, DATA, BDAT, or RSET in progress.
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
    /// A reply arrived (only with [`SessionConfig::reply_events`]): its
    /// codes, never its text (T-30).
    Reply {
        /// The command it answers.
        stage: Stage,
        /// The reply code.
        code: super::ReplyCode,
        /// The enhanced status code, when the server sends them.
        enhanced: Option<super::EnhancedCode>,
    },
    /// Ready for a transaction.
    Ready {
        /// The connection is TLS.
        secure: bool,
        /// AUTH succeeded.
        authenticated: bool,
    },
    /// Run the TLS handshake now, then call `tls_established`.
    StartTls,
    /// AUTH succeeded.
    Authenticated {
        /// The mechanism used.
        mechanism: MechanismName,
    },
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
    /// The server refused these recipients as too many for one transaction
    /// (`452` or `552` with `x.5.3`, FR-42): send them in a further
    /// transaction. Follows `Delivered`.
    Deferred {
        /// Indices in the envelope's recipients.
        recipients: Vec<usize>,
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
    Auth,
    Mail,
    Rcpt(usize),
    Data,
    DataEnd,
    /// The reply to a lone dot sent after an unwanted 354.
    Discard,
    /// The reply to a BDAT chunk that is not the last.
    Bdat,
    /// The reply to `BDAT n LAST`.
    BdatLast,
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
            Expect::Auth => Stage::Auth,
            Expect::Mail => Stage::Mail,
            Expect::Rcpt(_) => Stage::Rcpt,
            Expect::Data => Stage::Data,
            Expect::DataEnd | Expect::Discard => Stage::DataEnd,
            Expect::Bdat | Expect::BdatLast => Stage::Bdat,
            Expect::Rset => Stage::Rset,
            Expect::Noop => Stage::Noop,
            Expect::Quit => Stage::Quit,
        }
    }

    /// The reply that ends the data: lost after it was written means possibly delivered.
    fn is_end(self) -> bool {
        matches!(self, Expect::DataEnd | Expect::BdatLast)
    }

    /// Whether a reply of this class can answer the command (RFC 5321
    /// 4.2.1 and 4.3.2): only DATA and AUTH have a 3yz, DATA has no 2yz,
    /// and nothing has a 1yz. Anything else is out of sequence (T-14).
    fn allows(self, code: super::ReplyCode) -> bool {
        match (self, code.get() / 100) {
            (_, 4 | 5) => true,
            (Expect::Data, c) => c == 3,
            (Expect::Auth, c) => c == 2 || c == 3,
            (_, c) => c == 2,
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
    bdat: bool,
    dsn: bool,
    mail_queued: bool,
    next_rcpt: usize,
    data_queued: bool,
    accepted: usize,
    rejected: Vec<(usize, Reply, Disposition)>,
    deferred: Vec<usize>,
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
/// use smtp_net::protocol::{Event, Millis, Session, SessionConfig, SessionSecurity};
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
    exchange: Option<Exchange>,
    authenticated: bool,
    /// The output holds an AUTH response: wiped once it is transmitted.
    secret_out: bool,
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
            .field("authenticated", &self.authenticated)
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
    /// `Config(BufferTooSmall)` for an output capacity below 1 KiB;
    /// `Config(AuthWithPlaintextRemote)` for credentials over plaintext to a
    /// peer not confirmed loopback (T-8).
    pub fn new(config: SessionConfig, now: Millis) -> Result<Session, Error> {
        if config.output_capacity < MIN_OUTPUT {
            return Err(ConfigError::BufferTooSmall.into());
        }
        if config.auth.is_some()
            && config.security
                == (SessionSecurity::Plaintext {
                    peer_is_loopback: false,
                })
        {
            return Err(ConfigError::AuthWithPlaintextRemote.into());
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
            exchange: None,
            authenticated: false,
            secret_out: false,
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
            Expect::Bdat => t.data_block,
            Expect::DataEnd | Expect::Discard | Expect::BdatLast => t.data_end,
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

    fn end_written(&self) -> bool {
        self.txn.as_ref().is_some_and(|t| t.end_unsent == Some(0))
    }

    /// Closes the session with `error` and queues `Event::Closed`.
    fn close(&mut self, mut error: Error) -> Error {
        let possibly = self.pending.iter().any(|p| p.what.is_end()) && self.end_written();
        if possibly {
            error = error.delivered_maybe(true);
        }
        self.state = SessionState::Closed;
        self.pending.clear();
        self.wipe_output();
        self.txn = None;
        self.exchange = None;
        self.body_deadline = None;
        self.events.push_back(Event::Closed {
            error: Some(error.clone()),
        });
        error
    }

    /// Clears the output; when it held an AUTH response, overwrites the
    /// buffer first (best effort without unsafe code).
    fn wipe_output(&mut self) {
        if self.secret_out {
            let cap = self.out.capacity();
            self.out.clear();
            self.out.resize(cap, 0);
            self.secret_out = false;
        }
        self.out.clear();
    }

    /// Feeds bytes received from the server. Parses complete replies, advances
    /// the state, and queues events and output. Returns the bytes consumed;
    /// it stops right after the reply to STARTTLS, and any byte after that
    /// reply in `input` ends the session with `StartTlsInjection` (T-6).
    ///
    /// # Errors
    ///
    /// The error that closed the session (also reported as `Event::Closed`):
    /// `Protocol(..)`, `Rejected`, `AuthFailed`, `AuthUnavailable`,
    /// `StartTlsInjection`, `StartTlsUnavailable`, and `Usage` when the
    /// session expects no input.
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
                Error::from(ProtocolError::UnexpectedReply)
            };
            return Err(self.close(e));
        };
        let stage = p.what.stage();
        if self.config.reply_events {
            self.events.push_back(Event::Reply {
                stage,
                code,
                enhanced: self.parser.enhanced(),
            });
        }
        if code.get() == 421 {
            let reply = self.parser.take();
            let e = Error::new(ErrorKind::Rejected)
                .with_reply(reply)
                .with_disposition(Disposition::Temporary)
                .at(stage);
            self.pending.push_front(p);
            return Err(self.close(e));
        }
        if !p.what.allows(code) {
            // A reply that cannot answer this command: the replies are out
            // of step with the commands (an extra reply earlier, or a server
            // answering something else), so none of the later ones can be
            // trusted.
            let e = Error::from(ProtocolError::UnexpectedReply)
                .with_reply(self.parser.take())
                .at(stage);
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
                    Err(self.close(Error::from(ProtocolError::UnexpectedReply).at(stage)))
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
            Expect::Auth => self.on_auth_reply(code, now),
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
            Expect::Mail
            | Expect::Rcpt(_)
            | Expect::Data
            | Expect::DataEnd
            | Expect::Discard
            | Expect::Bdat
            | Expect::BdatLast => self.on_txn_reply(p.what, code, now),
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
        if self.config.auth.is_some() && !self.authenticated {
            return self.start_auth(now);
        }
        self.state = SessionState::Ready;
        self.events.push_back(Event::Ready {
            secure: self.secure,
            authenticated: self.authenticated,
        });
        Ok(())
    }

    fn start_auth(&mut self, now: Millis) -> Result<(), Error> {
        // No AUTH state is reachable without TLS or a confirmed loopback peer (T-8).
        let allowed = self.secure
            || self.config.security
                == (SessionSecurity::Plaintext {
                    peer_is_loopback: true,
                });
        if !allowed {
            return Err(
                self.close(Error::from(ConfigError::AuthWithPlaintextRemote).at(Stage::Auth))
            );
        }
        let Some(auth) = self.config.auth.as_ref() else {
            return Ok(());
        };
        let chosen = self
            .caps
            .as_ref()
            .filter(|c| c.has(Extension::Auth))
            .map_or(Ok(None), |c| {
                Exchange::choose(auth, c.auth_mechanism_names())
            });
        let mechanism = match chosen {
            Ok(Some(m)) => m,
            Ok(None) => {
                return Err(self.close(Error::new(ErrorKind::AuthUnavailable).at(Stage::Auth)));
            }
            Err(e) => return Err(self.close(Error::from(e).at(Stage::Auth))),
        };
        let (line, exchange) = match Exchange::start(auth, mechanism) {
            Ok(x) => x,
            Err(e) => return Err(self.close(Error::from(e).at(Stage::Auth))),
        };
        self.out.extend_from_slice(&line);
        self.out.extend_from_slice(b"\r\n");
        self.secret_out = true;
        self.exchange = Some(exchange);
        self.state = SessionState::Authenticating;
        self.expect(Expect::Auth, now);
        Ok(())
    }

    fn on_auth_reply(&mut self, code: super::ReplyCode, now: Millis) -> Result<(), Error> {
        match code.get() {
            235 => {
                let Some(mut ex) = self.exchange.take() else {
                    return Err(
                        self.close(Error::from(ProtocolError::UnexpectedReply).at(Stage::Auth))
                    );
                };
                match ex.finish() {
                    Ok(true) => {}
                    // 235 before the exchange was complete.
                    Ok(false) => {
                        return Err(
                            self.close(Error::from(ProtocolError::UnexpectedReply).at(Stage::Auth))
                        );
                    }
                    // The client refuses the success (SCRAM: no server proof).
                    Err(e) => return Err(self.close(Error::from(e).at(Stage::Auth))),
                }
                self.authenticated = true;
                self.events.push_back(Event::Authenticated {
                    mechanism: ex.mechanism,
                });
                self.state = SessionState::Ready;
                self.events.push_back(Event::Ready {
                    secure: self.secure,
                    authenticated: true,
                });
                Ok(())
            }
            334 => {
                let text = self.parser.text();
                let challenge = text.split(|&b| b == b'\n').next().unwrap_or(&[]);
                let step = match self.exchange.as_mut() {
                    Some(ex) => ex.respond(challenge),
                    None => {
                        return Err(
                            self.close(Error::from(ProtocolError::UnexpectedReply).at(Stage::Auth))
                        );
                    }
                };
                match step {
                    Ok(Some(response)) if response.len() + 2 <= MAX_AUTH_LINE => {
                        self.out.extend_from_slice(&response);
                        self.out.extend_from_slice(b"\r\n");
                        self.secret_out = true;
                        self.expect(Expect::Auth, now);
                        Ok(())
                    }
                    Ok(_) => Err(self
                        .close(Error::from(crate::proto::SaslError::TooManySteps).at(Stage::Auth))),
                    Err(e) => Err(self.close(Error::from(e).at(Stage::Auth))),
                }
            }
            _ => {
                let reply = self.parser.take();
                let detail = self
                    .exchange
                    .as_ref()
                    .and_then(|e| e.detail().map(String::from));
                Err(self.close(auth_error(reply).with_detail(detail.as_deref())))
            }
        }
    }

    fn on_txn_reply(
        &mut self,
        what: Expect,
        code: super::ReplyCode,
        now: Millis,
    ) -> Result<(), Error> {
        let Some(txn) = self.txn.as_mut() else {
            return Err(self.close(Error::from(ProtocolError::UnexpectedReply)));
        };
        match what {
            Expect::Mail if !code.is_positive() => {
                let reply = self.parser.take();
                txn.failed = Some(reply_error(Stage::Mail, reply));
            }
            Expect::Rcpt(i) if txn.failed.is_none() => {
                let too_many = matches!(code.get(), 452 | 552)
                    && self
                        .parser
                        .enhanced()
                        .is_some_and(|e| e.subject == 5 && e.detail == 3);
                if matches!(code.get(), 250 | 251) {
                    txn.accepted += 1;
                    self.events.push_back(Event::RecipientAccepted { index: i });
                } else if too_many {
                    txn.deferred.push(i);
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
                    let unwanted =
                        txn.failed.is_some() || txn.accepted == 0 || self.policy_refuses();
                    if unwanted {
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
            Expect::Bdat if !code.is_positive() && txn.failed.is_none() => {
                if txn.accepted == 0 {
                    self.fail_recipients_if_needed();
                } else {
                    let reply = self.parser.take();
                    if let Some(t) = self.txn.as_mut() {
                        t.failed = Some(reply_error(Stage::Bdat, reply));
                    }
                }
            }
            Expect::DataEnd | Expect::BdatLast => {
                let reply = self.parser.take();
                if code.is_positive() && txn.failed.is_none() {
                    let (accepted, rejected) = (txn.accepted, txn.rejected.len());
                    let deferred = core::mem::take(&mut txn.deferred);
                    self.events.push_back(Event::Delivered {
                        reply,
                        accepted,
                        rejected,
                        deferred: deferred.len(),
                    });
                    if !deferred.is_empty() {
                        self.events.push_back(Event::Deferred {
                            recipients: deferred,
                        });
                    }
                    self.txn = None;
                    self.state = SessionState::Ready;
                    return Ok(());
                }
                if txn.failed.is_none() {
                    let stage = if what == Expect::DataEnd {
                        Stage::DataEnd
                    } else {
                        Stage::Bdat
                    };
                    txn.failed = Some(reply_error(stage, reply));
                }
                if what == Expect::DataEnd {
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
                // After a failed BDAT the server's state is unknown (RFC 3030): RSET.
                self.state = SessionState::InTransaction;
            }
            _ => {}
        }
        if self.pending.is_empty() && self.state == SessionState::InTransaction {
            if let Err(e) = self.advance(now) {
                // The server holds an open transaction: never reuse the connection.
                return Err(self.close(e));
            }
        }
        Ok(())
    }

    fn policy_refuses(&self) -> bool {
        self.config.recipient_policy == RecipientPolicy::All
            && self
                .txn
                .as_ref()
                .is_some_and(|t| !t.rejected.is_empty() || !t.deferred.is_empty())
    }

    /// Sets the transaction's failure from its refused recipients, when it has none yet.
    fn fail_recipients_if_needed(&mut self) {
        let Some(txn) = self.txn.as_mut() else { return };
        if txn.failed.is_some() {
            return;
        }
        let temporary = !txn.deferred.is_empty()
            || txn
                .rejected
                .iter()
                .any(|(_, _, d)| *d == Disposition::Temporary);
        let kind = if txn.accepted == 0 {
            ErrorKind::AllRecipientsRejected
        } else {
            ErrorKind::Rejected
        };
        let mut recipients: Vec<_> = txn
            .rejected
            .iter()
            .filter_map(|(i, r, d)| {
                txn.envelope
                    .recipients()
                    .get(*i)
                    .map(|a| RejectedRecipient::new(a.clone(), r.clone(), *d))
            })
            .collect();
        for i in &txn.deferred {
            if let Some(a) = txn.envelope.recipients().get(*i) {
                let reply = Reply::too_many();
                recipients.push(RejectedRecipient::new(
                    a.clone(),
                    reply,
                    Disposition::Temporary,
                ));
            }
        }
        let e = Error::new(kind)
            .at(Stage::Rcpt)
            .with_disposition(if temporary {
                Disposition::Temporary
            } else {
                Disposition::Permanent
            })
            .with_rejected(recipients);
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
        let hold = !pipelined
            || self.config.recipient_policy == RecipientPolicy::All
            || (txn.bdat && txn.size > BDAT_PIPELINE_LIMIT);
        if waiting && hold {
            return Ok(());
        }
        if !waiting && (txn.accepted == 0 || self.policy_refuses()) {
            // Every recipient reply is in, and none (or not all) were accepted.
            self.fail_recipients_if_needed();
            return self.advance(now);
        }
        if txn.bdat {
            let size = txn.size;
            if size > 0 {
                let mut l = Line::new(&mut self.out);
                l.put(b"BDAT ").decimal(size);
                l.end()?;
                self.expect(Expect::Bdat, now);
            }
            if let Some(t) = self.txn.as_mut() {
                t.data_queued = true;
            }
            self.state = SessionState::Body;
            self.body_deadline = Some(now.after(self.config.timeouts.data_block));
            self.events.push_back(Event::BodyWanted);
            return Ok(());
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
        write_mail(&mut self.out, txn, caps_size)?;
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
        write_rcpt(&mut self.out, txn, i)?;
        txn.next_rcpt = i + 1;
        self.group += self.out.len() - start;
        self.expect(Expect::Rcpt(i), now);
        Ok(())
    }

    /// Formats the MAIL line and every RCPT line of the transaction and
    /// removes them again, so a line that cannot be sent is found before
    /// any line of the transaction is queued. Without this, a refusal half
    /// way through a pipelined group would leave the earlier lines queued,
    /// and the next transaction on the connection would join them.
    fn check_lines(&mut self) -> Result<(), Error> {
        let caps_size = self.caps.as_ref().is_some_and(|c| c.has(Extension::Size));
        let Some(txn) = self.txn.as_ref() else {
            return Ok(());
        };
        let start = self.out.len();
        let mut result = write_mail(&mut self.out, txn, caps_size).map_err(|e| e.at(Stage::Mail));
        self.out.truncate(start);
        for i in 0..txn.envelope.recipients().len() {
            if result.is_err() {
                break;
            }
            result = write_rcpt(&mut self.out, txn, i).map_err(|e| e.at(Stage::Rcpt));
            self.out.truncate(start);
        }
        result
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
    /// were written (saturating at the pending length). Output that held an
    /// AUTH response is overwritten once it is all written.
    pub fn transmitted(&mut self, n: usize) {
        let n = n.min(self.out.len());
        self.out.drain(..n);
        if self.out.is_empty() {
            self.wipe_output();
        }
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
    /// not read (RFC 1047, T-18). After a QUIT it closes cleanly and returns
    /// the error for the record only.
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
    /// capabilities (SIZE, SMTPUTF8, 8BITMIME, DSN), then queues MAIL, RCPT,
    /// and DATA or BDAT, as one group when PIPELINING is offered (PLAN 7.6).
    /// With CHUNKING, `size` must be the exact length of the bytes passed to
    /// [`body`](Session::body).
    ///
    /// # Errors
    ///
    /// `MessageTooLarge`, `ExtensionRequired(..)`, `Build(CommandTooLong)`
    /// when the MAIL line or any RCPT line would pass 512 octets (all
    /// permanent, nothing queued), `Usage(WrongState)`. Every line of the
    /// transaction is measured before the first is queued, so a refused
    /// `begin` leaves the session as it found it.
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
        let has = |e| caps.is_some_and(|c| c.has(e));
        let smtputf8 = flags.smtputf8 || envelope.needs_smtputf8();
        if smtputf8 && !has(Extension::Smtputf8) {
            return Err(
                Error::new(ErrorKind::ExtensionRequired(Extension::Smtputf8)).at(Stage::Mail),
            );
        }
        if flags.eight_bit && !has(Extension::EightBitMime) {
            return Err(
                Error::new(ErrorKind::ExtensionRequired(Extension::EightBitMime)).at(Stage::Mail),
            );
        }
        if let Some(limit) = caps.and_then(Capabilities::size_limit) {
            if limit > 0 && size > limit {
                return Err(Error::new(ErrorKind::MessageTooLarge { size, limit }).at(Stage::Mail));
            }
        }
        let dsn = match envelope.dsn() {
            Some(d) if !has(Extension::Dsn) && d.policy() == DsnPolicy::Required => {
                return Err(
                    Error::new(ErrorKind::ExtensionRequired(Extension::Dsn)).at(Stage::Mail)
                );
            }
            Some(_) => has(Extension::Dsn),
            None => false,
        };
        let pipelined = self.config.pipelining && has(Extension::Pipelining);
        let bdat = self.config.chunking && has(Extension::Chunking);
        self.txn = Some(Txn {
            envelope: envelope.clone(),
            flags: BodyFlags {
                eight_bit: flags.eight_bit,
                smtputf8,
            },
            size,
            pipelined,
            bdat,
            dsn,
            mail_queued: false,
            next_rcpt: 0,
            data_queued: false,
            accepted: 0,
            rejected: Vec::new(),
            deferred: Vec::new(),
            failed: None,
            stuffer: if bdat {
                DotStuffer::raw()
            } else {
                DotStuffer::new()
            },
            end_unsent: None,
        });
        if let Err(e) = self.check_lines() {
            self.txn = None;
            return Err(e);
        }
        self.state = SessionState::InTransaction;
        let (out_len, pending_len, group) = (self.out.len(), self.pending.len(), self.group);
        if let Err(e) = self.advance(now) {
            // Nothing of this transaction may stay queued (see check_lines).
            self.out.truncate(out_len);
            self.pending.truncate(pending_len);
            self.group = group;
            self.txn = None;
            self.state = SessionState::Ready;
            return Err(e);
        }
        Ok(())
    }

    /// Accepts body bytes (the serialized message) up to the free output
    /// capacity, dot-stuffing them for DATA (BDAT sends them as they are);
    /// returns how many were taken. Flush [`transmit`](Session::transmit) and
    /// call again with the rest.
    ///
    /// # Errors
    ///
    /// `Build(BareLineFeed)`, `Build(BareCarriageReturn)`, and with CHUNKING
    /// `Build(LengthMismatch)` past the size given to `begin` (permanent: the
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
        if txn.bdat && txn.stuffer.taken() + chunk.len() as u64 > txn.size {
            let actual = txn.stuffer.taken() + chunk.len() as u64;
            let e = Error::from(BuildError::LengthMismatch {
                declared: txn.size,
                actual,
            })
            .at(Stage::Body);
            return Err(self.close(e).with_disposition(Disposition::Permanent));
        }
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

    /// Ends the body: writes the end-of-data sequence (or the last BDAT
    /// chunk) and waits for its reply. From the moment those bytes are
    /// transmitted, a lost connection is `possibly_delivered`.
    ///
    /// # Errors
    ///
    /// `Build(BareCarriageReturn)` for a body ending in CR, with CHUNKING
    /// `Build(LengthMismatch)` when fewer bytes came than `begin` declared,
    /// `Usage(WrongState)`.
    pub fn end_body(&mut self, now: Millis) -> Result<(), Error> {
        if self.state != SessionState::Body {
            return Err(self.wrong_state());
        }
        let Some(txn) = self.txn.as_mut() else {
            return Err(self.wrong_state());
        };
        let what = if txn.bdat {
            let taken = txn.stuffer.taken();
            if taken != txn.size {
                let e = Error::from(BuildError::LengthMismatch {
                    declared: txn.size,
                    actual: taken,
                })
                .at(Stage::Body);
                return Err(self.close(e).with_disposition(Disposition::Permanent));
            }
            if txn.stuffer.pending_cr() {
                let e = Error::from(BuildError::BareCarriageReturn {
                    position: taken.saturating_sub(1),
                })
                .at(Stage::Body);
                return Err(self.close(e).with_disposition(Disposition::Permanent));
            }
            if taken > 0 && !txn.stuffer.ends_crlf() {
                // The same message as DATA would carry: it ends with CRLF.
                self.out.extend_from_slice(b"BDAT 2 LAST\r\n\r\n");
            } else {
                self.out.extend_from_slice(b"BDAT 0 LAST\r\n");
            }
            Expect::BdatLast
        } else {
            if let Err(b) = txn.stuffer.finish(&mut self.out) {
                let e = Error::from(b).at(Stage::Body);
                return Err(self.close(e).with_disposition(Disposition::Permanent));
            }
            Expect::DataEnd
        };
        if let Some(t) = self.txn.as_mut() {
            t.end_unsent = Some(self.out.len());
        }
        self.state = SessionState::AwaitDataEnd;
        self.body_deadline = None;
        self.expect(what, now);
        Ok(())
    }

    /// Sends RSET (to abandon a transaction, or after a failure).
    ///
    /// # Errors
    ///
    /// `Usage(WrongState)` outside `Ready`.
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

    /// True after AUTH succeeded.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
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

/// Appends the MAIL line of `txn` to `out`; on refusal nothing is appended.
fn write_mail(out: &mut Vec<u8>, txn: &Txn, caps_size: bool) -> Result<(), Error> {
    let mut l = Line::new(out);
    l.put(b"MAIL FROM:").path(txn.envelope.return_path());
    if caps_size && txn.size > 0 {
        l.put(b" SIZE=").decimal(txn.size);
    }
    if txn.flags.eight_bit {
        l.put(b" BODY=8BITMIME");
    }
    if txn.flags.smtputf8 {
        l.put(b" SMTPUTF8");
    }
    if let Some(d) = txn.envelope.dsn().filter(|_| txn.dsn) {
        match d.return_content() {
            Some(DsnReturn::Full) => {
                l.put(b" RET=FULL");
            }
            Some(DsnReturn::Headers) => {
                l.put(b" RET=HDRS");
            }
            None => {}
        }
        if let Some(id) = d.envelope_id() {
            l.put(b" ENVID=").xtext(id.as_bytes());
        }
    }
    l.end()
}

/// Appends the RCPT line for recipient `i` of `txn` to `out`; on refusal
/// nothing is appended.
fn write_rcpt(out: &mut Vec<u8>, txn: &Txn, i: usize) -> Result<(), Error> {
    let addr = txn.envelope.recipients().get(i);
    let mut l = Line::new(out);
    l.put(b"RCPT TO:").path(addr);
    if let Some(d) = txn.envelope.dsn().filter(|_| txn.dsn) {
        let n = d.notify();
        if n.bits() == 0 {
            l.put(b" NOTIFY=NEVER");
        } else {
            l.put(b" NOTIFY=");
            let mut first = true;
            for (on, word) in [
                (n.success(), &b"SUCCESS"[..]),
                (n.failure(), b"FAILURE"),
                (n.delay(), b"DELAY"),
            ] {
                if on {
                    if !first {
                        l.put(b",");
                    }
                    l.put(word);
                    first = false;
                }
            }
        }
        // ORCPT carries the address as given; UTF-8 addresses need RFC 6533 types: omitted.
        if let Some(a) = addr.filter(|a| !a.needs_smtputf8()) {
            l.put(b" ORCPT=rfc822;").xtext(a.as_str().as_bytes());
        }
    }
    l.end()
}

/// Appends a constant command line.
fn push_command(out: &mut Vec<u8>, command: &[u8]) {
    out.extend_from_slice(command);
    out.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests;
