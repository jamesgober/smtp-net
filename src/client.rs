//! The blocking driver over net-io (PLAN 7.12).

use std::{
    io,
    net::IpAddr,
    string::String,
    time::{Duration, Instant},
    vec::Vec,
};

use net_io::{ConnectOptions, Limits, MinRate, NetError, TcpConnection};

use crate::{
    address::{Address, Domain},
    error::{ConfigError, Disposition, Error, ErrorKind, Stage},
    message::{Message, prepared::PreparedMessage},
    proto::{
        BodyFlags, Capabilities, ClientName, Event, Millis, RecipientPolicy, Reply, Session,
        SessionConfig, SessionSecurity, SessionState, Timeouts, TlsProtocol,
    },
};

/// Read buffer per client **[est.]**.
const READ_BUFFER: usize = 16 * 1024;
/// Body bytes handed to the session per call.
const BODY_CHUNK: usize = 16 * 1024;
/// Default most messages per connection before reconnecting **[est.]**.
const DEFAULT_MAX_MESSAGES: u32 = 100;
/// The bound on the QUIT a dropped client attempts.
const DROP_QUIT: Duration = Duration::from_secs(1);

/// How the connection to the server is secured (PLAN 7.12). There is no
/// "opportunistic" value: submission carries credentials and private content.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Security {
    /// No TLS: only to a host that is `127.0.0.0/8`, `::1`, or `localhost`,
    /// and only when the connected peer address is loopback (T-32).
    PlaintextLoopback,
    /// STARTTLS on port 587, required (0.4).
    StartTls,
    /// TLS from the first byte on port 465 (0.4).
    ImplicitTls,
}

impl Security {
    fn default_port(self) -> u16 {
        match self {
            Security::PlaintextLoopback => crate::PORT_SMTP,
            Security::StartTls => crate::PORT_SUBMISSION,
            Security::ImplicitTls => crate::PORT_SUBMISSIONS,
        }
    }
}

/// Where and how to submit mail. `Send + Sync`; build one and share it.
///
/// # Examples
///
/// ```
/// use smtp_net::{Security, Server};
/// let local = Server::local();
/// assert_eq!(local.port(), 25);
/// let custom = Server::builder("127.0.0.1", Security::PlaintextLoopback).port(2525).build()?;
/// assert_eq!(custom.port(), 2525);
/// assert!(Server::builder("mail.example.com", Security::PlaintextLoopback).build().is_err());
/// # Ok::<(), smtp_net::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server {
    host: String,
    port: u16,
    security: Security,
    client_name: Option<ClientName>,
    timeouts: Timeouts,
    pipelining: bool,
    recipient_policy: RecipientPolicy,
    max_messages: u32,
}

impl Server {
    /// The mail server on this machine: `127.0.0.1:25`, plaintext to a
    /// verified loopback peer, no AUTH, [`Timeouts::local`], and the local
    /// socket's address literal as the EHLO name (D-009, D-011).
    #[must_use]
    pub fn local() -> Server {
        Server {
            host: String::from("127.0.0.1"),
            port: crate::PORT_SMTP,
            security: Security::PlaintextLoopback,
            client_name: None,
            timeouts: Timeouts::local(),
            pipelining: true,
            recipient_policy: RecipientPolicy::Any,
            max_messages: DEFAULT_MAX_MESSAGES,
        }
    }

    /// A builder for `host` with `security` (the port defaults to 25, 587, or
    /// 465 by security).
    pub fn builder(host: &str, security: Security) -> ServerBuilder {
        ServerBuilder {
            server: Server {
                host: String::from(host),
                port: security.default_port(),
                security,
                client_name: None,
                timeouts: if security == Security::PlaintextLoopback {
                    Timeouts::local()
                } else {
                    Timeouts::rfc5321()
                },
                pipelining: true,
                recipient_policy: RecipientPolicy::Any,
                max_messages: DEFAULT_MAX_MESSAGES,
            },
        }
    }

    /// The host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The security mode.
    #[must_use]
    pub fn security(&self) -> Security {
        self.security
    }

    /// The timeouts.
    #[must_use]
    pub fn timeouts(&self) -> &Timeouts {
        &self.timeouts
    }
}

/// Every option of a [`Server`].
#[must_use]
#[derive(Clone, Debug)]
pub struct ServerBuilder {
    server: Server,
}

impl ServerBuilder {
    /// Overrides the default port.
    pub fn port(mut self, port: u16) -> Self {
        self.server.port = port;
        self
    }

    /// The EHLO argument; the default is the local socket's address literal.
    pub fn client_name(mut self, name: ClientName) -> Self {
        self.server.client_name = Some(name);
        self
    }

    /// Replaces the timeouts.
    pub fn timeouts(mut self, timeouts: Timeouts) -> Self {
        self.server.timeouts = timeouts;
        self
    }

    /// Use PIPELINING when offered (default true).
    pub fn pipelining(mut self, use_it: bool) -> Self {
        self.server.pipelining = use_it;
        self
    }

    /// The policy for refused recipients (default `Any`).
    pub fn recipient_policy(mut self, policy: RecipientPolicy) -> Self {
        self.server.recipient_policy = policy;
        self
    }

    /// Messages per connection before the client reconnects (default 100).
    pub fn max_messages_per_connection(mut self, n: u32) -> Self {
        self.server.max_messages = n.max(1);
        self
    }

    /// Checks the configuration.
    ///
    /// # Errors
    ///
    /// `Config(PortZero)`, `Config(InvalidHost)`, `Config(PlaintextHostNotLoopback)`,
    /// `Config(TlsConnectorMissing)` for STARTTLS or implicit TLS (the TLS
    /// engine arrives in 0.4).
    pub fn build(self) -> Result<Server, Error> {
        let s = self.server;
        if s.port == 0 {
            return Err(ConfigError::PortZero.into());
        }
        let ip = s.host.parse::<IpAddr>().ok();
        if ip.is_none() && Domain::parse(&s.host).is_err() {
            return Err(ConfigError::InvalidHost.into());
        }
        match s.security {
            Security::PlaintextLoopback => {
                let loopback = ip.map_or_else(
                    || s.host.eq_ignore_ascii_case("localhost"),
                    |ip| ip.is_loopback(),
                );
                if !loopback {
                    return Err(ConfigError::PlaintextHostNotLoopback.into());
                }
            }
            Security::StartTls | Security::ImplicitTls => {
                return Err(ConfigError::TlsConnectorMissing.into());
            }
        }
        Ok(s)
    }
}

/// What the server said about a sent message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    message_id: String,
    accepted: Vec<Address>,
    rejected: Vec<(Address, Reply, Disposition)>,
    final_reply: Reply,
    secure: bool,
    tls_protocol: Option<TlsProtocol>,
    elapsed: Duration,
}

impl Report {
    /// The `Message-ID` sent (empty for a raw message without one).
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Recipients the server accepted.
    pub fn accepted(&self) -> impl Iterator<Item = &Address> {
        self.accepted.iter()
    }

    /// Recipients the server refused, with its reply and whether retrying can help.
    pub fn rejected(&self) -> impl Iterator<Item = (&Address, &Reply, Disposition)> {
        self.rejected.iter().map(|(a, r, d)| (a, r, *d))
    }

    /// The reply to the end of the data.
    #[must_use]
    pub fn final_reply(&self) -> &Reply {
        &self.final_reply
    }

    /// True when the message went over TLS.
    #[must_use]
    pub fn was_secure(&self) -> bool {
        self.secure
    }

    /// The TLS version, when the message went over TLS.
    #[must_use]
    pub fn tls_protocol(&self) -> Option<TlsProtocol> {
        self.tls_protocol
    }

    /// Time from the start of the transaction to the final reply.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }
}

/// Sends `message` to `server`: derives the envelope, serializes, connects,
/// sends, sends QUIT, and closes.
///
/// # Errors
///
/// Every [`ErrorKind`]; check [`Error::is_temporary`] and
/// [`Error::possibly_delivered`] to decide on a retry.
///
/// # Examples
///
/// ```no_run
/// let msg = smtp_net::Message::text("no-reply@example.com", "user@example.org", "Hi", "Hello")?;
/// let server = smtp_net::Server::builder("127.0.0.1", smtp_net::Security::PlaintextLoopback).port(2525).build()?;
/// let report = smtp_net::send(&server, &msg)?;
/// println!("{}", report.message_id());
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub fn send(server: &Server, message: &Message) -> Result<Report, Error> {
    let prepared = message.prepare()?;
    let mut client = Client::connect(server)?;
    let report = client.send_prepared(&prepared)?;
    // The message is accepted; a failed QUIT changes nothing.
    let _ = client.close();
    Ok(report)
}

/// `send(&Server::local(), message)`: submission to the mail server on this
/// machine (for example cPanel's Exim on `127.0.0.1:25`).
///
/// # Errors
///
/// As [`send`].
///
/// # Examples
///
/// ```no_run
/// let msg = smtp_net::Message::text(
///     "Example <no-reply@example.com>",
///     "user@example.org",
///     "Confirm your email address",
///     "Open this link to confirm: https://example.com/confirm/abc123",
/// )?;
/// let report = smtp_net::send_local(&msg)?;
/// println!("accepted as {}", report.message_id());
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub fn send_local(message: &Message) -> Result<Report, Error> {
    send(&Server::local(), message)
}

/// One connection and its session. `Send`, not `Sync`.
///
/// # Examples
///
/// ```no_run
/// let mut client = smtp_net::Client::connect(&smtp_net::Server::local())?;
/// for to in ["a@example.org", "b@example.org"] {
///     let msg = smtp_net::Message::text("no-reply@example.com", to, "Hi", "Hello")?;
///     client.send(&msg)?;
/// }
/// client.close()?;
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub struct Client {
    server: Server,
    conn: Option<TcpConnection>,
    session: Session,
    epoch: Instant,
    buf: Vec<u8>,
    sent: u32,
    last_used: Instant,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("host", &self.server.host)
            .field("port", &self.server.port)
            .field("state", &self.session.state())
            .field("sent", &self.sent)
            .finish()
    }
}

fn net_kind(e: NetError) -> io::ErrorKind {
    io::Error::from(e).kind()
}

impl Client {
    /// Resolves the host, connects within the connect timeout, checks the peer
    /// is loopback for plaintext, and drives the session to ready.
    ///
    /// # Errors
    ///
    /// `Connect`, `PlaintextRefused`, `Timeout`, `Rejected` (greeting or EHLO
    /// refused), `Protocol`, `Config`.
    pub fn connect(server: &Server) -> Result<Client, Error> {
        let (conn, session) = Client::open(server)?;
        let mut c = Client {
            server: server.clone(),
            conn: Some(conn),
            session,
            epoch: Instant::now(),
            buf: vec_of(READ_BUFFER),
            sent: 0,
            last_used: Instant::now(),
        };
        c.until_ready()?;
        Ok(c)
    }

    fn open(server: &Server) -> Result<(TcpConnection, Session), Error> {
        let t = &server.timeouts;
        // net-io's own deadlines stay above every stage timeout; the session's
        // per-stage deadline is applied as the exchange deadline.
        let longest = [
            t.greeting,
            t.command,
            t.mail,
            t.rcpt,
            t.data_init,
            t.data_block,
            t.data_end,
        ]
        .into_iter()
        .max()
        .unwrap_or(t.data_end)
            + Duration::from_secs(5);
        let limits = Limits::builder()
            .read_timeout(longest)
            .write_timeout(longest)
            .min_rate(MinRate::off())
            .build()
            .map_err(|e| Error::new(ErrorKind::Connect(net_kind(e))).at(Stage::Connect))?;
        let options = ConnectOptions::new().timeout(t.connect).limits(limits);
        let conn = TcpConnection::connect_host(&server.host, server.port, options)
            .map_err(|e| Error::new(ErrorKind::Connect(net_kind(e))).at(Stage::Connect))?;
        let peer_is_loopback = conn.peer_addr().ip().is_loopback();
        let security = match server.security {
            Security::PlaintextLoopback if peer_is_loopback => {
                SessionSecurity::Plaintext { peer_is_loopback }
            }
            Security::PlaintextLoopback => {
                conn.abort();
                return Err(Error::new(ErrorKind::PlaintextRefused).at(Stage::Connect));
            }
            Security::StartTls | Security::ImplicitTls => {
                conn.abort();
                return Err(ConfigError::TlsConnectorMissing.into());
            }
        };
        let config = SessionConfig {
            security,
            client_name: server
                .client_name
                .clone()
                .unwrap_or(ClientName::AddressLiteral(conn.local_addr().ip())),
            timeouts: server.timeouts,
            pipelining: server.pipelining,
            recipient_policy: server.recipient_policy,
            ..SessionConfig::default()
        };
        let session = Session::new(config, Millis(0))?;
        Ok((conn, session))
    }

    fn now(&self) -> Millis {
        Millis(u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    fn instant(&self, at: Millis) -> Instant {
        self.epoch + Duration::from_millis(at.0)
    }

    /// Writes all pending output.
    fn flush(&mut self) -> Result<(), Error> {
        while !self.session.transmit().is_empty() {
            let Some(conn) = self.conn.as_mut() else {
                return Err(Error::new(ErrorKind::ConnectionClosed));
            };
            match conn.send(self.session.transmit()) {
                Ok(0) => return Err(self.lost(ErrorKind::ConnectionClosed)),
                Ok(n) => self.session.transmitted(n),
                Err(e) => return Err(self.lost(ErrorKind::Io(net_kind(e)))),
            }
        }
        Ok(())
    }

    fn lost(&mut self, kind: ErrorKind) -> Error {
        if let Some(c) = self.conn.take() {
            c.abort();
        }
        self.session.connection_lost(kind)
    }

    /// Reads once and feeds the session.
    fn read(&mut self) -> Result<(), Error> {
        let deadline = self.session.deadline().map(|d| self.instant(d));
        let Some(conn) = self.conn.as_mut() else {
            return Err(Error::new(ErrorKind::ConnectionClosed));
        };
        conn.set_exchange_deadline(deadline);
        match conn.recv(&mut self.buf) {
            Ok(0) => Err(self.lost(ErrorKind::ConnectionClosed)),
            Ok(n) => {
                let now = self.now();
                let input = self.buf.get(..n).unwrap_or(&[]);
                match self.session.receive(input, now) {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        self.drop_conn();
                        Err(e)
                    }
                }
            }
            Err(NetError::TimedOut { .. }) => {
                let now = self.now().max(self.session.deadline().unwrap_or(Millis(0)));
                let e = match self.session.on_timeout(now) {
                    Err(e) => e,
                    Ok(()) => self.session.connection_lost(ErrorKind::Timeout),
                };
                self.drop_conn();
                Err(e)
            }
            Err(e) => Err(self.lost(ErrorKind::Io(net_kind(e)))),
        }
    }

    fn drop_conn(&mut self) {
        if let Some(c) = self.conn.take() {
            c.abort();
        }
    }

    fn until_ready(&mut self) -> Result<(), Error> {
        loop {
            self.flush()?;
            while let Some(event) = self.session.poll_event() {
                match event {
                    Event::Ready { .. } => return Ok(()),
                    Event::Closed { error } => {
                        self.drop_conn();
                        return Err(
                            error.unwrap_or_else(|| Error::new(ErrorKind::ConnectionClosed))
                        );
                    }
                    Event::StartTls => {
                        let e = self
                            .session
                            .connection_lost(ErrorKind::Config(ConfigError::TlsConnectorMissing));
                        self.drop_conn();
                        return Err(e);
                    }
                    _ => {}
                }
            }
            if self.session.state() == SessionState::Ready {
                return Ok(());
            }
            self.read()?;
        }
    }

    /// Sends a built message on this connection.
    ///
    /// # Errors
    ///
    /// Every send error; see [`send`].
    pub fn send(&mut self, message: &Message) -> Result<Report, Error> {
        let prepared = message.prepare()?;
        self.send_prepared(&prepared)
    }

    /// Sends prepared bytes as they are. Reconnects first when the connection
    /// was idle too long or carried its message limit, and once more when the
    /// server had closed an idle connection before accepting anything.
    ///
    /// # Errors
    ///
    /// Every send error; see [`send`].
    pub fn send_prepared(&mut self, message: &PreparedMessage) -> Result<Report, Error> {
        let reused = self.sent > 0;
        if !self.is_open()
            || self.last_used.elapsed() > self.server.timeouts.idle
            || self.sent >= self.server.max_messages
        {
            self.reconnect()?;
        }
        match self.transaction(message) {
            Err(e)
                if reused
                    && e.is_temporary()
                    && !e.possibly_delivered()
                    && e.recipients().is_empty()
                    && self.nothing_accepted(&e) =>
            {
                self.reconnect()?;
                self.transaction(message)
            }
            other => other,
        }
    }

    /// True when the failure happened before the server accepted any part of
    /// the transaction (an idle connection closed under us).
    fn nothing_accepted(&self, e: &Error) -> bool {
        matches!(e.stage(), Some(Stage::Mail))
            && matches!(
                e.kind(),
                ErrorKind::ConnectionClosed | ErrorKind::Io(_) | ErrorKind::Rejected
            )
            && e.reply().is_none_or(|r| r.code().get() == 421)
    }

    fn reconnect(&mut self) -> Result<(), Error> {
        if let Some(mut c) = self.conn.take() {
            let now = self.now();
            if self.session.quit(now).is_ok() {
                let _ = c.send_all(self.session.transmit());
            }
            c.abort();
        }
        let (conn, session) = Client::open(&self.server)?;
        self.conn = Some(conn);
        self.session = session;
        self.epoch = Instant::now();
        self.sent = 0;
        self.until_ready()
    }

    fn transaction(&mut self, message: &PreparedMessage) -> Result<Report, Error> {
        let start = Instant::now();
        let envelope = message.envelope();
        let flags = BodyFlags::new(message.has_8bit(), message.needs_smtputf8());
        let now = self.now();
        self.session
            .begin(envelope, flags, message.bytes().len() as u64, now)?;
        let mut accepted: Vec<Address> = Vec::new();
        let mut rejected = Vec::new();
        let mut body = message.bytes();
        let mut in_body = false;
        loop {
            if in_body {
                let now = self.now();
                let take = body.len().min(BODY_CHUNK);
                let n = self.session.body(body.get(..take).unwrap_or(&[]), now)?;
                body = body.get(n..).unwrap_or(&[]);
                if body.is_empty() {
                    self.session.end_body(now)?;
                    in_body = false;
                }
            }
            self.flush()?;
            while let Some(event) = self.session.poll_event() {
                match event {
                    Event::RecipientAccepted { index } => {
                        if let Some(a) = envelope.recipients().get(index) {
                            accepted.push(a.clone());
                        }
                    }
                    Event::RecipientRejected {
                        index,
                        reply,
                        disposition,
                    } => {
                        if let Some(a) = envelope.recipients().get(index) {
                            rejected.push((a.clone(), reply, disposition));
                        }
                    }
                    Event::BodyWanted => in_body = true,
                    Event::Delivered { reply, .. } => {
                        self.sent += 1;
                        self.last_used = Instant::now();
                        return Ok(Report {
                            message_id: String::from(message.message_id().unwrap_or("")),
                            accepted,
                            rejected,
                            final_reply: reply,
                            secure: self.session.is_secure(),
                            tls_protocol: self.session.tls_protocol(),
                            elapsed: start.elapsed(),
                        });
                    }
                    Event::TransactionFailed(e) => {
                        self.last_used = Instant::now();
                        return Err(e);
                    }
                    Event::Closed { error } => {
                        self.drop_conn();
                        return Err(
                            error.unwrap_or_else(|| Error::new(ErrorKind::ConnectionClosed))
                        );
                    }
                    _ => {}
                }
            }
            if !in_body && self.session.wants_read() {
                self.read()?;
            }
        }
    }

    /// True while the connection is up and the session can take a transaction.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.conn.is_some() && self.session.state() == SessionState::Ready
    }

    /// The capabilities from the latest EHLO.
    #[must_use]
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.session.capabilities()
    }

    /// Sends QUIT, waits for the reply, and closes.
    ///
    /// # Errors
    ///
    /// `Timeout`, `Io` while sending QUIT (the connection is closed either way).
    pub fn close(mut self) -> Result<(), Error> {
        self.quit_and_close(None)
    }

    fn quit_and_close(&mut self, bound: Option<Duration>) -> Result<(), Error> {
        if self.conn.is_none() || self.session.state() == SessionState::Closed {
            self.drop_conn();
            return Ok(());
        }
        let now = self.now();
        self.session.quit(now)?;
        if let (Some(b), Some(conn)) = (bound, self.conn.as_mut()) {
            conn.set_exchange_deadline(Some(Instant::now() + b));
            if let Ok(l) = Limits::builder()
                .write_timeout(b)
                .read_timeout(b)
                .min_rate(MinRate::off())
                .build()
            {
                conn.set_limits(l);
            }
        }
        let result = (|| -> Result<(), Error> {
            self.flush()?;
            while self.session.wants_read() {
                self.read()?;
            }
            Ok(())
        })();
        if let Some(c) = self.conn.take() {
            let _ = c.close();
        }
        match result {
            Err(e) if matches!(e.kind(), ErrorKind::ConnectionClosed) => Ok(()),
            other => other,
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.quit_and_close(Some(DROP_QUIT));
    }
}

fn vec_of(n: usize) -> Vec<u8> {
    std::vec![0; n]
}
