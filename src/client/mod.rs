//! The blocking driver over net-io (PLAN 7.12).

mod observe;
mod pool;
mod slots;
mod tls;

use std::{
    io,
    net::IpAddr,
    string::String,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    vec::Vec,
};

use net_io::{ConnectOptions, Limits, MinRate, NetError, TcpConnection};
pub use observe::{ObservedEvent, Observer, SecurityEventKind};
pub use pool::Pool;
use tls::{Read, TlsLink};
pub use tls::{TlsConnector, TlsSetupError};

use crate::{
    address::{Address, Domain},
    error::{ConfigError, Disposition, Error, ErrorKind, Stage},
    gate::{Admission, SendGate},
    message::{Message, prepared::PreparedMessage},
    proto::{
        Auth, BodyFlags, Capabilities, ClientName, Credentials, Event, MechanismList, Millis,
        RecipientPolicy, Reply, Secret, Session, SessionConfig, SessionSecurity, SessionState,
        Timeouts, TlsProtocol,
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
/// Most further transactions for deferred recipients in one send.
const MAX_DEFERRAL_ROUNDS: usize = 10;

/// How the connection to the server is secured (PLAN 7.12). There is no
/// "opportunistic" value: submission carries credentials and private content.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Security {
    /// No TLS: only to a host that is `127.0.0.0/8`, `::1`, or `localhost`,
    /// and only when the connected peer address is loopback (T-32).
    PlaintextLoopback,
    /// STARTTLS on port 587, required: no plaintext fallback (T-5).
    StartTls,
    /// TLS from the first byte on port 465 (RFC 8314).
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

fn is_loopback_host(host: &str) -> bool {
    host.parse::<IpAddr>().map_or_else(
        |_| host.eq_ignore_ascii_case("localhost"),
        |ip| ip.is_loopback(),
    )
}

/// The session's security for a connected peer: plaintext only when the
/// address the connection reached is loopback, whatever the host name
/// resolved from (T-8, T-32: `localhost` pointing elsewhere is refused).
fn session_security(security: Security, peer: IpAddr) -> Result<SessionSecurity, Error> {
    match security {
        Security::PlaintextLoopback if peer.is_loopback() => Ok(SessionSecurity::Plaintext {
            peer_is_loopback: true,
        }),
        Security::PlaintextLoopback => {
            Err(Error::new(ErrorKind::PlaintextRefused).at(Stage::Connect))
        }
        Security::StartTls => Ok(SessionSecurity::StartTlsRequired),
        Security::ImplicitTls => Ok(SessionSecurity::ImplicitTls),
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
/// let relay = Server::starttls("mail.example.com").login("no-reply@example.com", "app-password");
/// assert_eq!(relay.port(), 587);
/// assert!(Server::builder("mail.example.com", Security::PlaintextLoopback).build().is_err());
/// ```
#[derive(Clone)]
pub struct Server {
    host: String,
    port: u16,
    security: Security,
    client_name: Option<ClientName>,
    timeouts: Timeouts,
    pipelining: bool,
    chunking: bool,
    recipient_policy: RecipientPolicy,
    max_messages: u32,
    auth: Option<Auth>,
    tls: Option<Arc<dyn TlsConnector>>,
    insecure: bool,
    gate: Option<Arc<dyn SendGate>>,
    observer: Option<Arc<dyn Observer>>,
    #[cfg(feature = "dkim")]
    dkim: Vec<crate::DkimSigner>,
}

/// Most DKIM signers on one server (an RSA and an Ed25519 pair, twice
/// during a key rotation).
#[cfg(feature = "dkim")]
const MAX_DKIM_SIGNERS: usize = 4;

impl core::fmt::Debug for Server {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("Server");
        d.field("host", &self.host)
            .field("port", &self.port)
            .field("security", &self.security)
            .field("auth", &self.auth)
            .field("tls_connector", &self.tls.is_some())
            .field("insecure", &self.insecure)
            .field("gate", &self.gate.is_some())
            .field("observer", &self.observer.is_some());
        #[cfg(feature = "dkim")]
        d.field("dkim", &self.dkim);
        d.finish()
    }
}

impl Server {
    fn notify(&self, event: &ObservedEvent<'_>) {
        if let Some(o) = &self.observer {
            o.event(event);
        }
    }

    /// Tells the observer how a send ended.
    fn observe(&self, message: &PreparedMessage, result: &Result<Report, Error>) {
        if self.observer.is_none() {
            return;
        }
        match result {
            Ok(r) => self.notify(&ObservedEvent::Delivered {
                message_id: message.message_id().unwrap_or(""),
                accepted: r.accepted.len(),
                rejected: r.rejected.len(),
                elapsed: r.elapsed,
            }),
            Err(e) => {
                self.notify(&ObservedEvent::Failed {
                    stage: e.stage(),
                    disposition: e.disposition(),
                    possibly_delivered: e.possibly_delivered(),
                });
                if let Some(kind) = SecurityEventKind::of(e) {
                    self.notify(&ObservedEvent::SecurityEvent { kind });
                }
            }
        }
    }

    /// Serializes `message`, signed by the server's DKIM signers if it has any (O-23).
    fn prepare(&self, message: &Message) -> Result<PreparedMessage, Error> {
        #[cfg(feature = "dkim")]
        if !self.dkim.is_empty() {
            return message.prepare_signed(&self.dkim, now_unix_ms() / 1000);
        }
        message.prepare()
    }

    fn base(host: &str, security: Security) -> Server {
        Server {
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
            chunking: true,
            recipient_policy: RecipientPolicy::Any,
            max_messages: DEFAULT_MAX_MESSAGES,
            auth: None,
            tls: if security == Security::PlaintextLoopback {
                None
            } else {
                tls::default_connector()
            },
            insecure: false,
            gate: None,
            observer: None,
            #[cfg(feature = "dkim")]
            dkim: Vec::new(),
        }
    }

    /// The mail server on this machine: `127.0.0.1:25`, plaintext to a
    /// verified loopback peer, no AUTH, [`Timeouts::local`], and the local
    /// socket's address literal as the EHLO name (D-009, D-011).
    #[must_use]
    pub fn local() -> Server {
        Server::base("127.0.0.1", Security::PlaintextLoopback)
    }

    /// A relay with STARTTLS on port 587, certificate verification on, RFC
    /// 5321 timeouts. The TLS engine is tls-net's (feature `tls`, on by
    /// default); without the feature, set one with
    /// [`ServerBuilder::tls_connector`] (a server without one fails at
    /// connect with `Config(TlsConnectorMissing)`, nothing sent, D-025).
    #[must_use]
    pub fn starttls(host: &str) -> Server {
        Server::base(host, Security::StartTls)
    }

    /// A relay with implicit TLS on port 465 (RFC 8314); as [`Server::starttls`] otherwise.
    #[must_use]
    pub fn implicit_tls(host: &str) -> Server {
        Server::base(host, Security::ImplicitTls)
    }

    /// Sets a user name and password, with the default mechanism allowlist
    /// (`PLAIN`, then `LOGIN`).
    #[must_use]
    pub fn login(mut self, user: &str, password: impl Into<Secret>) -> Server {
        self.auth = Some(Auth::new(Credentials::password(user, password)));
        self
    }

    /// A builder for `host` with `security` (the port defaults to 25, 587, or
    /// 465 by security).
    pub fn builder(host: &str, security: Security) -> ServerBuilder {
        ServerBuilder {
            server: Server::base(host, security),
            credentials: None,
            mechanisms: None,
            insecure_remote: false,
        }
    }

    /// A builder starting from this server's settings.
    pub fn to_builder(&self) -> ServerBuilder {
        ServerBuilder {
            server: self.clone(),
            credentials: None,
            mechanisms: None,
            insecure_remote: false,
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
#[derive(Clone)]
pub struct ServerBuilder {
    server: Server,
    credentials: Option<Credentials>,
    mechanisms: Option<MechanismList>,
    insecure_remote: bool,
}

impl core::fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerBuilder")
            .field("server", &self.server)
            .finish()
    }
}

impl ServerBuilder {
    /// Overrides the default port.
    pub fn port(mut self, port: u16) -> Self {
        self.server.port = port;
        self
    }

    /// Credentials for AUTH (FR-34: sent only over TLS or to a verified loopback peer).
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// The mechanism allowlist, in order of preference (FR-35).
    ///
    /// # Errors
    ///
    /// `Config(TooManyMechanisms)` for an empty list or more than 8.
    pub fn mechanisms(mut self, list: &[crate::proto::MechanismName]) -> Result<Self, Error> {
        self.mechanisms = Some(MechanismList::new(list)?);
        Ok(self)
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

    /// The TLS engine for STARTTLS and implicit TLS.
    pub fn tls_connector(mut self, connector: impl TlsConnector + 'static) -> Self {
        self.server.tls = Some(Arc::new(connector));
        self
    }

    /// A tls-net client as the TLS engine: for example one that trusts only
    /// a private CA (`tls_net::client_with_ca_pem`).
    #[cfg(feature = "tls")]
    pub fn tls(self, client: tls_net::TlsClient) -> Self {
        self.tls_connector(client)
    }

    /// Turns certificate verification off. For test relays only: accepted
    /// for a loopback host; any other host also needs
    /// [`allow_insecure_remote(true)`](ServerBuilder::allow_insecure_remote)
    /// (D-024). The same rule holds in every build profile.
    pub fn dangerous_disable_certificate_verification(mut self) -> Self {
        self.server.insecure = true;
        self
    }

    /// The second, explicit flag for turning verification off for a remote host.
    pub fn allow_insecure_remote(mut self, allow: bool) -> Self {
        self.insecure_remote = allow;
        self
    }

    /// An observer for structured events (connections, TLS, reply codes,
    /// outcomes); it never sees secrets, bodies, or reply text.
    pub fn observer(mut self, observer: impl Observer + 'static) -> Self {
        self.server.observer = Some(Arc::new(observer));
        self
    }

    /// A pacing gate, asked before connecting and before each transaction.
    pub fn gate(mut self, gate: impl SendGate + 'static) -> Self {
        self.server.gate = Some(Arc::new(gate));
        self
    }

    /// Use PIPELINING when offered (default true).
    pub fn pipelining(mut self, use_it: bool) -> Self {
        self.server.pipelining = use_it;
        self
    }

    /// Use CHUNKING (BDAT) when offered (default true).
    pub fn chunking(mut self, use_it: bool) -> Self {
        self.server.chunking = use_it;
        self
    }

    /// The policy for refused recipients (default `Any`).
    pub fn recipient_policy(mut self, policy: RecipientPolicy) -> Self {
        self.server.recipient_policy = policy;
        self
    }

    /// A DKIM signer applied by [`send`] and [`Client::send`] to every
    /// message built here; repeat for several signatures (at most 4).
    /// [`send_prepared`] never signs: sign before storing the payload
    /// ([`Message::prepare_signed`]).
    #[cfg(feature = "dkim")]
    pub fn dkim(mut self, signer: crate::DkimSigner) -> Self {
        self.server.dkim.push(signer);
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
    /// `Config(TlsConnectorMissing)`, `Config(InsecureNotAllowed)`.
    pub fn build(self) -> Result<Server, Error> {
        let mut s = self.server;
        if s.port == 0 {
            return Err(ConfigError::PortZero.into());
        }
        if s.host.parse::<IpAddr>().is_err() && Domain::parse(&s.host).is_err() {
            return Err(ConfigError::InvalidHost.into());
        }
        let loopback = is_loopback_host(&s.host);
        match s.security {
            Security::PlaintextLoopback if !loopback => {
                return Err(ConfigError::PlaintextHostNotLoopback.into());
            }
            Security::StartTls | Security::ImplicitTls if s.tls.is_none() => {
                return Err(ConfigError::TlsConnectorMissing.into());
            }
            _ => {}
        }
        if s.insecure && !loopback && !self.insecure_remote {
            return Err(ConfigError::InsecureNotAllowed.into());
        }
        #[cfg(feature = "dkim")]
        if s.dkim.len() > MAX_DKIM_SIGNERS {
            return Err(ConfigError::TooManyDkimSigners.into());
        }
        if let Some(c) = self.credentials {
            s.auth = Some(Auth::new(c));
        }
        if let (Some(m), Some(a)) = (self.mechanisms, s.auth.as_mut()) {
            a.mechanisms = m;
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

    /// The reply to the end of the data (of the last transaction, when
    /// deferred recipients took several).
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

    /// Time from the start of the first transaction to the final reply.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn admit(server: &Server, message: &PreparedMessage) -> Result<(), Error> {
    let Some(gate) = &server.gate else {
        return Ok(());
    };
    let n = u32::try_from(message.envelope().recipients().len()).unwrap_or(u32::MAX);
    match gate.admit(n, now_unix_ms()) {
        Admission::RetryAfter(d) => Err(Error::new(ErrorKind::Throttled).with_retry_after(d)),
        _ => Ok(()),
    }
}

fn refund_on(server: &Server, message: &PreparedMessage, e: &Error) {
    if let Some(gate) = &server.gate {
        if !e.possibly_delivered() && !matches!(e.kind(), ErrorKind::Throttled) {
            let n = u32::try_from(message.envelope().recipients().len()).unwrap_or(u32::MAX);
            gate.refund(n, now_unix_ms());
        }
    }
}

/// Sends `message` to `server`: derives the envelope, serializes, asks the
/// server's gate, connects, sends, sends QUIT, and closes.
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
    send_prepared(server, &server.prepare(message)?)
}

/// Sends already prepared bytes (the job path): never re-serializes or
/// re-signs, so a retry sends the same bytes and `Message-ID`.
///
/// # Errors
///
/// As [`send`], without the build errors.
///
/// # Examples
///
/// ```no_run
/// # let payload: Vec<u8> = Vec::new();
/// let prepared = smtp_net::PreparedMessage::decode(&payload)?;
/// match smtp_net::send_prepared(&smtp_net::Server::local(), &prepared) {
///     Ok(_) => {}
///     Err(e) if e.is_temporary() => { /* retry later */ }
///     Err(e) => { /* dead-letter */ let _ = e; }
/// }
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub fn send_prepared(server: &Server, message: &PreparedMessage) -> Result<Report, Error> {
    admit(server, message)?;
    let result = (|| {
        let mut client = Client::connect(server)?;
        let report = client.deliver(message)?;
        // The message is accepted; a failed QUIT changes nothing.
        let _ = client.close();
        Ok(report)
    })();
    if let Err(e) = &result {
        refund_on(server, message, e);
    }
    server.observe(message, &result);
    result
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

/// The connection: TCP, and TLS once it is up.
struct Conn {
    tcp: TcpConnection,
    tls: Option<TlsLink>,
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
    conn: Option<Conn>,
    session: Session,
    epoch: Instant,
    buf: Vec<u8>,
    plain: Vec<u8>,
    sent: u32,
    last_used: Instant,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("host", &self.server.host)
            .field("port", &self.server.port)
            .field("state", &self.session.state())
            .field("secure", &self.session.is_secure())
            .field("sent", &self.sent)
            .finish()
    }
}

fn net_kind(e: NetError) -> io::ErrorKind {
    io::Error::from(e).kind()
}

impl Client {
    /// Resolves the host, connects within the connect timeout, checks the peer
    /// is loopback for plaintext, runs TLS when configured, authenticates when
    /// credentials are set, and drives the session to ready.
    ///
    /// # Errors
    ///
    /// `Connect`, `PlaintextRefused`, `Tls(..)`, `StartTlsUnavailable`,
    /// `StartTlsInjection`, `AuthUnavailable`, `AuthFailed`, `Timeout`,
    /// `Rejected`, `Protocol`, `Config`.
    pub fn connect(server: &Server) -> Result<Client, Error> {
        let (conn, session) = Client::open(server)?;
        let mut c = Client {
            server: server.clone(),
            conn: Some(conn),
            session,
            epoch: Instant::now(),
            buf: std::vec![0; READ_BUFFER],
            plain: Vec::with_capacity(READ_BUFFER),
            sent: 0,
            last_used: Instant::now(),
        };
        c.until_ready()?;
        Ok(c)
    }

    fn open(server: &Server) -> Result<(Conn, Session), Error> {
        let t = &server.timeouts;
        if matches!(server.security, Security::StartTls | Security::ImplicitTls)
            && server.tls.is_none()
        {
            return Err(ConfigError::TlsConnectorMissing.into());
        }
        // net-io's own deadlines stay above every stage timeout; the session's
        // per-stage deadline is applied as the exchange deadline.
        let longest = [
            t.greeting,
            t.command,
            t.tls_handshake,
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
        let tcp = TcpConnection::connect_host(&server.host, server.port, options)
            .map_err(|e| Error::new(ErrorKind::Connect(net_kind(e))).at(Stage::Connect))?;
        server.notify(&ObservedEvent::Connected {
            peer: tcp.peer_addr(),
        });
        let security = match session_security(server.security, tcp.peer_addr().ip()) {
            Ok(s) => s,
            Err(e) => {
                tcp.abort();
                return Err(e);
            }
        };
        let config = SessionConfig {
            security,
            auth: server.auth.clone(),
            client_name: server
                .client_name
                .clone()
                .unwrap_or(ClientName::AddressLiteral(tcp.local_addr().ip())),
            timeouts: server.timeouts,
            pipelining: server.pipelining,
            chunking: server.chunking,
            recipient_policy: server.recipient_policy,
            reply_events: server.observer.is_some(),
            ..SessionConfig::default()
        };
        let session = Session::new(config, Millis(0))?;
        Ok((Conn { tcp, tls: None }, session))
    }

    fn now(&self) -> Millis {
        Millis(u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    fn instant(&self, at: Millis) -> Instant {
        self.epoch + Duration::from_millis(at.0)
    }

    /// Writes all pending output.
    fn flush(&mut self) -> Result<(), Error> {
        let pending = self.session.transmit().len();
        if pending == 0 {
            return Ok(());
        }
        let Some(conn) = self.conn.as_mut() else {
            return Err(Error::new(ErrorKind::ConnectionClosed));
        };
        let result = match conn.tls.as_mut() {
            Some(tls) => tls.write(&mut conn.tcp, self.session.transmit()),
            None => conn.tcp.send_all(self.session.transmit()),
        };
        match result {
            Ok(()) => {
                self.session.transmitted(pending);
                Ok(())
            }
            Err(NetError::TimedOut { .. }) => Err(self.lost(ErrorKind::Timeout)),
            Err(e) => Err(self.lost(ErrorKind::Io(net_kind(e)))),
        }
    }

    fn lost(&mut self, kind: ErrorKind) -> Error {
        self.drop_conn();
        self.session.connection_lost(kind)
    }

    fn drop_conn(&mut self) {
        if let Some(c) = self.conn.take() {
            c.tcp.abort();
        }
    }

    /// Reads once and feeds the session.
    fn read(&mut self) -> Result<(), Error> {
        let deadline = self.session.deadline().map(|d| self.instant(d));
        let Some(conn) = self.conn.as_mut() else {
            return Err(Error::new(ErrorKind::ConnectionClosed));
        };
        conn.tcp.set_exchange_deadline(deadline);
        self.plain.clear();
        let got = match conn.tls.as_mut() {
            Some(tls) => match tls.read(&mut conn.tcp, &mut self.plain) {
                Ok(Read::Data) => Ok(true),
                Ok(Read::Closed) => Ok(false),
                Err(e) if matches!(e.kind(), ErrorKind::Timeout) => Err(NetError::TimedOut {
                    kind: net_io::TimeoutKind::Exchange,
                }),
                Err(e) => {
                    let kind = e.kind().clone();
                    return Err(self.lost(kind));
                }
            },
            None => match conn.tcp.recv(&mut self.buf) {
                Ok(0) => Ok(false),
                Ok(n) => {
                    self.plain
                        .extend_from_slice(self.buf.get(..n).unwrap_or(&[]));
                    Ok(true)
                }
                Err(e) => Err(e),
            },
        };
        match got {
            Ok(false) => Err(self.lost(ErrorKind::ConnectionClosed)),
            Ok(true) => {
                let now = self.now();
                match self.session.receive(&self.plain, now) {
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

    /// Runs the TLS handshake (after STARTTLS, or at the start for implicit TLS).
    fn start_tls(&mut self) -> Result<(), Error> {
        let Some(connector) = self.server.tls.clone() else {
            return Err(self.lost(ErrorKind::Config(ConfigError::TlsConnectorMissing)));
        };
        let session = match connector.session(&self.server.host, self.server.insecure) {
            Ok(s) => s,
            Err(e) => {
                let err = self.lost(ErrorKind::Tls(e.kind));
                return Err(err.with_disposition(Disposition::Permanent));
            }
        };
        let deadline = Instant::now() + self.server.timeouts.tls_handshake;
        let Some(conn) = self.conn.as_mut() else {
            return Err(Error::new(ErrorKind::ConnectionClosed));
        };
        let mut link = TlsLink::new(session);
        let mut early = Vec::new();
        match link.handshake(&mut conn.tcp, deadline, &mut early) {
            Ok(info) => {
                conn.tls = Some(link);
                self.server.notify(&ObservedEvent::Secure {
                    protocol: info.protocol,
                });
                let now = self.now();
                self.session.tls_established(info, now)?;
                if !early.is_empty() {
                    self.session.receive(&early, now)?;
                }
                Ok(())
            }
            Err(e) => {
                let kind = e.kind().clone();
                let permanent = e.is_permanent();
                let err = self.lost(kind).at(Stage::TlsHandshake);
                Err(if permanent {
                    err.with_disposition(Disposition::Permanent)
                } else {
                    err
                })
            }
        }
    }

    /// The next session event; reply events go to the observer.
    fn poll(&mut self) -> Option<Event> {
        loop {
            match self.session.poll_event()? {
                Event::Reply {
                    stage,
                    code,
                    enhanced,
                } => self.server.notify(&ObservedEvent::Reply {
                    stage,
                    code,
                    enhanced,
                }),
                other => return Some(other),
            }
        }
    }

    fn until_ready(&mut self) -> Result<(), Error> {
        if self.session.state() == SessionState::NeedTls {
            self.start_tls()?;
        }
        loop {
            self.flush()?;
            while let Some(event) = self.poll() {
                match event {
                    Event::Ready { .. } => return Ok(()),
                    Event::Closed { error } => {
                        self.drop_conn();
                        return Err(
                            error.unwrap_or_else(|| Error::new(ErrorKind::ConnectionClosed))
                        );
                    }
                    Event::StartTls => self.start_tls()?,
                    _ => {}
                }
            }
            if self.session.state() == SessionState::Ready {
                return Ok(());
            }
            // The handshake may have queued EHLO: write it before reading.
            self.flush()?;
            self.read()?;
        }
    }

    /// Sends a built message on this connection.
    ///
    /// # Errors
    ///
    /// Every send error; see [`send`].
    pub fn send(&mut self, message: &Message) -> Result<Report, Error> {
        let prepared = self.server.prepare(message)?;
        self.send_prepared(&prepared)
    }

    /// Sends prepared bytes as they are, after asking the server's gate.
    /// Reconnects first when the connection was idle too long or carried its
    /// message limit, and once more when the server had closed an idle
    /// connection before accepting anything. Recipients the server defers
    /// as too many for one transaction go in further transactions.
    ///
    /// # Errors
    ///
    /// Every send error; see [`send`].
    pub fn send_prepared(&mut self, message: &PreparedMessage) -> Result<Report, Error> {
        admit(&self.server, message)?;
        let result = self.deliver(message);
        if let Err(e) = &result {
            refund_on(&self.server, message, e);
        }
        self.server.observe(message, &result);
        result
    }

    fn deliver(&mut self, message: &PreparedMessage) -> Result<Report, Error> {
        let reused = self.sent > 0;
        if !self.is_open()
            || self.last_used.elapsed() > self.server.timeouts.idle
            || self.sent >= self.server.max_messages
        {
            self.reconnect()?;
        }
        let start = Instant::now();
        let envelope = message.envelope().clone();
        let first = match self.transaction(message, &envelope) {
            Err(e)
                if reused
                    && e.is_temporary()
                    && !e.possibly_delivered()
                    && e.recipients().is_empty()
                    && Client::nothing_accepted(&e) =>
            {
                self.reconnect()?;
                self.transaction(message, &envelope)
            }
            other => other,
        };
        let (mut report, mut deferred) = first?;
        let mut rounds = 0;
        while !deferred.is_empty() && rounds < MAX_DEFERRAL_ROUNDS {
            rounds += 1;
            let subset = envelope.subset(&deferred);
            let (next, more) = self.transaction(message, &subset)?;
            if next.accepted.is_empty() {
                break;
            }
            report.accepted.extend(next.accepted);
            report.rejected.extend(next.rejected);
            report.final_reply = next.final_reply;
            deferred = more
                .into_iter()
                .filter_map(|i| subset.recipients().get(i))
                .filter_map(|a| envelope.recipients().iter().position(|b| b == a))
                .collect();
        }
        if !deferred.is_empty() {
            // Recipients still deferred: reported as temporary refusals.
            for i in deferred {
                if let Some(a) = envelope.recipients().get(i) {
                    report
                        .rejected
                        .push((a.clone(), Reply::too_many(), Disposition::Temporary));
                }
            }
        }
        report.elapsed = start.elapsed();
        Ok(report)
    }

    /// True when the failure happened before the server accepted any part of
    /// the transaction (an idle connection closed under us).
    fn nothing_accepted(e: &Error) -> bool {
        matches!(e.stage(), Some(Stage::Mail))
            && matches!(
                e.kind(),
                ErrorKind::ConnectionClosed
                    | ErrorKind::Io(_)
                    | ErrorKind::Rejected
                    | ErrorKind::Tls(_)
            )
            && e.reply().is_none_or(|r| r.code().get() == 421)
    }

    fn reconnect(&mut self) -> Result<(), Error> {
        if let Some(mut c) = self.conn.take() {
            let now = self.now();
            if self.session.quit(now).is_ok() {
                let out = self.session.transmit().to_vec();
                match c.tls.as_mut() {
                    Some(tls) => {
                        let _ = tls.write(&mut c.tcp, &out);
                        tls.close(&mut c.tcp);
                    }
                    None => {
                        let _ = c.tcp.send_all(&out);
                    }
                }
            }
            c.tcp.abort();
        }
        let (conn, session) = Client::open(&self.server)?;
        self.conn = Some(conn);
        self.session = session;
        self.epoch = Instant::now();
        self.sent = 0;
        self.until_ready()
    }

    /// One transaction; the deferred recipients' indices in `envelope` come back with the report.
    fn transaction(
        &mut self,
        message: &PreparedMessage,
        envelope: &crate::message::prepared::Envelope,
    ) -> Result<(Report, Vec<usize>), Error> {
        let start = Instant::now();
        let flags = BodyFlags::new(message.has_8bit(), message.needs_smtputf8());
        let now = self.now();
        self.session
            .begin(envelope, flags, message.bytes().len() as u64, now)?;
        let mut accepted: Vec<Address> = Vec::new();
        let mut rejected = Vec::new();
        let mut deferred = Vec::new();
        let mut body = message.bytes();
        let mut in_body = false;
        let mut delivered: Option<Reply> = None;
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
            while let Some(event) = self.poll() {
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
                    Event::Delivered { reply, .. } => delivered = Some(reply),
                    Event::Deferred { recipients } => deferred = recipients,
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
            if let Some(reply) = delivered.take() {
                self.sent += 1;
                self.last_used = Instant::now();
                let report = Report {
                    message_id: String::from(message.message_id().unwrap_or("")),
                    accepted,
                    rejected,
                    final_reply: reply,
                    secure: self.session.is_secure(),
                    tls_protocol: self.session.tls_protocol(),
                    elapsed: start.elapsed(),
                };
                return Ok((report, deferred));
            }
            if !in_body && self.session.wants_read() {
                self.read()?;
            }
        }
    }

    /// Sends NOOP and waits for the reply (a liveness probe).
    ///
    /// # Errors
    ///
    /// `Timeout`, `Rejected`, `Usage` when the connection is not ready.
    pub fn noop(&mut self) -> Result<(), Error> {
        let now = self.now();
        self.session.noop(now)?;
        self.flush()?;
        while self.session.wants_read() {
            self.read()?;
        }
        while let Some(e) = self.poll() {
            if let Event::Closed { error: Some(e) } = e {
                return Err(e);
            }
        }
        Ok(())
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
            conn.tcp.set_exchange_deadline(Some(Instant::now() + b));
            if let Ok(l) = Limits::builder()
                .write_timeout(b)
                .read_timeout(b)
                .min_rate(MinRate::off())
                .build()
            {
                conn.tcp.set_limits(l);
            }
        }
        let result = (|| -> Result<(), Error> {
            self.flush()?;
            while self.session.wants_read() {
                self.read()?;
            }
            Ok(())
        })();
        if let Some(mut c) = self.conn.take() {
            if let Some(tls) = c.tls.as_mut() {
                tls.close(&mut c.tcp);
            }
            let _ = c.tcp.close();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plaintext_needs_a_loopback_peer_whatever_the_name() {
        // T-8, T-32: a host name such as `localhost` that resolved to a
        // remote address reaches a non-loopback peer, and is refused there.
        for peer in ["192.0.2.1", "2001:db8::1", "10.0.0.1"] {
            let e =
                session_security(Security::PlaintextLoopback, peer.parse().unwrap()).unwrap_err();
            assert!(matches!(e.kind(), ErrorKind::PlaintextRefused), "{peer}");
            assert_eq!(e.stage(), Some(Stage::Connect));
        }
        for peer in ["127.0.0.1", "127.8.9.10", "::1"] {
            assert_eq!(
                session_security(Security::PlaintextLoopback, peer.parse().unwrap()).unwrap(),
                SessionSecurity::Plaintext {
                    peer_is_loopback: true
                }
            );
        }
        // TLS is verified by certificate, not by address.
        let remote = "192.0.2.1".parse().unwrap();
        assert!(session_security(Security::StartTls, remote).is_ok());
        assert!(session_security(Security::ImplicitTls, remote).is_ok());
    }
}
