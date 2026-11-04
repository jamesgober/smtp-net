//! The TLS seam (D-026): smtp-net drives any engine that implements net-io's
//! sans-IO `TlsSession`, the same seam tls-net implements for servers.

use std::{boxed::Box, time::Instant, vec, vec::Vec};

use net_io::{NetError, TcpConnection, TlsError, TlsEvent, TlsSession};

use crate::{
    error::{Error, ErrorKind, Stage, TlsFailure},
    proto::{TlsInfo, TlsProtocol},
};

/// Builds client TLS sessions for STARTTLS and implicit TLS.
///
/// # Examples
///
/// ```
/// use smtp_net::{TlsConnector, TlsSetupError};
/// struct Refuse;
/// impl TlsConnector for Refuse {
///     fn session(&self, _: &str, _: bool) -> Result<Box<dyn net_io::TlsSession>, TlsSetupError> {
///         Err(TlsSetupError::new(smtp_net::TlsFailure::Setup))
///     }
/// }
/// let server = smtp_net::Server::builder("localhost", smtp_net::Security::StartTls)
///     .tls_connector(Refuse)
///     .build()?;
/// # let _ = server;
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub trait TlsConnector: Send + Sync {
    /// A new client session for `server_name` (the configured host, never
    /// the EHLO greeting). The engine verifies the server's certificate
    /// against that name unless `insecure` is set; smtp-net sets it only when
    /// the configuration allowed it (D-024).
    ///
    /// # Errors
    ///
    /// [`TlsSetupError`] when no session can be built.
    fn session(
        &self,
        server_name: &str,
        insecure: bool,
    ) -> Result<Box<dyn TlsSession>, TlsSetupError>;
}

/// A connector could not build a session.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsSetupError {
    /// Why.
    pub kind: TlsFailure,
}

impl TlsSetupError {
    /// An error of `kind`.
    #[must_use]
    pub const fn new(kind: TlsFailure) -> TlsSetupError {
        TlsSetupError { kind }
    }
}

impl From<TlsSetupError> for Error {
    fn from(e: TlsSetupError) -> Error {
        Error::new(ErrorKind::Tls(e.kind)).at(Stage::TlsHandshake)
    }
}

/// tls-net's client is a connector: verification is always on, against the
/// configured host name. tls-net has no way to turn verification off, so an
/// `insecure` request is refused here; trust a test relay's own CA with
/// `tls_net::client_with_ca_pem` instead.
#[cfg(feature = "tls")]
impl TlsConnector for tls_net::TlsClient {
    fn session(
        &self,
        server_name: &str,
        insecure: bool,
    ) -> Result<Box<dyn TlsSession>, TlsSetupError> {
        if insecure {
            return Err(TlsSetupError::new(TlsFailure::Setup));
        }
        match self.connect(server_name) {
            Ok(s) => Ok(Box::new(TlsNetSession(s))),
            Err(_) => Err(TlsSetupError::new(TlsFailure::Setup)),
        }
    }
}

/// A tls-net client session with its error codes classified for SMTP:
/// tls-net names the cause by code (its `docs/API.md` error table), and the
/// classification needs to know which ones are certificate problems.
#[cfg(feature = "tls")]
struct TlsNetSession(tls_net::ClientSession);

#[cfg(feature = "tls")]
impl TlsNetSession {
    fn classify(e: TlsError) -> TlsError {
        match e.code {
            // No common version or suite; certificate invalid, required,
            // revoked; pin mismatch: retrying the same server cannot pass.
            35 | 37 | 38 | 39 | 40 => TlsError::new(e.kind, e.code, Some(e.alert.unwrap_or(42))),
            // The peer did not answer TLS.
            31 => TlsError::new(net_io::TlsFailure::Protocol, e.code, e.alert),
            _ => e,
        }
    }
}

#[cfg(feature = "tls")]
impl TlsSession for TlsNetSession {
    fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<net_io::TlsProgress<'i>, TlsError> {
        TlsSession::step(&mut self.0, input, output).map_err(TlsNetSession::classify)
    }

    fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError> {
        TlsSession::encrypt(&mut self.0, plaintext, output)
    }

    fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        TlsSession::close(&mut self.0, output)
    }

    fn on_transport_closed(&mut self) -> net_io::TlsCloseKind {
        TlsSession::on_transport_closed(&mut self.0)
    }

    fn info(&self) -> Option<net_io::TlsInfo> {
        TlsSession::info(&self.0)
    }

    fn input_capacity_required(&self) -> usize {
        TlsSession::input_capacity_required(&self.0)
    }
}

/// The engine `Server::starttls` and `Server::implicit_tls` use: one shared
/// tls-net client with the Mozilla roots, so sessions can be resumed.
#[cfg(feature = "tls")]
pub(crate) fn default_connector() -> Option<std::sync::Arc<dyn TlsConnector>> {
    static CLIENT: std::sync::OnceLock<Option<tls_net::TlsClient>> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| tls_net::client().ok())
        .clone()
        .map(|c| std::sync::Arc::new(c) as std::sync::Arc<dyn TlsConnector>)
}

#[cfg(not(feature = "tls"))]
pub(crate) fn default_connector() -> Option<std::sync::Arc<dyn TlsConnector>> {
    None
}

/// TLS alerts that mean the certificate or the version was refused.
const CERTIFICATE_ALERTS: [u8; 9] = [42, 43, 44, 45, 46, 48, 49, 70, 112];

/// Classifies an engine error (PLAN 7.7).
pub(crate) fn failure_of(e: TlsError) -> TlsFailure {
    match (e.kind, e.alert) {
        (_, Some(a)) if CERTIFICATE_ALERTS.contains(&a) => TlsFailure::CertificateRejected,
        (net_io::TlsFailure::Protocol, _) => TlsFailure::ProtocolMismatch,
        (net_io::TlsFailure::HelloRefused, _) => TlsFailure::CertificateRejected,
        (net_io::TlsFailure::Capacity | net_io::TlsFailure::State, _) => TlsFailure::Setup,
        _ => TlsFailure::Handshake,
    }
}

/// Largest plaintext encrypted per call (one TLS record carries 16 KiB).
const PLAIN_CHUNK: usize = 8 * 1024;
/// Output room for engine records: above one full TLS record with its
/// overhead (18,437 octets, the least rustls accepts), with headroom.
const RECORD_ROOM: usize = 32 * 1024;

/// A TLS session over a TCP connection: the ciphertext buffers around the
/// engine.
pub(crate) struct TlsLink {
    session: Box<dyn TlsSession>,
    input: Vec<u8>,
    filled: usize,
    output: Vec<u8>,
    closed: bool,
}

/// The outcome of one read.
pub(crate) enum Read {
    /// Plaintext was appended (possibly none, after a record that carried only TLS data).
    Data,
    /// The peer closed the TLS stream or the connection.
    Closed,
}

impl TlsLink {
    pub(crate) fn new(session: Box<dyn TlsSession>) -> TlsLink {
        let need = session.input_capacity_required().max(18_437);
        TlsLink {
            session,
            input: vec![0; need],
            filled: 0,
            output: vec![0; RECORD_ROOM],
            closed: false,
        }
    }

    fn io(_e: NetError) -> Error {
        Error::new(ErrorKind::Tls(TlsFailure::Handshake))
            .at(Stage::TlsHandshake)
            .with_disposition(crate::Disposition::Temporary)
    }

    /// Runs the handshake until it completes; plaintext that arrives with
    /// the last flight is appended to `early`.
    pub(crate) fn handshake(
        &mut self,
        conn: &mut TcpConnection,
        deadline: Instant,
        early: &mut Vec<u8>,
    ) -> Result<TlsInfo, Error> {
        conn.set_exchange_deadline(Some(deadline));
        let mut done = false;
        loop {
            let progress = self.step(conn, early, &mut done)?;
            if done {
                let version = self.session.info().map_or(0, |i| i.version());
                return Ok(TlsInfo::new(TlsProtocol::from_wire(version)));
            }
            match progress {
                Step::NeedInput => {
                    if !self.fill(conn)? {
                        return Err(Error::new(ErrorKind::Tls(TlsFailure::ProtocolMismatch))
                            .at(Stage::TlsHandshake));
                    }
                }
                Step::Closed => {
                    return Err(
                        Error::new(ErrorKind::Tls(TlsFailure::Closed)).at(Stage::TlsHandshake)
                    );
                }
                Step::Again => {}
            }
        }
    }

    /// Reads once and decrypts what arrived into `plain`.
    pub(crate) fn read(
        &mut self,
        conn: &mut TcpConnection,
        plain: &mut Vec<u8>,
    ) -> Result<Read, Error> {
        let mut done = true;
        // Records already buffered first.
        loop {
            match self.step(conn, plain, &mut done)? {
                Step::Again => {}
                Step::Closed => return Ok(Read::Closed),
                Step::NeedInput => break,
            }
        }
        if !plain.is_empty() {
            return Ok(Read::Data);
        }
        if !self.fill(conn)? {
            self.closed = true;
            return Ok(Read::Closed);
        }
        loop {
            match self.step(conn, plain, &mut done)? {
                Step::Again => {}
                Step::Closed => return Ok(Read::Closed),
                Step::NeedInput => return Ok(Read::Data),
            }
        }
    }

    /// Encrypts and sends all of `plain`.
    pub(crate) fn write(&mut self, conn: &mut TcpConnection, plain: &[u8]) -> Result<(), NetError> {
        for chunk in plain.chunks(PLAIN_CHUNK) {
            let n = self
                .session
                .encrypt(chunk, &mut self.output)
                .map_err(|_| NetError::Closed)?;
            conn.send_all(self.output.get(..n).unwrap_or(&[]))?;
        }
        Ok(())
    }

    /// Sends close_notify (best effort).
    pub(crate) fn close(&mut self, conn: &mut TcpConnection) {
        if let Ok(n) = self.session.close(&mut self.output) {
            let _ = conn.send_all(self.output.get(..n).unwrap_or(&[]));
        }
    }

    fn fill(&mut self, conn: &mut TcpConnection) -> Result<bool, Error> {
        let need = self.session.input_capacity_required().max(self.filled + 1);
        if self.input.len() < need {
            self.input.resize(need, 0);
        }
        if self.filled == self.input.len() {
            self.input.resize(self.input.len() * 2, 0);
        }
        let room = self.input.get_mut(self.filled..).unwrap_or(&mut []);
        match conn.recv(room) {
            Ok(0) => Ok(false),
            Ok(n) => {
                self.filled += n;
                Ok(true)
            }
            Err(NetError::TimedOut { .. }) => {
                Err(Error::new(ErrorKind::Timeout).at(Stage::TlsHandshake))
            }
            Err(e) => Err(Self::io(e)),
        }
    }

    fn step(
        &mut self,
        conn: &mut TcpConnection,
        plain: &mut Vec<u8>,
        done: &mut bool,
    ) -> Result<Step, Error> {
        if self.closed {
            return Ok(Step::Closed);
        }
        let filled = self.filled;
        let input = self.input.get_mut(..filled).unwrap_or(&mut []);
        let progress = self
            .session
            .step(input, &mut self.output)
            .map_err(|e| Error::new(ErrorKind::Tls(failure_of(e))).at(Stage::TlsHandshake))?;
        let (consumed, written) = (progress.consumed, progress.written);
        let mut acted = consumed > 0 || written > 0;
        let step = match progress.event {
            // A step that consumed or wrote something is called again before
            // reading: more records may already be buffered.
            TlsEvent::NeedInput if acted => Step::Again,
            TlsEvent::NeedInput => Step::NeedInput,
            TlsEvent::HandshakeComplete => {
                *done = true;
                acted = true;
                Step::Again
            }
            TlsEvent::Data(d) => {
                plain.extend_from_slice(d);
                acted = true;
                Step::Again
            }
            TlsEvent::PeerClosed | TlsEvent::Closed => {
                self.closed = true;
                Step::Closed
            }
            TlsEvent::OutputFull if !acted => {
                // The engine cannot write a record into the room it has: no
                // read could fix that.
                return Err(Error::new(ErrorKind::Tls(TlsFailure::Setup)).at(Stage::TlsHandshake));
            }
            _ => Step::Again,
        };
        if written > 0 {
            conn.send_all(self.output.get(..written).unwrap_or(&[]))
                .map_err(Self::io)?;
        }
        let consumed = consumed.min(filled);
        self.input.copy_within(consumed..filled, 0);
        self.filled = filled - consumed;
        if !acted && matches!(step, Step::Again) {
            // No progress and no event the caller can act on: wait for input.
            return Ok(Step::NeedInput);
        }
        Ok(step)
    }
}

enum Step {
    NeedInput,
    Again,
    Closed,
}
