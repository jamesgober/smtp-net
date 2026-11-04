//! Test support (feature `testing`): a scripted sans-IO peer driven by
//! conversation transcripts, and a blocking loopback SMTP server with fault
//! injection.

use std::{
    boxed::Box,
    format,
    io::{Read as _, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    string::{String, ToString},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
    vec::Vec,
};

use net_io::{
    TlsCloseKind, TlsError, TlsEvent, TlsFailure as NetTlsFailure, TlsInfo as NetTlsInfo,
    TlsProgress, TlsSession,
};

use crate::{
    client::{Security, Server, ServerBuilder, TlsConnector, TlsSetupError},
    error::{Error, ErrorKind, Stage},
    message::prepared::PreparedMessage,
    proto::Credentials,
    proto::{BodyFlags, Event, Millis, Session, TlsInfo, TlsProtocol},
};

// ---------------------------------------------------------------------------
// Transcripts and the scripted sans-IO server
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    /// A line the client must send (without CRLF).
    Client(String),
    /// Any client lines up to and including the end-of-data `.` line.
    ClientBody,
    /// Exactly this many client octets (a BDAT chunk).
    ClientRaw(usize),
    /// Bytes the server sends (with CRLF).
    Server(Vec<u8>),
    /// The server closes the connection.
    Eof,
    /// Time passes beyond every deadline.
    Timeout,
}

/// A conversation as data: `C: ` lines the client must send, `S: ` lines the
/// server answers with. `C: <BODY>` stands for the message body through the
/// end-of-data line; `C: <EMPTY>` for an empty line (an empty AUTH
/// response); `C: <RAW n>` for exactly `n` octets (a BDAT chunk); `S: <EOF>` closes the connection; `S: <TIMEOUT>` lets
/// every deadline pass. Lines starting with `#` and blank lines are ignored.
///
/// # Examples
///
/// ```
/// let t = smtp_net::Transcript::parse("S: 220 ready\nC: EHLO [127.0.0.1]\nS: 250 ok\n")?;
/// assert_eq!(t.len(), 3);
/// # Ok::<(), smtp_net::ScriptMismatch>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    entries: Vec<(usize, Entry)>,
}

impl Transcript {
    /// Parses transcript text.
    ///
    /// # Errors
    ///
    /// [`ScriptMismatch`] naming the first line that is not `C: `, `S: `, a
    /// comment, or blank.
    pub fn parse(text: &str) -> Result<Transcript, ScriptMismatch> {
        let mut entries = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let entry = if let Some(c) = line.strip_prefix("C: ") {
                if c == "<EMPTY>" {
                    Entry::Client(String::new())
                } else if c == "<BODY>" {
                    Entry::ClientBody
                } else if let Some(count) =
                    c.strip_prefix("<RAW ").and_then(|r| r.strip_suffix('>'))
                {
                    let count = count.parse().map_err(|_| ScriptMismatch {
                        line: n + 1,
                        expected: "<RAW n>".into(),
                        got: c.to_string(),
                    })?;
                    Entry::ClientRaw(count)
                } else {
                    Entry::Client(c.to_string())
                }
            } else if let Some(s) = line.strip_prefix("S: ") {
                match s {
                    "<EOF>" => Entry::Eof,
                    "<TIMEOUT>" => Entry::Timeout,
                    _ => {
                        let mut b = s.as_bytes().to_vec();
                        b.extend_from_slice(b"\r\n");
                        Entry::Server(b)
                    }
                }
            } else {
                return Err(ScriptMismatch {
                    line: n + 1,
                    expected: "C: or S:".into(),
                    got: line.to_string(),
                });
            };
            entries.push((n + 1, entry));
        }
        Ok(Transcript { entries })
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Where a scripted conversation and the session disagreed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptMismatch {
    /// One-based transcript line.
    pub line: usize,
    /// What the transcript expected.
    pub expected: String,
    /// What the session did.
    pub got: String,
}

impl core::fmt::Display for ScriptMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "transcript line {}: expected {:?}, got {:?}",
            self.line, self.expected, self.got
        )
    }
}

impl std::error::Error for ScriptMismatch {}

/// What a scripted conversation produced.
#[derive(Clone, Debug, Default)]
pub struct ScriptOutcome {
    /// One result per message, in order (messages not reached are absent).
    pub messages: Vec<Result<(), Error>>,
    /// The error the session closed with, if any.
    pub closed: Option<Error>,
}

/// A sans-IO peer that plays a [`Transcript`] against a [`Session`], acting
/// as a simple driver: it begins each message when the session is ready,
/// writes the body when asked, simulates the TLS handshake on STARTTLS, and
/// sends QUIT after the last message.
#[derive(Clone, Debug)]
pub struct ScriptedServer {
    transcript: Transcript,
}

impl ScriptedServer {
    /// A server for `transcript`.
    #[must_use]
    pub fn new(transcript: Transcript) -> ScriptedServer {
        ScriptedServer { transcript }
    }

    /// Runs the whole conversation, passing server bytes in one piece.
    ///
    /// # Errors
    ///
    /// [`ScriptMismatch`] at the first difference.
    pub fn run(
        &self,
        session: &mut Session,
        messages: &[PreparedMessage],
    ) -> Result<ScriptOutcome, ScriptMismatch> {
        self.run_split(session, messages, usize::MAX)
    }

    /// Runs the conversation passing server bytes, and acknowledging client
    /// bytes, in pieces of at most `split` octets.
    ///
    /// # Errors
    ///
    /// [`ScriptMismatch`] at the first difference.
    pub fn run_split(
        &self,
        session: &mut Session,
        messages: &[PreparedMessage],
        split: usize,
    ) -> Result<ScriptOutcome, ScriptMismatch> {
        let mut d = Driver {
            session,
            messages,
            next: 0,
            in_body: None,
            outcome: ScriptOutcome::default(),
            sent: Vec::new(),
            now: 1,
            split: split.max(1),
            tls_pending: false,
            in_group: false,
            begin_due: false,
        };
        if d.session.state() == crate::proto::SessionState::NeedTls {
            let _ = d
                .session
                .tls_established(TlsInfo::new(TlsProtocol::Tls13), Millis(d.now));
        }
        d.pump();
        let entries = &self.transcript.entries;
        let mut i = 0;
        while let Some((line, entry)) = entries.get(i) {
            match entry {
                Entry::Server(_) => {
                    let mut group = Vec::new();
                    while let Some((_, Entry::Server(b))) = entries.get(i) {
                        group.extend_from_slice(b);
                        i += 1;
                    }
                    d.feed(&group);
                    continue;
                }
                Entry::Eof => {
                    // The session reports the classified error as `Event::Closed`.
                    let _ = d.session.connection_lost(ErrorKind::ConnectionClosed);
                    d.pump();
                }
                Entry::Timeout => {
                    d.now = u64::MAX / 2;
                    if let Err(e) = d.session.on_timeout(Millis(d.now)) {
                        d.note_close(e);
                    }
                    d.pump();
                }
                Entry::Client(want) => {
                    let got = d.take_line();
                    if got.as_deref() != Some(want.as_str()) {
                        return Err(ScriptMismatch {
                            line: *line,
                            expected: want.clone(),
                            got: got.unwrap_or_else(|| "(nothing)".into()),
                        });
                    }
                }
                Entry::ClientRaw(n) => {
                    if d.sent.len() < *n {
                        return Err(ScriptMismatch {
                            line: *line,
                            expected: format!("{n} raw octets"),
                            got: format!("{} octets", d.sent.len()),
                        });
                    }
                    d.sent.drain(..*n);
                }
                Entry::ClientBody => loop {
                    match d.take_line() {
                        Some(l) if l == "." => break,
                        Some(_) => {}
                        None => {
                            return Err(ScriptMismatch {
                                line: *line,
                                expected: "body through \".\"".into(),
                                got: "(nothing)".into(),
                            });
                        }
                    }
                },
            }
            i += 1;
        }
        if !d.sent.is_empty() {
            return Err(ScriptMismatch {
                line: 0,
                expected: "(end of transcript)".into(),
                got: String::from_utf8_lossy(&d.sent).into_owned(),
            });
        }
        Ok(d.outcome)
    }
}

struct Driver<'a> {
    session: &'a mut Session,
    messages: &'a [PreparedMessage],
    next: usize,
    in_body: Option<usize>,
    outcome: ScriptOutcome,
    sent: Vec<u8>,
    now: u64,
    split: usize,
    /// STARTTLS was accepted: the handshake runs once the server's current burst is in.
    tls_pending: bool,
    /// Feeding a server burst: new transactions wait until it is all in.
    in_group: bool,
    begin_due: bool,
}

impl Driver<'_> {
    fn note_close(&mut self, e: Error) {
        if self.outcome.closed.is_none() {
            self.outcome.closed = Some(e);
        }
    }

    fn schedule_begin(&mut self) {
        if self.in_group {
            self.begin_due = true;
        } else {
            self.begin_next();
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        self.in_group = true;
        self.feed_group(bytes);
        self.in_group = false;
        if self.begin_due {
            self.begin_due = false;
            self.begin_next();
            self.pump();
        }
    }

    fn feed_group(&mut self, bytes: &[u8]) {
        let mut rest = bytes;
        while !rest.is_empty() {
            let take = rest.len().min(self.split);
            let piece = rest.get(..take).unwrap_or(&[]);
            self.now += 1;
            match self.session.receive(piece, Millis(self.now)) {
                Ok(n) if n < piece.len() => {
                    // Stopped after the STARTTLS 220: the rest goes in again
                    // (and is refused as an injection).
                    rest = rest.get(n..).unwrap_or(&[]);
                    self.pump();
                    continue;
                }
                Ok(_) => {}
                Err(e) => {
                    self.tls_pending = false;
                    self.note_close(e);
                    self.pump();
                    return;
                }
            }
            rest = rest.get(take..).unwrap_or(&[]);
            self.pump();
        }
        if self.tls_pending {
            self.tls_pending = false;
            let _ = self
                .session
                .tls_established(TlsInfo::new(TlsProtocol::Tls13), Millis(self.now));
            self.pump();
        }
    }

    fn collect(&mut self) {
        while !self.session.transmit().is_empty() {
            let n = self.session.transmit().len().min(self.split);
            self.sent
                .extend_from_slice(self.session.transmit().get(..n).unwrap_or(&[]));
            self.session.transmitted(n);
        }
    }

    fn begin_next(&mut self) {
        if self.session.state() != crate::proto::SessionState::Ready {
            return;
        }
        let now = Millis(self.now);
        if let Some(m) = self.messages.get(self.next) {
            let flags = BodyFlags::new(m.has_8bit(), m.needs_smtputf8());
            match self
                .session
                .begin(m.envelope(), flags, m.bytes().len() as u64, now)
            {
                Ok(()) => {}
                Err(e) => {
                    self.outcome.messages.push(Err(e));
                    self.next += 1;
                    self.begin_next();
                }
            }
        } else {
            let _ = self.session.quit(now);
        }
    }

    fn pump(&mut self) {
        loop {
            self.collect();
            if let Some(offset) = self.in_body {
                let body = self
                    .messages
                    .get(self.next)
                    .map_or(&[][..], PreparedMessage::bytes);
                let rest = body.get(offset..).unwrap_or(&[]);
                let now = Millis(self.now);
                if rest.is_empty() {
                    self.in_body = None;
                    if let Err(e) = self.session.end_body(now) {
                        self.note_close(e);
                    }
                } else {
                    match self
                        .session
                        .body(rest.get(..rest.len().min(self.split)).unwrap_or(&[]), now)
                    {
                        Ok(n) => self.in_body = Some(offset + n),
                        Err(e) => {
                            self.in_body = None;
                            self.note_close(e);
                        }
                    }
                }
                continue;
            }
            let Some(event) = self.session.poll_event() else {
                break;
            };
            match event {
                Event::Ready { .. } => self.schedule_begin(),
                Event::StartTls => self.tls_pending = true,
                Event::BodyWanted => self.in_body = Some(0),
                Event::Delivered { .. } => {
                    self.outcome.messages.push(Ok(()));
                    self.next += 1;
                    self.schedule_begin();
                }
                Event::TransactionFailed(e) => {
                    self.outcome.messages.push(Err(e));
                    self.next += 1;
                    self.schedule_begin();
                }
                Event::Closed { error: Some(e) } => self.note_close(e),
                _ => {}
            }
        }
        self.collect();
    }

    fn take_line(&mut self) -> Option<String> {
        let pos = self.sent.windows(2).position(|w| w == b"\r\n")?;
        let line = String::from_utf8_lossy(self.sent.get(..pos).unwrap_or(&[])).into_owned();
        self.sent.drain(..pos + 2);
        Some(line)
    }
}

// ---------------------------------------------------------------------------
// A test TLS engine: framing only, no cryptography
// ---------------------------------------------------------------------------

/// A TLS stand-in for tests: a one-line handshake that checks the server
/// name, then length-prefixed records of plaintext. It encrypts nothing and
/// verifies nothing real; it exists so the driver's STARTTLS, implicit TLS,
/// certificate-refusal, and injection paths run end to end against
/// [`TestServer`] without a TLS library. Never use it for real mail.
///
/// # Examples
///
/// ```
/// let server = smtp_net::TestServer::builder().starttls().start()?;
/// let msg = smtp_net::Message::text("a@example.com", "b@example.org", "Hi", "over test TLS")?;
/// let report = smtp_net::send(&server.server(), &msg)?;
/// assert!(report.was_secure());
/// # Ok::<(), smtp_net::Error>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct TestTls;

impl TlsConnector for TestTls {
    fn session(
        &self,
        server_name: &str,
        insecure: bool,
    ) -> Result<Box<dyn TlsSession>, TlsSetupError> {
        let mut hello = b"TESTTLS1 ".to_vec();
        hello.extend_from_slice(server_name.as_bytes());
        hello.extend_from_slice(if insecure {
            b" insecure\n"
        } else {
            b" verify\n"
        });
        Ok(Box::new(TestTlsSession {
            state: TestTlsState::Start,
            hello,
            sni: server_name.to_string(),
        }))
    }
}

/// The largest test TLS record payload.
const TEST_RECORD: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestTlsState {
    Start,
    AwaitReply,
    Open,
    Closed,
}

struct TestTlsSession {
    state: TestTlsState,
    hello: Vec<u8>,
    sni: String,
}

impl TlsSession for TestTlsSession {
    fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<TlsProgress<'i>, TlsError> {
        match self.state {
            TestTlsState::Start => {
                let n = self.hello.len();
                let dst =
                    output
                        .get_mut(..n)
                        .ok_or(TlsError::new(NetTlsFailure::OutputFull, 1, None))?;
                dst.copy_from_slice(&self.hello);
                self.state = TestTlsState::AwaitReply;
                Ok(TlsProgress {
                    consumed: 0,
                    written: n,
                    event: TlsEvent::Transmit,
                })
            }
            TestTlsState::AwaitReply => {
                let Some(nl) = input.iter().position(|&b| b == b'\n') else {
                    if input.len() > 64
                        || (!input.is_empty()
                            && !b"TESTTLS1 "
                                .starts_with(input.get(..input.len().min(9)).unwrap_or(&[])))
                    {
                        return Err(TlsError::new(NetTlsFailure::Protocol, 2, Some(50)));
                    }
                    return Ok(TlsProgress {
                        consumed: 0,
                        written: 0,
                        event: TlsEvent::NeedInput,
                    });
                };
                let line = input.get(..nl).unwrap_or(&[]);
                if line == b"TESTTLS1 OK" {
                    self.state = TestTlsState::Open;
                    Ok(TlsProgress {
                        consumed: nl + 1,
                        written: 0,
                        event: TlsEvent::HandshakeComplete,
                    })
                } else if line == b"TESTTLS1 REJECT" {
                    // bad_certificate
                    Err(TlsError::new(NetTlsFailure::Handshake, 3, Some(42)))
                } else {
                    Err(TlsError::new(NetTlsFailure::Protocol, 2, Some(50)))
                }
            }
            TestTlsState::Open => {
                let (Some(&hi), Some(&lo)) = (input.first(), input.get(1)) else {
                    return Ok(TlsProgress {
                        consumed: 0,
                        written: 0,
                        event: TlsEvent::NeedInput,
                    });
                };
                let len = usize::from(u16::from_be_bytes([hi, lo]));
                if len == 0 {
                    self.state = TestTlsState::Closed;
                    return Ok(TlsProgress {
                        consumed: 2,
                        written: 0,
                        event: TlsEvent::PeerClosed,
                    });
                }
                if len > TEST_RECORD {
                    return Err(TlsError::new(NetTlsFailure::Protocol, 4, Some(22)));
                }
                if input.len() < 2 + len {
                    return Ok(TlsProgress {
                        consumed: 0,
                        written: 0,
                        event: TlsEvent::NeedInput,
                    });
                }
                let data = input.get(2..2 + len).unwrap_or(&[]);
                Ok(TlsProgress {
                    consumed: 2 + len,
                    written: 0,
                    event: TlsEvent::Data(data),
                })
            }
            TestTlsState::Closed => Ok(TlsProgress {
                consumed: 0,
                written: 0,
                event: TlsEvent::Closed,
            }),
        }
    }

    fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != TestTlsState::Open {
            return Err(TlsError::new(NetTlsFailure::State, 5, None));
        }
        let records = plaintext.len().div_ceil(TEST_RECORD);
        if output.len() < plaintext.len() + 2 * records {
            return Err(TlsError::new(NetTlsFailure::OutputFull, 6, None));
        }
        let mut at = 0;
        for chunk in plaintext.chunks(TEST_RECORD) {
            let len = u16::try_from(chunk.len()).unwrap_or(u16::MAX).to_be_bytes();
            if let Some(d) = output.get_mut(at..at + 2) {
                d.copy_from_slice(&len);
            }
            if let Some(d) = output.get_mut(at + 2..at + 2 + chunk.len()) {
                d.copy_from_slice(chunk);
            }
            at += 2 + chunk.len();
        }
        Ok(at)
    }

    fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        let d = output
            .get_mut(..2)
            .ok_or(TlsError::new(NetTlsFailure::OutputFull, 7, None))?;
        d.copy_from_slice(&[0, 0]);
        self.state = TestTlsState::Closed;
        Ok(2)
    }

    fn on_transport_closed(&mut self) -> TlsCloseKind {
        if self.state == TestTlsState::Closed {
            TlsCloseKind::Clean
        } else {
            TlsCloseKind::Unclean
        }
    }

    fn info(&self) -> Option<NetTlsInfo> {
        (self.state == TestTlsState::Open)
            .then(|| NetTlsInfo::new(Some(&self.sni), None, 0x0304, 0x1301))
            .flatten()
    }

    fn input_capacity_required(&self) -> usize {
        2 + TEST_RECORD
    }
}

// ---------------------------------------------------------------------------
// The blocking loopback test server
// ---------------------------------------------------------------------------

/// A fault the [`TestServer`] injects (PLAN section 10 attack tests).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Answer `stage` with `reply` (CRLF added) instead of the normal reply.
    ReplyAt {
        /// Where.
        stage: Stage,
        /// The reply line or lines, without the final CRLF.
        reply: &'static str,
    },
    /// Close the connection when the command of `stage` arrives.
    CloseAt(Stage),
    /// Store the message, then close without answering the end of data.
    CloseAfterDataEnd,
    /// Close the connection after answering this many messages on it.
    CloseAfterMessages(usize),
    /// Wait before answering `stage`.
    DelayAt {
        /// Where.
        stage: Stage,
        /// How long.
        by: Duration,
    },
    /// Send these plaintext bytes right after the `220` to STARTTLS (T-6).
    InjectAfterStartTls(&'static [u8]),
    /// Never advertise STARTTLS (T-5).
    OmitStartTls,
    /// Refuse the test TLS handshake as a bad certificate (T-11).
    RejectCertificate,
    /// Answer `stage` with a reply that is not valid SMTP.
    MalformedReply(Stage),
    /// Answer `stage` with a 2,000-octet line.
    OversizedReply(Stage),
    /// Answer `stage` twice.
    ExtraReply(Stage),
    /// Refuse the recipient at this zero-based index with `550 5.1.1`.
    RejectRecipient(usize),
    /// Answer `452 4.5.3` to every recipient after the first `n` of a transaction.
    TooManyRecipientsAfter(usize),
    /// Send replies at this many bytes per second.
    SlowDrip {
        /// The rate.
        bytes_per_second: u32,
    },
    /// SCRAM-SHA-256: send a server signature with one bit flipped, as a
    /// server that does not know the password would.
    BadScramSignature,
}

/// A message as the [`TestServer`] received it.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedMessage {
    /// The reverse-path, without angle brackets (empty for `<>`).
    pub from: String,
    /// The forward-paths the server accepted.
    pub recipients: Vec<String>,
    /// The MAIL parameters (`SIZE=...`, `BODY=8BITMIME`, `RET=...`, ...).
    pub mail_parameters: Vec<String>,
    /// The RCPT parameters of each accepted recipient (`NOTIFY=...`, `ORCPT=...`).
    pub rcpt_parameters: Vec<Vec<String>>,
    /// The message bytes after dot-unstuffing (or as BDAT carried them).
    pub data: Vec<u8>,
    /// True when the message arrived over the test TLS.
    pub secure: bool,
    /// True when it arrived with BDAT.
    pub chunked: bool,
    /// The user that authenticated on the connection, if any.
    pub user: Option<String>,
}

#[derive(Default)]
struct Shared {
    received: Vec<ReceivedMessage>,
    transcript: String,
    connections: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TlsMode {
    None,
    StartTls,
    Implicit,
}

/// Makes a server-side TLS session for each TLS connection.
type EngineFactory = Arc<dyn Fn() -> Option<Box<dyn TlsSession>> + Send + Sync>;

#[derive(Clone)]
struct Engine(EngineFactory);

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Engine")
    }
}

/// Configures a [`TestServer`].
#[must_use]
#[derive(Clone, Debug)]
pub struct TestServerBuilder {
    engine: Option<Engine>,
    extensions: Vec<String>,
    faults: Vec<Fault>,
    ehlo_refused: bool,
    tls: TlsMode,
    tls_name: String,
    auth: Option<(String, String)>,
    oauth: Option<(String, String)>,
}

impl TestServerBuilder {
    /// Replaces the advertised extensions (default: `PIPELINING`, `8BITMIME`,
    /// `SIZE 10485760`, `ENHANCEDSTATUSCODES`, `SMTPUTF8`, `DSN`).
    /// `STARTTLS` and `AUTH` are added by [`starttls`](TestServerBuilder::starttls)
    /// and [`auth`](TestServerBuilder::auth).
    pub fn extensions(mut self, list: &[&str]) -> Self {
        self.extensions = list.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// Adds a fault.
    pub fn fault(mut self, fault: Fault) -> Self {
        self.faults.push(fault);
        self
    }

    /// Answer EHLO with `502` so clients fall back to HELO.
    pub fn refuse_ehlo(mut self) -> Self {
        self.ehlo_refused = true;
        self
    }

    /// Offer STARTTLS over the [`TestTls`] stand-in.
    pub fn starttls(mut self) -> Self {
        self.tls = TlsMode::StartTls;
        self
    }

    /// Speak the [`TestTls`] stand-in from the first byte (implicit TLS).
    pub fn implicit_tls(mut self) -> Self {
        self.tls = TlsMode::Implicit;
        self
    }

    /// The name the test certificate is for (default `localhost`); a client
    /// that verifies and asks for another name is refused.
    pub fn tls_name(mut self, name: &str) -> Self {
        self.tls_name = name.to_string();
        self
    }

    /// Use a real server-side TLS engine (any net-io `TlsSession`, such as a
    /// tls-net `ServerSession` built from the fixture certificates) instead of
    /// the [`TestTls`] stand-in, for STARTTLS or implicit TLS. The client then
    /// needs a matching connector (`ServerBuilder::tls_connector`).
    pub fn tls_engine(
        mut self,
        factory: impl Fn() -> Option<Box<dyn TlsSession>> + Send + Sync + 'static,
    ) -> Self {
        self.engine = Some(Engine(Arc::new(factory)));
        self
    }

    /// Offer `AUTH PLAIN LOGIN` (and `SCRAM-SHA-256` with the `scram`
    /// feature) and accept this user and password.
    pub fn auth(mut self, user: &str, password: &str) -> Self {
        self.auth = Some((user.to_string(), password.to_string()));
        self
    }

    /// Offer `AUTH XOAUTH2` and accept this user and token. A wrong token
    /// gets Google's answer: a `334` error document (`"status":"401"`),
    /// then `535` after the client's empty line.
    pub fn oauth2(mut self, user: &str, token: &str) -> Self {
        self.oauth = Some((user.to_string(), token.to_string()));
        self
    }

    /// Binds `127.0.0.1:0` and starts serving.
    ///
    /// # Errors
    ///
    /// `Io` when the listener cannot be bound.
    pub fn start(self) -> Result<TestServer, Error> {
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|e| Error::new(ErrorKind::Io(e.kind())))?;
        let addr = listener
            .local_addr()
            .map_err(|e| Error::new(ErrorKind::Io(e.kind())))?;
        let shared = Arc::new(Mutex::new(Shared::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let config = Arc::new(self);
        let (s, st, c0) = (Arc::clone(&shared), Arc::clone(&stop), Arc::clone(&config));
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if st.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let (s, c) = (Arc::clone(&s), Arc::clone(&c0));
                thread::spawn(move || {
                    let _ = serve(stream, &c, &s);
                });
            }
        });
        Ok(TestServer {
            addr,
            shared,
            stop,
            thread: Some(thread),
            config,
        })
    }
}

/// A blocking SMTP server on `127.0.0.1` for tests: it speaks enough SMTP to
/// accept, record, and misbehave on command, with AUTH, BDAT, DSN, and the
/// [`TestTls`] stand-in. Stops when dropped.
///
/// # Examples
///
/// ```
/// let server = smtp_net::TestServer::start()?;
/// let msg = smtp_net::Message::text("a@example.com", "b@example.org", "Hi", "Hello\n.\n")?;
/// smtp_net::send(&server.server(), &msg)?;
/// let got = server.received();
/// assert_eq!(got.len(), 1);
/// assert!(got[0].data.ends_with(b"Hello\r\n.\r\n"));
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub struct TestServer {
    addr: SocketAddr,
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    config: Arc<TestServerBuilder>,
}

impl core::fmt::Debug for TestServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestServer")
            .field("addr", &self.addr)
            .finish()
    }
}

impl TestServer {
    /// A server with the default extensions and no faults.
    ///
    /// # Errors
    ///
    /// As [`TestServerBuilder::start`].
    pub fn start() -> Result<TestServer, Error> {
        TestServer::builder().start()
    }

    /// A builder.
    pub fn builder() -> TestServerBuilder {
        TestServerBuilder {
            extensions: [
                "PIPELINING",
                "8BITMIME",
                "SIZE 10485760",
                "ENHANCEDSTATUSCODES",
                "SMTPUTF8",
                "DSN",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            engine: None,
            faults: Vec::new(),
            ehlo_refused: false,
            tls: TlsMode::None,
            tls_name: "localhost".to_string(),
            auth: None,
            oauth: None,
        }
    }

    /// The port it listens on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// A [`ServerBuilder`] pointing at it: plaintext loopback, or STARTTLS or
    /// implicit TLS over [`TestTls`] to `localhost`, with the configured user
    /// and password.
    pub fn server_builder(&self) -> ServerBuilder {
        let security = match self.config.tls {
            TlsMode::None => Security::PlaintextLoopback,
            TlsMode::StartTls => Security::StartTls,
            TlsMode::Implicit => Security::ImplicitTls,
        };
        let host = if security == Security::PlaintextLoopback {
            "127.0.0.1"
        } else {
            "localhost"
        };
        let mut b = Server::builder(host, security)
            .port(self.port())
            .tls_connector(TestTls);
        if let Some((u, p)) = &self.config.auth {
            b = b.credentials(Credentials::password(u, p.as_str()));
        }
        if let Some((u, t)) = &self.config.oauth {
            b = b.credentials(Credentials::oauth2(u, t.as_str()));
        }
        b
    }

    /// The [`Server`] of [`server_builder`](TestServer::server_builder).
    #[must_use]
    pub fn server(&self) -> Server {
        self.server_builder()
            .build()
            .unwrap_or_else(|_| Server::local())
    }

    /// The messages received so far.
    #[must_use]
    pub fn received(&self) -> Vec<ReceivedMessage> {
        self.shared
            .lock()
            .map(|s| s.received.clone())
            .unwrap_or_default()
    }

    /// The conversation so far, `C: ` and `S: ` lines; message bodies omitted
    /// and AUTH payloads shown as `<redacted N octets>` (T-9).
    #[must_use]
    pub fn transcript(&self) -> String {
        self.shared
            .lock()
            .map(|s| s.transcript.clone())
            .unwrap_or_default()
    }

    /// Connections accepted so far.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.shared.lock().map(|s| s.connections).unwrap_or(0)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// A real TLS engine's buffers on the server side.
struct EngineLink {
    session: Box<dyn TlsSession>,
    input: Vec<u8>,
    filled: usize,
    output: Vec<u8>,
}

impl EngineLink {
    /// Steps the engine once over the buffered ciphertext.
    fn step(&mut self, stream: &mut TcpStream, plain: &mut Vec<u8>) -> std::io::Result<EngineStep> {
        let filled = self.filled;
        let input = self.input.get_mut(..filled).unwrap_or(&mut []);
        let p = self
            .session
            .step(input, &mut self.output)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let (consumed, written) = (p.consumed, p.written);
        let mut acted = consumed > 0 || written > 0;
        let step = match p.event {
            TlsEvent::NeedInput if acted => EngineStep::Again,
            TlsEvent::NeedInput => EngineStep::NeedInput,
            TlsEvent::HandshakeComplete => {
                acted = true;
                EngineStep::Handshaken
            }
            TlsEvent::Data(d) => {
                plain.extend_from_slice(d);
                acted = true;
                EngineStep::Again
            }
            TlsEvent::PeerClosed | TlsEvent::Closed => EngineStep::Closed,
            _ => EngineStep::Again,
        };
        if written > 0 {
            stream.write_all(self.output.get(..written).unwrap_or(&[]))?;
        }
        let consumed = consumed.min(filled);
        self.input.copy_within(consumed..filled, 0);
        self.filled = filled - consumed;
        if !acted && matches!(step, EngineStep::Again) {
            return Ok(EngineStep::NeedInput);
        }
        Ok(step)
    }

    /// Reads more ciphertext; false at EOF.
    fn read(&mut self, stream: &mut TcpStream) -> std::io::Result<bool> {
        let need = self
            .session
            .input_capacity_required()
            .max(self.filled + 4096);
        if self.input.len() < need {
            self.input.resize(need, 0);
        }
        let room = self.input.get_mut(self.filled..).unwrap_or(&mut []);
        let n = stream.read(room)?;
        self.filled += n;
        Ok(n > 0)
    }
}

enum EngineStep {
    NeedInput,
    Again,
    Handshaken,
    Closed,
}

struct Conn<'a> {
    stream: TcpStream,
    engine: Option<EngineLink>,
    /// Plaintext received and not yet used.
    plain: Vec<u8>,
    tls: bool,
    cfg: &'a TestServerBuilder,
    shared: &'a Mutex<Shared>,
}

impl Conn<'_> {
    fn log(&self, dir: &str, line: &str) {
        if let Ok(mut s) = self.shared.lock() {
            s.transcript.push_str(dir);
            s.transcript.push_str(line);
            s.transcript.push('\n');
        }
    }

    fn fault(&self, f: impl Fn(&Fault) -> bool) -> Option<&Fault> {
        self.cfg.faults.iter().find(|x| f(x))
    }

    /// Sends `normal` (lines without CRLF) for `stage`, applying faults.
    fn reply(&mut self, stage: Stage, normal: &str) -> std::io::Result<()> {
        if let Some(Fault::DelayAt { by, .. }) =
            self.fault(|f| matches!(f, Fault::DelayAt { stage: s, .. } if *s == stage))
        {
            thread::sleep(*by);
        }
        let text = if let Some(Fault::ReplyAt { reply, .. }) =
            self.fault(|f| matches!(f, Fault::ReplyAt { stage: s, .. } if *s == stage))
        {
            (*reply).to_string()
        } else if self.fault(|f| *f == Fault::MalformedReply(stage)).is_some() {
            "2x0 not smtp".to_string()
        } else if self.fault(|f| *f == Fault::OversizedReply(stage)).is_some() {
            format!("250 {}", "x".repeat(2000))
        } else {
            normal.to_string()
        };
        let mut bytes = Vec::new();
        for line in text.split('\n') {
            self.log("S: ", line);
            bytes.extend_from_slice(line.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        if self.fault(|f| *f == Fault::ExtraReply(stage)).is_some() {
            let again = bytes.clone();
            bytes.extend_from_slice(&again);
        }
        self.write(&bytes)
    }

    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if let Some(e) = self.engine.as_mut() {
            for chunk in bytes.chunks(8 * 1024) {
                let n = e
                    .session
                    .encrypt(chunk, &mut e.output)
                    .map_err(|x| std::io::Error::other(format!("{x:?}")))?;
                self.stream.write_all(e.output.get(..n).unwrap_or(&[]))?;
            }
            return Ok(());
        }
        let framed;
        let bytes = if self.tls {
            let mut f = Vec::with_capacity(bytes.len() + 2);
            for chunk in bytes.chunks(TEST_RECORD) {
                f.extend_from_slice(&u16::try_from(chunk.len()).unwrap_or(u16::MAX).to_be_bytes());
                f.extend_from_slice(chunk);
            }
            framed = f;
            &framed[..]
        } else {
            bytes
        };
        if let Some(Fault::SlowDrip { bytes_per_second }) =
            self.fault(|f| matches!(f, Fault::SlowDrip { .. }))
        {
            let gap = Duration::from_secs(1) / (*bytes_per_second).max(1);
            for b in bytes {
                self.stream.write_all(core::slice::from_ref(b))?;
                thread::sleep(gap);
            }
            return Ok(());
        }
        self.stream.write_all(bytes)
    }

    fn closes_at(&self, stage: Stage) -> bool {
        self.fault(|f| *f == Fault::CloseAt(stage)).is_some()
    }

    /// Reads more plaintext; false at EOF.
    fn fill(&mut self) -> std::io::Result<bool> {
        if let Some(e) = self.engine.as_mut() {
            let before = self.plain.len();
            loop {
                match e.step(&mut self.stream, &mut self.plain)? {
                    EngineStep::Closed => return Ok(self.plain.len() > before),
                    EngineStep::NeedInput if self.plain.len() > before => return Ok(true),
                    EngineStep::NeedInput => {
                        if !e.read(&mut self.stream)? {
                            return Ok(false);
                        }
                    }
                    EngineStep::Again | EngineStep::Handshaken => {}
                }
            }
        }
        if self.tls {
            let mut len = [0u8; 2];
            if self.stream.read_exact(&mut len).is_err() {
                return Ok(false);
            }
            let n = usize::from(u16::from_be_bytes(len));
            if n == 0 {
                return Ok(false);
            }
            let mut rec = std::vec![0u8; n];
            self.stream.read_exact(&mut rec)?;
            self.plain.extend_from_slice(&rec);
            return Ok(true);
        }
        let mut buf = [0u8; 4096];
        let n = self.stream.read(&mut buf)?;
        self.plain.extend_from_slice(buf.get(..n).unwrap_or(&[]));
        Ok(n > 0)
    }

    fn read_line(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(nl) = self.plain.iter().position(|&b| b == b'\n') {
                return Ok(Some(self.plain.drain(..=nl).collect()));
            }
            if !self.fill()? {
                return Ok(None);
            }
        }
    }

    fn read_exact_plain(&mut self, n: usize) -> std::io::Result<Option<Vec<u8>>> {
        while self.plain.len() < n {
            if !self.fill()? {
                return Ok(None);
            }
        }
        Ok(Some(self.plain.drain(..n).collect()))
    }

    /// The server side of the TLS handshake (the real engine when one is
    /// configured, the test stand-in otherwise); false when it failed.
    fn tls_accept(&mut self) -> std::io::Result<bool> {
        if let Some(factory) = self.cfg.engine.clone() {
            let Some(session) = (factory.0)() else {
                return Ok(false);
            };
            let mut link = EngineLink {
                session,
                input: std::vec![0; 32 * 1024],
                filled: 0,
                output: std::vec![0; 32 * 1024],
            };
            loop {
                match link.step(&mut self.stream, &mut self.plain) {
                    Ok(EngineStep::Handshaken) => break,
                    Ok(EngineStep::NeedInput) => {
                        if !link.read(&mut self.stream)? {
                            return Ok(false);
                        }
                    }
                    Ok(EngineStep::Again) => {}
                    Ok(EngineStep::Closed) => {
                        self.log("S: ", "<TLS refused: closed>");
                        return Ok(false);
                    }
                    Err(e) => {
                        self.log("S: ", &format!("<TLS refused: {e}>"));
                        return Ok(false);
                    }
                }
            }
            self.log("S: ", "<TLS established>");
            self.engine = Some(link);
            self.tls = true;
            return Ok(true);
        }
        let Some(hello) = self.read_line()? else {
            return Ok(false);
        };
        let hello = String::from_utf8_lossy(&hello).trim_end().to_string();
        let mut parts = hello.split(' ');
        let ok_shape = parts.next() == Some("TESTTLS1");
        let name = parts.next().unwrap_or("");
        let insecure = parts.next() == Some("insecure");
        let name_ok = insecure || name.eq_ignore_ascii_case(&self.cfg.tls_name);
        let accept =
            ok_shape && name_ok && self.fault(|f| *f == Fault::RejectCertificate).is_none();
        self.stream.write_all(if accept {
            b"TESTTLS1 OK\n"
        } else {
            b"TESTTLS1 REJECT\n"
        })?;
        self.log(
            "S: ",
            if accept {
                "<TLS established>"
            } else {
                "<TLS refused>"
            },
        );
        self.tls = accept;
        Ok(accept)
    }
}

fn serve(
    stream: TcpStream,
    cfg: &TestServerBuilder,
    shared: &Mutex<Shared>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    if let Ok(mut s) = shared.lock() {
        s.connections += 1;
    }
    let mut c = Conn {
        stream,
        engine: None,
        plain: Vec::new(),
        tls: false,
        cfg,
        shared,
    };
    if cfg.tls == TlsMode::Implicit && !c.tls_accept()? {
        return c.stream.shutdown(Shutdown::Both);
    }
    if c.closes_at(Stage::Greeting) {
        return c.stream.shutdown(Shutdown::Both);
    }
    c.reply(Stage::Greeting, "220 test.smtp-net.invalid ESMTP")?;
    let mut from: Option<(String, Vec<String>)> = None;
    let mut rcpts: Vec<(String, Vec<String>)> = Vec::new();
    let mut rcpt_index = 0usize;
    let mut delivered = 0usize;
    let mut user: Option<String> = None;
    let mut chunk: Vec<u8> = Vec::new();
    while let Some(raw) = c.read_line()? {
        let line = String::from_utf8_lossy(raw.strip_suffix(b"\r\n").unwrap_or(&raw)).into_owned();
        let upper = line.to_ascii_uppercase();
        let verb = upper.split(' ').next().unwrap_or("").to_string();
        if verb == "AUTH" {
            let mech = upper.split(' ').nth(1).unwrap_or("");
            let shown = format!(
                "AUTH {mech} <redacted {} octets>",
                line.len().saturating_sub(6 + mech.len())
            );
            c.log("C: ", &shown);
        } else {
            c.log("C: ", &line);
        }
        let stage = match verb.as_str() {
            "EHLO" => Stage::Ehlo,
            "HELO" => Stage::Helo,
            "MAIL" => Stage::Mail,
            "RCPT" => Stage::Rcpt,
            "DATA" => Stage::Data,
            "BDAT" => Stage::Bdat,
            "RSET" => Stage::Rset,
            "NOOP" => Stage::Noop,
            "QUIT" => Stage::Quit,
            "STARTTLS" => Stage::StartTls,
            "AUTH" => Stage::Auth,
            _ => Stage::Total,
        };
        if c.closes_at(stage) {
            return c.stream.shutdown(Shutdown::Both);
        }
        match stage {
            Stage::Ehlo if cfg.ehlo_refused => c.reply(stage, "502 5.5.1 EHLO not implemented")?,
            Stage::Ehlo => {
                let mut lines = std::vec!["250-test.smtp-net.invalid".to_string()];
                for e in &cfg.extensions {
                    lines.push(format!("250-{e}"));
                }
                if cfg.tls == TlsMode::StartTls
                    && !c.tls
                    && c.fault(|f| *f == Fault::OmitStartTls).is_none()
                {
                    lines.push("250-STARTTLS".to_string());
                }
                let mut mechs = String::new();
                if cfg.auth.is_some() {
                    mechs.push_str(" PLAIN LOGIN");
                    if cfg!(feature = "scram") {
                        mechs.push_str(" SCRAM-SHA-256");
                    }
                }
                if cfg.oauth.is_some() {
                    mechs.push_str(" XOAUTH2");
                }
                if !mechs.is_empty() {
                    lines.push(format!("250-AUTH{mechs}"));
                }
                if let Some(last) = lines.last_mut() {
                    *last = last.replacen("250-", "250 ", 1);
                }
                c.reply(stage, &lines.join("\n"))?;
            }
            Stage::Helo => c.reply(stage, "250 test.smtp-net.invalid")?,
            Stage::StartTls => {
                if cfg.tls != TlsMode::StartTls || c.tls {
                    c.reply(stage, "503 5.5.1 STARTTLS not available")?;
                    continue;
                }
                c.reply(stage, "220 2.0.0 go ahead")?;
                if let Some(Fault::InjectAfterStartTls(b)) =
                    c.fault(|f| matches!(f, Fault::InjectAfterStartTls(_)))
                {
                    let b: &[u8] = b;
                    c.stream.write_all(b)?;
                }
                if !c.tls_accept()? {
                    return c.stream.shutdown(Shutdown::Both);
                }
                // RFC 3207 4.2: forget everything from before TLS.
                from = None;
                rcpts.clear();
            }
            Stage::Auth => {
                let mut words = line.split(' ').skip(1);
                let mech = words.next().unwrap_or("").to_ascii_uppercase();
                let initial = words.next().map(str::to_string);
                let decode = |s: &str| {
                    let mut out = Vec::new();
                    crate::encode::base64_decode(s.trim().as_bytes(), &mut out)
                        .ok()
                        .map(|()| out)
                };
                if mech == "XOAUTH2" {
                    let Some((want_user, want_token)) = cfg.oauth.clone() else {
                        c.reply(stage, "504 5.5.4 mechanism not available")?;
                        continue;
                    };
                    let want = format!("user={want_user}\x01auth=Bearer {want_token}\x01\x01");
                    let got = initial.as_deref().and_then(decode).unwrap_or_default();
                    if got == want.as_bytes() {
                        user = Some(want_user);
                        c.reply(stage, "235 2.7.0 authenticated")?;
                    } else {
                        let mut doc = Vec::new();
                        crate::encode::base64_append(
                            br#"{"status":"401","schemes":"bearer","scope":"https://mail.google.com/"}"#,
                            &mut doc,
                        );
                        c.reply(stage, &format!("334 {}", String::from_utf8_lossy(&doc)))?;
                        let Some(l) = c.read_line()? else {
                            return Ok(());
                        };
                        c.log("C: ", &format!("<{} octets>", l.len().saturating_sub(2)));
                        c.reply(stage, "535 5.7.8 Username and Password not accepted")?;
                    }
                    continue;
                }
                let Some((want_user, want_pass)) = cfg.auth.clone() else {
                    c.reply(stage, "503 5.5.1 AUTH not available")?;
                    continue;
                };
                #[cfg(feature = "scram")]
                if mech == "SCRAM-SHA-256" {
                    let first = initial.as_deref().and_then(decode).unwrap_or_default();
                    match scram_server(&mut c, stage, &first, &want_user, &want_pass)? {
                        Some(true) => {
                            user = Some(want_user);
                            c.reply(stage, "235 2.7.0 authenticated")?;
                        }
                        Some(false) => c.reply(stage, "535 5.7.8 authentication failed")?,
                        None => return Ok(()),
                    }
                    continue;
                }
                let (got_user, got_pass) = match mech.as_str() {
                    "PLAIN" => {
                        let payload = match initial {
                            Some(p) => p,
                            None => {
                                c.reply(stage, "334 ")?;
                                let Some(l) = c.read_line()? else {
                                    return Ok(());
                                };
                                c.log(
                                    "C: ",
                                    &format!("<redacted {} octets>", l.len().saturating_sub(2)),
                                );
                                String::from_utf8_lossy(&l).trim_end().to_string()
                            }
                        };
                        let raw = decode(&payload).unwrap_or_default();
                        let mut parts = raw.split(|&b| b == 0).skip(1);
                        let u = parts
                            .next()
                            .map(|u| String::from_utf8_lossy(u).into_owned());
                        let p = parts
                            .next()
                            .map(|p| String::from_utf8_lossy(p).into_owned());
                        (u, p)
                    }
                    "LOGIN" => {
                        c.reply(stage, "334 VXNlcm5hbWU6")?;
                        let Some(u) = c.read_line()? else {
                            return Ok(());
                        };
                        c.log(
                            "C: ",
                            &format!("<redacted {} octets>", u.len().saturating_sub(2)),
                        );
                        c.reply(stage, "334 UGFzc3dvcmQ6")?;
                        let Some(p) = c.read_line()? else {
                            return Ok(());
                        };
                        c.log(
                            "C: ",
                            &format!("<redacted {} octets>", p.len().saturating_sub(2)),
                        );
                        let s = |b: Vec<u8>| {
                            decode(String::from_utf8_lossy(&b).trim_end())
                                .map(|v| String::from_utf8_lossy(&v).into_owned())
                        };
                        (s(u), s(p))
                    }
                    _ => (None, None),
                };
                if got_user.as_deref() == Some(want_user.as_str())
                    && got_pass.as_deref() == Some(want_pass.as_str())
                {
                    user = got_user;
                    c.reply(stage, "235 2.7.0 authenticated")?;
                } else {
                    c.reply(stage, "535 5.7.8 authentication failed")?;
                }
            }
            Stage::Mail => {
                let path = between(&line, '<', '>');
                let params: Vec<String> = line
                    .rsplit_once('>')
                    .map(|(_, p)| p.split_whitespace().map(str::to_string).collect())
                    .unwrap_or_default();
                from = Some((path, params));
                rcpts.clear();
                rcpt_index = 0;
                chunk.clear();
                c.reply(stage, "250 2.1.0 ok")?;
            }
            Stage::Rcpt => {
                let i = rcpt_index;
                rcpt_index += 1;
                if from.is_none() {
                    c.reply(stage, "503 5.5.1 MAIL first")?;
                } else if c.fault(|f| *f == Fault::RejectRecipient(i)).is_some() {
                    c.reply(stage, "550 5.1.1 no such user")?;
                } else if c
                    .fault(|f| matches!(f, Fault::TooManyRecipientsAfter(n) if i >= *n))
                    .is_some()
                {
                    c.reply(stage, "452 4.5.3 too many recipients")?;
                } else {
                    let params: Vec<String> = line
                        .rsplit_once('>')
                        .map(|(_, p)| p.split_whitespace().map(str::to_string).collect())
                        .unwrap_or_default();
                    rcpts.push((between(&line, '<', '>'), params));
                    c.reply(stage, "250 2.1.5 ok")?;
                }
            }
            Stage::Data => {
                if from.is_none() || rcpts.is_empty() {
                    c.reply(stage, "554 5.5.1 no valid recipients")?;
                    continue;
                }
                c.reply(stage, "354 end with <CRLF>.<CRLF>")?;
                let mut data = Vec::new();
                loop {
                    let Some(l) = c.read_line()? else {
                        return Ok(());
                    };
                    if l == b".\r\n" {
                        break;
                    }
                    data.extend_from_slice(l.strip_prefix(b".").unwrap_or(&l));
                }
                c.log("C: ", "<BODY>");
                if !store(
                    &mut c,
                    shared,
                    &mut from,
                    &mut rcpts,
                    data,
                    false,
                    &user,
                    &mut delivered,
                )? {
                    return Ok(());
                }
            }
            Stage::Bdat => {
                let mut words = upper.split_whitespace().skip(1);
                let n: usize = words.next().and_then(|n| n.parse().ok()).unwrap_or(0);
                let last = words.next() == Some("LAST");
                let Some(bytes) = c.read_exact_plain(n)? else {
                    return Ok(());
                };
                c.log("C: ", &format!("<BDAT {n} octets>"));
                if from.is_none() || rcpts.is_empty() {
                    c.reply(stage, "554 5.5.1 no valid recipients")?;
                    continue;
                }
                chunk.extend_from_slice(&bytes);
                if last {
                    let data = core::mem::take(&mut chunk);
                    if !store(
                        &mut c,
                        shared,
                        &mut from,
                        &mut rcpts,
                        data,
                        true,
                        &user,
                        &mut delivered,
                    )? {
                        return Ok(());
                    }
                } else {
                    c.reply(stage, "250 2.0.0 chunk received")?;
                }
            }
            Stage::Rset => {
                from = None;
                rcpts.clear();
                rcpt_index = 0;
                chunk.clear();
                c.reply(stage, "250 2.0.0 ok")?;
            }
            Stage::Noop => c.reply(stage, "250 2.0.0 ok")?,
            Stage::Quit => {
                c.reply(stage, "221 2.0.0 bye")?;
                return Ok(());
            }
            _ => c.reply(stage, "500 5.5.2 command not recognized")?,
        }
    }
    Ok(())
}

/// Records a received message and answers its end; false when the
/// connection must close instead.
#[allow(clippy::too_many_arguments)]
fn store(
    c: &mut Conn<'_>,
    shared: &Mutex<Shared>,
    from: &mut Option<(String, Vec<String>)>,
    rcpts: &mut Vec<(String, Vec<String>)>,
    data: Vec<u8>,
    chunked: bool,
    user: &Option<String>,
    delivered: &mut usize,
) -> std::io::Result<bool> {
    let (path, params) = from.take().unwrap_or_default();
    let taken = core::mem::take(rcpts);
    if let Ok(mut s) = shared.lock() {
        s.received.push(ReceivedMessage {
            from: path,
            recipients: taken.iter().map(|(r, _)| r.clone()).collect(),
            mail_parameters: params,
            rcpt_parameters: taken.into_iter().map(|(_, p)| p).collect(),
            data,
            secure: c.tls,
            chunked,
            user: user.clone(),
        });
    }
    if c.fault(|f| *f == Fault::CloseAfterDataEnd).is_some() {
        c.stream.shutdown(Shutdown::Both)?;
        return Ok(false);
    }
    c.reply(
        if chunked { Stage::Bdat } else { Stage::DataEnd },
        "250 2.0.0 queued",
    )?;
    *delivered += 1;
    if c.fault(|f| *f == Fault::CloseAfterMessages(*delivered))
        .is_some()
    {
        c.stream.shutdown(Shutdown::Both)?;
        return Ok(false);
    }
    Ok(true)
}

fn between(s: &str, open: char, close: char) -> String {
    let start = s.find(open).map_or(0, |i| i + 1);
    let end = s.rfind(close).unwrap_or(s.len());
    s.get(start..end).unwrap_or("").to_string()
}

/// The server side of SCRAM-SHA-256 for [`TestServer`]: salt and iteration
/// count fixed, nonce extended with a fixed suffix. `Some(true)` when the
/// client's proof is right (the server signature has been sent and
/// acknowledged), `Some(false)` when it is wrong, `None` on EOF.
#[cfg(feature = "scram")]
fn scram_server(
    c: &mut Conn<'_>,
    stage: Stage,
    client_first: &[u8],
    want_user: &str,
    password: &str,
) -> std::io::Result<Option<bool>> {
    use crypt_io::{hash::sha256, kdf::pbkdf2_hmac_sha256, mac::hmac_sha256};

    const SALT: &[u8] = b"smtp-net-test-salt";
    let b64 = |b: &[u8]| {
        let mut out = Vec::new();
        crate::encode::base64_append(b, &mut out);
        String::from_utf8_lossy(&out).into_owned()
    };
    let Some(bare) = client_first.strip_prefix(b"n,,") else {
        return Ok(Some(false));
    };
    let bare = String::from_utf8_lossy(bare).into_owned();
    let Some((name, nonce)) = bare.strip_prefix("n=").and_then(|b| b.split_once(",r=")) else {
        return Ok(Some(false));
    };
    let name = name.replace("=2C", ",").replace("=3D", "=");
    let server_first = format!("r={nonce}srv-test-nonce,s={},i=4096", b64(SALT));
    c.reply(stage, &format!("334 {}", b64(server_first.as_bytes())))?;
    let Some(l) = c.read_line()? else {
        return Ok(None);
    };
    c.log(
        "C: ",
        &format!("<redacted {} octets>", l.len().saturating_sub(2)),
    );
    let mut final_msg = Vec::new();
    let text = String::from_utf8_lossy(&l).trim_end().to_string();
    if crate::encode::base64_decode(text.as_bytes(), &mut final_msg).is_err() {
        return Ok(Some(false));
    }
    let final_msg = String::from_utf8_lossy(&final_msg).into_owned();
    let Some((without_proof, proof)) = final_msg.rsplit_once(",p=") else {
        return Ok(Some(false));
    };
    let mut salted = [0u8; 32];
    let mac = |k: &[u8], d: &[u8]| hmac_sha256(k, d).unwrap_or([0; 32]);
    if pbkdf2_hmac_sha256(password.as_bytes(), SALT, 4096, &mut salted).is_err() {
        return Ok(Some(false));
    }
    let stored = sha256(&mac(&salted, b"Client Key"));
    let auth_message = format!("{bare},{server_first},{without_proof}");
    let signature = mac(&stored, auth_message.as_bytes());
    let mut proof_bytes = Vec::new();
    let _ = crate::encode::base64_decode(proof.as_bytes(), &mut proof_bytes);
    let client_key: Vec<u8> = proof_bytes
        .iter()
        .zip(signature.iter())
        .map(|(p, s)| p ^ s)
        .collect();
    let expected_final = format!("c=biws,r={nonce}srv-test-nonce");
    if name != want_user || without_proof != expected_final || sha256(&client_key) != stored {
        return Ok(Some(false));
    }
    let server_sig = mac(&mac(&salted, b"Server Key"), auth_message.as_bytes());
    let fault = c.fault(|f| *f == Fault::BadScramSignature).is_some();
    let mut v = server_sig;
    if fault {
        v[0] ^= 1;
    }
    c.reply(
        stage,
        &format!("334 {}", b64(format!("v={}", b64(&v)).as_bytes())),
    )?;
    let Some(l) = c.read_line()? else {
        return Ok(None);
    };
    c.log("C: ", &format!("<{} octets>", l.len().saturating_sub(2)));
    Ok(Some(true))
}
