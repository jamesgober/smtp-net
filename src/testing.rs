//! Test support (feature `testing`): a scripted sans-IO peer driven by
//! conversation transcripts, and a blocking loopback SMTP server with fault
//! injection.

use std::{
    format,
    io::{BufRead, BufReader, Write},
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

use crate::{
    client::{Security, Server},
    error::{Error, ErrorKind, Stage},
    message::prepared::PreparedMessage,
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
    /// Bytes the server sends (with CRLF).
    Server(Vec<u8>),
    /// The server closes the connection.
    Eof,
    /// Time passes beyond every deadline.
    Timeout,
}

/// A conversation as data: `C: ` lines the client must send, `S: ` lines the
/// server answers with. `C: <BODY>` stands for the message body through the
/// end-of-data line; `S: <EOF>` closes the connection; `S: <TIMEOUT>` lets
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
                if c == "<BODY>" {
                    Entry::ClientBody
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
    /// Send these plaintext bytes right after the `220` to STARTTLS.
    InjectAfterStartTls(&'static [u8]),
    /// Never advertise STARTTLS.
    OmitStartTls,
    /// Answer `stage` with a reply that is not valid SMTP.
    MalformedReply(Stage),
    /// Answer `stage` with a 2,000-octet line.
    OversizedReply(Stage),
    /// Answer `stage` twice.
    ExtraReply(Stage),
    /// Refuse the recipient at this zero-based index with `550 5.1.1`.
    RejectRecipient(usize),
    /// Answer `452 4.5.3` to every recipient after the first `n`.
    TooManyRecipientsAfter(usize),
    /// Send replies at this many bytes per second.
    SlowDrip {
        /// The rate.
        bytes_per_second: u32,
    },
}

/// A message as the [`TestServer`] received it.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedMessage {
    /// The reverse-path, without angle brackets (empty for `<>`).
    pub from: String,
    /// The forward-paths the server accepted.
    pub recipients: Vec<String>,
    /// The MAIL parameters (`SIZE=...`, `BODY=8BITMIME`, ...).
    pub mail_parameters: Vec<String>,
    /// The message bytes after dot-unstuffing, CRLF line endings.
    pub data: Vec<u8>,
}

#[derive(Default)]
struct Shared {
    received: Vec<ReceivedMessage>,
    transcript: String,
    connections: usize,
}

/// Configures a [`TestServer`].
#[must_use]
#[derive(Clone, Debug)]
pub struct TestServerBuilder {
    extensions: Vec<String>,
    faults: Vec<Fault>,
    ehlo_refused: bool,
}

impl TestServerBuilder {
    /// Replaces the advertised extensions (default: `PIPELINING`, `8BITMIME`,
    /// `SIZE 10485760`, `ENHANCEDSTATUSCODES`, `SMTPUTF8`).
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
        let (s, st) = (Arc::clone(&shared), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if st.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let (s, c) = (Arc::clone(&s), Arc::clone(&config));
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
        })
    }
}

/// A blocking SMTP server on `127.0.0.1` for tests: it speaks enough SMTP to
/// accept, record, and misbehave on command. Stops when dropped.
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
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            faults: Vec::new(),
            ehlo_refused: false,
        }
    }

    /// The port it listens on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// A [`Server`] pointing at it (plaintext loopback, short timeouts).
    #[must_use]
    pub fn server(&self) -> Server {
        Server::builder("127.0.0.1", Security::PlaintextLoopback)
            .port(self.port())
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

    /// The conversation so far, `C: ` and `S: ` lines; message bodies omitted.
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

struct Conn<'a> {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
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
        if let Some(Fault::SlowDrip { bytes_per_second }) =
            self.fault(|f| matches!(f, Fault::SlowDrip { .. }))
        {
            let gap = Duration::from_secs(1) / (*bytes_per_second).max(1);
            for b in bytes {
                self.writer.write_all(core::slice::from_ref(b))?;
                thread::sleep(gap);
            }
            return Ok(());
        }
        self.writer.write_all(bytes)
    }

    fn closes_at(&self, stage: Stage) -> bool {
        self.fault(|f| *f == Fault::CloseAt(stage)).is_some()
    }

    fn read_line(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        let n = self.reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(line))
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
    let writer = stream.try_clone()?;
    let mut c = Conn {
        reader: BufReader::new(stream),
        writer,
        cfg,
        shared,
    };
    if c.closes_at(Stage::Greeting) {
        return c.writer.shutdown(Shutdown::Both);
    }
    c.reply(Stage::Greeting, "220 test.smtp-net.invalid ESMTP")?;
    let mut from: Option<(String, Vec<String>)> = None;
    let mut rcpts: Vec<String> = Vec::new();
    let mut rcpt_index = 0usize;
    let mut delivered = 0usize;
    while let Some(raw) = c.read_line()? {
        let line = String::from_utf8_lossy(raw.strip_suffix(b"\r\n").unwrap_or(&raw)).into_owned();
        c.log("C: ", &line);
        let upper = line.to_ascii_uppercase();
        let verb = upper.split(' ').next().unwrap_or("").to_string();
        let stage = match verb.as_str() {
            "EHLO" => Stage::Ehlo,
            "HELO" => Stage::Helo,
            "MAIL" => Stage::Mail,
            "RCPT" => Stage::Rcpt,
            "DATA" => Stage::Data,
            "RSET" => Stage::Rset,
            "NOOP" => Stage::Noop,
            "QUIT" => Stage::Quit,
            "STARTTLS" => Stage::StartTls,
            _ => Stage::Total,
        };
        if c.closes_at(stage) {
            return c.writer.shutdown(Shutdown::Both);
        }
        match stage {
            Stage::Ehlo if cfg.ehlo_refused => c.reply(stage, "502 5.5.1 EHLO not implemented")?,
            Stage::Ehlo => {
                let mut lines = vec!["250-test.smtp-net.invalid".to_string()];
                for e in &cfg.extensions {
                    if e.eq_ignore_ascii_case("STARTTLS")
                        && c.fault(|f| *f == Fault::OmitStartTls).is_some()
                    {
                        continue;
                    }
                    lines.push(format!("250-{e}"));
                }
                if let Some(last) = lines.last_mut() {
                    *last = last.replacen("250-", "250 ", 1);
                }
                c.reply(stage, &lines.join("\n"))?;
            }
            Stage::Helo => c.reply(stage, "250 test.smtp-net.invalid")?,
            Stage::StartTls => {
                c.reply(stage, "220 2.0.0 go ahead")?;
                if let Some(Fault::InjectAfterStartTls(b)) =
                    c.fault(|f| matches!(f, Fault::InjectAfterStartTls(_)))
                {
                    let b: &[u8] = b;
                    c.write(b)?;
                }
                // No TLS engine here: the client either handshakes (and fails) or leaves.
                return Ok(());
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
                    rcpts.push(between(&line, '<', '>'));
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
                let (path, params) = from.take().unwrap_or_default();
                if let Ok(mut s) = shared.lock() {
                    s.received.push(ReceivedMessage {
                        from: path,
                        recipients: core::mem::take(&mut rcpts),
                        mail_parameters: params,
                        data,
                    });
                }
                if c.fault(|f| *f == Fault::CloseAfterDataEnd).is_some() {
                    return c.writer.shutdown(Shutdown::Both);
                }
                c.reply(Stage::DataEnd, "250 2.0.0 queued")?;
                delivered += 1;
                if c.fault(|f| *f == Fault::CloseAfterMessages(delivered))
                    .is_some()
                {
                    return c.writer.shutdown(Shutdown::Both);
                }
            }
            Stage::Rset => {
                from = None;
                rcpts.clear();
                rcpt_index = 0;
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

fn between(s: &str, open: char, close: char) -> String {
    let start = s.find(open).map_or(0, |i| i + 1);
    let end = s.rfind(close).unwrap_or(s.len());
    s.get(start..end).unwrap_or("").to_string()
}
