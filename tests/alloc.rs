//! Counting-allocator tests for the "0 alloc" costs in docs/API.md (PLAN 12.6).

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use smtp_net::mime::{
    Multipart, Part, QuotedPrintableState, RandomSource, base64_encode_lines, check_header_value,
    quoted_printable_encode, quoted_printable_finish,
};
use smtp_net::protocol::{
    BodyFlags, Event, Millis, ReplyLimits, ReplyParser, Session, SessionConfig, SessionSecurity,
};
use smtp_net::{Address, BuildError, Envelope, ErrorKind, Message};

struct Counting;

std::thread_local! {
    /// Allocations made by this thread; other test threads cannot touch it.
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    /// Bytes this thread holds (allocated minus freed).
    static LIVE: Cell<isize> = const { Cell::new(0) };
    /// The most `LIVE` has been since it was last reset.
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn bump() {
    let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
}

fn live(delta: isize) {
    let _ = LIVE.try_with(|c| {
        let now = c.get() + delta;
        c.set(now);
        let _ = PEAK.try_with(|p| p.set(p.get().max(now)));
    });
}

/// The most this thread held during `f`, above what it held before.
fn peak<R>(f: impl FnOnce() -> R) -> (isize, R) {
    let base = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(base));
    let r = f();
    (PEAK.with(Cell::get) - base, r)
}

// SAFETY: forwards to the system allocator; only counts calls.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump();
        live(layout.size() as isize);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        live(-(layout.size() as isize));
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        bump();
        live(new as isize - layout.size() as isize);
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn count<R>(f: impl FnOnce() -> R) -> (usize, R) {
    let before = ALLOCS.with(Cell::get);
    let r = f();
    (ALLOCS.with(Cell::get) - before, r)
}

struct Counter(u8);
impl RandomSource for Counter {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), smtp_net::Error> {
        for b in buf {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

#[test]
fn test_encoders_and_header_check_allocate_nothing() {
    let input: Vec<u8> = (0..10_000u32).map(|i| (i * 7) as u8).collect();
    let mut out = vec![0u8; 40_000];
    let (n, _) = count(|| base64_encode_lines(&input, &mut out).unwrap());
    assert_eq!(n, 0, "base64");
    let text = "caf\u{e9} = r\u{e9}sum\u{e9} \n.line\nFrom here\n".repeat(100);
    let (n, _) = count(|| {
        let mut st = QuotedPrintableState::new();
        let k = quoted_printable_encode(text.as_bytes(), &mut out, &mut st).unwrap();
        quoted_printable_finish(&mut out[k..], &mut st).unwrap()
    });
    assert_eq!(n, 0, "quoted-printable");
    let value = "A perfectly ordinary subject line\twith a tab".repeat(20);
    let (n, _) = count(|| check_header_value("Subject", &value).unwrap());
    assert_eq!(n, 0, "header check");
}

#[test]
fn test_write_to_presized_buffer_allocates_nothing() {
    let m = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .subject("Receipt")
        .unwrap()
        .text(&"caf\u{e9} line\n".repeat(200))
        .unwrap()
        .html(&"<p>\u{65e5}\u{672c}</p>\n".repeat(200))
        .unwrap()
        .attachment(
            smtp_net::Attachment::new("a.bin", "application/octet-stream", vec![7; 5000]).unwrap(),
        )
        .unwrap()
        .build_with(&mut Counter(0), 1_700_000_000)
        .unwrap();
    let mut buf = Vec::with_capacity(m.encoded_len() as usize);
    let (n, _) = count(|| m.write_to(&mut buf).unwrap());
    assert_eq!(n, 0, "write_to");
    assert_eq!(buf.len() as u64, m.encoded_len());
}

#[test]
fn test_text_plus_html_build_allocation_budget() {
    let (n, _) = count(|| {
        Message::builder()
            .from("Example <no-reply@example.com>")
            .unwrap()
            .to("user@example.org")
            .unwrap()
            .subject("Reset your password")
            .unwrap()
            .text("Reset: https://example.com/r/xyz")
            .unwrap()
            .html("<p>Reset: <a href=\"https://example.com/r/xyz\">link</a></p>")
            .unwrap()
            .build_with(&mut Counter(0), 1_700_000_000)
            .unwrap()
    });
    // 97 at 0.3.0, 21 at 0.6.0 (D-083): five setters store their input, and
    // the message owns its head, header index, parts, and id. The PLAN 11.1
    // estimate of 8 is recorded as missed with that reason.
    assert!(n <= 21, "{n} allocations");
    println!("text plus HTML build: {n} allocations");
}

fn ready() -> Session {
    let mut c = SessionConfig::default();
    c.security = SessionSecurity::Plaintext {
        peer_is_loopback: true,
    };
    let mut s = Session::new(c, Millis(0)).unwrap();
    s.receive(b"220 x\r\n", Millis(1)).unwrap();
    s.transmitted(s.transmit().len());
    s.receive(b"250-x\r\n250 PIPELINING\r\n", Millis(1))
        .unwrap();
    while s.poll_event().is_some() {}
    s
}

#[test]
fn test_session_body_and_positive_replies_allocate_nothing() {
    let mut s = ready();
    let env = Envelope::new(
        Address::parse("a@example.com").unwrap(),
        &[Address::parse("b@example.org").unwrap()],
    )
    .unwrap();
    // The envelope is shared, not copied (D-084): MAIL and RCPT are written
    // into the preallocated output.
    let (n, _) = count(|| s.begin(&env, BodyFlags::default(), 10, Millis(2)).unwrap());
    assert_eq!(n, 0, "begin");
    s.transmitted(s.transmit().len());
    let (n, _) = count(|| {
        s.receive(b"250 ok\r\n250 ok\r\n354 go\r\n", Millis(3))
            .unwrap()
    });
    assert_eq!(n, 0, "MAIL, RCPT, DATA replies");
    while let Some(e) = s.poll_event() {
        let _ = matches!(e, Event::BodyWanted);
    }
    let body = b"line one\r\n.dot line\r\n".repeat(100);
    let (n, _) = count(|| {
        let mut rest = &body[..];
        while !rest.is_empty() {
            let k = s.body(rest, Millis(4)).unwrap();
            rest = &rest[k..];
            s.transmitted(s.transmit().len());
        }
        s.end_body(Millis(5)).unwrap();
    });
    assert_eq!(n, 0, "body and end_body");
}

#[test]
fn test_reply_parser_allocates_once_per_owned_reply() {
    let mut p = ReplyParser::new(ReplyLimits::default(), true);
    let (n, r) = count(|| p.push(b"250-a\r\n250-b\r\n250 2.0.0 c\r\n").unwrap());
    assert!(r.1.is_some());
    assert!(n <= 1, "{n}");
}

#[test]
fn test_session_memory() {
    // PLAN 11.1: a ready session holding one transaction. The output buffer
    // is SessionConfig::output_capacity (16 KiB by default); the rest is the
    // reply buffer, capabilities, and the transaction (D-085).
    let env = Envelope::new(
        Address::parse("a@example.com").unwrap(),
        &[Address::parse("b@example.org").unwrap()],
    )
    .unwrap();
    let before = LIVE.with(Cell::get);
    let mut s = ready();
    s.begin(&env, BodyFlags::default(), 10, Millis(2)).unwrap();
    let total = LIVE.with(Cell::get) - before;
    println!("session memory: {total} bytes");
    assert!(total <= 16 * 1024 + 3 * 1024, "{total} bytes");
    let mut small = SessionConfig::default();
    small.output_capacity = 4096;
    let before = LIVE.with(Cell::get);
    let session = Session::new(small, Millis(0)).unwrap();
    let small_total = LIVE.with(Cell::get) - before;
    println!("session with a 4 KiB output buffer: {small_total} bytes");
    assert!(small_total <= 4096 + 3 * 1024, "{small_total} bytes");
    drop(session);
}

#[test]
fn test_t12_reply_flood_stays_within_the_budget() {
    // T-12: a 10 MiB line and 100,000 continuation lines, fed in network
    // sized pieces, are refused while the parser holds no more than its
    // budget (8,192 octets of reply by default).
    let limits = ReplyLimits::default();
    let budget = limits.max_total as isize + 4096;
    let mut line = b"250 ".to_vec();
    line.resize(10 << 20, b'x');
    line.extend_from_slice(b"\r\n");
    let continuation = b"250-x\r\n".repeat(100_000);
    for (name, input) in [("10 MiB line", &line), ("100,000 lines", &continuation)] {
        let mut p = ReplyParser::new(limits, true);
        let (held, refused) = peak(|| {
            for piece in input.chunks(4096) {
                let mut rest = piece;
                while !rest.is_empty() {
                    match p.push(rest) {
                        Ok((n, _)) if n > 0 => rest = &rest[n..],
                        Ok(_) => break,
                        Err(e) => return Some(e),
                    }
                }
            }
            None
        });
        assert!(refused.is_some(), "{name}: not refused");
        assert!(held <= budget, "{name}: held {held} octets");
    }
}

#[test]
fn test_t26_huge_trees_refused_before_encoding() {
    // T-26: 10,000 parts and depth 100 are
    // refused at build, before anything is encoded: the build itself holds
    // little beyond what the caller gave it.
    let from = |b: smtp_net::MessageBuilder| {
        b.from("a@example.com")
            .unwrap()
            .to("b@example.org")
            .unwrap()
    };
    let many: Vec<Part> = (0..10_000)
        .map(|_| Part::text("text/plain", "x").unwrap())
        .collect();
    let b = from(Message::builder()).body(Part::multipart(Multipart::Mixed, many));
    let (held, r) = peak(|| b.build_with(&mut Counter(0), 0));
    assert!(matches!(
        r.unwrap_err().kind(),
        ErrorKind::Build(BuildError::TooManyParts)
    ));
    assert!(held <= 64 * 1024, "10,000 parts: held {held} octets");

    let mut p = Part::text("text/plain", "x").unwrap();
    for _ in 0..99 {
        p = Part::multipart(Multipart::Mixed, vec![p]);
    }
    let b = from(Message::builder()).body(p);
    let (held, r) = peak(|| b.build_with(&mut Counter(0), 0));
    assert!(matches!(
        r.unwrap_err().kind(),
        ErrorKind::Build(BuildError::DepthExceeded)
    ));
    assert!(held <= 64 * 1024, "depth 100: held {held} octets");
}

#[cfg(feature = "std")]
#[test]
fn test_t26_gib_attachment_refused_when_added() {
    // T-26: a 1 GiB streamed attachment is refused from its declared length
    // as soon as it is added; nothing is read.
    let gib = smtp_net::Attachment::from_source(
        "big.bin",
        "application/octet-stream",
        1 << 30,
        Box::new(smtp_net::mime::ReadSource::new(std::io::repeat(0))),
    )
    .unwrap();
    let b = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.org")
        .unwrap();
    let (held, r) = peak(|| b.attachment(gib));
    assert!(matches!(
        r.unwrap_err().kind(),
        ErrorKind::Build(BuildError::TooLarge { .. })
    ));
    assert!(held <= 64 * 1024, "1 GiB: held {held} octets");
}
