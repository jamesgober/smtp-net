//! Counting-allocator tests for the "0 alloc" costs in docs/API.md (PLAN 12.6).

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use smtp_net::{
    Address, BodyFlags, Envelope, Event, Message, Millis, QpState, RandomSource, ReplyLimits,
    ReplyParser, Session, SessionConfig, SessionSecurity, base64_encode_lines, check_header_value,
    quoted_printable_encode, quoted_printable_finish,
};

struct Counting;

std::thread_local! {
    /// Allocations made by this thread; other test threads cannot touch it.
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}

fn bump() {
    let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
}

// SAFETY: forwards to the system allocator; only counts calls.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump();
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        bump();
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
        let mut st = QpState::new();
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
    s.begin(&env, BodyFlags::default(), 10, Millis(2)).unwrap();
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
