//! Every PLAN 11.1 target in one table, each the minimum over many short
//! batches, so a busy machine skews it far less than a mean. The criterion
//! benches (`cargo bench`) give the full distributions on a quiet machine.
//!
//! ```text
//! cargo run --release --example targets
//! ```
use std::hint::black_box as bb;
use std::time::{Duration, Instant};

use smtp_net::{Address, Canonicalization, DkimKey, DkimSigner, Envelope, HourlyLimit, Message, SendGate};
use smtp_net::dkim::BodyCanonicalizer;
use smtp_net::mime::{QuotedPrintableState, RandomSource};
use smtp_net::protocol::{BodyFlags, Millis, ReplyLimits, ReplyParser, Session, SessionConfig, SessionSecurity};

struct Fixed;
impl RandomSource for Fixed {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), smtp_net::Error> {
        buf.fill(7);
        Ok(())
    }
}

fn min_time(batches: u32, per: u32, mut f: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..batches {
        let t = Instant::now();
        for _ in 0..per {
            f();
        }
        best = best.min(t.elapsed() / per);
    }
    best
}

fn show(name: &str, target: &str, d: Duration, bytes: Option<usize>) {
    let ns = d.as_nanos() as f64;
    let t = if ns < 1e3 {
        format!("{ns:.0} ns")
    } else if ns < 1e6 {
        format!("{:.2} µs", ns / 1e3)
    } else {
        format!("{:.2} ms", ns / 1e6)
    };
    let rate = bytes.map(|b| format!(" ({:.2} GB/s)", b as f64 / d.as_secs_f64() / 1e9)).unwrap_or_default();
    println!("| {name} | {t}{rate} | {target} |");
}

const TEXT: &str = "Hello,\n\nPlease confirm your email address by opening this link:\nhttps://example.com/confirm/0123456789abcdef0123456789abcdef\n\nIf you did not create an account, ignore this message.\n\nThanks,\nThe Example team\n";
const HTML: &str = "<!doctype html><html><body><p>Hello,</p><p>Please confirm your email address by opening <a href=\"https://example.com/confirm/0123456789abcdef0123456789abcdef\">this link</a>.</p><p>If you did not create an account, ignore this message.</p><p>Thanks,<br>The Example team</p></body></html>\n";

fn verification() -> Message {
    Message::builder()
        .from("Example <no-reply@example.com>")
        .unwrap()
        .to("user@example.org")
        .unwrap()
        .subject("Confirm your email address")
        .unwrap()
        .text(TEXT)
        .unwrap()
        .html(HTML)
        .unwrap()
        .build_with(&mut Fixed, 1_700_000_000)
        .unwrap()
}

fn main() {
    println!("| Operation | Measured | Target (PLAN 11.1) |");
    println!("|---|---|---|");
    show(
        "Build and serialize a verification email",
        "at most 5 µs",
        min_time(300, 50, || drop(bb(verification().to_bytes().unwrap()))),
        None,
    );

    let data: Vec<u8> = (0..1u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    let att = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .text("see attached")
        .unwrap()
        .attachment(smtp_net::Attachment::new("d.bin", "application/octet-stream", data.clone()).unwrap())
        .unwrap()
        .build_with(&mut Fixed, 1_700_000_000)
        .unwrap();
    let mut big = Vec::with_capacity(att.encoded_len() as usize);
    show(
        "Serialize a message with a 1 MiB attachment",
        "at least 1.5 GB/s",
        min_time(30, 4, || {
            big.clear();
            att.write_to(&mut big).unwrap();
        }),
        Some(data.len()),
    );

    let mut out = vec![0u8; 3 << 20];
    show(
        "base64, 76-column lines",
        "at least 2 GB/s",
        min_time(30, 4, || {
            bb(smtp_net::mime::base64_encode_lines(&data, &mut out).unwrap());
        }),
        Some(data.len()),
    );
    let text = "Caf\u{e9} au lait, r\u{e9}sum\u{e9}, na\u{ef}ve. Plain words mostly, with = signs.\n".repeat(16_000);
    show(
        "quoted-printable",
        "at least 800 MB/s",
        min_time(30, 2, || {
            let mut st = QuotedPrintableState::new();
            let n = smtp_net::mime::quoted_printable_encode(text.as_bytes(), &mut out, &mut st).unwrap();
            bb(n + smtp_net::mime::quoted_printable_finish(&mut out[n..], &mut st).unwrap());
        }),
        Some(text.len()),
    );
    let value = "An ordinary subject line with nothing special in it at all ".repeat(64);
    show(
        "Header value check, 4 KiB",
        "at least 4 GB/s",
        min_time(300, 50, || {
            bb(smtp_net::mime::check_header_value("Subject", bb(&value)).unwrap());
        }),
        Some(value.len()),
    );

    let mut p = ReplyParser::new(ReplyLimits::default(), true);
    show(
        "Reply parsing, single line",
        "at most 50 ns",
        min_time(300, 100, || drop(bb(p.push(bb(b"250 2.1.0 Ok\r\n")).unwrap()))),
        None,
    );
    let ehlo = b"250-mx.example.com Hello\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n250-SMTPUTF8\r\n250-CHUNKING\r\n250-DSN\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n";
    show(
        "EHLO reply, 10 lines (parse and capabilities)",
        "at most 400 ns",
        min_time(300, 50, || {
            let (_, r) = p.push(bb(ehlo)).unwrap();
            bb(smtp_net::Capabilities::parse(&r.unwrap()).unwrap());
        }),
        None,
    );

    let body = b"Hello there, this is an ordinary line of text in a message body.\r\n.a dot line\r\n".repeat(13_000);
    let mut s = {
        let mut c = SessionConfig::default();
        c.security = SessionSecurity::Plaintext { peer_is_loopback: true };
        c.output_capacity = 64 * 1024;
        let mut s = Session::new(c, Millis(0)).unwrap();
        s.receive(b"220 x\r\n", Millis(1)).unwrap();
        s.transmitted(s.transmit().len());
        s.receive(b"250-x\r\n250 PIPELINING\r\n", Millis(1)).unwrap();
        s.transmitted(s.transmit().len());
        while s.poll_event().is_some() {}
        s
    };
    let env = Envelope::new(Address::parse("a@example.com").unwrap(), &[Address::parse("b@example.org").unwrap()]).unwrap();
    s.begin(&env, BodyFlags::default(), 0, Millis(2)).unwrap();
    s.transmitted(s.transmit().len());
    s.receive(b"250 ok\r\n250 ok\r\n354 go\r\n", Millis(3)).unwrap();
    while s.poll_event().is_some() {}
    show(
        "Dot-stuffing (session body path)",
        "at least 4 GB/s",
        min_time(20, 2, || {
            let mut rest = &body[..];
            while !rest.is_empty() {
                let k = s.body(rest, Millis(4)).unwrap();
                rest = &rest[k..];
                s.transmitted(s.transmit().len());
            }
        }),
        Some(body.len()),
    );

    let canon_body = b"Please confirm your address by opening the link below.  Thanks!   \r\n".repeat(16_000);
    show(
        "DKIM relaxed body canonicalization",
        "at least 2 GB/s",
        min_time(20, 2, || {
            let mut n = 0usize;
            let mut c = BodyCanonicalizer::new(Canonicalization::Relaxed);
            c.update(&canon_body, &mut |x| n += x.len());
            c.finish(&mut |x| n += x.len());
            bb(n);
        }),
        Some(canon_body.len()),
    );
    let mut msg = b"From: Example <no-reply@example.com>\r\nTo: user@example.org\r\nSubject: Confirm\r\nDate: Tue, 14 Nov 2023 22:13:20 +0000\r\nMessage-ID: <abc@example.com>\r\n\r\n".to_vec();
    while msg.len() < 10 * 1024 {
        msg.extend_from_slice(b"Please confirm your address by opening the link below.  Thanks!\r\n");
    }
    let ed = DkimSigner::new("example.com", "ed", DkimKey::ed25519_from_seed(&[7; 32]).unwrap()).unwrap();
    let pem = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/dkim/rsa-2048.pem")).unwrap();
    let rsa = DkimSigner::new("example.com", "rsa", DkimKey::rsa_from_pem(&pem).unwrap()).unwrap();
    let mut sig = Vec::with_capacity(1024);
    show(
        "DKIM Ed25519 signature, 10 KiB message",
        "at most 40 µs",
        min_time(200, 20, || {
            sig.clear();
            ed.sign_into(&msg, 1_700_000_000, &mut sig).unwrap();
        }),
        None,
    );
    show(
        "DKIM RSA-2048 signature, 10 KiB message",
        "at most 1.6 ms",
        min_time(40, 5, || {
            sig.clear();
            rsa.sign_into(&msg, 1_700_000_000, &mut sig).unwrap();
        }),
        None,
    );

    let limit = HourlyLimit::messages(u32::MAX);
    let one = smtp_net::Envelope::new(
        smtp_net::Address::parse("no-reply@example.com").unwrap(),
        &[smtp_net::Address::parse("user@example.org").unwrap()],
    )
    .unwrap();
    let mut t = 1_700_000_000_000u64;
    show(
        "HourlyLimit::admit, uncontended",
        "at most 30 ns",
        min_time(300, 1000, || {
            t += 1;
            bb(limit.admit(&one, t));
        }),
        None,
    );
}
