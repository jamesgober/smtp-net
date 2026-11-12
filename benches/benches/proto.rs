//! Reply parsing and the session's hot paths (PLAN 11.1).
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use smtp_net::{Address, Envelope};
use smtp_net::protocol::{BodyFlags, Millis, ReplyLimits, ReplyParser, Session, SessionConfig, SessionSecurity};

fn ready() -> Session {
    let mut c = SessionConfig::default();
    c.security = SessionSecurity::Plaintext { peer_is_loopback: true };
    let mut s = Session::new(c, Millis(0)).unwrap();
    s.receive(b"220 x\r\n", Millis(1)).unwrap();
    s.transmitted(s.transmit().len());
    s.receive(b"250-x\r\n250 PIPELINING\r\n", Millis(1)).unwrap();
    while s.poll_event().is_some() {}
    s
}

fn bench(c: &mut Criterion) {
    let mut p = ReplyParser::new(ReplyLimits::default(), true);
    c.bench_function("reply_single_line", |b| b.iter(|| black_box(p.push(b"250 2.1.5 Recipient ok\r\n").unwrap())));
    let ehlo = b"250-mx.example.com Hello [127.0.0.1]\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-PIPELINING\r\n250-PIPE_CONNECT\r\n250-AUTH PLAIN LOGIN\r\n250-CHUNKING\r\n250-STARTTLS\r\n250-SMTPUTF8\r\n250 HELP\r\n";
    c.bench_function("reply_ehlo_10_lines", |b| b.iter(|| black_box(p.push(ehlo).unwrap())));
    let body = b"A line of ordinary message text that is about this long.\r\n".repeat(17_000);
    let env = Envelope::new(Address::parse("a@example.com").unwrap(), &[Address::parse("b@example.org").unwrap()]).unwrap();
    let mut g = c.benchmark_group("session");
    g.throughput(Throughput::Bytes(body.len() as u64));
    g.bench_function("dot_stuff_1mib", |b| {
        b.iter_batched(
            || {
                let mut s = ready();
                s.begin(&env, BodyFlags::default(), 1, Millis(2)).unwrap();
                s.transmitted(s.transmit().len());
                s.receive(b"250 ok\r\n250 ok\r\n354 go\r\n", Millis(3)).unwrap();
                while s.poll_event().is_some() {}
                s
            },
            |mut s| {
                let mut rest = &body[..];
                while !rest.is_empty() {
                    let n = s.body(rest, Millis(4)).unwrap();
                    rest = &rest[n..];
                    s.transmitted(s.transmit().len());
                }
                s.end_body(Millis(5)).unwrap();
                black_box(s.transmit().len())
            },
            criterion::BatchSize::SmallInput,
        )
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
