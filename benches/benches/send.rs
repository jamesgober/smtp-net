//! End to end over loopback against TestServer, at 0, 1, and 10 ms of
//! simulated round trip (PLAN 11.1, NFR-5): one connection, prepared
//! messages, with and without PIPELINING and CHUNKING.
use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use smtp_net::{Client, Message, PreparedMessage};
use smtp_net::testing::{Fault, TestServer};

fn prepared() -> PreparedMessage {
    Message::text("Example <no-reply@example.com>", "user@example.org", "Confirm your email address", "Open https://example.com/c/0123456789abcdef to confirm.\n")
        .unwrap()
        .prepare()
        .unwrap()
}

fn bench(c: &mut Criterion) {
    let msg = prepared();
    let mut g = c.benchmark_group("send");
    g.sample_size(10);
    for (rtt_ms, count) in [(0u64, 1000usize), (1, 50), (10, 10)] {
        for (label, pipelining, chunking) in [("pipelined_chunked", true, true), ("pipelined", true, false), ("plain", false, false)] {
            let mut b = TestServer::builder().extensions(&["PIPELINING", "CHUNKING", "8BITMIME", "SIZE 10485760"]);
            if rtt_ms > 0 {
                b = b.fault(Fault::RoundTrip(Duration::from_millis(rtt_ms)));
            }
            let server = b.start().unwrap();
            let s = server.server_builder().pipelining(pipelining).chunking(chunking).max_messages_per_connection(u32::MAX).build().unwrap();
            let mut client = Client::connect(&s).unwrap();
            g.bench_function(format!("{count}_messages_rtt_{rtt_ms}ms_{label}"), |bench| {
                bench.iter(|| {
                    for _ in 0..count {
                        black_box(client.send_prepared(&msg).unwrap());
                    }
                })
            });
        }
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
