//! Encoders and the header gate (PLAN 11.1).
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use smtp_net::mime::{QuotedPrintableState, base64_encode_lines, check_header_value, encode_word, quoted_printable_encode, quoted_printable_finish};

fn bench(c: &mut Criterion) {
    let data: Vec<u8> = (0..1u32 << 20).map(|i| (i * 2_654_435_761u32 >> 24) as u8).collect();
    let mut out = vec![0u8; 3 << 20];
    let mut g = c.benchmark_group("encode");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("base64_1mib", |b| b.iter(|| black_box(base64_encode_lines(&data, &mut out).unwrap())));
    let text = "Caf\u{e9} au lait, r\u{e9}sum\u{e9}, na\u{ef}ve. Plain words mostly, with = signs.\n".repeat(16_000);
    g.throughput(Throughput::Bytes(text.len() as u64));
    g.bench_function("quoted_printable_1mib", |b| {
        b.iter(|| {
            let mut st = QuotedPrintableState::new();
            let n = quoted_printable_encode(text.as_bytes(), &mut out, &mut st).unwrap();
            black_box(n + quoted_printable_finish(&mut out[n..], &mut st).unwrap())
        })
    });
    let value = "An ordinary subject line with nothing special in it at all ".repeat(64);
    g.throughput(Throughput::Bytes(value.len() as u64));
    g.bench_function("check_header_value_4kib", |b| b.iter(|| check_header_value("Subject", black_box(&value)).unwrap()));
    g.finish();
    let mut w = String::with_capacity(256);
    c.bench_function("encode_word_subject", |b| {
        b.iter(|| {
            w.clear();
            encode_word(black_box("R\u{e9}initialisez votre mot de passe"), &mut w).unwrap();
            black_box(w.len())
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
