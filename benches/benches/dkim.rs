//! DKIM: canonicalization and signing (PLAN 11.1).
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use smtp_net::{BodyCanonicalizer, Canonicalization, DkimKey, DkimSigner};

fn message(body_len: usize) -> Vec<u8> {
    let mut m = b"From: Example <no-reply@example.com>\r\nTo: user@example.org\r\nSubject: Confirm your email address\r\nDate: Tue, 14 Nov 2023 22:13:20 +0000\r\nMessage-ID: <abc@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n".to_vec();
    let line = b"Please confirm your address by opening the link below.  Thanks!   \r\n";
    while m.len() < body_len {
        m.extend_from_slice(line);
    }
    m
}

fn bench(c: &mut Criterion) {
    let body = message(1 << 20);
    let mut g = c.benchmark_group("dkim");
    g.throughput(Throughput::Bytes(body.len() as u64));
    for (name, mode) in [("relaxed", Canonicalization::Relaxed), ("simple", Canonicalization::Simple)] {
        g.bench_function(format!("body_canon_{name}_1mib"), |b| {
            b.iter(|| {
                let mut n = 0usize;
                let mut canon = BodyCanonicalizer::new(mode);
                canon.update(black_box(&body), &mut |x| n += x.len());
                canon.finish(&mut |x| n += x.len());
                black_box(n)
            })
        });
    }
    g.finish();

    let msg = message(10 * 1024);
    let ed = DkimSigner::new("example.com", "ed", DkimKey::ed25519_from_seed(&[7; 32]).unwrap()).unwrap();
    let pem = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/dkim/rsa-2048.pem")).unwrap();
    let rsa = DkimSigner::new("example.com", "rsa", DkimKey::rsa_from_pem(&pem).unwrap()).unwrap();
    let mut out = Vec::with_capacity(1024);
    c.bench_function("dkim_sign_ed25519_10kib", |b| {
        b.iter(|| {
            out.clear();
            ed.sign_into(black_box(&msg), 1_700_000_000, &mut out).unwrap();
            black_box(out.len())
        })
    });
    c.bench_function("dkim_sign_rsa2048_10kib", |b| {
        b.iter(|| {
            out.clear();
            rsa.sign_into(black_box(&msg), 1_700_000_000, &mut out).unwrap();
            black_box(out.len())
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
