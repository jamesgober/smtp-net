//! The pacing gate (PLAN 11.1).
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use smtp_net::{HourlyLimit, SendGate};

fn bench(c: &mut Criterion) {
    let limit = HourlyLimit::messages(u32::MAX);
    let mut t = 1_700_000_000_000u64;
    c.bench_function("hourly_limit_admit_uncontended", |b| {
        b.iter(|| {
            t += 1;
            black_box(limit.admit(1, t))
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
