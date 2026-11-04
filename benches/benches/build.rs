//! Message build and serialization (PLAN 11.1, NFR-6).
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use smtp_net::{Attachment, Message, RandomSource};

struct Fixed;
impl RandomSource for Fixed {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), smtp_net::Error> {
        buf.fill(7);
        Ok(())
    }
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

fn bench(c: &mut Criterion) {
    c.bench_function("build_verification_text_html", |b| b.iter(|| black_box(verification())));
    let m = verification();
    let mut buf = Vec::with_capacity(m.encoded_len() as usize);
    c.bench_function("serialize_verification_text_html", |b| {
        b.iter(|| {
            buf.clear();
            m.write_to(&mut buf).unwrap();
            black_box(buf.len())
        })
    });
    let att = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .text("see attached")
        .unwrap()
        .attachment(Attachment::new("data.bin", "application/octet-stream", vec![0xa5; 1 << 20]).unwrap())
        .unwrap()
        .build_with(&mut Fixed, 1_700_000_000)
        .unwrap();
    let mut big = Vec::with_capacity(att.encoded_len() as usize);
    c.bench_function("serialize_1mib_attachment", |b| {
        b.iter(|| {
            big.clear();
            att.write_to(&mut big).unwrap();
            black_box(big.len())
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
