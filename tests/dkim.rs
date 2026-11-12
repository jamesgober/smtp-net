//! 0.5 DKIM end to end: `ServerBuilder::dkim` signs what `send` sends,
//! `send_prepared` never re-signs, raw input is signed, and several
//! signatures stack (PLAN 7.10, FR-43 to FR-46, FR-53, O-23).
//!
//! With `SMTP_NET_DKIM_CORPUS=<dir>` set, the corpus test also writes signed
//! messages and their DNS records for the independent verifier that CI runs
//! (`.github/scripts/dkim_verify.py`, dkimpy): files named `pass-*.eml` must
//! verify, `fail-*.eml` (changed after signing) must not.

use std::fmt::Write as _;

use smtp_net::testing::TestServer;
use smtp_net::{
    Address, Attachment, Canonicalization, ConfigError, DkimKey, DkimSigner, Envelope, ErrorKind,
    Message, PreparedMessage,
};

const RFC8032_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/dkim/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn ed25519() -> DkimSigner {
    DkimSigner::new(
        "example.com",
        "ed2026",
        DkimKey::ed25519_from_seed(&RFC8032_SEED).unwrap(),
    )
    .unwrap()
}

fn rsa(file: &str) -> DkimSigner {
    DkimSigner::new(
        "example.com",
        "rsa2026",
        DkimKey::rsa_from_pem(&fixture(file)).unwrap(),
    )
    .unwrap()
}

fn msg() -> Message {
    Message::text(
        "Example <no-reply@example.com>",
        "user@example.org",
        "Confirm your address",
        "Open https://example.com/c/abc to confirm.\n",
    )
    .unwrap()
}

#[test]
fn test_send_signs_with_every_server_signer() {
    let server = TestServer::start().unwrap();
    let s = server
        .server_builder()
        .dkim(ed25519())
        .dkim(rsa("rsa-2048.pem"))
        .build()
        .unwrap();
    smtp_net::send(&s, &msg()).unwrap();
    let data = &server.received()[0].data;
    let text = String::from_utf8_lossy(data);
    assert!(
        text.starts_with("DKIM-Signature: v=1; a=ed25519-sha256;"),
        "{text}"
    );
    assert_eq!(text.matches("DKIM-Signature: ").count(), 2);
    assert!(text.contains("a=rsa-sha256;"));
}

#[test]
fn test_send_prepared_never_resigns() {
    let server = TestServer::start().unwrap();
    let s = server.server_builder().dkim(ed25519()).build().unwrap();
    let plain = msg().prepare().unwrap();
    smtp_net::send_prepared(&s, &plain).unwrap();
    let signed = msg()
        .prepare()
        .unwrap()
        .sign(&[ed25519()], 1_700_000_000)
        .unwrap();
    smtp_net::send_prepared(&s, &signed).unwrap();
    let got = server.received();
    assert!(!got[0].data.starts_with(b"DKIM-Signature"));
    assert_eq!(got[1].data, signed.bytes());
    // The job payload keeps the signature: retries send the same bytes.
    assert_eq!(PreparedMessage::decode(&signed.encode()).unwrap(), signed);
}

#[test]
fn test_too_many_signers_refused() {
    let mut b = smtp_net::Server::local();
    let mut builder = b.to_builder();
    for _ in 0..5 {
        builder = builder.dkim(ed25519());
    }
    let e = builder.build().unwrap_err();
    assert_eq!(
        e.kind(),
        &ErrorKind::Config(ConfigError::TooManyDkimSigners)
    );
    b = smtp_net::Server::local();
    assert!(format!("{b:?}").contains("dkim: []"));
}

#[test]
fn test_raw_input_is_signed() {
    let env = Envelope::new(
        Address::parse("a@example.com").unwrap(),
        &[Address::parse("b@example.org").unwrap()],
    )
    .unwrap();
    let raw = b"From: a@example.com\r\nSubject: raw\r\n\r\nbody\r\n".to_vec();
    let p = PreparedMessage::from_raw(env, raw.clone()).unwrap();
    let signed = p.clone().sign(&[ed25519()], 0).unwrap();
    assert!(signed.bytes().ends_with(&raw));
    assert_eq!(p.sign(&[], 0).unwrap().bytes(), &raw[..]);
}

fn rich() -> Message {
    Message::builder()
        .from("Example Shop <orders@example.com>")
        .unwrap()
        .to("Ana Müller <ana@example.org>")
        .unwrap()
        .cc("team@example.org")
        .unwrap()
        .subject("Your order 1042 has shipped: here is everything you need to know about the delivery window")
        .unwrap()
        .text("Thanks for your order.\n\nTrailing spaces here   \n\n\n")
        .unwrap()
        .html("<p>Thanks for your order.</p>")
        .unwrap()
        .attachment(Attachment::new("invoice.pdf", "application/pdf", vec![0x25, 0x50, 0x44, 0x46, 0, 1, 2, 255]).unwrap())
        .unwrap()
        .date_unix(1_700_000_000)
        .build()
        .unwrap()
}

/// Writes the corpus for the independent verifier when asked to.
#[test]
fn test_write_verifier_corpus() {
    let Ok(dir) = std::env::var("SMTP_NET_DKIM_CORPUS") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut records = String::new();
    let mut signers = Vec::new();
    for (selector, key) in [
        ("ed", DkimKey::ed25519_from_seed(&RFC8032_SEED).unwrap()),
        (
            "edpem",
            DkimKey::ed25519_from_pkcs8_pem(&fixture("ed25519.pem")).unwrap(),
        ),
        (
            "rsa2048",
            DkimKey::rsa_from_pem(&fixture("rsa-2048.pem")).unwrap(),
        ),
        (
            "rsa2048p1",
            DkimKey::rsa_from_pem(&fixture("rsa-2048-pkcs1.pem")).unwrap(),
        ),
        (
            "rsa4096",
            DkimKey::rsa_from_pem(&fixture("rsa-4096.pem")).unwrap(),
        ),
    ] {
        writeln!(
            records,
            "{selector}._domainkey.example.com.\t{}",
            key.dns_record()
        )
        .unwrap();
        signers.push((selector, key));
    }
    std::fs::write(dir.join("records.txt"), records).unwrap();

    let modes = [
        ("rr", Canonicalization::Relaxed, Canonicalization::Relaxed),
        ("ss", Canonicalization::Simple, Canonicalization::Simple),
        ("rs", Canonicalization::Relaxed, Canonicalization::Simple),
        ("sr", Canonicalization::Simple, Canonicalization::Relaxed),
    ];
    let messages = [("plain", msg()), ("rich", rich())];
    for (selector, key) in &signers {
        for (mode, h, b) in modes {
            let signer = DkimSigner::new("example.com", selector, key.clone())
                .unwrap()
                .canonicalization(h, b)
                .expiry(86_400)
                .identity(&Address::parse("orders@mail.example.com").unwrap())
                .unwrap();
            for (name, m) in &messages {
                let signed = m
                    .prepare()
                    .unwrap()
                    .sign(std::slice::from_ref(&signer), now)
                    .unwrap();
                let bytes = signed.bytes();
                let file = |kind: &str| dir.join(format!("{kind}-{selector}-{mode}-{name}.eml"));
                std::fs::write(file("pass"), bytes).unwrap();
                let text = String::from_utf8_lossy(bytes).into_owned();
                // T-20: a second Subject added in transit.
                let added =
                    text.replacen("\r\nSubject: ", "\r\nSubject: Win a prize\r\nSubject: ", 1);
                std::fs::write(file("fail-added-subject"), added).unwrap();
                // T-19: content appended to the body.
                let appended = format!("{text}Appended after signing.\r\n");
                std::fs::write(file("fail-appended"), appended).unwrap();
            }
        }
    }
    // Two signatures on one message, each checked by the verifier.
    let pair = msg()
        .prepare()
        .unwrap()
        .sign(
            &[
                DkimSigner::new("example.com", "rsa2048", signers[2].1.clone()).unwrap(),
                DkimSigner::new("example.com", "ed", signers[0].1.clone()).unwrap(),
            ],
            now,
        )
        .unwrap();
    std::fs::write(dir.join("pass-pair-rsa-ed.eml"), pair.bytes()).unwrap();
}
