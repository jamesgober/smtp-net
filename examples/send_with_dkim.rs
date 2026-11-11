//! Sends a message signed with Ed25519 and RSA under two selectors (RFC 8463
//! section 6), through the crate's `TestServer`, and prints the signature
//! headers it received.
//!
//! ```text
//! cargo run --example send_with_dkim --features testing,dkim
//! ```

use smtp_net::testing::TestServer;
use smtp_net::{DkimKey, DkimSigner, Message};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // In production: DkimKey::ed25519_from_pkcs8_pem(&std::fs::read_to_string(...)?)
    // or a seed from a key vault. Never a fixed seed like this one.
    let ed = DkimSigner::new(
        "example.com",
        "ed2026",
        DkimKey::ed25519_from_seed(&[42; 32])?,
    )?;
    let rsa_pem = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dkim/rsa-2048.pem"
    ))?;
    let rsa = DkimSigner::new("example.com", "rsa2026", DkimKey::rsa_from_pem(&rsa_pem)?)?;
    println!("publish: {}", ed.key().dns_record());

    let server = TestServer::start()?;
    let relay = server.server_builder().dkim(rsa).dkim(ed).build()?;
    let msg = Message::text(
        "Example <no-reply@example.com>",
        "user@example.org",
        "Your sign-in code",
        "Your code is 314159.",
    )?;
    smtp_net::send(&relay, &msg)?;

    let received = String::from_utf8_lossy(&server.received()[0].data).into_owned();
    let headers = received.split("\r\nFrom:").next().unwrap_or("");
    println!("{headers}");
    Ok(())
}
