//! Prints the DNS TXT record to publish for a DKIM key.
//!
//! ```text
//! cargo run --example dkim_dns_record --features dkim -- dkim-rsa.pem rsa2026 example.com
//! ```
//!
//! The key file is PKCS#8 (`BEGIN PRIVATE KEY`, RSA or Ed25519) or PKCS#1
//! (`BEGIN RSA PRIVATE KEY`), as `openssl genpkey` writes them.

use smtp_net::{DkimKey, DkimSigner};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(selector), Some(domain)) = (args.next(), args.next(), args.next()) else {
        eprintln!("usage: dkim_dns_record <key.pem> <selector> <domain>");
        std::process::exit(2);
    };
    let pem = std::fs::read_to_string(&path)?;
    let key = DkimKey::rsa_from_pem(&pem).or_else(|_| DkimKey::ed25519_from_pkcs8_pem(&pem))?;
    // Checks the selector and domain the same way signing will.
    let signer = DkimSigner::new(&domain, &selector, key)?;
    println!(
        "{}._domainkey.{}. TXT \"{}\"",
        signer.selector(),
        signer.domain(),
        signer.key().dns_record()
    );
    Ok(())
}
