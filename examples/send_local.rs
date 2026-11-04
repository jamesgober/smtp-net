//! Sends a verification email through the mail server on this machine
//! (for example cPanel's Exim on 127.0.0.1:25).
//!
//! ```text
//! cargo run --example send_local -- user@example.org
//! ```
//!
//! Set `SMTP_PORT` to use another port, such as a local Mailpit on 1025.

fn main() {
    let to = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "user@example.org".to_string());
    let port = std::env::var("SMTP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(smtp_net::PORT_SMTP);
    let result = smtp_net::Message::text(
        "Example <no-reply@example.com>",
        &to,
        "Confirm your email address",
        "Open this link to confirm: https://example.com/confirm/abc123",
    )
    .and_then(|msg| {
        let server = smtp_net::Server::builder("127.0.0.1", smtp_net::Security::PlaintextLoopback)
            .port(port)
            .build()?;
        smtp_net::send(&server, &msg)
    });
    match result {
        Ok(report) => println!(
            "accepted as {}: {}",
            report.message_id(),
            report.final_reply().text_lossy()
        ),
        Err(e) if e.possibly_delivered() => {
            eprintln!("unknown outcome, the server may have the message: {e}")
        }
        Err(e) if e.is_temporary() => eprintln!("temporary failure, retry later: {e}"),
        Err(e) => eprintln!("permanent failure, do not retry: {e}"),
    }
}
