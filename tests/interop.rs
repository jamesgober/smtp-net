//! Interop against real mail servers (PLAN 12.8). Runs only when
//! `SMTP_NET_INTEROP_PORT` is set (the CI interop job starts Mailpit and Exim
//! and sets it); otherwise every test returns at once.
//!
//! `SMTP_NET_INTEROP_TO` is the recipient (default `user@example.org`). Each
//! test prints the `Message-ID` it sent so the job can look it up in the
//! server's mailbox.

use smtp_net::{Attachment, Client, Inline, Message, Security, Server};

fn target() -> Option<(Server, String)> {
    let port: u16 = std::env::var("SMTP_NET_INTEROP_PORT").ok()?.parse().ok()?;
    let to =
        std::env::var("SMTP_NET_INTEROP_TO").unwrap_or_else(|_| "user@example.org".to_string());
    let server = Server::builder("127.0.0.1", Security::PlaintextLoopback)
        .port(port)
        .build()
        .ok()?;
    Some((server, to))
}

fn shapes(to: &str) -> Vec<Message> {
    let from = "Example <no-reply@example.com>";
    vec![
        Message::text(
            from,
            to,
            "Confirm your email address",
            "Open this link to confirm:\nhttps://example.com/confirm/abc123\n",
        )
        .unwrap(),
        Message::html(
            from,
            to,
            "Reset your password",
            "<p>Reset: <a href=\"https://example.com/r/xyz\">link</a></p>",
            "Reset: https://example.com/r/xyz",
        )
        .unwrap(),
        Message::builder()
            .from(from)
            .unwrap()
            .to(to)
            .unwrap()
            .subject("R\u{e9}sum\u{e9}: caf\u{e9} \u{65e5}\u{672c}")
            .unwrap()
            .text(".leading dot\nFrom the start\ncaf\u{e9}\n")
            .unwrap()
            .html("<p>logo <img src=\"cid:logo@example.com\"></p>")
            .unwrap()
            .inline(
                Inline::new(
                    "logo@example.com",
                    "image/png",
                    vec![0x89, b'P', b'N', b'G', 13, 10, 26, 10],
                )
                .unwrap(),
            )
            .unwrap()
            .attachment(
                Attachment::new(
                    "r\u{e9}sum\u{e9}.pdf",
                    "application/pdf",
                    b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec(),
                )
                .unwrap(),
            )
            .unwrap()
            .build()
            .unwrap(),
    ]
}

#[test]
fn test_interop_every_shape_one_connection() {
    let Some((server, to)) = target() else { return };
    let mut client = Client::connect(&server).unwrap();
    for m in shapes(&to) {
        let report = client.send(&m).unwrap();
        println!("SENT {}", report.message_id());
    }
    client.close().unwrap();
}

#[test]
fn test_interop_tier1_send() {
    let Some((server, to)) = target() else { return };
    let m = Message::text("no-reply@example.com", &to, "Tier 1", "one call").unwrap();
    let report = smtp_net::send(&server, &m).unwrap();
    println!("SENT {}", report.message_id());
}
