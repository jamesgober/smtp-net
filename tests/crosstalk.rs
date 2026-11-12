//! A refused transaction must leave nothing on the connection for the next
//! message. `TestServer` answers a MAIL inside an open transaction with
//! `503 5.5.1` and keeps the open transaction, as Postfix does, so a MAIL or
//! RCPT line left queued by a failed send would add its recipients to the
//! next message on the same connection.

use smtp_net::{
    Address, BuildError, Client, Dsn, DsnNotify, Envelope, ErrorKind, Pool, PreparedMessage, Stage,
    TestServer,
};

/// 64 + 1 + 182 octets: with DSN its RCPT line passes 512 octets.
fn long_address() -> Address {
    let domain = format!(
        "{}.{}.{}.com",
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(50)
    );
    Address::parse(&format!("{}@{domain}", "a".repeat(64))).unwrap()
}

/// An invitation to two recipients the sender chose, the second too long
/// for its RCPT line with DSN parameters.
fn invitation() -> PreparedMessage {
    let envelope = Envelope::new(
        Address::parse("no-reply@example.com").unwrap(),
        &[
            Address::parse("attacker@evil.example").unwrap(),
            long_address(),
        ],
    )
    .unwrap()
    .dsn(Dsn::new(DsnNotify::FAILURE));
    PreparedMessage::from_raw(
        envelope,
        b"From: no-reply@example.com\r\nSubject: invite\r\n\r\nYou are invited.\r\n".to_vec(),
    )
    .unwrap()
}

/// Another user's password reset, next on the same connection.
fn reset() -> PreparedMessage {
    let envelope = Envelope::new(
        Address::parse("no-reply@example.com").unwrap(),
        &[Address::parse("victim@example.org").unwrap()],
    )
    .unwrap();
    PreparedMessage::from_raw(
        envelope,
        b"From: no-reply@example.com\r\nTo: victim@example.org\r\nSubject: reset\r\n\r\nReset: https://example.com/r/SECRET-TOKEN\r\n"
            .to_vec(),
    )
    .unwrap()
}

fn server(chunking: bool) -> TestServer {
    let mut ext = vec!["PIPELINING", "ENHANCEDSTATUSCODES", "DSN"];
    if chunking {
        ext.push("CHUNKING");
    }
    TestServer::builder().extensions(&ext).start().unwrap()
}

fn assert_refused_before_sending(e: &smtp_net::Error) {
    assert!(
        matches!(e.kind(), ErrorKind::Build(BuildError::CommandTooLong)),
        "{e}"
    );
    assert_eq!(e.stage(), Some(Stage::Rcpt));
    assert!(e.is_permanent());
    assert!(!e.possibly_delivered());
}

/// Only the reset was delivered, only to its own recipient, and the server
/// never saw a line of the refused invitation.
fn assert_only_the_reset_was_delivered(server: &TestServer) {
    let got = server.received();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].recipients, ["victim@example.org"]);
    assert!(String::from_utf8_lossy(&got[0].data).contains("SECRET-TOKEN"));
    let transcript = server.transcript();
    assert_eq!(transcript.matches("MAIL FROM:").count(), 1, "{transcript}");
    assert!(
        !transcript.contains("attacker@evil.example"),
        "{transcript}"
    );
    assert!(!transcript.contains("503"), "{transcript}");
}

#[test]
fn test_failed_send_leaves_nothing_queued_for_the_next_message_on_a_client() {
    for chunking in [true, false] {
        let server = server(chunking);
        let mut client = Client::connect(&server.server()).unwrap();
        let e = client.send_prepared(&invitation()).unwrap_err();
        assert_refused_before_sending(&e);
        // Nothing was sent, so the connection stays usable.
        assert!(client.is_open());
        let report = client.send_prepared(&reset()).unwrap();
        assert_eq!(
            report.accepted().map(Address::as_str).collect::<Vec<_>>(),
            ["victim@example.org"]
        );
        drop(client);
        assert_only_the_reset_was_delivered(&server);
    }
}

#[test]
fn test_failed_send_leaves_nothing_queued_for_the_next_message_in_a_pool() {
    for chunking in [true, false] {
        let server = server(chunking);
        let pool = Pool::new(server.server(), 1).unwrap();
        let e = pool.send_prepared(&invitation()).unwrap_err();
        assert_refused_before_sending(&e);
        pool.send_prepared(&reset()).unwrap();
        drop(pool);
        assert_only_the_reset_was_delivered(&server);
    }
}

#[test]
fn test_test_server_refuses_a_nested_mail_and_keeps_the_transaction() {
    // The model the two tests above rely on, checked through the sans-IO
    // session: a second MAIL inside an open transaction is answered 503.
    use std::io::{BufRead, BufReader, Write};
    let server = server(false);
    let stream = std::net::TcpStream::connect(("127.0.0.1", server.port())).unwrap();
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);
    let mut line = String::new();
    let mut reply = |r: &mut BufReader<std::net::TcpStream>| {
        let mut last = String::new();
        loop {
            line.clear();
            r.read_line(&mut line).unwrap();
            if line.as_bytes().get(3) != Some(&b'-') {
                last.clone_from(&line);
                return last;
            }
        }
    };
    assert!(reply(&mut r).starts_with("220"));
    w.write_all(b"EHLO [127.0.0.1]\r\n").unwrap();
    assert!(reply(&mut r).starts_with("250"));
    w.write_all(b"MAIL FROM:<a@example.com>\r\n").unwrap();
    assert!(reply(&mut r).starts_with("250"));
    w.write_all(b"RCPT TO:<first@example.org>\r\n").unwrap();
    assert!(reply(&mut r).starts_with("250"));
    w.write_all(b"MAIL FROM:<b@example.com>\r\n").unwrap();
    assert!(reply(&mut r).starts_with("503 5.5.1"));
    w.write_all(b"RCPT TO:<second@example.org>\r\n").unwrap();
    assert!(reply(&mut r).starts_with("250"));
    w.write_all(b"DATA\r\nSubject: x\r\n\r\nbody\r\n.\r\n")
        .unwrap();
    assert!(reply(&mut r).starts_with("354"));
    assert!(reply(&mut r).starts_with("250"));
    w.write_all(b"QUIT\r\n").unwrap();
    assert!(reply(&mut r).starts_with("221"));
    let got = server.received();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].from, "a@example.com");
    assert_eq!(
        got[0].recipients,
        ["first@example.org", "second@example.org"]
    );
}
