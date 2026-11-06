//! 0.4 end to end against `TestServer`: STARTTLS and implicit TLS through
//! the TLS seam (with the test engine), AUTH, CHUNKING, DSN, pacing, the
//! too-many-recipients deferral, and job payloads (PLAN 10.1 T-5 to T-11,
//! T-32, T-33).

use std::time::Duration;

use smtp_net::{
    Address, Admission, Dsn, DsnNotify, DsnReturn, Envelope, ErrorKind, Fault, HourlyLimit,
    MechanismName, Message, PreparedMessage, Security, SendGate, Server, Stage, TestServer,
    TestTls, Timeouts, TlsFailure,
};

fn msg(to: &str) -> Message {
    Message::text(
        "Example <no-reply@example.com>",
        to,
        "Reset your password",
        "Reset: https://example.com/r/xyz\n.\n",
    )
    .unwrap()
}

fn quick() -> Timeouts {
    let mut t = Timeouts::rfc5321();
    for d in [
        &mut t.greeting,
        &mut t.command,
        &mut t.tls_handshake,
        &mut t.mail,
        &mut t.rcpt,
        &mut t.data_init,
        &mut t.data_end,
    ] {
        *d = Duration::from_secs(2);
    }
    t
}

#[test]
fn test_starttls_delivery_is_secure() {
    let server = TestServer::builder().starttls().start().unwrap();
    let report = smtp_net::send(&server.server(), &msg("a@example.org")).unwrap();
    assert!(report.was_secure());
    assert!(report.tls_protocol().is_some());
    let got = &server.received()[0];
    assert!(got.secure);
    let t = server.transcript();
    let tls = t.find("<TLS established>").unwrap();
    assert!(
        t[tls..].contains("C: EHLO"),
        "EHLO is sent again after TLS: {t}"
    );
}

#[test]
fn test_implicit_tls_delivery() {
    let server = TestServer::builder().implicit_tls().start().unwrap();
    let report = smtp_net::send(&server.server(), &msg("a@example.org")).unwrap();
    assert!(report.was_secure());
    assert!(server.received()[0].secure);
}

#[test]
fn test_stripped_starttls_sends_nothing() {
    // T-5 and T-8: no AUTH, no MAIL when STARTTLS is missing.
    let server = TestServer::builder()
        .starttls()
        .auth("user", "pass")
        .fault(Fault::OmitStartTls)
        .start()
        .unwrap();
    let e = smtp_net::send(&server.server(), &msg("a@example.org")).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::StartTlsUnavailable), "{e:?}");
    assert!(e.is_temporary() && e.is_security_event());
    let t = server.transcript();
    assert!(!t.contains("C: AUTH") && !t.contains("C: MAIL"), "{t}");
}

#[test]
fn test_starttls_response_injection_refused() {
    // T-6: replies queued behind the 220 are never read as TLS data.
    let server = TestServer::builder()
        .starttls()
        .auth("user", "pass")
        .fault(Fault::InjectAfterStartTls(b"250-AUTH PLAIN\r\n250 OK\r\n"))
        .start()
        .unwrap();
    let s = server.server_builder().timeouts(quick()).build().unwrap();
    let e = smtp_net::send(&s, &msg("a@example.org")).unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::StartTlsInjection | ErrorKind::Tls(_)),
        "{e:?}"
    );
    let t = server.transcript();
    assert!(!t.contains("C: AUTH") && !t.contains("C: MAIL"), "{t}");
}

#[test]
fn test_certificate_rejection_is_permanent() {
    // T-11.
    let server = TestServer::builder()
        .starttls()
        .fault(Fault::RejectCertificate)
        .start()
        .unwrap();
    let e = smtp_net::send(&server.server(), &msg("a@example.org")).unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::Tls(TlsFailure::CertificateRejected)),
        "{e:?}"
    );
    assert!(e.is_permanent());
    assert!(!server.transcript().contains("C: MAIL"));
}

#[test]
fn test_wrong_name_refused_unless_verification_off_on_loopback() {
    let server = TestServer::builder()
        .starttls()
        .tls_name("mail.example.com")
        .start()
        .unwrap();
    let e = smtp_net::send(&server.server(), &msg("a@example.org")).unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::Tls(TlsFailure::CertificateRejected)),
        "{e:?}"
    );
    let insecure = server
        .server_builder()
        .dangerous_disable_certificate_verification()
        .build()
        .unwrap();
    smtp_net::send(&insecure, &msg("a@example.org")).unwrap();
}

#[test]
fn test_insecure_remote_needs_the_second_flag() {
    let b = Server::builder("mail.example.com", Security::StartTls)
        .tls_connector(TestTls)
        .dangerous_disable_certificate_verification();
    let e = b.clone().build().unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Config(smtp_net::ConfigError::InsecureNotAllowed)
    ));
    assert!(b.allow_insecure_remote(true).build().is_ok());
}

#[cfg(feature = "tls")]
#[test]
fn test_tls_feature_gives_starttls_servers_an_engine() {
    assert!(
        Server::builder("mail.example.com", Security::StartTls)
            .build()
            .is_ok()
    );
    assert!(
        Server::builder("mail.example.com", Security::ImplicitTls)
            .build()
            .is_ok()
    );
}

#[cfg(not(feature = "tls"))]
#[test]
fn test_tls_without_engine_refused_before_anything_is_sent() {
    let e = Server::builder("mail.example.com", Security::StartTls)
        .build()
        .unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Config(smtp_net::ConfigError::TlsConnectorMissing)
    ));
    let server = TestServer::builder().starttls().start().unwrap();
    let bare = Server::starttls("localhost")
        .to_builder()
        .port(server.port());
    // Server::starttls without an engine: refused at connect, nothing sent.
    let e = smtp_net::Client::connect(&Server::starttls("localhost")).unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Config(smtp_net::ConfigError::TlsConnectorMissing)
    ));
    assert!(bare.build().is_err());
    assert_eq!(server.connections(), 0);
}

#[test]
fn test_implicit_tls_to_plaintext_port_is_protocol_mismatch() {
    let plain = TestServer::start().unwrap();
    let s = Server::builder("localhost", Security::ImplicitTls)
        .port(plain.port())
        .tls_connector(TestTls)
        .timeouts(quick())
        .build()
        .unwrap();
    let e = smtp_net::send(&s, &msg("a@example.org")).unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::Tls(TlsFailure::ProtocolMismatch)),
        "{e:?}"
    );
    assert!(e.is_permanent());
    assert!(e.to_string().contains("587"), "{e}");
}

#[test]
fn test_starttls_to_implicit_port_times_out_with_a_hint() {
    let implicit = TestServer::builder().implicit_tls().start().unwrap();
    let s = Server::builder("localhost", Security::StartTls)
        .port(implicit.port())
        .tls_connector(TestTls)
        .timeouts(quick())
        .build()
        .unwrap();
    let e = smtp_net::send(&s, &msg("a@example.org")).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Timeout), "{e:?}");
    assert_eq!(e.stage(), Some(Stage::Greeting));
    assert!(e.to_string().contains("465"), "{e}");
}

#[test]
fn test_auth_plain_over_starttls_and_redacted_transcript() {
    let server = TestServer::builder()
        .starttls()
        .auth("mailer@example.com", "s3cr3t-pass")
        .start()
        .unwrap();
    let plain = server
        .server_builder()
        .mechanisms(&[MechanismName::Plain])
        .unwrap()
        .build()
        .unwrap();
    smtp_net::send(&plain, &msg("a@example.org")).unwrap();
    let got = &server.received()[0];
    assert_eq!(got.user.as_deref(), Some("mailer@example.com"));
    let t = server.transcript();
    assert!(t.contains("C: AUTH PLAIN <redacted"), "{t}");
    assert!(!t.contains("s3cr3t") && !t.contains("czNjcjN0"), "T-9: {t}");
    let tls = t.find("<TLS established>").unwrap();
    assert!(t.find("C: AUTH").unwrap() > tls, "AUTH only after TLS");
}

#[test]
fn test_auth_login_only_allowlist() {
    let server = TestServer::builder()
        .starttls()
        .auth("u", "p")
        .start()
        .unwrap();
    let s = server
        .server_builder()
        .mechanisms(&[MechanismName::Login])
        .unwrap()
        .build()
        .unwrap();
    smtp_net::send(&s, &msg("a@example.org")).unwrap();
    assert!(server.transcript().contains("C: AUTH LOGIN"));
}

#[test]
fn test_wrong_password_is_permanent_auth_failure() {
    let server = TestServer::builder()
        .starttls()
        .auth("u", "right")
        .start()
        .unwrap();
    let s = server
        .server_builder()
        .credentials(smtp_net::Credentials::password("u", "wrong"))
        .build()
        .unwrap();
    let e = smtp_net::send(&s, &msg("a@example.org")).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::AuthFailed), "{e:?}");
    assert!(e.is_permanent());
    assert_eq!(e.reply().unwrap().code().get(), 535);
    assert!(!format!("{e:?}{e}").contains("wrong"));
}

#[test]
fn test_auth_over_verified_loopback_plaintext() {
    let server = TestServer::builder().auth("u", "p").start().unwrap();
    smtp_net::send(&server.server(), &msg("a@example.org")).unwrap();
    assert_eq!(server.received()[0].user.as_deref(), Some("u"));
}

#[test]
fn test_chunking_carries_the_same_message() {
    let server = TestServer::builder()
        .extensions(&["PIPELINING", "CHUNKING", "8BITMIME", "ENHANCEDSTATUSCODES"])
        .start()
        .unwrap();
    let m = msg("a@example.org");
    smtp_net::send(&server.server(), &m).unwrap();
    let got = &server.received()[0];
    assert!(got.chunked);
    let mut want = m.to_bytes().unwrap();
    if !want.ends_with(b"\r\n") {
        want.extend_from_slice(b"\r\n");
    }
    assert_eq!(
        got.data, want,
        "BDAT sends the bytes as they are (no dot-stuffing)"
    );
    assert!(
        server.transcript().contains("C: BDAT 0 LAST")
            || server.transcript().contains("C: BDAT 2 LAST")
    );
}

#[test]
fn test_chunking_off_uses_data() {
    let server = TestServer::builder()
        .extensions(&["CHUNKING"])
        .start()
        .unwrap();
    let s = server.server_builder().chunking(false).build().unwrap();
    smtp_net::send(&s, &msg("a@example.org")).unwrap();
    assert!(!server.received()[0].chunked);
}

#[test]
fn test_large_chunked_message_waits_for_recipient_replies() {
    let server = TestServer::builder()
        .extensions(&["PIPELINING", "CHUNKING", "SIZE 50000000"])
        .start()
        .unwrap();
    let big = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .attachment(
            smtp_net::Attachment::new("big.bin", "application/octet-stream", vec![0x5a; 300_000])
                .unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
    smtp_net::send(&server.server(), &big).unwrap();
    assert_eq!(
        server.received()[0].data.len() as u64,
        big.encoded_len() + 2 - u64::from(big.to_bytes().unwrap().ends_with(b"\r\n")) * 2
    );
}

#[test]
fn test_dsn_parameters_sent_when_offered_and_required_refused_otherwise() {
    let server = TestServer::start().unwrap();
    let m = msg("a@example.org");
    let env = m.envelope().unwrap().dsn(
        Dsn::new(DsnNotify::FAILURE | DsnNotify::DELAY)
            .ret(DsnReturn::Headers)
            .envelope_id("order+42")
            .unwrap(),
    );
    let p = PreparedMessage::from_raw(env, m.to_bytes().unwrap()).unwrap();
    smtp_net::send_prepared(&server.server(), &p).unwrap();
    let got = &server.received()[0];
    assert!(got.mail_parameters.iter().any(|x| x == "RET=HDRS"));
    assert!(got.mail_parameters.iter().any(|x| x == "ENVID=order+2B42"));
    assert_eq!(
        got.rcpt_parameters[0],
        ["NOTIFY=FAILURE,DELAY", "ORCPT=rfc822;a@example.org"]
    );

    let no_dsn = TestServer::builder()
        .extensions(&["PIPELINING"])
        .start()
        .unwrap();
    let env = m
        .envelope()
        .unwrap()
        .dsn(Dsn::new(DsnNotify::FAILURE).required());
    let p = PreparedMessage::from_raw(env, m.to_bytes().unwrap()).unwrap();
    let e = smtp_net::send_prepared(&no_dsn.server(), &p).unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::ExtensionRequired(smtp_net::Extension::Dsn)
    ));
    assert!(e.is_permanent());
}

#[test]
fn test_too_many_recipients_deferred_to_further_transactions() {
    // FR-42: the server takes one recipient per transaction.
    let server = TestServer::builder()
        .fault(Fault::TooManyRecipientsAfter(1))
        .start()
        .unwrap();
    let m = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .to("c@example.org")
        .unwrap()
        .to("d@example.org")
        .unwrap()
        .text("x")
        .unwrap()
        .build()
        .unwrap();
    let report = smtp_net::send(&server.server(), &m).unwrap();
    assert_eq!(report.accepted().count(), 3);
    let got = server.received();
    assert_eq!(got.len(), 3);
    assert!(
        got.iter().all(|g| g.data == got[0].data),
        "the same bytes every time"
    );
    let all: Vec<String> = got.iter().flat_map(|g| g.recipients.clone()).collect();
    assert_eq!(all, ["b@example.org", "c@example.org", "d@example.org"]);
}

#[test]
fn test_hourly_limit_throttles_and_refunds() {
    let server = TestServer::start().unwrap();
    let gated = server
        .server_builder()
        .gate(HourlyLimit::messages(1))
        .build()
        .unwrap();
    smtp_net::send(&gated, &msg("a@example.org")).unwrap();
    let e = smtp_net::send(&gated, &msg("a@example.org")).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Throttled), "{e:?}");
    assert!(e.is_temporary());
    assert!(e.retry_after().unwrap() > Duration::from_secs(3000));
    assert_eq!(server.received().len(), 1);

    // A send that fails before anything was accepted gives its allowance
    // back. (A closed port could be taken by a parallel test's server.)
    let busy = TestServer::builder()
        .fault(Fault::ReplyAt {
            stage: Stage::Mail,
            reply: "451 4.3.0 try later",
        })
        .start()
        .unwrap();
    let limit = std::sync::Arc::new(HourlyLimit::messages(1));
    struct Shared(std::sync::Arc<HourlyLimit>);
    impl SendGate for Shared {
        fn admit(&self, n: u32, t: u64) -> Admission {
            self.0.admit(n, t)
        }
        fn refund(&self, n: u32, t: u64) {
            self.0.refund(n, t)
        }
    }
    let down = busy
        .server_builder()
        .gate(Shared(limit.clone()))
        .build()
        .unwrap();
    assert!(smtp_net::send(&down, &msg("a@example.org")).is_err());
    assert_eq!(limit.remaining(now_ms()), 1);
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[test]
fn test_job_payload_round_trip_and_send_prepared() {
    let server = TestServer::start().unwrap();
    let m = msg("a@example.org");
    let payload = m.prepare().unwrap().encode();
    let p = PreparedMessage::decode(&payload).unwrap();
    assert_eq!(p.message_id(), Some(m.message_id()));
    let report = smtp_net::send_prepared(&server.server(), &p).unwrap();
    assert_eq!(report.message_id(), m.message_id());
    let mut bad = payload.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x40;
    let e = PreparedMessage::decode(&bad).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Payload(_)));
    assert!(e.is_permanent());
}

/// The job system's handler contract: decode, send, then retry a temporary
/// failure and dead-letter a permanent one (task-io's `Fail::retry` and
/// `Fail::permanent`).
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Done,
    Retry,
    DeadLetter,
}

fn handle(server: &Server, payload: &[u8]) -> Outcome {
    let Ok(prepared) = PreparedMessage::decode(payload) else {
        return Outcome::DeadLetter;
    };
    match smtp_net::send_prepared(server, &prepared) {
        Ok(_) => Outcome::Done,
        Err(e) if e.is_temporary() => Outcome::Retry,
        Err(_) => Outcome::DeadLetter,
    }
}

#[test]
fn test_job_contract_retries_temporary_and_dead_letters_permanent() {
    let payload = msg("a@example.org").prepare().unwrap().encode();
    let busy = TestServer::builder()
        .fault(Fault::ReplyAt {
            stage: Stage::Mail,
            reply: "451 4.3.0 try later",
        })
        .start()
        .unwrap();
    assert_eq!(handle(&busy.server(), &payload), Outcome::Retry);
    let ok = TestServer::start().unwrap();
    assert_eq!(handle(&ok.server(), &payload), Outcome::Done);
    let refusing = TestServer::builder()
        .fault(Fault::ReplyAt {
            stage: Stage::Mail,
            reply: "550 5.7.1 sender refused",
        })
        .start()
        .unwrap();
    assert_eq!(handle(&refusing.server(), &payload), Outcome::DeadLetter);
    assert_eq!(
        handle(&ok.server(), b"SMTPNET1 garbage"),
        Outcome::DeadLetter
    );
}

#[test]
fn test_null_sender_envelope() {
    let server = TestServer::start().unwrap();
    let env = Envelope::null_sender(&[Address::parse("a@example.org").unwrap()]).unwrap();
    let p = PreparedMessage::from_raw(
        env,
        b"From: mailer-daemon@example.com\r\nAuto-Submitted: auto-replied\r\n\r\nbounce\r\n"
            .to_vec(),
    )
    .unwrap();
    smtp_net::send_prepared(&server.server(), &p).unwrap();
    assert_eq!(server.received()[0].from, "");
}

#[test]
fn test_list_unsubscribe_and_auto_submitted_headers() {
    let m = Message::builder()
        .from("news@example.com")
        .unwrap()
        .to("a@example.org")
        .unwrap()
        .list_unsubscribe(
            &[
                "https://example.com/u/123",
                "mailto:unsub@example.com?subject=123",
            ],
            true,
        )
        .unwrap()
        .auto_submitted(smtp_net::AutoSubmitted::AutoGenerated)
        .text("x")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        m.headers().get("List-Unsubscribe"),
        Some("<https://example.com/u/123>, <mailto:unsub@example.com?subject=123>")
    );
    assert_eq!(
        m.headers().get("List-Unsubscribe-Post"),
        Some("List-Unsubscribe=One-Click")
    );
    assert_eq!(m.headers().get("Auto-Submitted"), Some("auto-generated"));
    assert!(
        Message::builder()
            .list_unsubscribe(&["mailto:a@b"], true)
            .is_err(),
        "one-click needs https"
    );
    assert!(
        Message::builder()
            .list_unsubscribe(&["https://a/b c"], false)
            .is_err()
    );
    assert!(
        Message::builder()
            .list_unsubscribe(&["javascript:alert(1)"], false)
            .is_err()
    );
    assert!(
        Message::builder()
            .header("List-Unsubscribe", "<https://x>")
            .is_err(),
        "reserved"
    );
}

#[test]
fn test_round_trips_pipelining_and_chunking_save() {
    // PLAN 11.3 item 1: one turnaround for MAIL, RCPT, and the body with
    // PIPELINING and CHUNKING; one per command without them.
    const RTT: Duration = Duration::from_millis(40);
    let time = |pipelining: bool, chunking: bool| {
        let server = TestServer::builder()
            .fault(Fault::RoundTrip(RTT))
            .extensions(&["PIPELINING", "CHUNKING", "8BITMIME"])
            .start()
            .unwrap();
        let s = server
            .server_builder()
            .pipelining(pipelining)
            .chunking(chunking)
            .build()
            .unwrap();
        let start = std::time::Instant::now();
        smtp_net::send(&s, &msg("a@example.org")).unwrap();
        start.elapsed()
    };
    let fast = time(true, true);
    let slow = time(false, false);
    // Turnarounds: greeting, EHLO, MAIL+RCPT+BDAT, QUIT against greeting,
    // EHLO, MAIL, RCPT, DATA, body, QUIT.
    assert!(fast < RTT * 5, "{fast:?}");
    assert!(slow >= RTT * 6, "{slow:?}");
    assert!(slow > fast + RTT * 2, "{fast:?} {slow:?}");
}
