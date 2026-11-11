//! The blocking driver against `TestServer`, with faults (PLAN 10.1 attack tests).

use std::time::Duration;

use smtp_net::testing::{Fault, TestServer};
use smtp_net::{
    Attachment, Client, ErrorKind, Message, RecipientPolicy, Security, Server, Stage, Timeouts,
};

fn msg(to: &str) -> Message {
    Message::text(
        "Example <no-reply@example.com>",
        to,
        "Confirm your email address",
        "Open this link:\nhttps://example.com/c/abc\n.\n..dots\n",
    )
    .unwrap()
}

fn quick(server: &TestServer) -> Server {
    let mut t = Timeouts::local();
    t.greeting = Duration::from_secs(2);
    t.command = Duration::from_secs(2);
    t.mail = Duration::from_secs(2);
    t.rcpt = Duration::from_secs(2);
    t.data_init = Duration::from_secs(2);
    t.data_end = Duration::from_secs(2);
    Server::builder("127.0.0.1", Security::PlaintextLoopback)
        .port(server.port())
        .timeouts(t)
        .build()
        .unwrap()
}

#[test]
fn test_send_delivers_exact_bytes_after_unstuffing() {
    let server = TestServer::start().unwrap();
    let m = msg("user@example.org");
    let report = smtp_net::send(&server.server(), &m).unwrap();
    assert_eq!(report.message_id(), m.message_id());
    assert_eq!(report.accepted().len(), 1);
    assert!(!report.was_secure());
    let got = server.received();
    assert_eq!(got.len(), 1);
    let mut want = m.to_bytes().unwrap();
    if !want.ends_with(b"\r\n") {
        want.extend_from_slice(b"\r\n");
    }
    assert_eq!(got[0].data, want);
    assert_eq!(got[0].from, "no-reply@example.com");
    assert_eq!(got[0].recipients, ["user@example.org"]);
    assert!(
        got[0]
            .mail_parameters
            .iter()
            .any(|p| p.starts_with("SIZE="))
    );
    let t = server.transcript();
    assert!(t.contains("C: EHLO [127.0.0.1]"), "{t}");
    assert!(t.contains("C: QUIT"));
}

#[test]
fn test_bcc_only_in_envelope_on_the_wire() {
    let server = TestServer::start().unwrap();
    let m = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .bcc("secret@example.net")
        .unwrap()
        .text("x")
        .unwrap()
        .build()
        .unwrap();
    smtp_net::send(&server.server(), &m).unwrap();
    let got = &server.received()[0];
    assert_eq!(got.recipients, ["b@example.org", "secret@example.net"]);
    assert!(!String::from_utf8_lossy(&got.data).contains("secret@example.net"));
}

#[test]
fn test_reuse_three_messages_one_connection() {
    let server = TestServer::start().unwrap();
    let mut client = Client::connect(&server.server()).unwrap();
    for i in 0..3 {
        client.send(&msg(&format!("u{i}@example.org"))).unwrap();
    }
    client.close().unwrap();
    assert_eq!(server.received().len(), 3);
    assert_eq!(server.connections(), 1);
}

#[test]
fn test_reconnects_once_when_server_closed_idle_connection() {
    let server = TestServer::builder()
        .fault(Fault::CloseAfterMessages(1))
        .start()
        .unwrap();
    let mut client = Client::connect(&server.server()).unwrap();
    client.send(&msg("a@example.org")).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    client.send(&msg("b@example.org")).unwrap();
    assert_eq!(server.received().len(), 2);
    assert_eq!(server.connections(), 2);
}

#[test]
fn test_close_after_data_end_is_possibly_delivered() {
    let server = TestServer::builder()
        .fault(Fault::CloseAfterDataEnd)
        .start()
        .unwrap();
    let e = smtp_net::send(&quick(&server), &msg("a@example.org")).unwrap_err();
    assert!(e.is_temporary(), "{e:?}");
    assert!(e.possibly_delivered(), "{e:?}");
    assert_eq!(server.received().len(), 1, "the server holds the message");
}

#[test]
fn test_close_before_data_is_not_possibly_delivered() {
    let server = TestServer::builder()
        .fault(Fault::CloseAt(Stage::Data))
        .start()
        .unwrap();
    let e = smtp_net::send(&quick(&server), &msg("a@example.org")).unwrap_err();
    assert!(e.is_temporary() && !e.possibly_delivered(), "{e:?}");
}

#[test]
fn test_rejected_recipient_reported_and_others_delivered() {
    let server = TestServer::builder()
        .fault(Fault::RejectRecipient(1))
        .start()
        .unwrap();
    let m = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .to("c@example.org")
        .unwrap()
        .text("x")
        .unwrap()
        .build()
        .unwrap();
    let report = smtp_net::send(&server.server(), &m).unwrap();
    assert_eq!(report.accepted().len(), 1);
    let rejected = report.rejected();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].address().as_str(), "c@example.org");
    assert!(rejected[0].is_permanent());
    assert_eq!(server.received()[0].recipients, ["b@example.org"]);
}

#[test]
fn test_policy_all_refuses_partial_delivery() {
    let server = TestServer::builder()
        .fault(Fault::RejectRecipient(0))
        .start()
        .unwrap();
    let s = Server::builder("127.0.0.1", Security::PlaintextLoopback)
        .port(server.port())
        .recipient_policy(RecipientPolicy::All)
        .build()
        .unwrap();
    let m = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .to("c@example.org")
        .unwrap()
        .text("x")
        .unwrap()
        .build()
        .unwrap();
    let e = smtp_net::send(&s, &m).unwrap_err();
    assert!(e.is_permanent());
    assert_eq!(e.rejected().len(), 1);
    assert!(server.received().is_empty());
}

#[test]
fn test_all_recipients_rejected() {
    let server = TestServer::builder()
        .fault(Fault::RejectRecipient(0))
        .start()
        .unwrap();
    let e = smtp_net::send(&server.server(), &msg("a@example.org")).unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::AllRecipientsRejected),
        "{e:?}"
    );
    assert!(e.is_permanent());
    assert_eq!(e.rejected()[0].address().as_str(), "a@example.org");
}

#[test]
fn test_too_many_recipients_temporary() {
    let server = TestServer::builder()
        .fault(Fault::TooManyRecipientsAfter(0))
        .start()
        .unwrap();
    let e = smtp_net::send(&server.server(), &msg("a@example.org")).unwrap_err();
    assert!(e.is_temporary(), "{e:?}");
}

#[test]
fn test_greeting_421_temporary_and_554_permanent() {
    let server = TestServer::builder()
        .fault(Fault::ReplyAt {
            stage: Stage::Greeting,
            reply: "421 4.3.2 busy",
        })
        .start()
        .unwrap();
    assert!(
        smtp_net::send(&server.server(), &msg("a@example.org"))
            .unwrap_err()
            .is_temporary()
    );
    let server = TestServer::builder()
        .fault(Fault::ReplyAt {
            stage: Stage::Greeting,
            reply: "554 no service",
        })
        .start()
        .unwrap();
    assert!(
        smtp_net::send(&server.server(), &msg("a@example.org"))
            .unwrap_err()
            .is_permanent()
    );
}

#[test]
fn test_end_of_data_refusals() {
    let server = TestServer::builder()
        .fault(Fault::ReplyAt {
            stage: Stage::DataEnd,
            reply: "451 4.3.0 later",
        })
        .start()
        .unwrap();
    let e = smtp_net::send(&server.server(), &msg("a@example.org")).unwrap_err();
    assert!(e.is_temporary() && !e.possibly_delivered());
    assert_eq!(e.stage(), Some(Stage::DataEnd));
    let server = TestServer::builder()
        .fault(Fault::ReplyAt {
            stage: Stage::DataEnd,
            reply: "554 5.7.1 spam",
        })
        .start()
        .unwrap();
    assert!(
        smtp_net::send(&server.server(), &msg("a@example.org"))
            .unwrap_err()
            .is_permanent()
    );
}

#[test]
fn test_ehlo_refused_falls_back_to_helo_on_loopback() {
    let server = TestServer::builder().refuse_ehlo().start().unwrap();
    smtp_net::send(&server.server(), &msg("a@example.org")).unwrap();
    assert!(server.transcript().contains("C: HELO [127.0.0.1]"));
}

#[test]
fn test_hostile_reply_flood_refused_within_budget() {
    let server = TestServer::builder()
        .fault(Fault::OversizedReply(Stage::Ehlo))
        .start()
        .unwrap();
    let e = smtp_net::send(&server.server(), &msg("a@example.org")).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Protocol(_)), "{e:?}");
    assert!(e.is_security_event());
}

#[test]
fn test_malformed_and_extra_replies_close_the_session() {
    let server = TestServer::builder()
        .fault(Fault::MalformedReply(Stage::Mail))
        .start()
        .unwrap();
    let e = smtp_net::send(&server.server(), &msg("a@example.org")).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Protocol(_)), "{e:?}");
    let server = TestServer::builder()
        .fault(Fault::ExtraReply(Stage::Quit))
        .start()
        .unwrap();
    // Extra reply after QUIT: delivered anyway.
    smtp_net::send(&server.server(), &msg("a@example.org")).unwrap();
}

#[test]
fn test_slow_drip_ends_in_timeout_at_stage_deadline() {
    let server = TestServer::builder()
        .fault(Fault::SlowDrip {
            bytes_per_second: 2,
        })
        .start()
        .unwrap();
    let mut t = Timeouts::local();
    t.greeting = Duration::from_millis(800);
    let s = Server::builder("127.0.0.1", Security::PlaintextLoopback)
        .port(server.port())
        .timeouts(t)
        .build()
        .unwrap();
    let start = std::time::Instant::now();
    let e = smtp_net::send(&s, &msg("a@example.org")).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Timeout), "{e:?}");
    assert_eq!(e.stage(), Some(Stage::Greeting));
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn test_delay_beyond_deadline_times_out() {
    let server = TestServer::builder()
        .fault(Fault::DelayAt {
            stage: Stage::DataEnd,
            by: Duration::from_secs(3),
        })
        .start()
        .unwrap();
    let e = smtp_net::send(&quick(&server), &msg("a@example.org")).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Timeout), "{e:?}");
    assert!(e.possibly_delivered());
}

#[test]
fn test_connect_refused_is_temporary() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let s = Server::builder("127.0.0.1", Security::PlaintextLoopback)
        .port(port)
        .build()
        .unwrap();
    let e = smtp_net::send(&s, &msg("a@example.org")).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Connect(_)), "{e:?}");
    assert!(e.is_temporary());
}

#[test]
fn test_plaintext_to_remote_host_refused_at_build() {
    for host in ["mail.example.com", "192.0.2.1", "10.0.0.1"] {
        let e = Server::builder(host, Security::PlaintextLoopback)
            .build()
            .unwrap_err();
        assert!(
            matches!(
                e.kind(),
                ErrorKind::Config(smtp_net::ConfigError::PlaintextHostNotLoopback)
            ),
            "{host}"
        );
    }
    for host in ["127.0.0.1", "127.1.2.3", "::1", "localhost", "LOCALHOST"] {
        assert!(
            Server::builder(host, Security::PlaintextLoopback)
                .build()
                .is_ok(),
            "{host}"
        );
    }
    assert!(
        Server::builder("127.0.0.1", Security::PlaintextLoopback)
            .port(0)
            .build()
            .is_err()
    );
    assert!(
        Server::builder("bad host", Security::PlaintextLoopback)
            .build()
            .is_err()
    );
}

#[test]
fn test_size_limit_refused_before_mail() {
    let server = TestServer::builder()
        .extensions(&["SIZE 100"])
        .start()
        .unwrap();
    let m = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .attachment(Attachment::new("a.bin", "application/octet-stream", vec![0; 500]).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let e = smtp_net::send(&server.server(), &m).unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::MessageTooLarge { .. }),
        "{e:?}"
    );
    assert!(!server.transcript().contains("C: MAIL"));
}

#[test]
fn test_smtputf8_required_and_used() {
    let m = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("j\u{f6}rg@example.org")
        .unwrap()
        .text("x")
        .unwrap()
        .build()
        .unwrap();
    let plain = TestServer::builder()
        .extensions(&["8BITMIME"])
        .start()
        .unwrap();
    let e = smtp_net::send(&plain.server(), &m).unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::ExtensionRequired(smtp_net::Extension::Smtputf8)
    ));
    let eai = TestServer::start().unwrap();
    smtp_net::send(&eai.server(), &m).unwrap();
    let got = &eai.received()[0];
    assert!(got.mail_parameters.iter().any(|p| p == "SMTPUTF8"));
    assert!(got.mail_parameters.iter().any(|p| p == "BODY=8BITMIME"));
}

#[test]
fn test_without_pipelining_one_command_per_round_trip() {
    let server = TestServer::builder()
        .extensions(&["8BITMIME"])
        .start()
        .unwrap();
    smtp_net::send(&server.server(), &msg("a@example.org")).unwrap();
    let t = server.transcript();
    let mail = t.find("C: MAIL").unwrap();
    let rcpt = t.find("C: RCPT").unwrap();
    assert!(t[mail..rcpt].contains("S: 250"), "{t}");
}

#[test]
fn test_raw_prepared_message() {
    let server = TestServer::start().unwrap();
    let env = smtp_net::Envelope::new(
        smtp_net::Address::parse("a@example.com").unwrap(),
        &[smtp_net::Address::parse("b@example.org").unwrap()],
    )
    .unwrap();
    let raw = b"From: a@example.com\r\nTo: b@example.org\r\nMessage-ID: <x.1@example.com>\r\nSubject: raw\r\n\r\n.leading dot\r\n".to_vec();
    let p = smtp_net::PreparedMessage::from_raw(env, raw.clone()).unwrap();
    let mut c = Client::connect(&server.server()).unwrap();
    let report = c.send_prepared(&p).unwrap();
    assert_eq!(report.message_id(), "x.1@example.com");
    assert_eq!(server.received()[0].data, raw);
}

#[test]
fn test_drop_sends_quit_quickly() {
    let server = TestServer::start().unwrap();
    let start = std::time::Instant::now();
    {
        let _c = Client::connect(&server.server()).unwrap();
    }
    assert!(start.elapsed() < Duration::from_secs(2));
    std::thread::sleep(Duration::from_millis(50));
    assert!(server.transcript().contains("C: QUIT"));
}

#[test]
fn test_localhost_connects_quickly_when_the_server_listens_on_ipv4_only() {
    // Windows resolves `localhost` to `::1` first, and a refused connect there
    // takes about 2 s (the SYN is retried); the server below listens on
    // 127.0.0.1 only. The attempts race (D-107), so the IPv4 one wins within
    // the loopback attempt delay instead of after the IPv6 attempt's share of
    // the connect timeout.
    let server = TestServer::start().unwrap();
    let s = Server::builder("localhost", Security::PlaintextLoopback)
        .port(server.port())
        .timeouts(Timeouts::local())
        .build()
        .unwrap();
    for _ in 0..3 {
        let began = std::time::Instant::now();
        let client = Client::connect(&s).unwrap();
        let took = began.elapsed();
        drop(client);
        assert!(took < Duration::from_millis(600), "connect took {took:?}");
    }
}

#[test]
fn test_client_name_is_checked_by_build_and_sent_in_ehlo() {
    let server = TestServer::start().unwrap();
    let bad = server.server_builder().client_name("not a name").build();
    assert!(matches!(
        bad.unwrap_err().kind(),
        ErrorKind::Config(smtp_net::ConfigError::InvalidClientName)
    ));
    let named = server
        .server_builder()
        .client_name("app-1.example.com")
        .build()
        .unwrap();
    smtp_net::send(&named, &msg("a@example.org")).unwrap();
    assert!(server.transcript().contains("C: EHLO app-1.example.com"));
}

#[test]
fn test_mechanism_list_is_checked_by_build() {
    let server = TestServer::start().unwrap();
    let empty = server
        .server_builder()
        .credentials(smtp_net::Credentials::password("u", "p"))
        .mechanisms(&[])
        .build();
    assert!(matches!(
        empty.unwrap_err().kind(),
        ErrorKind::Config(smtp_net::ConfigError::TooManyMechanisms)
    ));
}

#[test]
fn test_rejected_recipient_accessors_agree_with_the_error() {
    let server = TestServer::builder()
        .fault(Fault::RejectRecipient(0))
        .start()
        .unwrap();
    let e = smtp_net::send(&quick(&server), &msg("gone@example.org")).unwrap_err();
    let r = &e.rejected()[0];
    assert_eq!(r.address().as_str(), "gone@example.org");
    assert_eq!(r.reply().code().get() / 100, 5);
    assert!(r.is_permanent() && !r.is_temporary());
    assert_eq!(r.disposition(), smtp_net::Disposition::Permanent);
}
