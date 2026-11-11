//! Attack tests for the rows of the threat table (dev/PLAN.md 10.1) that no
//! other test covers in full. `docs/SECURITY.md` maps every row to its
//! tests, here and elsewhere.

use smtp_net::testing::{Fault, TestServer};
use smtp_net::{
    Client, Credentials, ErrorKind, HeaderError, MechanismName, Message, Pool, Secret, Stage,
    TlsFailure,
};

fn msg() -> Message {
    Message::text(
        "no-reply@example.com",
        "user@example.org",
        "Hello",
        "Hello.\n",
    )
    .unwrap()
}

fn header_error(r: Result<impl core::fmt::Debug, smtp_net::Error>) -> HeaderError {
    match r.unwrap_err().kind() {
        ErrorKind::Header(h) => *h,
        k => panic!("not a header error: {k:?}"),
    }
}

/// T-1: List-Unsubscribe targets with a control are refused, like every
/// other field.
#[test]
fn t01_list_unsubscribe_controls_refused() {
    for bad in ["\r", "\n", "\r\n", "\0", "\u{85}", "\u{2028}"] {
        let target = format!("https://example.com/u{bad}Bcc: victim@example.net");
        let r = Message::builder().list_unsubscribe(&[&target], false);
        assert!(r.is_err(), "{bad:?} let through");
    }
}

/// T-3: bodies built to end DATA early arrive whole: the server, which
/// removes the stuffing, receives exactly what was written.
#[test]
fn t03_dot_bodies_arrive_whole() {
    let server = TestServer::start().unwrap();
    let bodies = [
        "a\n.\nRCPT TO:<x@example.net>\n",
        "a\n\n.\nb\n",
        ".at the start\n",
        "..\n...\n",
        ".\n.\n.\n",
    ];
    let mut client = Client::connect(&server.server()).unwrap();
    for body in bodies {
        let m = Message::text("a@example.com", "b@example.org", "Dots", body).unwrap();
        client.send(&m).unwrap();
    }
    client.close().unwrap();
    let got = server.received();
    assert_eq!(got.len(), bodies.len());
    for (m, body) in got.iter().zip(bodies) {
        let want = body.replace('\n', "\r\n");
        assert!(
            m.data.ends_with(format!("\r\n\r\n{want}").as_bytes()),
            "{body:?}: {}",
            String::from_utf8_lossy(&m.data)
        );
    }
}

/// T-9: every type that holds credentials prints none of them.
#[test]
fn t09_no_secret_in_debug() {
    let server = TestServer::builder()
        .auth("mailer", "s3cr3t-pw")
        .start()
        .unwrap();
    let b = server
        .server_builder()
        .credentials(Credentials::password("mailer", "s3cr3t-pw"));
    let s = b.clone().build().unwrap();
    let client = Client::connect(&s).unwrap();
    let pool = Pool::new(s.clone(), 1).unwrap();
    let shown = [
        format!("{b:?}"),
        format!("{s:?}"),
        format!("{client:?}"),
        format!("{pool:?}"),
        format!("{:?}", Credentials::password("mailer", "s3cr3t-pw")),
        format!(
            "{:?} {}",
            Secret::from("s3cr3t-pw"),
            Secret::from("s3cr3t-pw")
        ),
    ];
    for text in shown {
        assert!(!text.contains("s3cr3t"), "{text}");
    }
}

/// T-10: a server offering only LOGIN to a client that allows only
/// SCRAM-SHA-256 gets no AUTH at all.
#[test]
fn t10_no_downgrade_outside_the_allowlist() {
    let server = TestServer::builder()
        .extensions(&["PIPELINING", "AUTH LOGIN"])
        .start()
        .unwrap();
    let s = server
        .server_builder()
        .credentials(Credentials::password("mailer", "pw"))
        .mechanisms(&[MechanismName::ScramSha256])
        .build()
        .unwrap();
    let e = smtp_net::send(&s, &msg()).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::AuthUnavailable), "{e:?}");
    let t = server.transcript();
    assert!(!t.contains("C: AUTH") && !t.contains("C: MAIL"), "{t}");
}

/// T-11: a certificate for another name is refused, permanently.
#[test]
fn t11_wrong_name_is_permanent() {
    let server = TestServer::builder()
        .starttls()
        .tls_name("mail.example.net")
        .start()
        .unwrap();
    let e = smtp_net::send(&server.server(), &msg()).unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::Tls(TlsFailure::CertificateRejected)),
        "{e:?}"
    );
    assert!(e.is_permanent());
}

/// T-13: one byte a second ends at the stage deadline.
#[test]
fn t13_one_byte_a_second_times_out() {
    let server = TestServer::builder()
        .fault(Fault::SlowDrip {
            bytes_per_second: 1,
        })
        .start()
        .unwrap();
    let mut t = smtp_net::Timeouts::local();
    t.greeting = std::time::Duration::from_secs(2);
    let s = server.server_builder().timeouts(t).build().unwrap();
    let start = std::time::Instant::now();
    let e = smtp_net::send(&s, &msg()).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Timeout), "{e:?}");
    assert_eq!(e.stage(), Some(Stage::Greeting));
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
}

/// T-14: an extra reply at any stage closes the session, and no message is
/// reported delivered that the server did not take.
#[test]
fn t14_extra_reply_at_every_stage() {
    for stage in [
        Stage::Ehlo,
        Stage::Mail,
        Stage::Rcpt,
        Stage::Data,
        Stage::DataEnd,
    ] {
        let server = TestServer::builder()
            .fault(Fault::ExtraReply(stage))
            .start()
            .unwrap();
        let mut sent = 0;
        let mut client = Client::connect(&server.server()).ok();
        for _ in 0..2 {
            let r = match client.as_mut() {
                Some(c) => c.send(&msg()),
                None => smtp_net::send(&server.server(), &msg()),
            };
            match r {
                Ok(_) => sent += 1,
                Err(e) => {
                    assert!(
                        matches!(
                            e.kind(),
                            ErrorKind::Protocol(_) | ErrorKind::ConnectionClosed
                        ),
                        "{stage:?}: {e:?}"
                    );
                    client = None;
                }
            }
        }
        assert!(
            sent <= server.messages(),
            "{stage:?}: {sent} reported, {} taken",
            server.messages()
        );
        if stage != Stage::DataEnd {
            assert_eq!(sent, 0, "{stage:?}");
        }
    }
}

/// T-15: text full of boundary look-alikes never meets the real boundary.
#[test]
fn t15_adversarial_text_and_boundaries() {
    let mut x = 0x0123_4567_89ab_cdefu64;
    for round in 0..200 {
        let mut text = String::new();
        for i in 0..20 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            text.push_str(&format!("--=_{x:016x}{i}\n--=_\n=_{round}\n"));
        }
        let m = Message::builder()
            .from("a@example.com")
            .unwrap()
            .to("b@example.org")
            .unwrap()
            .text(&text)
            .unwrap()
            .html(&format!("<pre>{text}</pre>"))
            .unwrap()
            .build()
            .unwrap();
        let bytes = String::from_utf8(m.to_bytes().unwrap()).unwrap();
        let boundary = bytes
            .split("boundary=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .unwrap()
            .to_string();
        let delimiters = bytes
            .split("\r\n")
            .filter(|l| l.starts_with(&format!("--{boundary}")))
            .count();
        assert_eq!(delimiters, 3, "two parts and the close");
    }
}

/// T-17: nothing sent carries the machine's host name.
#[test]
fn t17_no_host_name_in_output() {
    let name = std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    if name.len() < 4 {
        return;
    }
    let server = TestServer::start().unwrap();
    smtp_net::send(&server.server(), &msg()).unwrap();
    let wire = format!(
        "{}{}",
        server.transcript(),
        String::from_utf8_lossy(&server.received()[0].data)
    )
    .to_ascii_lowercase();
    assert!(!wire.contains(&name), "host name {name} sent");
}

/// T-18: a retry after an ambiguous failure sends the same bytes, Message-ID
/// included.
#[test]
fn t18_retry_sends_identical_bytes() {
    let flaky = TestServer::builder()
        .fault(Fault::CloseAfterDataEnd)
        .start()
        .unwrap();
    let good = TestServer::start().unwrap();
    let prepared = msg().prepare().unwrap();
    let e = smtp_net::send_prepared(&flaky.server(), &prepared).unwrap_err();
    assert!(e.is_temporary() && e.possibly_delivered(), "{e:?}");
    smtp_net::send_prepared(&good.server(), &prepared).unwrap();
    assert_eq!(flaky.received()[0].data, good.received()[0].data);
}

/// T-23: user text that looks like an encoded word reads back literally
/// through an independent RFC 2047 decoder.
#[test]
fn t23_encoded_word_lookalike_reads_literally() {
    let subject = "=?utf-8?q?Bank_alert?=";
    let m = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .subject(subject)
        .unwrap()
        .text("x")
        .unwrap()
        .build()
        .unwrap();
    let bytes = m.to_bytes().unwrap();
    let text = String::from_utf8_lossy(&bytes);
    let start = text.find("\r\nSubject: ").unwrap() + 11;
    let mut value = String::new();
    for (i, line) in text[start..].split("\r\n").enumerate() {
        if i > 0 && !line.starts_with([' ', '\t']) {
            break;
        }
        value.push_str(line);
    }
    let mut out = [0u8; 256];
    let decoded =
        parse_net::mail::decode_words(value.as_bytes(), &parse_net::Limits::DEFAULT, &mut out)
            .unwrap();
    assert_eq!(decoded, subject);
}

/// T-25: with the policy on, a display name that looks like an address is
/// refused in every field that shows one.
#[test]
fn t25_address_like_display_names() {
    let spoof = "\"support@bank.example\" <evil@example.net>";
    let b = || {
        Message::builder()
            .refuse_address_like_display_names(true)
            .text("x")
            .unwrap()
    };
    let r = b()
        .from(spoof)
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .build();
    assert_eq!(
        header_error(r),
        HeaderError::AddressLikeDisplayName { field: "From" }
    );
    let r = b()
        .from("a@example.com")
        .unwrap()
        .reply_to(spoof)
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .build();
    assert_eq!(
        header_error(r),
        HeaderError::AddressLikeDisplayName { field: "Reply-To" }
    );
    let r = b()
        .from("a@example.com")
        .unwrap()
        .cc(spoof)
        .unwrap()
        .build();
    assert_eq!(
        header_error(r),
        HeaderError::AddressLikeDisplayName { field: "Cc" }
    );
    // Off by default, and a name without @ passes with it on.
    assert!(
        Message::builder()
            .from(spoof)
            .unwrap()
            .to("b@example.org")
            .unwrap()
            .text("x")
            .unwrap()
            .build()
            .is_ok()
    );
    assert!(
        b().from("Support <a@example.com>")
            .unwrap()
            .to("b@example.org")
            .unwrap()
            .build()
            .is_ok()
    );
}

/// T-34: the test server's transcript never holds a message body.
#[test]
fn t34_transcript_omits_bodies() {
    let server = TestServer::start().unwrap();
    let m = Message::text(
        "no-reply@example.com",
        "user@example.org",
        "Reset",
        "Your link: https://example.com/reset?token=Zm9vYmFy\n",
    )
    .unwrap();
    smtp_net::send(&server.server(), &m).unwrap();
    let t = server.transcript();
    assert!(t.contains("C: <BODY>"), "{t}");
    assert!(!t.contains("Zm9vYmFy") && !t.contains("Your link"), "{t}");
}

/// T-35: bidirectional overrides and isolates are refused in the Subject
/// and display names unless allowed; right-to-left text and the RLM and
/// LRM marks pass.
#[test]
fn t35_bidi_controls() {
    let b = || {
        Message::builder()
            .from("a@example.com")
            .unwrap()
            .to("b@example.org")
            .unwrap()
            .text("x")
            .unwrap()
    };
    for c in [
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
        '\u{2068}', '\u{2069}',
    ] {
        let subject = format!("Invoice {c}fdp.exe");
        let r = b().subject(&subject).unwrap().build();
        assert_eq!(
            header_error(r),
            HeaderError::BidiControl {
                field: "Subject",
                position: 8
            },
            "{c:?}"
        );
        let name = format!("\"Bob{c}\" <bob@example.org>");
        let r = b().cc(name.as_str()).unwrap().build();
        assert!(
            matches!(
                header_error(r),
                HeaderError::BidiControl { field: "Cc", .. }
            ),
            "{c:?}"
        );
        assert!(
            b().subject(&subject)
                .unwrap()
                .allow_bidi_controls(true)
                .build()
                .is_ok()
        );
    }
    for fine in ["\u{5e9}\u{5dc}\u{5d5}\u{5dd}", "a\u{200F}b", "a\u{200E}b"] {
        assert!(b().subject(fine).unwrap().build().is_ok(), "{fine:?}");
    }
}
