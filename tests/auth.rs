//! 0.5 SASL end to end against `TestServer`: XOAUTH2 (success, and the
//! error document of an expired token), SCRAM-SHA-256 with server
//! verification (feature `scram`), and the ASCII rule for SCRAM (O-12).

use smtp_net::{Credentials, ErrorKind, Message, TestServer};

fn msg() -> Message {
    Message::text(
        "no-reply@example.com",
        "user@example.org",
        "Sign-in code",
        "Your code is 314159.\n",
    )
    .unwrap()
}

#[test]
fn test_xoauth2_token_accepted() {
    let server = TestServer::builder()
        .starttls()
        .oauth2("mailer@example.com", "ya29.good-token")
        .start()
        .unwrap();
    smtp_net::send(&server.server(), &msg()).unwrap();
    assert_eq!(
        server.received()[0].user.as_deref(),
        Some("mailer@example.com")
    );
    let t = server.transcript();
    assert!(t.contains("C: AUTH XOAUTH2 <redacted"), "{t}");
    assert!(!t.contains("good-token"), "{t}");
}

#[test]
fn test_xoauth2_expired_token_reports_status() {
    let server = TestServer::builder()
        .starttls()
        .oauth2("mailer@example.com", "ya29.good-token")
        .start()
        .unwrap();
    let s = server
        .server_builder()
        .credentials(Credentials::oauth2("mailer@example.com", "ya29.expired"))
        .build()
        .unwrap();
    let e = smtp_net::send(&s, &msg()).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::AuthFailed, "{e:?}");
    assert!(e.is_permanent());
    // The cue to refresh the token and retry.
    assert_eq!(e.auth_detail(), Some("401"));
    assert!(server.received().is_empty());
}

#[test]
fn test_password_never_goes_to_xoauth2() {
    // The server offers only XOAUTH2; a password has no mechanism to use.
    let server = TestServer::builder()
        .starttls()
        .oauth2("mailer@example.com", "t")
        .start()
        .unwrap();
    let s = server
        .server_builder()
        .credentials(Credentials::password("mailer@example.com", "pw"))
        .build()
        .unwrap();
    let e = smtp_net::send(&s, &msg()).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::AuthUnavailable, "{e:?}");
}

#[cfg(feature = "scram")]
mod scram {
    use smtp_net::{Fault, MechanismName, SaslError, Server};

    use super::*;

    fn with_password(server: &TestServer, password: &str) -> Server {
        server
            .server_builder()
            .credentials(Credentials::password("mailer", password))
            .build()
            .unwrap()
    }

    #[test]
    fn test_scram_is_preferred_and_verifies_the_server() {
        let server = TestServer::builder()
            .starttls()
            .auth("mailer", "correct horse")
            .start()
            .unwrap();
        smtp_net::send(&server.server(), &msg()).unwrap();
        assert_eq!(server.received()[0].user.as_deref(), Some("mailer"));
        let t = server.transcript();
        assert!(t.contains("C: AUTH SCRAM-SHA-256"), "{t}");
        assert!(!t.contains("correct horse"), "{t}");
    }

    #[test]
    fn test_scram_wrong_password_is_auth_failed() {
        let server = TestServer::builder()
            .starttls()
            .auth("mailer", "correct horse")
            .start()
            .unwrap();
        let e = smtp_net::send(&with_password(&server, "wrong"), &msg()).unwrap_err();
        assert_eq!(e.kind(), &ErrorKind::AuthFailed, "{e:?}");
    }

    #[test]
    fn test_scram_server_without_the_key_is_refused() {
        // T-29 end to end: a server that cannot sign is not trusted, and no
        // MAIL follows even though it said the proof was right.
        let server = TestServer::builder()
            .starttls()
            .auth("mailer", "correct horse")
            .fault(Fault::BadScramSignature)
            .start()
            .unwrap();
        let e = smtp_net::send(&server.server(), &msg()).unwrap_err();
        assert_eq!(
            e.kind(),
            &ErrorKind::Sasl(SaslError::ServerSignatureMismatch),
            "{e:?}"
        );
        assert!(e.is_security_event());
        assert!(!server.transcript().contains("C: MAIL"));
    }

    #[test]
    fn test_non_ascii_password_falls_through_to_plain() {
        // O-12: SCRAM needs ASCII until SASLprep exists; PLAIN carries UTF-8.
        let server = TestServer::builder()
            .starttls()
            .auth("mailer", "pässwörd")
            .start()
            .unwrap();
        smtp_net::send(&server.server(), &msg()).unwrap();
        assert!(server.transcript().contains("C: AUTH PLAIN"));
        let only_scram = server
            .server_builder()
            .mechanisms(&[MechanismName::ScramSha256])
            .unwrap()
            .build()
            .unwrap();
        let e = smtp_net::send(&only_scram, &msg()).unwrap_err();
        assert_eq!(
            e.kind(),
            &ErrorKind::Sasl(SaslError::NonAsciiCredential),
            "{e:?}"
        );
        assert!(e.is_permanent());
    }
}

#[test]
fn test_observer_sees_codes_and_outcomes_never_secrets() {
    use std::sync::Mutex;

    use smtp_net::{ObservedEvent, Observer, SecurityEventKind};

    #[derive(Default)]
    struct Log(Mutex<Vec<String>>);
    impl Observer for Log {
        fn event(&self, event: &ObservedEvent<'_>) {
            self.0.lock().unwrap().push(format!("{event:?}"));
        }
    }
    let log = std::sync::Arc::new(Log::default());
    struct Shared(std::sync::Arc<Log>);
    impl Observer for Shared {
        fn event(&self, event: &ObservedEvent<'_>) {
            self.0.event(event);
        }
    }
    let server = TestServer::builder()
        .starttls()
        .oauth2("mailer@example.com", "ya29.secret-token")
        .start()
        .unwrap();
    let s = server
        .server_builder()
        .observer(Shared(log.clone()))
        .build()
        .unwrap();
    smtp_net::send(&s, &msg()).unwrap();
    let events = log.0.lock().unwrap().clone();
    let all = events.join("\n");
    assert!(events[0].starts_with("Connected"), "{all}");
    assert!(all.contains("Secure { protocol:"), "{all}");
    assert!(all.contains("stage: Auth, code: ReplyCode(235)"), "{all}");
    assert!(events.last().unwrap().starts_with("Delivered"), "{all}");
    assert!(
        !all.contains("secret-token") && !all.contains("test.smtp-net"),
        "T-30: {all}"
    );

    // A failure, then the security event that follows it.
    log.0.lock().unwrap().clear();
    let plain = TestServer::builder().start().unwrap();
    let s = smtp_net::Server::starttls("localhost")
        .to_builder()
        .port(plain.port())
        .tls_connector(smtp_net::TestTls)
        .observer(Shared(log.clone()))
        .build()
        .unwrap();
    assert!(smtp_net::send(&s, &msg()).is_err());
    let events = log.0.lock().unwrap().clone();
    let n = events.len();
    assert!(
        events[n - 2].starts_with("Failed { stage: Some(Ehlo)"),
        "{events:?}"
    );
    assert_eq!(
        events[n - 1],
        format!(
            "{:?}",
            ObservedEvent::SecurityEvent {
                kind: SecurityEventKind::StartTlsMissing
            }
        )
    );
}
