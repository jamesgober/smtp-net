//! STARTTLS and implicit TLS with a real TLS stack: tls-net (rustls) on both
//! sides, the fixture certificates in `tests/fixtures/` (a test CA and a
//! `localhost` certificate it signed; never use them elsewhere).

use smtp_net::{
    ErrorKind, Message, Server, TestServer, TestServerBuilder, TlsFailure, TlsProtocol,
};

const CA: &[u8] = include_bytes!("fixtures/ca.pem");
const OTHER_CA: &[u8] = include_bytes!("fixtures/other-ca.pem");
const CHAIN: &[u8] = include_bytes!("fixtures/localhost.pem");
const KEY: &[u8] = include_bytes!("fixtures/localhost.key");
const SELF_SIGNED: &[u8] = include_bytes!("fixtures/self-signed.pem");
const SELF_SIGNED_KEY: &[u8] = include_bytes!("fixtures/self-signed.key");

fn with_rustls(b: TestServerBuilder) -> TestServer {
    let tls = tls_net::server_from_pem(CHAIN, KEY).expect("fixture certificate");
    b.tls_engine(move || {
        tls.accept()
            .ok()
            .map(|s| Box::new(s) as Box<dyn net_io::TlsSession>)
    })
    .start()
    .unwrap()
}

fn msg() -> Message {
    Message::text(
        "Example <no-reply@example.com>",
        "user@example.org",
        "Over rustls",
        "Hello over real TLS.\n",
    )
    .unwrap()
}

fn trusting(server: &TestServer, ca: &[u8]) -> Server {
    server
        .server_builder()
        .tls(tls_net::client_with_ca_pem(ca).unwrap())
        .build()
        .unwrap()
}

#[test]
fn test_starttls_with_rustls_and_verification() {
    let server = with_rustls(TestServer::builder().starttls().auth("mailer", "pw"));
    let report = smtp_net::send(&trusting(&server, CA), &msg()).unwrap();
    assert!(report.was_secure());
    assert_eq!(report.tls_protocol(), Some(TlsProtocol::Tls13));
    let got = &server.received()[0];
    assert!(got.secure);
    assert_eq!(got.user.as_deref(), Some("mailer"));
}

#[test]
fn test_implicit_tls_with_rustls() {
    let server = with_rustls(TestServer::builder().implicit_tls());
    let report = smtp_net::send(&trusting(&server, CA), &msg()).unwrap();
    assert!(report.was_secure());
    assert_eq!(server.received().len(), 1);
}

#[test]
fn test_reused_connection_over_rustls() {
    let server = with_rustls(TestServer::builder().starttls());
    let mut client = smtp_net::Client::connect(&trusting(&server, CA)).unwrap();
    for _ in 0..3 {
        client.send(&msg()).unwrap();
    }
    client.close().unwrap();
    assert_eq!(server.received().len(), 3);
    assert_eq!(server.connections(), 1);
}

#[test]
fn test_untrusted_ca_is_certificate_rejected() {
    // T-11: a certificate the client cannot verify is permanent; nothing is sent.
    let server = with_rustls(TestServer::builder().starttls().auth("mailer", "pw"));
    let e = smtp_net::send(&trusting(&server, OTHER_CA), &msg()).unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::Tls(TlsFailure::CertificateRejected)),
        "{e:?}"
    );
    assert!(e.is_permanent());
    let t = server.transcript();
    assert!(!t.contains("C: AUTH") && !t.contains("C: MAIL"), "{t}");
}

#[test]
fn test_self_signed_certificate_is_rejected() {
    // T-11: a self-signed certificate for the right name is refused.
    let tls = tls_net::server_from_pem(SELF_SIGNED, SELF_SIGNED_KEY).expect("fixture");
    let server = TestServer::builder()
        .starttls()
        .tls_engine(move || {
            tls.accept()
                .ok()
                .map(|s| Box::new(s) as Box<dyn net_io::TlsSession>)
        })
        .start()
        .unwrap();
    let e = smtp_net::send(&trusting(&server, CA), &msg()).unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::Tls(TlsFailure::CertificateRejected)),
        "{e:?}"
    );
    assert!(e.is_permanent());
    assert!(!server.transcript().contains("C: MAIL"));
}

#[test]
fn test_default_engine_uses_public_roots_and_refuses_the_test_ca() {
    let server = with_rustls(TestServer::builder().starttls());
    let s = Server::starttls("localhost")
        .to_builder()
        .port(server.port())
        .build()
        .unwrap();
    let e = smtp_net::send(&s, &msg()).unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::Tls(TlsFailure::CertificateRejected)),
        "{e:?}"
    );
}

#[test]
fn test_tls_net_never_turns_verification_off() {
    let server = with_rustls(TestServer::builder().starttls());
    let s = server
        .server_builder()
        .tls(tls_net::client_with_ca_pem(OTHER_CA).unwrap())
        .dangerous_disable_certificate_verification()
        .build()
        .unwrap();
    let e = smtp_net::send(&s, &msg()).unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::Tls(TlsFailure::Setup)),
        "{e:?}"
    );
    assert!(e.is_permanent());
}
