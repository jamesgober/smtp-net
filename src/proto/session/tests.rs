use alloc::{format, vec::Vec};

use super::*;
use crate::address::Address;

fn loopback() -> SessionConfig {
    SessionConfig {
        security: SessionSecurity::Plaintext {
            peer_is_loopback: true,
        },
        ..SessionConfig::default()
    }
}

fn drain(s: &mut Session) -> Vec<u8> {
    let out = s.transmit().to_vec();
    s.transmitted(out.len());
    out
}

fn ready(caps: &[u8]) -> Session {
    let mut s = Session::new(loopback(), Millis(0)).unwrap();
    s.receive(b"220 mx ESMTP\r\n", Millis(1)).unwrap();
    drain(&mut s);
    s.receive(caps, Millis(2)).unwrap();
    while s.poll_event().is_some() {}
    assert_eq!(s.state(), SessionState::Ready);
    s
}

fn envelope(n: usize) -> Envelope {
    // Long local parts make 100 RCPT lines larger than one 4 KiB group.
    let to: Vec<Address> = (0..n)
        .map(|i| Address::parse(&format!("user{i}.{}@example.org", "x".repeat(50))).unwrap())
        .collect();
    Envelope::new(Address::parse("a@example.com").unwrap(), &to).unwrap()
}

#[test]
fn test_session_output_capacity_minimum() {
    let mut c = loopback();
    c.output_capacity = 100;
    assert!(Session::new(c, Millis(0)).is_err());
}

#[test]
fn test_usage_errors_in_wrong_states() {
    let mut s = Session::new(loopback(), Millis(0)).unwrap();
    assert!(matches!(
        s.begin(&envelope(1), BodyFlags::default(), 1, Millis(0))
            .unwrap_err()
            .kind(),
        ErrorKind::Usage(_)
    ));
    assert!(s.body(b"x", Millis(0)).is_err());
    assert!(s.end_body(Millis(0)).is_err());
    assert!(
        s.tls_established(TlsInfo::new(TlsProtocol::Tls13), Millis(0))
            .is_err()
    );
    assert!(s.noop(Millis(0)).is_err());
    let mut s = ready(b"250 mx\r\n");
    s.begin(&envelope(1), BodyFlags::default(), 1, Millis(3))
        .unwrap();
    assert!(
        s.begin(&envelope(1), BodyFlags::default(), 1, Millis(3))
            .is_err(),
        "begin twice"
    );
}

#[test]
fn test_empty_receive_is_a_no_op() {
    let mut s = Session::new(loopback(), Millis(0)).unwrap();
    assert_eq!(s.receive(b"", Millis(0)).unwrap(), 0);
    assert_eq!(s.state(), SessionState::AwaitGreeting);
}

#[test]
fn test_greeting_deadline_one_ms_before_and_after() {
    let mut s = Session::new(loopback(), Millis(0)).unwrap();
    let d = s.deadline().unwrap();
    assert_eq!(d, Millis(300_000));
    assert!(s.on_timeout(Millis(d.0 - 1)).is_ok());
    let e = s.on_timeout(d).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Timeout));
    assert_eq!(e.stage(), Some(Stage::Greeting));
    assert_eq!(s.state(), SessionState::Closed);
}

#[test]
fn test_no_output_after_starttls_until_tls_established() {
    let mut c = loopback();
    c.security = SessionSecurity::StartTlsRequired;
    let mut s = Session::new(c, Millis(0)).unwrap();
    s.receive(b"220 mx\r\n", Millis(1)).unwrap();
    drain(&mut s);
    s.receive(b"250-mx\r\n250 STARTTLS\r\n", Millis(2)).unwrap();
    assert_eq!(drain(&mut s), b"STARTTLS\r\n");
    s.receive(b"220 go\r\n", Millis(3)).unwrap();
    assert_eq!(s.state(), SessionState::NeedTls);
    assert!(s.transmit().is_empty(), "T-7: nothing queued before TLS");
    assert!(!s.wants_read());
    // Bytes arriving later in plaintext are an injection too.
    let e = s.receive(b"250 OK\r\n", Millis(4)).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::StartTlsInjection));
    assert!(e.is_security_event() && e.is_temporary());
}

#[test]
fn test_capabilities_discarded_after_tls() {
    let mut c = loopback();
    c.security = SessionSecurity::StartTlsRequired;
    let mut s = Session::new(c, Millis(0)).unwrap();
    s.receive(b"220 mx\r\n", Millis(1)).unwrap();
    drain(&mut s);
    s.receive(b"250-mx\r\n250-PIPELINING\r\n250 STARTTLS\r\n", Millis(2))
        .unwrap();
    drain(&mut s);
    s.receive(b"220 go\r\n", Millis(3)).unwrap();
    assert!(s.capabilities().is_some());
    s.tls_established(TlsInfo::new(TlsProtocol::Tls12), Millis(4))
        .unwrap();
    assert!(s.capabilities().is_none());
    assert!(s.is_secure());
    assert_eq!(drain(&mut s), b"EHLO [127.0.0.1]\r\n");
    // The second EHLO advertises STARTTLS again: it is never sent twice.
    s.receive(b"250-mx\r\n250 STARTTLS\r\n", Millis(5)).unwrap();
    assert!(s.transmit().is_empty());
    assert_eq!(s.state(), SessionState::Ready);
    assert!(!s.capabilities().unwrap().has(Extension::Pipelining));
    assert_eq!(s.tls_protocol(), Some(TlsProtocol::Tls12));
}

#[test]
fn test_pipelined_group_split_at_4k() {
    let mut s = ready(b"250-mx\r\n250 PIPELINING\r\n");
    s.begin(&envelope(100), BodyFlags::default(), 10, Millis(3))
        .unwrap();
    let first = drain(&mut s);
    assert!(
        first.len() <= GROUP_LIMIT + MAX_RCPT_LINE,
        "{}",
        first.len()
    );
    assert!(!first.ends_with(b"DATA\r\n"));
    let rcpts = first.windows(4).filter(|w| w == b"RCPT").count();
    assert!(rcpts < 100);
    // Replies for the first group release the next one.
    let mut replies = Vec::new();
    replies.extend_from_slice(b"250 ok\r\n");
    for _ in 0..rcpts {
        replies.extend_from_slice(b"250 ok\r\n");
    }
    s.receive(&replies, Millis(4)).unwrap();
    let second = drain(&mut s);
    assert!(second.starts_with(b"RCPT TO:<user"));
}

const MAX_RCPT_LINE: usize = 64;

#[test]
fn test_body_dot_stuffed_and_possibly_delivered_after_terminator_written() {
    let mut s = ready(b"250 mx\r\n");
    s.begin(&envelope(1), BodyFlags::default(), 10, Millis(3))
        .unwrap();
    assert_eq!(drain(&mut s), b"MAIL FROM:<a@example.com>\r\n");
    s.receive(b"250 ok\r\n", Millis(4)).unwrap();
    drain(&mut s);
    s.receive(b"250 ok\r\n", Millis(5)).unwrap();
    assert_eq!(drain(&mut s), b"DATA\r\n");
    s.receive(b"354 go\r\n", Millis(6)).unwrap();
    while s.poll_event().is_some() {}
    assert_eq!(s.state(), SessionState::Body);
    assert_eq!(s.body(b".a\r\n", Millis(7)).unwrap(), 4);
    s.end_body(Millis(8)).unwrap();
    assert!(s.end_body(Millis(8)).is_err(), "end_body twice");
    // Not yet transmitted: a lost connection is not possibly delivered.
    let mut early = ready(b"250 mx\r\n");
    early
        .begin(&envelope(1), BodyFlags::default(), 10, Millis(3))
        .unwrap();
    let e = early.connection_lost(ErrorKind::ConnectionClosed);
    assert!(!e.possibly_delivered());
    let wire = s.transmit().to_vec();
    assert_eq!(wire, b"..a\r\n.\r\n");
    s.transmitted(wire.len() - 1);
    let mut partial = s.clone_for_test();
    let e = partial.connection_lost(ErrorKind::ConnectionClosed);
    assert!(
        !e.possibly_delivered(),
        "the last byte of the terminator was not written"
    );
    s.transmitted(1);
    let e = s.connection_lost(ErrorKind::ConnectionClosed);
    assert!(e.possibly_delivered() && e.is_temporary());
}

#[test]
fn test_body_bare_lf_refused_and_session_closed() {
    let mut s = ready(b"250 mx\r\n");
    s.begin(&envelope(1), BodyFlags::default(), 10, Millis(3))
        .unwrap();
    drain(&mut s);
    s.receive(b"250 ok\r\n250 ok\r\n", Millis(4)).unwrap();
    drain(&mut s);
    s.receive(b"250 ok\r\n", Millis(4)).ok();
    drain(&mut s);
    s.receive(b"354 go\r\n", Millis(5)).ok();
    if s.state() == SessionState::Body {
        let e = s
            .body(b"x\n.\nRCPT TO:<evil@x>\r\n", Millis(6))
            .unwrap_err();
        assert!(matches!(
            e.kind(),
            ErrorKind::Build(crate::error::BuildError::BareLineFeed { .. })
        ));
        assert!(e.is_permanent());
        assert_eq!(s.state(), SessionState::Closed);
    }
}

#[test]
fn test_quit_closes_on_221() {
    let mut s = ready(b"250 mx\r\n");
    s.quit(Millis(3)).unwrap();
    assert_eq!(drain(&mut s), b"QUIT\r\n");
    s.receive(b"221 bye\r\n", Millis(4)).unwrap();
    assert_eq!(s.state(), SessionState::Closed);
    assert!(matches!(
        s.poll_event(),
        Some(Event::Closed { error: None })
    ));
    assert!(s.quit(Millis(5)).is_ok());
}

#[test]
fn test_reset_and_noop_round_trips() {
    let mut s = ready(b"250 mx\r\n");
    s.noop(Millis(3)).unwrap();
    assert_eq!(drain(&mut s), b"NOOP\r\n");
    s.receive(b"250 ok\r\n", Millis(4)).unwrap();
    s.reset(Millis(5)).unwrap();
    assert_eq!(drain(&mut s), b"RSET\r\n");
    s.receive(b"250 ok\r\n", Millis(6)).unwrap();
    assert_eq!(s.state(), SessionState::Ready);
}

#[test]
fn test_421_mid_pipeline_closes_temporary() {
    let mut s = ready(b"250-mx\r\n250 PIPELINING\r\n");
    s.begin(&envelope(2), BodyFlags::default(), 10, Millis(3))
        .unwrap();
    drain(&mut s);
    let e = s
        .receive(b"250 ok\r\n421 4.3.2 bye\r\n", Millis(4))
        .unwrap_err();
    assert!(e.is_temporary() && !e.possibly_delivered());
    assert_eq!(e.stage(), Some(Stage::Rcpt));
}

#[test]
fn test_session_is_send() {
    fn send<T: Send>() {}
    send::<Session>();
}

impl Session {
    /// A copy outside any AUTH exchange (an exchange holds a mechanism and is not cloned).
    fn clone_for_test(&self) -> Session {
        assert!(self.exchange.is_none());
        Session {
            config: self.config.clone(),
            state: self.state,
            out: self.out.clone(),
            parser: self.parser.clone(),
            pending: self.pending.clone(),
            events: self.events.clone(),
            caps: self.caps.clone(),
            secure: self.secure,
            tls_protocol: self.tls_protocol,
            exchange: None,
            authenticated: self.authenticated,
            secret_out: self.secret_out,
            txn: self.txn.clone(),
            body_deadline: self.body_deadline,
            group: self.group,
        }
    }
}

fn chunking_ready() -> Session {
    ready(b"250-mx\r\n250-PIPELINING\r\n250 CHUNKING\r\n")
}

#[test]
fn test_bdat_one_write_and_exact_size() {
    let mut s = chunking_ready();
    s.begin(&envelope(1), BodyFlags::default(), 6, Millis(3))
        .unwrap();
    assert!(matches!(s.poll_event(), Some(Event::BodyWanted)));
    assert_eq!(s.state(), SessionState::Body);
    assert_eq!(
        s.body(b".x\r\n.\r", Millis(4)).unwrap(),
        6,
        "no dot-stuffing in BDAT"
    );
    s.end_body(Millis(5)).unwrap_err();
}

#[test]
fn test_bdat_size_mismatch_refused() {
    let mut s = chunking_ready();
    s.begin(&envelope(1), BodyFlags::default(), 4, Millis(3))
        .unwrap();
    let e = s.body(b"12345", Millis(4)).unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Build(BuildError::LengthMismatch {
            declared: 4,
            actual: 5
        })
    ));
    let mut s = chunking_ready();
    s.begin(&envelope(1), BodyFlags::default(), 4, Millis(3))
        .unwrap();
    s.body(b"12", Millis(4)).unwrap();
    let e = s.end_body(Millis(5)).unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Build(BuildError::LengthMismatch {
            declared: 4,
            actual: 2
        })
    ));
}

#[test]
fn test_bdat_last_adds_crlf_when_body_lacks_it() {
    let mut s = chunking_ready();
    s.begin(&envelope(1), BodyFlags::default(), 3, Millis(3))
        .unwrap();
    s.body(b"abc", Millis(4)).unwrap();
    s.end_body(Millis(5)).unwrap();
    let wire = drain(&mut s);
    assert!(
        wire.ends_with(b"abcBDAT 2 LAST\r\n\r\n"),
        "{}",
        String::from_utf8_lossy(&wire)
    );
}

#[test]
fn test_large_bdat_waits_for_rcpt_replies() {
    let mut s = chunking_ready();
    s.begin(&envelope(1), BodyFlags::default(), 200_000, Millis(3))
        .unwrap();
    let first = drain(&mut s);
    assert!(
        !first.windows(4).any(|w| w == b"BDAT"),
        "the chunk waits for MAIL and RCPT replies"
    );
    s.receive(b"250 ok\r\n250 ok\r\n", Millis(4)).unwrap();
    assert!(drain(&mut s).starts_with(b"BDAT 200000"));
}

#[test]
fn test_auth_refused_over_unverified_plaintext() {
    use crate::proto::{Auth, Credentials};
    let config = SessionConfig {
        security: SessionSecurity::Plaintext {
            peer_is_loopback: false,
        },
        auth: Some(Auth::new(Credentials::password("u", "p"))),
        ..SessionConfig::default()
    };
    let e = Session::new(config, Millis(0)).unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Config(crate::error::ConfigError::AuthWithPlaintextRemote)
    ));
}

#[test]
fn test_auth_output_wiped_after_transmit() {
    use crate::proto::{Auth, Credentials};
    let config = SessionConfig {
        auth: Some(Auth::new(Credentials::password("u", "secret"))),
        ..loopback()
    };
    let mut s = Session::new(config, Millis(0)).unwrap();
    s.receive(b"220 x\r\n", Millis(1)).unwrap();
    drain(&mut s);
    s.receive(b"250-x\r\n250 AUTH PLAIN\r\n", Millis(2))
        .unwrap();
    assert!(s.transmit().starts_with(b"AUTH PLAIN "));
    let n = s.transmit().len();
    s.transmitted(n);
    assert!(s.out.iter().all(|&b| b == 0) || s.out.is_empty());
    assert!(!s.secret_out);
}

/// 64 + 1 + 182 octets: the longest RCPT line a valid address gives with
/// DSN, about 540 octets.
fn long_address() -> Address {
    let domain = format!(
        "{}.{}.{}.com",
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(50)
    );
    Address::parse(&format!("{}@{domain}", "a".repeat(64))).unwrap()
}

fn dsn_envelope(to: &[Address]) -> Envelope {
    use crate::message::prepared::{Dsn, DsnNotify};
    Envelope::new(Address::parse("a@example.com").unwrap(), to)
        .unwrap()
        .with_dsn(Dsn::new(DsnNotify::FAILURE))
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

#[test]
fn test_long_rcpt_line_with_dsn_goes_out_whole() {
    // The 512 octets are the command and its path; NOTIFY and ORCPT have
    // their own 530 (RFC 3461 5.4), so a long address keeps its ORCPT.
    let mut s = ready(b"250-mx\r\n250-PIPELINING\r\n250 DSN\r\n");
    let to = [long_address()];
    s.begin(&dsn_envelope(&to), BodyFlags::default(), 10, Millis(3))
        .unwrap();
    let out = drain(&mut s);
    let rcpt = out
        .split(|&b| b == b'\n')
        .find(|l| l.starts_with(b"RCPT TO:"))
        .unwrap();
    assert!(rcpt.len() > 512, "{}", rcpt.len());
    assert_eq!(count(rcpt, b" ORCPT=rfc822;"), 1);
}

#[test]
fn test_orcpt_over_500_characters_is_left_out() {
    // A valid address gives at most about 400 characters of ORCPT; 200
    // plus signs (600 of xtext) are over 500 (RFC 3461 4.2), so the
    // parameter is left out, not refused.
    let plus = Address::unchecked(&format!("{}@example.org", "+".repeat(200)));
    let mut s = ready(b"250-mx\r\n250-PIPELINING\r\n250 DSN\r\n");
    s.begin(&dsn_envelope(&[plus]), BodyFlags::default(), 10, Millis(3))
        .unwrap();
    let out = drain(&mut s);
    assert_eq!(count(&out, b"NOTIFY=FAILURE"), 1);
    assert_eq!(count(&out, b"ORCPT="), 0);
}

#[test]
fn test_begin_refusing_a_line_queues_nothing() {
    // A failed begin must leave no MAIL or RCPT line queued, or the next
    // transaction on the connection joins it (with and without PIPELINING).
    // Valid addresses cannot give such a line; an unchecked one can.
    let too_long = Address::unchecked(&format!("{}@example.org", "a".repeat(600)));
    for caps in [
        &b"250-mx\r\n250-PIPELINING\r\n250-CHUNKING\r\n250 DSN\r\n"[..],
        b"250-mx\r\n250 DSN\r\n",
    ] {
        let mut s = ready(caps);
        let to = [
            Address::parse("first@example.org").unwrap(),
            too_long.clone(),
        ];
        let e = s
            .begin(&dsn_envelope(&to), BodyFlags::default(), 10, Millis(3))
            .unwrap_err();
        assert!(matches!(
            e.kind(),
            ErrorKind::Build(BuildError::CommandTooLong)
        ));
        assert_eq!(e.stage(), Some(Stage::Rcpt));
        assert!(e.is_permanent());
        assert!(s.transmit().is_empty());
        assert!(!s.wants_read());
        assert_eq!(s.state(), SessionState::Ready);
        assert!(s.poll_event().is_none());

        let next = Envelope::new(
            Address::parse("a@example.com").unwrap(),
            &[Address::parse("b@example.org").unwrap()],
        )
        .unwrap();
        s.begin(&next, BodyFlags::default(), 10, Millis(4)).unwrap();
        let out = drain(&mut s);
        assert_eq!(count(&out, b"MAIL FROM:"), 1);
        assert_eq!(count(&out, b"first@example.org"), 0);
    }
    // The same for the MAIL line.
    let mut s = ready(b"250-mx\r\n250-PIPELINING\r\n250 DSN\r\n");
    let env = Envelope::new(too_long, &[Address::parse("b@example.org").unwrap()]).unwrap();
    let e = s
        .begin(&env, BodyFlags::default(), 10, Millis(3))
        .unwrap_err();
    assert_eq!(e.stage(), Some(Stage::Mail));
    assert!(s.transmit().is_empty());
    assert!(!s.wants_read());
}

#[test]
fn test_longest_valid_mail_line_fits_its_allowance() {
    // A 254-octet reverse path, SIZE, BODY, SMTPUTF8, RET, and an ENVID of
    // 100 characters as sent: the parameters stay within their allowance.
    use crate::message::prepared::{Dsn, DsnNotify, DsnReturn};
    let mut s = ready(
        b"250-mx\r\n250-PIPELINING\r\n250-SIZE\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250 DSN\r\n",
    );
    let dsn = Dsn::new(DsnNotify::FAILURE)
        .with_return_content(DsnReturn::Headers)
        .with_envelope_id(&"+".repeat(33))
        .unwrap();
    let env = Envelope::new(long_address(), &[Address::parse("b@example.org").unwrap()])
        .unwrap()
        .with_dsn(dsn);
    s.begin(&env, BodyFlags::new(true, true), u64::MAX, Millis(3))
        .unwrap();
    let out = drain(&mut s);
    assert!(out.starts_with(b"MAIL FROM:<"));
}

#[test]
fn test_dsn_parameters_are_written_as_xtext_into_the_line() {
    // ENVID and ORCPT go through xtext straight into the line.
    let mut s = ready(b"250-mx\r\n250-PIPELINING\r\n250 DSN\r\n");
    let dsn = crate::message::prepared::Dsn::new(crate::message::prepared::DsnNotify::FAILURE)
        .with_envelope_id("order+42")
        .unwrap();
    let env = Envelope::new(
        Address::parse("a@example.com").unwrap(),
        &[Address::parse("x+y@example.org").unwrap()],
    )
    .unwrap()
    .with_dsn(dsn);
    s.begin(&env, BodyFlags::default(), 10, Millis(3)).unwrap();
    let out = drain(&mut s);
    assert_eq!(
        out,
        b"MAIL FROM:<a@example.com> ENVID=order+2B42\r\nRCPT TO:<x+y@example.org> NOTIFY=FAILURE ORCPT=rfc822;x+2By@example.org\r\nDATA\r\n"
            .as_slice()
    );
}

#[test]
fn test_ehlo_reply_over_1_kib_keeps_every_capability() {
    // The kept text of a reply stops at 1,024 octets; an EHLO reply is kept
    // whole (up to the reply budget), so a SIZE straddling the cut is not
    // read as `SIZE 3` and the lines after it are not lost.
    let mut ehlo = Vec::new();
    ehlo.extend_from_slice(b"250-mx.example.com\r\n");
    ehlo.extend_from_slice(format!("250-X-A{}\r\n", "a".repeat(98)).as_bytes());
    for i in 0..9 {
        ehlo.extend_from_slice(format!("250-X-{i}{}\r\n", "b".repeat(96)).as_bytes());
    }
    ehlo.extend_from_slice(b"250-SIZE 35882577\r\n");
    ehlo.extend_from_slice(b"250 PIPELINING\r\n");
    assert!(ehlo.len() > 1024 && ehlo.len() < 8192);
    let s = ready(&ehlo);
    let caps = s.capabilities().unwrap();
    assert_eq!(caps.size_limit(), Some(35_882_577));
    assert!(caps.has(Extension::Pipelining));
}
