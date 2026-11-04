#![no_main]
//! Arbitrary server bytes against a session in each starting state: no
//! panic, and nothing is ever written after STARTTLS before the handshake.
use libfuzzer_sys::fuzz_target;
use smtp_net::{Address, BodyFlags, Envelope, Millis, Session, SessionConfig, SessionSecurity, SessionState};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let mut config = SessionConfig::default();
    config.security = match mode % 3 {
        0 => SessionSecurity::Plaintext { peer_is_loopback: true },
        1 => SessionSecurity::StartTlsRequired,
        _ => SessionSecurity::Plaintext { peer_is_loopback: false },
    };
    let mut s = Session::new(config, Millis(0)).unwrap();
    if mode & 4 != 0 {
        let _ = s.receive(b"220 x\r\n", Millis(1));
        s.transmitted(s.transmit().len());
        let _ = s.receive(b"250-x\r\n250-PIPELINING\r\n250-8BITMIME\r\n250 SIZE 1000\r\n", Millis(2));
        s.transmitted(s.transmit().len());
        let env = Envelope::new(Address::parse("a@example.com").unwrap(), &[Address::parse("b@example.org").unwrap()]).unwrap();
        let _ = s.begin(&env, BodyFlags::default(), 10, Millis(3));
    }
    let split = usize::from(mode >> 4) + 1;
    let mut now = 10;
    for piece in rest.chunks(split) {
        now += 1;
        if s.receive(piece, Millis(now)).is_err() {
            break;
        }
        if s.state() == SessionState::NeedTls {
            assert!(s.transmit().is_empty());
        }
        s.transmitted(s.transmit().len());
        while s.poll_event().is_some() {}
        if s.state() == SessionState::Body {
            let _ = s.body(b"x\r\n", Millis(now));
            let _ = s.end_body(Millis(now));
        }
    }
    let _ = s.on_timeout(Millis(u64::MAX / 2));
});
