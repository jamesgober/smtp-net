#![no_main]
//! Arbitrary server bytes during AUTH (SCRAM server-first and server-final,
//! XOAUTH2 error documents, PLAIN, LOGIN): no panic, and a session that ends
//! up authenticated by SCRAM only got there with the server's proof, which
//! random bytes cannot forge (so it never does here).
use libfuzzer_sys::fuzz_target;
use smtp_net::{Credentials, MechanismName};
use smtp_net::protocol::{Auth, Event, MechanismList, Millis, Session, SessionConfig, SessionSecurity};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let (auth, offer): (Auth, &[u8]) = match mode % 4 {
        0 => (
            Auth::new(Credentials::password("user", "pencil"))
                .mechanisms(MechanismList::new(&[MechanismName::ScramSha256]).unwrap())
                .scram_nonce("rOprNGfwEbeRWgbNEkqO")
                .unwrap(),
            b"250 AUTH SCRAM-SHA-256\r\n",
        ),
        1 => (Auth::new(Credentials::oauth2("u@example.com", "token")), b"250 AUTH XOAUTH2\r\n"),
        2 => (
            Auth::new(Credentials::password("u", "p"))
                .mechanisms(MechanismList::new(&[MechanismName::Login]).unwrap()),
            b"250 AUTH LOGIN\r\n",
        ),
        _ => (Auth::new(Credentials::password("u", "p")), b"250 AUTH PLAIN\r\n"),
    };
    let mut config = SessionConfig::default();
    config.security = SessionSecurity::Plaintext { peer_is_loopback: true };
    config.auth = Some(auth);
    let mut s = Session::new(config, Millis(0)).unwrap();
    let _ = s.receive(b"220 x\r\n", Millis(1));
    s.transmitted(s.transmit().len());
    let mut hello = b"250-x\r\n".to_vec();
    hello.extend_from_slice(offer);
    let _ = s.receive(&hello, Millis(2));
    s.transmitted(s.transmit().len());
    let split = usize::from(mode >> 4) + 1;
    let mut now = 10;
    for piece in rest.chunks(split) {
        now += 1;
        if s.receive(piece, Millis(now)).is_err() {
            break;
        }
        s.transmitted(s.transmit().len());
        while let Some(e) = s.poll_event() {
            if let Event::Authenticated { mechanism } = e {
                assert_ne!(mechanism, MechanismName::ScramSha256, "SCRAM without the server's proof");
            }
        }
    }
});
