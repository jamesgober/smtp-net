#![no_main]
//! Raw messages: no panic; anything accepted has CRLF line endings only.
use libfuzzer_sys::fuzz_target;
use smtp_net::{Address, Envelope, PreparedMessage};

fuzz_target!(|data: &[u8]| {
    let env = Envelope::new(Address::parse("a@example.com").unwrap(), &[Address::parse("b@example.org").unwrap()]).unwrap();
    if let Ok(p) = PreparedMessage::from_raw(env, data.to_vec()) {
        let b = p.bytes();
        for (i, &c) in b.iter().enumerate() {
            if c == b'\n' {
                assert!(i > 0 && b[i - 1] == b'\r');
            }
        }
    }
});
