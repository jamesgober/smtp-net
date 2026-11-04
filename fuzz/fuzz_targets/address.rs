#![no_main]
//! Addresses and mailboxes: no panic; anything accepted is clean.
use libfuzzer_sys::fuzz_target;
use smtp_net::{Address, Mailbox};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(a) = Address::parse(s) {
        assert!(!a.as_str().chars().any(char::is_control));
        assert!(a.as_str().len() <= 254);
        assert_eq!(Address::parse(a.as_str()).as_ref(), Ok(&a));
    }
    let _ = Address::parse_allowing_literal(s);
    if let Ok(m) = Mailbox::parse(s) {
        let shown = m.to_string();
        assert!(!shown.contains('\r') && !shown.contains('\n') || shown.contains("=?"));
    }
});
