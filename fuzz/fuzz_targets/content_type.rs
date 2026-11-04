#![no_main]
//! Content types: no panic; parameters added never carry controls.
use libfuzzer_sys::fuzz_target;
use smtp_net::ContentType;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(ct) = ContentType::parse(s) {
        assert!(ct.essence().contains('/'));
        let _ = ct.with_parameter("x", s);
    }
});
