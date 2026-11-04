#![no_main]
//! The transcript parser: no panic.
use libfuzzer_sys::fuzz_target;
use smtp_net::Transcript;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Transcript::parse(s);
    }
});
