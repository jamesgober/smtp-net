#![no_main]
//! The header gate and encoders: no panic; accepted values produce no CR or
//! LF except the CRLF SP of a fold.
use libfuzzer_sys::fuzz_target;
use smtp_net::mime::{check_header_value, encode_word, fold_header};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let ok = check_header_value("Subject", s).is_ok();
    let mut w = String::new();
    if encode_word(s, &mut w).is_ok() {
        assert!(ok);
        for word in w.split("\r\n ") {
            assert!(!word.contains('\r') && !word.contains('\n'));
        }
    }
    let mut out = Vec::new();
    if fold_header("X-Test", s, &mut out).is_ok() {
        for line in out.split(|&b| b == b'\n') {
            assert!(line.len() <= 999);
        }
    }
});
