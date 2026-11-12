#![no_main]
//! EHLO capabilities: no panic on any reply text.
use libfuzzer_sys::fuzz_target;
use smtp_net::{Capabilities, Extension};
use smtp_net::protocol::{ReplyLimits, ReplyParser};

fuzz_target!(|data: &[u8]| {
    let mut input = b"250-x\r\n".to_vec();
    for line in data.split(|&b| b == b'\n').take(60) {
        input.extend_from_slice(b"250-");
        input.extend_from_slice(line.strip_suffix(b"\r").unwrap_or(line));
        input.extend_from_slice(b"\r\n");
    }
    input.extend_from_slice(b"250 END\r\n");
    let mut p = ReplyParser::new(ReplyLimits::default(), false);
    if let Ok((_, Some(r))) = p.push(&input) {
        if let Ok(c) = Capabilities::parse(&r) {
            let _ = c.has(Extension::Pipelining);
            let _ = c.size_limit().map(|s| assert!(s <= 1 << 53));
            assert!(c.unknown().count() <= 32);
        }
    }
});
