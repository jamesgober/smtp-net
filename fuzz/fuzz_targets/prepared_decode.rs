#![no_main]
//! Job payloads: no panic; anything decoded encodes back to the same bytes.
use libfuzzer_sys::fuzz_target;
use smtp_net::PreparedMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = PreparedMessage::decode(data) {
        assert_eq!(p.encode(), data);
    }
});
