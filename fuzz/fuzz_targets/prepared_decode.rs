#![no_main]
//! Job payloads: no panic; anything decoded encodes back to the same bytes.
//! Inputs whose first byte is odd get the payload header in front and a
//! correct CRC-32C behind, so the fuzzer reaches the fields past the
//! checksum (random bytes almost never carry a valid one).
use libfuzzer_sys::fuzz_target;
use smtp_net::PreparedMessage;

/// CRC-32C (Castagnoli), bit by bit: an independent copy of the checksum
/// the payload format uses.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fuzz_target!(|data: &[u8]| {
    let framed;
    let input = match data.split_first() {
        Some((first, rest)) if first & 1 == 1 => {
            let mut p = b"SMTPNET1\x01".to_vec();
            p.extend_from_slice(rest);
            let crc = crc32c(&p);
            p.extend_from_slice(&crc.to_be_bytes());
            framed = p;
            &framed[..]
        }
        _ => data,
    };
    if let Ok(p) = PreparedMessage::decode(input) {
        assert_eq!(p.encode(), input);
    }
});
