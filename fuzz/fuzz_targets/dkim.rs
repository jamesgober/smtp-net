#![no_main]
//! DKIM: canonicalization gives the same output however the body is split;
//! signing any input never panics, and every header it returns is ASCII,
//! folded to 78 columns, ends in CRLF, and has no `l=` tag.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use smtp_net::{Canonicalization, DkimKey, DkimSigner};
use smtp_net::dkim::BodyCanonicalizer;

fn body(mode: Canonicalization, pieces: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut c = BodyCanonicalizer::new(mode);
    for p in pieces {
        c.update(p, &mut |b| out.extend_from_slice(b));
    }
    c.finish(&mut |b| out.extend_from_slice(b));
    out
}

fuzz_target!(|data: &[u8]| {
    let a = data.first().map_or(0, |&b| usize::from(b)) % (data.len() + 1);
    let b = a + data.get(1).map_or(0, |&b| usize::from(b)) % (data.len() - a + 1);
    for mode in [Canonicalization::Simple, Canonicalization::Relaxed] {
        let whole = body(mode, &[data]);
        assert_eq!(whole, body(mode, &[&data[..a], &data[a..b], &data[b..]]));
    }

    static SIGNER: OnceLock<DkimSigner> = OnceLock::new();
    let signer = SIGNER.get_or_init(|| {
        DkimSigner::new("example.com", "fuzz", DkimKey::ed25519_from_seed(&[7; 32]).unwrap()).unwrap()
    });
    if let Ok(header) = signer.sign(data, 0) {
        assert!(header.is_ascii() && header.ends_with("\r\n"));
        assert!(header.split("\r\n").all(|line| line.len() <= 78));
        assert!(!header.replace("\r\n ", "").contains("; l="));
    }
});
