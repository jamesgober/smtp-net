#![no_main]
//! Reply parser: no panic, budgets hold, and the same result for any split.
use libfuzzer_sys::fuzz_target;
use smtp_net::{ReplyLimits, ReplyParser};

fuzz_target!(|data: &[u8]| {
    let split = data.first().map_or(1, |b| usize::from(*b % 16) + 1);
    let mut whole = ReplyParser::new(ReplyLimits::default(), true);
    let w = whole.push(data);
    let mut parts = ReplyParser::new(ReplyLimits::default(), true);
    let mut used = 0;
    let mut got = None;
    let mut err = None;
    while used < data.len() && got.is_none() && err.is_none() {
        let end = (used + split).min(data.len());
        match parts.push(&data[used..end]) {
            Ok((n, r)) => {
                used += n;
                got = r;
            }
            Err(e) => err = Some(e),
        }
    }
    match w {
        Ok((_, Some(r))) => {
            assert_eq!(got.as_ref(), Some(&r));
            assert!(r.lines().map(<[u8]>::len).sum::<usize>() <= 8192);
            let _ = r.text_lossy().to_string();
        }
        Ok((_, None)) => assert!(got.is_none() && err.is_none()),
        Err(e) => assert_eq!(err, Some(e)),
    }
});
