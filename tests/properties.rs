//! Property tests for the invariants in dev/PLAN.md 12.3.

use proptest::prelude::*;
use smtp_net::{
    Address, BodyFlags, Envelope, Event, Message, Millis, QpState, RandomSource, ReplyLimits,
    ReplyParser, Session, SessionConfig, SessionSecurity, base64_encode_lines, base64_encoded_len,
    encode_word, quoted_printable_encode, quoted_printable_finish,
};

struct Counter(u8);
impl RandomSource for Counter {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), smtp_net::Error> {
        for b in buf {
            *b = self.0;
            self.0 = self.0.wrapping_add(31);
        }
        Ok(())
    }
}

fn qp_decode(enc: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < enc.len() {
        match enc[i] {
            b'=' if enc.get(i + 1) == Some(&b'\r') => i += 3,
            b'=' => {
                out.push(
                    u8::from_str_radix(std::str::from_utf8(&enc[i + 1..i + 3]).unwrap(), 16)
                        .unwrap(),
                );
                i += 3;
            }
            b'\r' => {
                out.push(b'\n');
                i += 2;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn b64_decode(s: &[u8]) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    };
    let clean: Vec<u8> = s
        .iter()
        .copied()
        .filter(|&c| c != b'\r' && c != b'\n')
        .collect();
    let mut out = Vec::new();
    for q in clean.chunks(4) {
        let n = (u32::from(val(q[0])) << 18)
            | (u32::from(val(q[1])) << 12)
            | (u32::from(val(q[2])) << 6)
            | u32::from(val(q[3]));
        out.push((n >> 16) as u8);
        if q[2] != b'=' {
            out.push((n >> 8) as u8);
        }
        if q[3] != b'=' {
            out.push(n as u8);
        }
    }
    out
}

fn wire_ok(bytes: &[u8]) -> Result<(), TestCaseError> {
    for (i, &c) in bytes.iter().enumerate() {
        if c == b'\n' {
            prop_assert!(i > 0 && bytes[i - 1] == b'\r', "bare LF");
        }
        if c == b'\r' {
            prop_assert!(bytes.get(i + 1) == Some(&b'\n'), "bare CR");
        }
    }
    for line in bytes.split(|&b| b == b'\n') {
        prop_assert!(line.len() <= 999, "line over 998");
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    #[test]
    fn prop_address_parse_never_panics_and_accepts_only_clean(s in "\\PC{0,80}|[a-z.@\"\\\\ \r\n\0-]{0,40}") {
        if let Ok(a) = Address::parse(&s) {
            prop_assert!(!a.as_str().chars().any(char::is_control));
            prop_assert!(a.as_str().len() <= 254);
            prop_assert!(a.as_str().contains('@'));
        }
    }

    #[test]
    fn prop_builder_output_obeys_wire_rules(
        subject in "\\PC{0,200}",
        name in "\\PC{0,40}",
        text in "(\\PC|\n){0,600}",
        html in proptest::option::of("(\\PC|\n){0,300}"),
        allow8 in any::<bool>(),
    ) {
        let from = smtp_net::Mailbox::new(Some(&name), Address::parse("a@example.com").unwrap());
        let Ok(from) = from else { return Ok(()) };
        let mut b = Message::builder().from(from).unwrap().to("b@example.org").unwrap().bcc("hidden@example.net").unwrap().allow_8bit(allow8);
        b = match b.subject(&subject) { Ok(b) => b, Err(_) => return Ok(()) };
        b = match b.text(&text) { Ok(b) => b, Err(_) => return Ok(()) };
        if let Some(h) = &html {
            b = match b.html(h) { Ok(b) => b, Err(_) => return Ok(()) };
        }
        let Ok(m) = b.build_with(&mut Counter(1), 1_700_000_000) else { return Ok(()) };
        let bytes = m.to_bytes().unwrap();
        prop_assert_eq!(bytes.len() as u64, m.encoded_len());
        wire_ok(&bytes)?;
        let s = String::from_utf8_lossy(&bytes);
        prop_assert!(!s.contains("hidden@example.net"));
        let head = s.split("\r\n\r\n").next().unwrap();
        let fields = head.split("\r\n").filter(|l| !l.starts_with(' ') && !l.starts_with('\t')).count();
        prop_assert_eq!(fields, m.headers().len());
        if !allow8 {
            prop_assert!(bytes.is_ascii(), "7-bit output by default");
        }
    }

    #[test]
    fn prop_qp_round_trips_with_short_lines(input in proptest::collection::vec(any::<u8>(), 0..2000), split in 0usize..2000) {
        let input: Vec<u8> = input.into_iter().filter(|&b| b != b'\r').collect();
        let split = split.min(input.len());
        let mut out = vec![0u8; input.len() * 4 + 64];
        let mut state = QpState::new();
        let mut n = quoted_printable_encode(&input[..split], &mut out, &mut state).unwrap();
        n += quoted_printable_encode(&input[split..], &mut out[n..], &mut state).unwrap();
        n += quoted_printable_finish(&mut out[n..], &mut state).unwrap();
        let enc = &out[..n];
        for line in enc.split(|&b| b == b'\n') {
            prop_assert!(line.strip_suffix(b"\r").unwrap_or(line).len() <= 76);
        }
        prop_assert_eq!(qp_decode(enc), input);
    }

    #[test]
    fn prop_base64_round_trips(input in proptest::collection::vec(any::<u8>(), 0..3000)) {
        let mut out = vec![0u8; base64_encoded_len(input.len() as u64) as usize];
        let n = base64_encode_lines(&input, &mut out).unwrap();
        prop_assert_eq!(n, out.len());
        prop_assert_eq!(b64_decode(&out), input);
    }

    #[test]
    fn prop_encode_word_words_bounded(text in "\\PC{0,300}") {
        let mut out = String::new();
        if encode_word(&text, &mut out).is_ok() {
            for w in out.split_whitespace().filter(|w| w.starts_with("=?")) {
                prop_assert!(w.len() <= 75, "{}", w);
            }
        }
    }

    #[test]
    fn prop_reply_parser_never_panics_and_split_invariant(input in proptest::collection::vec(any::<u8>(), 0..600), split in 1usize..64) {
        let mut whole = ReplyParser::new(ReplyLimits::default(), true);
        let w = whole.push(&input);
        let mut parts = ReplyParser::new(ReplyLimits::default(), true);
        let mut used = 0;
        let mut got = None;
        let mut err = None;
        while used < input.len() && got.is_none() && err.is_none() {
            let end = (used + split).min(input.len());
            match parts.push(&input[used..end]) {
                Ok((n, r)) => { used += n; got = r; }
                Err(e) => err = Some(e),
            }
        }
        match w {
            Ok((n, Some(r))) => { prop_assert_eq!(got, Some(r)); prop_assert_eq!(used, n); }
            Ok((_, None)) => prop_assert!(got.is_none() && err.is_none()),
            Err(e) => prop_assert_eq!(err, Some(e)),
        }
    }

    #[test]
    fn prop_body_dot_stuffing_round_trips_at_any_split(lines in proptest::collection::vec("[.a-z ]{0,20}", 0..30), split in 1usize..40) {
        let mut body: Vec<u8> = Vec::new();
        for l in &lines {
            body.extend_from_slice(l.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
        let mut c = SessionConfig::default();
        c.security = SessionSecurity::Plaintext { peer_is_loopback: true };
        let mut s = Session::new(c, Millis(0)).unwrap();
        s.receive(b"220 x\r\n", Millis(1)).unwrap();
        s.transmitted(s.transmit().len());
        s.receive(b"250 x\r\n", Millis(1)).unwrap();
        let env = Envelope::new(Address::parse("a@example.com").unwrap(), &[Address::parse("b@example.org").unwrap()]).unwrap();
        s.begin(&env, BodyFlags::default(), 1, Millis(2)).unwrap();
        s.transmitted(s.transmit().len());
        s.receive(b"250 ok\r\n", Millis(2)).unwrap();
        s.transmitted(s.transmit().len());
        s.receive(b"250 ok\r\n", Millis(2)).unwrap();
        s.transmitted(s.transmit().len());
        s.receive(b"354 go\r\n", Millis(2)).unwrap();
        while let Some(e) = s.poll_event() { let _ = matches!(e, Event::BodyWanted); }
        let mut wire = Vec::new();
        let mut rest = &body[..];
        while !rest.is_empty() {
            let take = rest.len().min(split);
            let n = s.body(&rest[..take], Millis(3)).unwrap();
            rest = &rest[n..];
            wire.extend_from_slice(s.transmit());
            s.transmitted(s.transmit().len());
        }
        s.end_body(Millis(4)).unwrap();
        wire.extend_from_slice(s.transmit());
        let mut un = Vec::new();
        for line in wire.split_inclusive(|&b| b == b'\n') {
            if line == b".\r\n" { break; }
            un.extend_from_slice(line.strip_prefix(b".").unwrap_or(line));
        }
        prop_assert_eq!(un, body);
    }
}
