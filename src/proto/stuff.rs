//! Streaming dot-stuffing for DATA (RFC 5321 4.5.2), correct across every
//! chunk boundary (T-3: the `CRLF CRLF .` case of RUSTSEC-2021-0069), with
//! bare CR and bare LF refused (T-4: SMTP smuggling).

use alloc::vec::Vec;

use crate::error::BuildError;

/// Dot-stuffing state carried across `body` calls.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DotStuffer {
    at_line_start: bool,
    pending_cr: bool,
    /// True when the last bytes written were CRLF (or nothing was written).
    ends_crlf: bool,
    offset: u64,
    /// False for BDAT: the bytes go as they are, still checked for bare CR and LF.
    stuff: bool,
}

impl DotStuffer {
    pub(crate) fn new() -> DotStuffer {
        DotStuffer {
            at_line_start: true,
            pending_cr: false,
            ends_crlf: false,
            offset: 0,
            stuff: true,
        }
    }

    /// For BDAT chunks: no dot-stuffing (RFC 3030), the same line checks.
    pub(crate) fn raw() -> DotStuffer {
        DotStuffer {
            stuff: false,
            ..DotStuffer::new()
        }
    }

    /// Input bytes taken so far.
    pub(crate) fn taken(&self) -> u64 {
        self.offset
    }

    /// True when the input so far ends with CRLF.
    pub(crate) fn ends_crlf(&self) -> bool {
        self.ends_crlf
    }

    /// True when the input so far ends with a CR whose LF has not come yet.
    pub(crate) fn pending_cr(&self) -> bool {
        self.pending_cr
    }

    /// Stuffs bytes of `input` into `out` while `out` stays within `cap`;
    /// returns how many input bytes were taken.
    pub(crate) fn push(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        cap: usize,
    ) -> Result<usize, BuildError> {
        let mut taken = 0usize;
        while let Some(&b) = input.get(taken) {
            // Room for the byte, a stuffed dot, and a held CR.
            let room = cap.saturating_sub(out.len());
            if room < 3 {
                break;
            }
            if self.pending_cr {
                if b != b'\n' {
                    return Err(BuildError::BareCarriageReturn {
                        position: self.offset - 1,
                    });
                }
                self.pending_cr = false;
                out.extend_from_slice(b"\r\n");
                self.at_line_start = true;
                self.ends_crlf = true;
                self.offset += 1;
                taken += 1;
                continue;
            }
            match b {
                b'\r' => {
                    self.pending_cr = true;
                    self.offset += 1;
                    taken += 1;
                }
                b'\n' => {
                    return Err(BuildError::BareLineFeed {
                        position: self.offset,
                    });
                }
                _ => {
                    if self.stuff && self.at_line_start && b == b'.' {
                        out.push(b'.');
                    }
                    // The rest of the line up to its CR (or the room left)
                    // goes in one copy (PLAN 11.3 item 4).
                    let rest = input.get(taken..).unwrap_or(&[]);
                    let max = rest.len().min(room - 2);
                    let window = rest.get(..max).unwrap_or(&[]);
                    let run = crate::scan::find_line_end(window).unwrap_or(max).max(1);
                    out.extend_from_slice(rest.get(..run).unwrap_or(&[]));
                    self.at_line_start = false;
                    self.ends_crlf = false;
                    self.offset += run as u64;
                    taken += run;
                }
            }
        }
        Ok(taken)
    }

    /// Writes the end-of-data sequence: CRLF (unless the body ended with one)
    /// and `.` CRLF.
    pub(crate) fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), BuildError> {
        if self.pending_cr {
            return Err(BuildError::BareCarriageReturn {
                position: self.offset - 1,
            });
        }
        if !self.ends_crlf && self.offset > 0 {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn stuff_split(body: &[u8], split: usize) -> Result<Vec<u8>, BuildError> {
        let mut s = DotStuffer::new();
        let mut out = Vec::new();
        let mut all = Vec::new();
        for part in [&body[..split], &body[split..]] {
            let mut rest = part;
            while !rest.is_empty() {
                let n = s.push(rest, &mut out, 8)?;
                if n == 0 {
                    // The driver drains the output buffer.
                    all.append(&mut out);
                }
                rest = &rest[n..];
            }
        }
        s.finish(&mut out)?;
        all.append(&mut out);
        Ok(all)
    }

    fn unstuff(wire: &[u8]) -> Vec<u8> {
        // Receiver side (RFC 5321 4.5.2): drop a leading dot of each line; stop at the lone dot.
        let mut out = Vec::new();
        let mut lines = wire.split_inclusive(|&b| b == b'\n');
        for line in &mut lines {
            if line == b".\r\n" {
                break;
            }
            out.extend_from_slice(line.strip_prefix(b".").unwrap_or(line));
        }
        out
    }

    #[test]
    fn test_dot_stuffer_dot_after_double_crlf_split_at_every_byte_stuffed() {
        let bodies: [&[u8]; 6] = [
            b"a\r\n.\r\nRCPT TO:<x@y>\r\n",
            b"a\r\n\r\n.\r\nQUIT\r\n",
            b".starts with a dot\r\n",
            b"..\r\n.\r\n...\r\n",
            b"no final crlf .",
            b"",
        ];
        for body in bodies {
            for split in 0..=body.len() {
                let wire = stuff_split(body, split).unwrap();
                if body.is_empty() {
                    assert_eq!(wire, b".\r\n");
                    continue;
                }
                assert!(wire.ends_with(b"\r\n.\r\n"), "{wire:?}");
                // The only lone dot line is the terminator.
                let lone = wire.windows(5).filter(|w| w == b"\r\n.\r\n").count();
                assert_eq!(lone, 1, "body {body:?} split {split}: {wire:?}");
                let mut want = body.to_vec();
                if !want.is_empty() && !want.ends_with(b"\r\n") {
                    want.extend_from_slice(b"\r\n");
                }
                assert_eq!(unstuff(&wire), want, "body {body:?} split {split}");
            }
        }
    }

    #[test]
    fn test_dot_stuffer_smuggling_sequences_refused() {
        for body in [
            &b"x\n.\nmore"[..],
            b"x\r.\rmore",
            b"x\r\n.\nmore",
            b"x\n.\r\nmore",
            b"end\r",
        ] {
            let mut s = DotStuffer::new();
            let mut out = Vec::new();
            let r = s
                .push(body, &mut out, 1 << 16)
                .and_then(|_| s.finish(&mut out));
            assert!(r.is_err(), "{body:?}");
        }
    }

    #[test]
    fn test_dot_stuffer_respects_capacity() {
        let mut s = DotStuffer::new();
        let mut out = vec![0u8; 6];
        assert_eq!(s.push(b"abcdef", &mut out, 8).unwrap(), 0);
        out.clear();
        assert_eq!(s.push(b"abcdef", &mut out, 8).unwrap(), 6);
    }

    #[test]
    fn test_dot_stuffer_empty_body_gets_lone_dot() {
        let mut s = DotStuffer::new();
        let mut out = Vec::new();
        s.finish(&mut out).unwrap();
        assert_eq!(out, b".\r\n");
    }

    /// Deterministic inputs biased to the octets the encoders treat specially.
    fn corpus(cases: usize) -> Vec<Vec<u8>> {
        const ALPHABET: &[u8] = b" \t=.Fromx\r\n\xc3\xa9a!~\x7f\x00";
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        (0..cases)
            .map(|_| {
                let len = (next() % 300) as usize;
                (0..len)
                    .map(|_| {
                        let r = next();
                        if r % 4 == 0 {
                            ALPHABET[(r >> 8) as usize % ALPHABET.len()]
                        } else {
                            b'a' + (r >> 8) as u8 % 26
                        }
                    })
                    .collect()
            })
            .collect()
    }

    /// The stuffer before the run fast path, for comparison.
    fn reference(input: &[u8]) -> Result<Vec<u8>, BuildError> {
        let mut out = Vec::new();
        let (mut start, mut cr) = (true, false);
        for (i, &b) in input.iter().enumerate() {
            if cr {
                if b != b'\n' {
                    return Err(BuildError::BareCarriageReturn {
                        position: i as u64 - 1,
                    });
                }
                cr = false;
                out.extend_from_slice(b"\r\n");
                start = true;
            } else if b == b'\r' {
                cr = true;
            } else if b == b'\n' {
                return Err(BuildError::BareLineFeed { position: i as u64 });
            } else {
                if start && b == b'.' {
                    out.push(b'.');
                }
                out.push(b);
                start = false;
            }
        }
        Ok(out)
    }

    #[test]
    fn test_run_path_matches_the_octet_at_a_time_stuffer() {
        for (n, mut input) in corpus(3000).into_iter().enumerate() {
            // Mostly valid CRLF text, with some bare CR and LF left in.
            if n % 3 != 0 {
                let mut fixed = Vec::new();
                for &b in &input {
                    match b {
                        b'\r' => {}
                        b'\n' => fixed.extend_from_slice(b"\r\n"),
                        _ => fixed.push(b),
                    }
                }
                input = fixed;
            }
            for cap in [3, 4, 9, 64, 4096] {
                let mut s = DotStuffer::new();
                let mut out = Vec::new();
                let mut all = Vec::new();
                let mut rest = &input[..];
                let got = loop {
                    if rest.is_empty() {
                        break Ok(());
                    }
                    match s.push(rest, &mut out, cap) {
                        Ok(k) => {
                            assert!(out.len() <= cap);
                            if k == 0 {
                                all.append(&mut out);
                            }
                            rest = &rest[k..];
                        }
                        Err(e) => break Err(e),
                    }
                };
                all.append(&mut out);
                match (got, reference(&input)) {
                    (Ok(()), Ok(want)) => assert_eq!(all, want, "cap {cap}"),
                    (Err(a), Err(b)) => assert_eq!(a, b, "cap {cap}"),
                    (a, b) => panic!("cap {cap}: {a:?} against {b:?}"),
                }
            }
        }
    }
}
