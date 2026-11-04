//! DKIM canonicalization (RFC 6376 section 3.4): streaming, `no_std`, and
//! correct at every split point of the input.

use alloc::vec::Vec;

/// A DKIM canonicalization algorithm (RFC 6376 section 3.4).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Canonicalization {
    /// `simple`: the text as it is; any rewrite in transit (whitespace,
    /// header case, refolding) breaks the signature.
    Simple,
    /// `relaxed`: survives whitespace and header-case changes in transit.
    /// The default.
    #[default]
    Relaxed,
}

impl Canonicalization {
    /// The algorithm's name in the `c=` tag.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Canonicalization::Simple => "simple",
            Canonicalization::Relaxed => "relaxed",
        }
    }
}

/// Output is gathered into runs this long before it reaches the sink, so a
/// hasher sees a few large updates instead of one per word.
const RUN: usize = 512;

/// Streams a message body through a canonicalization algorithm.
///
/// Feed the body in pieces of any size with [`update`](Self::update), then
/// call [`finish`](Self::finish). The output goes to a closure (a hasher, a
/// buffer); nothing is allocated.
///
/// - simple: trailing empty lines are removed, and a body that does not
///   end in CRLF (an empty body too) gets one (RFC 6376 section 3.4.3).
/// - relaxed: whitespace at the end of each line is removed, runs of spaces
///   and tabs become one space, trailing empty lines are removed, and a
///   non-empty body that does not end in CRLF gets one; an empty body stays
///   empty (section 3.4.4).
///
/// # Examples
///
/// ```
/// use smtp_net::{BodyCanonicalizer, Canonicalization};
/// let mut out = Vec::new();
/// let mut c = BodyCanonicalizer::new(Canonicalization::Relaxed);
/// c.update(b"Hi  there \t\r\n", &mut |b| out.extend_from_slice(b));
/// c.update(b"\r\n\r\n", &mut |b| out.extend_from_slice(b));
/// c.finish(&mut |b| out.extend_from_slice(b));
/// assert_eq!(out, b"Hi there\r\n");
/// ```
pub struct BodyCanonicalizer {
    mode: Canonicalization,
    /// Line ends withheld: they are output only if content follows them.
    held: u64,
    /// A CR withheld until the next octet says whether it ends a line.
    cr: bool,
    /// Relaxed: spaces or tabs withheld until content follows them.
    wsp: bool,
    /// Relaxed: some content was output.
    any: bool,
    run: [u8; RUN],
    len: usize,
}

impl BodyCanonicalizer {
    /// A canonicalizer at the start of a body.
    #[must_use]
    pub const fn new(mode: Canonicalization) -> BodyCanonicalizer {
        BodyCanonicalizer {
            mode,
            held: 0,
            cr: false,
            wsp: false,
            any: false,
            run: [0; RUN],
            len: 0,
        }
    }

    /// Canonicalizes the next piece of the body.
    pub fn update(&mut self, input: &[u8], out: &mut impl FnMut(&[u8])) {
        match self.mode {
            Canonicalization::Simple => self.simple(input, out),
            Canonicalization::Relaxed => self.relaxed(input, out),
        }
    }

    /// Ends the body and writes what was withheld.
    pub fn finish(mut self, out: &mut impl FnMut(&[u8])) {
        if self.cr {
            // A CR at the very end is content, not a line end.
            self.cr = false;
            self.content(b"\r", out);
        }
        // Withheld line ends were trailing empty lines: dropped, and the
        // last line gets exactly one CRLF.
        if self.mode == Canonicalization::Simple || self.any {
            self.put(b"\r\n", out);
        }
        self.flush(out);
    }

    fn simple(&mut self, mut input: &[u8], out: &mut impl FnMut(&[u8])) {
        if input.is_empty() {
            return;
        }
        if self.cr {
            self.cr = false;
            if let Some(rest) = input.strip_prefix(b"\n") {
                self.held += 1;
                input = rest;
            } else {
                self.content(b"\r", out);
            }
        }
        // The tail of this piece that may turn out to be trailing empty
        // lines: CRLF pairs, then perhaps a CR whose LF is in the next piece.
        let cr = input.last() == Some(&b'\r');
        let mut end = input.len() - usize::from(cr);
        let mut pairs = 0u64;
        while end >= 2 && input.get(end - 2..end) == Some(b"\r\n") {
            end -= 2;
            pairs += 1;
        }
        if end > 0 {
            self.content(input.get(..end).unwrap_or(&[]), out);
            self.held = pairs;
        } else {
            self.held += pairs;
        }
        self.cr = cr;
    }

    fn relaxed(&mut self, input: &[u8], out: &mut impl FnMut(&[u8])) {
        let mut i = 0;
        while let Some(&c) = input.get(i) {
            match c {
                b' ' | b'\t' => {
                    if self.cr {
                        self.cr = false;
                        self.content(b"\r", out);
                    }
                    self.wsp = true;
                    i += 1;
                }
                b'\r' => {
                    if self.cr {
                        self.content(b"\r", out);
                    }
                    self.cr = true;
                    i += 1;
                }
                b'\n' => {
                    if self.cr {
                        // End of line: whitespace before it is dropped.
                        self.cr = false;
                        self.wsp = false;
                        self.held += 1;
                    } else {
                        self.content(b"\n", out);
                    }
                    i += 1;
                }
                _ => {
                    if self.cr {
                        self.cr = false;
                        self.content(b"\r", out);
                    }
                    let start = i;
                    while input
                        .get(i)
                        .is_some_and(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
                    {
                        i += 1;
                    }
                    self.content(input.get(start..i).unwrap_or(&[]), out);
                }
            }
        }
    }

    /// Content follows: release withheld line ends and whitespace first.
    fn content(&mut self, bytes: &[u8], out: &mut impl FnMut(&[u8])) {
        while self.held > 0 {
            self.put(b"\r\n", out);
            self.held -= 1;
        }
        if self.wsp {
            self.wsp = false;
            self.put(b" ", out);
        }
        self.put(bytes, out);
        self.any = true;
    }

    fn put(&mut self, bytes: &[u8], out: &mut impl FnMut(&[u8])) {
        if bytes.len() > RUN - self.len {
            self.flush(out);
            if bytes.len() >= RUN {
                out(bytes);
                return;
            }
        }
        if let Some(dst) = self.run.get_mut(self.len..self.len + bytes.len()) {
            dst.copy_from_slice(bytes);
            self.len += bytes.len();
        }
    }

    fn flush(&mut self, out: &mut impl FnMut(&[u8])) {
        if self.len > 0 {
            out(self.run.get(..self.len).unwrap_or(&[]));
            self.len = 0;
        }
    }
}

impl core::fmt::Debug for BodyCanonicalizer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BodyCanonicalizer")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// Canonicalizes one header field (RFC 6376 sections 3.4.1 and 3.4.2).
///
/// # Examples
///
/// ```
/// use smtp_net::{Canonicalization, HeaderCanonicalizer};
/// let mut out = Vec::new();
/// HeaderCanonicalizer::new(Canonicalization::Relaxed)
///     .canonicalize(b"SubJect :  Hello\r\n   there  \r\n", &mut out);
/// assert_eq!(out, b"subject:Hello there\r\n");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderCanonicalizer {
    mode: Canonicalization,
}

impl HeaderCanonicalizer {
    /// A header canonicalizer for `mode`.
    #[must_use]
    pub const fn new(mode: Canonicalization) -> HeaderCanonicalizer {
        HeaderCanonicalizer { mode }
    }

    /// Appends the canonical form of `field` (one header field with its
    /// folded lines, with or without the final CRLF) to `out`, ending in
    /// CRLF.
    ///
    /// simple writes the field unchanged. relaxed lowercases the name,
    /// removes whitespace around the colon, unfolds, turns runs of spaces
    /// and tabs into one space, and removes trailing whitespace. A field
    /// without a colon is treated as a name with no value.
    pub fn canonicalize(&self, field: &[u8], out: &mut Vec<u8>) {
        let field = field.strip_suffix(b"\r\n").unwrap_or(field);
        if self.mode == Canonicalization::Simple {
            out.extend_from_slice(field);
            out.extend_from_slice(b"\r\n");
            return;
        }
        let colon = field.iter().position(|&c| c == b':');
        let (name, value) = match colon {
            Some(at) => (
                field.get(..at).unwrap_or(&[]),
                field.get(at + 1..).unwrap_or(&[]),
            ),
            None => (field, &[][..]),
        };
        let name_end = name
            .iter()
            .rposition(|c| !matches!(c, b' ' | b'\t'))
            .map_or(0, |p| p + 1);
        out.extend(
            name.get(..name_end)
                .unwrap_or(&[])
                .iter()
                .map(u8::to_ascii_lowercase),
        );
        if colon.is_some() {
            out.push(b':');
        }
        let mut wsp = false;
        let mut wrote = false;
        let mut i = 0;
        while let Some(&c) = value.get(i) {
            if c == b'\r' && value.get(i + 1) == Some(&b'\n') {
                // Unfold: the CRLF goes, the whitespace after it stays.
                i += 2;
                continue;
            }
            if c == b' ' || c == b'\t' {
                wsp = true;
            } else {
                if wsp && wrote {
                    out.push(b' ');
                }
                wsp = false;
                wrote = true;
                out.push(c);
            }
            i += 1;
        }
        out.extend_from_slice(b"\r\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(mode: Canonicalization, pieces: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut c = BodyCanonicalizer::new(mode);
        for p in pieces {
            c.update(p, &mut |b| out.extend_from_slice(b));
        }
        c.finish(&mut |b| out.extend_from_slice(b));
        out
    }

    /// Plain-text reference implementations straight from the RFC's prose.
    fn reference(mode: Canonicalization, input: &[u8]) -> Vec<u8> {
        let mut lines: Vec<Vec<u8>> = Vec::new();
        let mut cur = Vec::new();
        let mut i = 0;
        let mut terminated = true;
        while i < input.len() {
            if input[i] == b'\r' && input.get(i + 1) == Some(&b'\n') {
                lines.push(core::mem::take(&mut cur));
                i += 2;
                terminated = true;
            } else {
                cur.push(input[i]);
                i += 1;
                terminated = false;
            }
        }
        if !terminated {
            lines.push(cur);
        }
        if mode == Canonicalization::Relaxed {
            for l in &mut lines {
                let mut o = Vec::new();
                let mut w = false;
                for &c in l.iter() {
                    if c == b' ' || c == b'\t' {
                        w = true;
                    } else {
                        if w {
                            o.push(b' ');
                        }
                        w = false;
                        o.push(c);
                    }
                }
                *l = o;
            }
        }
        while lines.last().is_some_and(Vec::is_empty) {
            lines.pop();
        }
        if lines.is_empty() {
            return if mode == Canonicalization::Simple {
                b"\r\n".to_vec()
            } else {
                Vec::new()
            };
        }
        let mut out = Vec::new();
        for l in lines {
            out.extend_from_slice(&l);
            out.extend_from_slice(b"\r\n");
        }
        out
    }

    #[test]
    fn test_empty_bodies() {
        use Canonicalization::{Relaxed, Simple};
        assert_eq!(body(Simple, &[]), b"\r\n");
        assert_eq!(body(Relaxed, &[]), b"");
        assert_eq!(body(Simple, &[b"\r\n\r\n"]), b"\r\n");
        assert_eq!(body(Relaxed, &[b"  \r\n\t\r\n"]), b"");
    }

    #[test]
    fn test_rfc6376_section_3_4_5_example() {
        let input = b" C \r\nD \t E\r\n\r\n\r\n";
        assert_eq!(body(Canonicalization::Relaxed, &[input]), b" C\r\nD E\r\n");
        assert_eq!(
            body(Canonicalization::Simple, &[input]),
            b" C \r\nD \t E\r\n"
        );
        let mut out = Vec::new();
        let h = HeaderCanonicalizer::new(Canonicalization::Relaxed);
        h.canonicalize(b"A: X\r\n", &mut out);
        h.canonicalize(b"B : Y\t\r\n\tZ  \r\n", &mut out);
        assert_eq!(out, b"a:X\r\nb:Y Z\r\n");
    }

    #[test]
    fn test_body_matches_reference_at_every_split() {
        let samples: &[&[u8]] = &[
            b"a\r\n\r\n\r\n",
            b"a",
            b"a\r",
            b"\r\r\n",
            b"x\r\r\n\n",
            b"  lead\r\n\ttab  \r\n \r\n",
            b"a  \rb\r\n",
            b"line\r\n\r\nafter gap\r\n\r\n",
            b"\n\r\r\r\n\r",
            b"one long line without an end",
        ];
        for mode in [Canonicalization::Simple, Canonicalization::Relaxed] {
            for s in samples {
                let want = reference(mode, s);
                assert_eq!(body(mode, &[s]), want, "{mode:?} {s:?}");
                for a in 0..=s.len() {
                    for b in a..=s.len() {
                        let got = body(mode, &[&s[..a], &s[a..b], &s[b..]]);
                        assert_eq!(got, want, "{mode:?} {s:?} split {a} {b}");
                    }
                }
            }
        }
    }

    #[test]
    fn test_long_runs_bypass_the_buffer() {
        let line = [b'x'; 2000];
        let mut input = line.to_vec();
        input.extend_from_slice(b"\r\n");
        for mode in [Canonicalization::Simple, Canonicalization::Relaxed] {
            assert_eq!(body(mode, &[&input]), input);
        }
    }

    #[test]
    fn test_simple_header_is_unchanged() {
        let mut out = Vec::new();
        HeaderCanonicalizer::new(Canonicalization::Simple).canonicalize(b"SubJect :  x ", &mut out);
        assert_eq!(out, b"SubJect :  x \r\n");
    }
}
