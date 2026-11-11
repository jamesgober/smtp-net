//! SMTP replies (RFC 5321 4.2) and enhanced status codes (RFC 2034, RFC 3463).

use alloc::vec::Vec;
use core::fmt;

use crate::error::ProtocolError;

/// A validated three-digit reply code: first digit 2 to 5, second 0 to 5,
/// third 0 to 9.
///
/// # Examples
///
/// ```
/// use smtp_net::ReplyCode;
/// let c = ReplyCode::new(250).unwrap();
/// assert!(c.is_positive());
/// assert!(ReplyCode::new(199).is_none() && ReplyCode::new(600).is_none() && ReplyCode::new(260).is_none());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReplyCode(pub(crate) u16);

impl ReplyCode {
    /// `Some` when `code` is a valid reply code.
    #[must_use]
    pub const fn new(code: u16) -> Option<ReplyCode> {
        let (a, b) = (code / 100, code / 10 % 10);
        if a >= 2 && a <= 5 && b <= 5 && code < 600 {
            Some(ReplyCode(code))
        } else {
            None
        }
    }

    /// The number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// `2yz` or `3yz`.
    #[must_use]
    pub const fn is_positive(self) -> bool {
        self.0 < 400
    }

    /// `4yz`: a temporary failure (RFC 5321 calls it transient); retrying later can succeed.
    #[must_use]
    pub const fn is_temporary(self) -> bool {
        self.0 >= 400 && self.0 < 500
    }

    /// `5yz`: permanent failure.
    #[must_use]
    pub const fn is_permanent(self) -> bool {
        self.0 >= 500
    }

    pub(crate) const fn class(self) -> u8 {
        (self.0 / 100) as u8
    }
}

impl fmt::Display for ReplyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An RFC 3463 enhanced status code: `class.subject.detail`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EnhancedCode {
    /// 2, 4, or 5.
    pub class: u8,
    /// 0 to 999.
    pub subject: u16,
    /// 0 to 999.
    pub detail: u16,
}

impl EnhancedCode {
    /// Parses `class.subject.detail` at the start of `text`, followed by a
    /// space or the end.
    fn parse(text: &[u8]) -> Option<EnhancedCode> {
        let end = text.iter().position(|&b| b == b' ').unwrap_or(text.len());
        let s = core::str::from_utf8(text.get(..end)?).ok()?;
        let mut it = s.split('.');
        let (c, sub, det) = (it.next()?, it.next()?, it.next()?);
        if it.next().is_some() {
            return None;
        }
        let num = |p: &str, max: usize| -> Option<u16> {
            if p.is_empty() || p.len() > max || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse().ok()
        };
        let class = num(c, 1)?;
        if !matches!(class, 2 | 4 | 5) {
            return None;
        }
        Some(EnhancedCode {
            class: class as u8,
            subject: num(sub, 3)?,
            detail: num(det, 3)?,
        })
    }
}

impl fmt::Display for EnhancedCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.class, self.subject, self.detail)
    }
}

/// Longest reply text kept in a [`Reply`], in octets.
const KEPT_TEXT: usize = 1024;

/// A complete server reply: the code, the enhanced code when present, and
/// the text of each line (bounded to the first 1 KiB).
#[derive(Clone, PartialEq, Eq)]
pub struct Reply {
    code: ReplyCode,
    enhanced: Option<EnhancedCode>,
    /// Line texts, each followed by '\n'.
    text: Vec<u8>,
    lines: u16,
    truncated: bool,
}

impl Reply {
    /// The reply recorded for a recipient deferred as one too many (FR-42).
    pub(crate) fn too_many() -> Reply {
        let mut text = Vec::with_capacity(40);
        text.extend_from_slice(b"4.5.3 too many recipients for one transaction");
        text.push(b'\n');
        Reply {
            code: ReplyCode(452),
            enhanced: Some(EnhancedCode {
                class: 4,
                subject: 5,
                detail: 3,
            }),
            text,
            lines: 1,
            truncated: false,
        }
    }

    /// A reply built from parts (tests, test servers).
    #[cfg(test)]
    pub(crate) fn synthetic(code: ReplyCode, text: &[u8]) -> Reply {
        let mut t = Vec::with_capacity(text.len() + 1);
        t.extend_from_slice(text);
        t.push(b'\n');
        Reply {
            code,
            enhanced: None,
            text: t,
            lines: 1,
            truncated: false,
        }
    }

    /// The reply code.
    #[must_use]
    pub fn code(&self) -> ReplyCode {
        self.code
    }

    /// The enhanced status code, when ENHANCEDSTATUSCODES was advertised and
    /// the first line starts with one of the reply's class.
    #[must_use]
    pub fn enhanced(&self) -> Option<EnhancedCode> {
        self.enhanced
    }

    /// The text of each line kept (without the code and separator).
    pub fn lines(&self) -> impl Iterator<Item = &[u8]> {
        let body = self.text.strip_suffix(b"\n").unwrap_or(&self.text);
        body.split(|&b| b == b'\n')
            .filter(move |_| !self.text.is_empty())
    }

    /// The text, lines joined by spaces, with every byte outside printable
    /// ASCII shown as `?` (T-30).
    #[must_use]
    pub fn text_lossy(&self) -> TextLossy<'_> {
        TextLossy(self)
    }

    /// True when the text was longer than the 1 KiB kept.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Number of lines in the reply.
    #[must_use]
    pub fn line_count(&self) -> u16 {
        self.lines
    }
}

impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Reply({} {})", self.code, self.text_lossy())
    }
}

/// Sanitized reply text; see [`Reply::text_lossy`].
pub struct TextLossy<'a>(&'a Reply);

impl fmt::Display for TextLossy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for line in self.0.lines() {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            for &b in line {
                let c = if (32..127).contains(&b) {
                    b as char
                } else {
                    '?'
                };
                fmt::Write::write_char(f, c)?;
            }
        }
        if self.0.truncated {
            f.write_str(" ...")?;
        }
        Ok(())
    }
}

/// Reply budgets (D-020).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyLimits {
    /// Longest line, including CRLF (default 1,000).
    pub max_line: u16,
    /// Most lines in one reply (default 64).
    pub max_lines: u16,
    /// Most octets in one reply (default 8,192).
    pub max_total: u32,
}

impl Default for ReplyLimits {
    fn default() -> ReplyLimits {
        ReplyLimits {
            max_line: 1000,
            max_lines: 64,
            max_total: 8192,
        }
    }
}

/// A streaming reply parser, correct for input split at any byte.
///
/// # Examples
///
/// ```
/// use smtp_net::protocol::{ReplyLimits, ReplyParser};
/// let mut p = ReplyParser::new(ReplyLimits::default(), false);
/// let (used, reply) = p.push(b"250-mail.example.com\r\n250 SIZE 1000\r\n221 bye\r\n")?;
/// let reply = reply.unwrap();
/// assert_eq!((used, reply.code().get(), reply.line_count()), (37, 250, 2));
/// # Ok::<(), smtp_net::ProtocolError>(())
/// ```
#[derive(Clone, Debug)]
pub struct ReplyParser {
    limits: ReplyLimits,
    enhanced: bool,
    /// Bytes of the current line (code and separator included), until CRLF.
    line: Vec<u8>,
    saw_cr: bool,
    code: Option<ReplyCode>,
    lines: u16,
    total: u32,
    text: Vec<u8>,
    truncated: bool,
    first_enhanced: Option<EnhancedCode>,
    done: bool,
}

impl ReplyParser {
    /// A parser with `limits`; `enhanced` when ENHANCEDSTATUSCODES was advertised.
    #[must_use]
    pub fn new(limits: ReplyLimits, enhanced: bool) -> ReplyParser {
        ReplyParser {
            limits,
            enhanced,
            line: Vec::with_capacity(usize::from(limits.max_line)),
            saw_cr: false,
            code: None,
            lines: 0,
            total: 0,
            text: Vec::with_capacity(KEPT_TEXT + 64),
            truncated: false,
            first_enhanced: None,
            done: false,
        }
    }

    pub(crate) fn set_enhanced(&mut self, on: bool) {
        self.enhanced = on;
    }

    /// True when part of a reply has been read and not completed.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.line.is_empty() || self.saw_cr || self.lines > 0
    }

    fn reset(&mut self) {
        self.line.clear();
        self.saw_cr = false;
        self.code = None;
        self.lines = 0;
        self.total = 0;
        self.text.clear();
        self.truncated = false;
        self.first_enhanced = None;
        self.done = false;
    }

    /// Reads as much of `input` as completes at most one reply. Returns the
    /// bytes consumed and the reply when it completed; a later call continues
    /// where this one stopped.
    ///
    /// # Errors
    ///
    /// [`ProtocolError`]: `MalformedReply`, `InconsistentReply`,
    /// `ReplyTooLong`, `BareLineFeed`, `Nul`. The parser must not be used
    /// after an error.
    pub fn push(&mut self, input: &[u8]) -> Result<(usize, Option<Reply>), ProtocolError> {
        let (used, done) = self.push_view(input)?;
        if !done {
            return Ok((used, None));
        }
        let reply = self.take();
        Ok((used, Some(reply)))
    }

    /// As `push`, but leaves a completed reply inside the parser (read it with
    /// `code`, `text`, then `clear`): no allocation.
    pub(crate) fn push_view(&mut self, input: &[u8]) -> Result<(usize, bool), ProtocolError> {
        if self.done {
            self.reset();
        }
        for (i, &b) in input.iter().enumerate() {
            if self.saw_cr {
                if b != b'\n' {
                    return Err(ProtocolError::MalformedReply);
                }
                self.saw_cr = false;
                if self.end_line()? {
                    self.done = true;
                    return Ok((i + 1, true));
                }
                continue;
            }
            match b {
                b'\r' => {
                    self.saw_cr = true;
                    continue;
                }
                b'\n' => return Err(ProtocolError::BareLineFeed),
                0 => return Err(ProtocolError::Nul),
                _ => {}
            }
            // The line including its CRLF must fit in max_line; checked
            // before the byte is stored.
            if self.line.len() + 3 > usize::from(self.limits.max_line) {
                return Err(ProtocolError::ReplyTooLong);
            }
            self.line.push(b);
            self.total = self.total.saturating_add(1);
            if self.total > self.limits.max_total {
                return Err(ProtocolError::ReplyTooLong);
            }
        }
        Ok((input.len(), false))
    }

    /// Ends the current line; returns true when it was the last of the reply.
    fn end_line(&mut self) -> Result<bool, ProtocolError> {
        self.total = self.total.saturating_add(2);
        if self.total > self.limits.max_total {
            return Err(ProtocolError::ReplyTooLong);
        }
        self.lines += 1;
        if self.lines > self.limits.max_lines {
            return Err(ProtocolError::ReplyTooLong);
        }
        let line = core::mem::take(&mut self.line);
        let digits = line.get(..3).ok_or(ProtocolError::MalformedReply)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return Err(ProtocolError::MalformedReply);
        }
        let n = digits
            .iter()
            .fold(0u16, |n, &d| n * 10 + u16::from(d - b'0'));
        let code = ReplyCode::new(n).ok_or(ProtocolError::MalformedReply)?;
        if let Some(prev) = self.code {
            if prev != code {
                return Err(ProtocolError::InconsistentReply);
            }
        }
        self.code = Some(code);
        let (last, text) = match line.get(3) {
            None => (true, &[][..]),
            Some(b' ') => (true, line.get(4..).unwrap_or(&[])),
            Some(b'-') => (false, line.get(4..).unwrap_or(&[])),
            Some(_) => return Err(ProtocolError::MalformedReply),
        };
        if self.lines == 1 && self.enhanced {
            self.first_enhanced = EnhancedCode::parse(text).filter(|e| e.class == code.class());
        }
        let room = KEPT_TEXT.saturating_sub(self.text.len());
        if !self.truncated {
            let keep = if text.len() < room {
                text.len()
            } else {
                room.saturating_sub(1)
            };
            self.text.extend_from_slice(text.get(..keep).unwrap_or(&[]));
            self.text.push(b'\n');
            self.truncated = keep < text.len();
        }
        self.line = line;
        self.line.clear();
        Ok(last)
    }

    pub(crate) fn code(&self) -> Option<ReplyCode> {
        self.code
    }

    /// The enhanced code of the completed reply, when there is one.
    pub(crate) fn enhanced(&self) -> Option<EnhancedCode> {
        self.first_enhanced
    }

    pub(crate) fn text(&self) -> &[u8] {
        &self.text
    }

    /// The completed reply, owned.
    pub(crate) fn take(&mut self) -> Reply {
        let reply = Reply {
            code: self.code.unwrap_or(ReplyCode(500)),
            enhanced: self.first_enhanced,
            text: self.text.clone(),
            lines: self.lines,
            truncated: self.truncated,
        };
        self.reset();
        reply
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use super::*;

    fn parse(input: &[u8]) -> Result<Reply, ProtocolError> {
        let mut p = ReplyParser::new(ReplyLimits::default(), true);
        let (used, r) = p.push(input)?;
        assert_eq!(used, input.len());
        r.ok_or(ProtocolError::MalformedReply)
    }

    #[test]
    fn test_reply_parser_forms() {
        let r = parse(b"250\r\n").unwrap();
        assert_eq!((r.code().get(), r.line_count()), (250, 1));
        let r = parse(b"250 \r\n").unwrap();
        assert_eq!(r.lines().next(), Some(&b""[..]));
        let r = parse(b"220-a\r\n220-b\r\n220 c\r\n").unwrap();
        assert_eq!(r.lines().collect::<Vec<_>>(), vec![&b"a"[..], b"b", b"c"]);
        assert_eq!(r.text_lossy().to_string(), "a b c");
    }

    #[test]
    fn test_reply_parser_bad_codes_refused() {
        for bad in [
            &b"199 x\r\n"[..],
            b"600 x\r\n",
            b"2a0 x\r\n",
            b"25\r\n",
            b"2500 x\r\n",
            b"260 x\r\n",
            b"250x\r\n",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_reply_parser_mismatched_continuation_code_refused() {
        assert_eq!(
            parse(b"250-a\r\n251 b\r\n").unwrap_err(),
            ProtocolError::InconsistentReply
        );
    }

    #[test]
    fn test_reply_parser_line_endings() {
        assert_eq!(parse(b"250 a\n").unwrap_err(), ProtocolError::BareLineFeed);
        assert_eq!(
            parse(b"250 a\rb\r\n").unwrap_err(),
            ProtocolError::MalformedReply
        );
        assert_eq!(parse(b"250 a\0\r\n").unwrap_err(), ProtocolError::Nul);
    }

    #[test]
    fn test_reply_parser_line_budget_exact() {
        let ok = [&b"250 "[..], &[b'x'; 994], b"\r\n"].concat();
        assert_eq!(ok.len(), 1000);
        assert!(parse(&ok).is_ok());
        let bad = [&b"250 "[..], &[b'x'; 995], b"\r\n"].concat();
        assert_eq!(parse(&bad).unwrap_err(), ProtocolError::ReplyTooLong);
        let mut p = ReplyParser::new(
            ReplyLimits {
                max_line: 512,
                max_lines: 64,
                max_total: 8192,
            },
            false,
        );
        let at = [&b"250 "[..], &[b'x'; 506], b"\r\n"].concat();
        assert!(p.push(&at).unwrap().1.is_some());
        let over = [&b"250 "[..], &[b'x'; 507], b"\r\n"].concat();
        assert!(p.push(&over).is_err());
    }

    #[test]
    fn test_reply_parser_line_count_and_total_budgets() {
        let mut ok = Vec::new();
        for _ in 0..63 {
            ok.extend_from_slice(b"250-x\r\n");
        }
        ok.extend_from_slice(b"250 x\r\n");
        assert!(parse(&ok).is_ok());
        let mut bad = Vec::new();
        for _ in 0..64 {
            bad.extend_from_slice(b"250-x\r\n");
        }
        bad.extend_from_slice(b"250 x\r\n");
        assert_eq!(parse(&bad).unwrap_err(), ProtocolError::ReplyTooLong);
        // Total 8,192 accepted, 8,193 refused.
        let mut total = Vec::new();
        let line = [&b"250-"[..], &[b'y'; 506], b"\r\n"].concat(); // 512
        for _ in 0..15 {
            total.extend_from_slice(&line);
        }
        let rest = 8192 - total.len() - 6;
        total.extend_from_slice(&[&b"250 "[..], &vec![b'z'; rest], b"\r\n"].concat());
        assert_eq!(total.len(), 8192);
        assert!(parse(&total).is_ok());
        let mut over = total.clone();
        over.insert(over.len() - 2, b'z');
        assert_eq!(parse(&over).unwrap_err(), ProtocolError::ReplyTooLong);
    }

    #[test]
    fn test_reply_parser_split_at_every_byte_same_result() {
        let input =
            b"250-mx.example.com greets you\r\n250-PIPELINING\r\n250 2.0.0 OK\r\n354 go\r\n";
        let mut whole = ReplyParser::new(ReplyLimits::default(), true);
        let (n, first) = whole.push(input).unwrap();
        let first = first.unwrap();
        for split in 0..input.len() {
            let mut p = ReplyParser::new(ReplyLimits::default(), true);
            let (a, r) = p.push(&input[..split]).unwrap();
            let got = match r {
                Some(r) => r,
                None => {
                    let (b, r) = p.push(&input[a..]).unwrap();
                    assert_eq!(a + b, n);
                    r.unwrap()
                }
            };
            assert_eq!(got, first, "split {split}");
        }
        let (_, second) = whole.push(&input[n..]).unwrap();
        assert_eq!(second.unwrap().code().get(), 354);
    }

    #[test]
    fn test_enhanced_code_rules() {
        assert_eq!(
            parse(b"250 2.1.5 ok\r\n").unwrap().enhanced(),
            Some(EnhancedCode {
                class: 2,
                subject: 1,
                detail: 5
            })
        );
        assert_eq!(parse(b"250 5.0.0 ok\r\n").unwrap().enhanced(), None);
        assert_eq!(parse(b"550 5.1000.1 x\r\n").unwrap().enhanced(), None);
        assert_eq!(
            parse(b"550 5.100.100 x\r\n").unwrap().enhanced(),
            Some(EnhancedCode {
                class: 5,
                subject: 100,
                detail: 100
            })
        );
        let mut p = ReplyParser::new(ReplyLimits::default(), false);
        assert_eq!(
            p.push(b"250 2.1.5 ok\r\n").unwrap().1.unwrap().enhanced(),
            None
        );
    }

    #[test]
    fn test_text_lossy_sanitizes_terminal_escapes() {
        let r = parse(b"550 \x1b[31mred\xff\r\n").unwrap();
        assert_eq!(r.text_lossy().to_string(), "?[31mred?");
    }

    #[test]
    fn test_reply_text_kept_bounded() {
        let mut input = Vec::new();
        for _ in 0..20 {
            input.extend_from_slice(&[&b"250-"[..], &[b'q'; 200], b"\r\n"].concat());
        }
        input.extend_from_slice(b"250 end\r\n");
        let r = parse(&input).unwrap();
        assert!(r.is_truncated());
        assert!(r.text.len() <= KEPT_TEXT + 1);
    }
}
