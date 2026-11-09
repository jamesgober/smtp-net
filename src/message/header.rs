//! Header names, values, encoding, and folding.
//!
//! Every value that reaches the header block passes [`check_header_value`]
//! first; there is no other way in (PLAN 10.2). Folding and RFC 2047 words
//! come from parse-net (`mail::fold`, `mail::encode_words`, `mail::encode_words_b`).

use alloc::{borrow::Cow, string::String, vec::Vec};
use core::fmt;

use parse_net::{CountSink, WriteError, mail, write};

use crate::{address::Mailbox, error::HeaderError};

/// Longest header line, excluding CRLF (RFC 5322 2.1.1).
pub const MAX_HEADER_LINE: usize = 998;
/// Recommended header line length (RFC 5322 2.1.1).
pub const RECOMMENDED_HEADER_LINE: usize = 78;
/// Longest RFC 2047 encoded word (RFC 2047 section 2).
pub const MAX_ENCODED_WORD: usize = 75;
/// Longest custom header name accepted, in octets.
pub const MAX_HEADER_NAME: usize = 76;

/// Names the builder writes itself; [`MessageBuilder::header`](crate::MessageBuilder::header) refuses them.
const RESERVED: &[&str] = &[
    "from",
    "sender",
    "reply-to",
    "to",
    "cc",
    "bcc",
    "subject",
    "date",
    "message-id",
    "mime-version",
    "dkim-signature",
    "return-path",
    "received",
    "in-reply-to",
    "references",
    "list-unsubscribe",
    "list-unsubscribe-post",
    "auto-submitted",
];

/// The single injection gate: refuses CR, LF, NUL, every other C0 control
/// except TAB, DEL, C1 controls, and U+2028 and U+2029, naming `field` and
/// the byte position (T-1). Exposed so other crates can check user input
/// early, before it reaches a message.
///
/// # Errors
///
/// [`HeaderError::ControlCharacter`].
///
/// # Examples
///
/// ```
/// use smtp_net::{check_header_value, HeaderError};
/// assert!(check_header_value("Subject", "Hello\tthere").is_ok());
/// assert_eq!(
///     check_header_value("Subject", "Hi\r\nBcc: victim@example.com"),
///     Err(HeaderError::ControlCharacter { field: "Subject", position: 2 }),
/// );
/// ```
pub fn check_header_value(field: &'static str, value: &str) -> Result<(), HeaderError> {
    // Fast path: printable ASCII and TAB only, eight octets at a time.
    if crate::scan::is_printable_or_tab(value.as_bytes()) {
        return Ok(());
    }
    for (i, c) in value.char_indices() {
        if (c.is_control() && c != '\t') || c == '\u{2028}' || c == '\u{2029}' {
            return Err(HeaderError::ControlCharacter { field, position: i });
        }
    }
    Ok(())
}

/// A validated header name: RFC 5322 `ftext` (printable ASCII 33 to 126 except
/// `:`), 1 to 76 octets.
#[derive(Clone, PartialEq, Eq)]
pub struct HeaderName(Cow<'static, str>);

impl HeaderName {
    /// Validates `name`.
    ///
    /// # Errors
    ///
    /// [`HeaderError::InvalidName`].
    pub fn new(name: &str) -> Result<HeaderName, HeaderError> {
        if name.len() > MAX_HEADER_NAME || !mail::is_field_name(name.as_bytes()) {
            return Err(HeaderError::InvalidName);
        }
        Ok(HeaderName(Cow::Owned(String::from(name))))
    }

    /// A name the crate itself writes, held without an allocation.
    pub(crate) fn of(name: &str) -> HeaderName {
        match WRITTEN.iter().find(|w| **w == name) {
            Some(w) => HeaderName(Cow::Borrowed(w)),
            None => HeaderName(Cow::Owned(String::from(name))),
        }
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_reserved(&self) -> bool {
        RESERVED.iter().any(|r| r.eq_ignore_ascii_case(&self.0))
            || self
                .0
                .get(..8)
                .is_some_and(|p| p.eq_ignore_ascii_case("content-"))
    }
}

impl fmt::Debug for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The ordered header fields of a message, as they are written (values
/// unfolded, non-ASCII text already RFC 2047 encoded).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Headers {
    /// Each name with the start and end of its value in `text`.
    list: Vec<(HeaderName, usize, usize)>,
    /// Every value, back to back: one allocation for all of them.
    text: String,
}

impl Headers {
    /// The first value of `name`, compared without ASCII case.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.list
            .iter()
            .find(|(n, _, _)| n.as_str().eq_ignore_ascii_case(name))
            .map(|&(_, s, e)| self.text.get(s..e).unwrap_or(""))
    }

    /// Every field in order.
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &str)> {
        self.list
            .iter()
            .map(|(n, s, e)| (n, self.text.get(*s..*e).unwrap_or("")))
    }

    /// Number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// True when there are no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Records `name` with the unfolded form of the written `line` (the
    /// octets after `Name:`, folding CRLFs removed).
    fn push_unfolded(&mut self, name: &str, line: &[u8]) {
        if self.list.capacity() == 0 {
            self.list.reserve(12);
            self.text.reserve(256);
        }
        let start = self.text.len();
        let line = line.strip_prefix(b" ").unwrap_or(line);
        // The block holds only ASCII and UTF-8 the crate wrote itself.
        let text = core::str::from_utf8(line).unwrap_or("");
        if text.contains('\r') {
            for piece in text.split("\r\n") {
                self.text.push_str(piece);
            }
        } else {
            self.text.push_str(text);
        }
        self.list
            .push((HeaderName::of(name), start, self.text.len()));
    }
}

/// Appends `text` as RFC 2047 encoded words (`=?UTF-8?Q?...?=` or
/// `=?UTF-8?B?...?=`, whichever is shorter; at most 75 characters each,
/// split only between characters, separated by CRLF SP) to `out`. Printable
/// ASCII without `=?` is appended as it is.
///
/// # Errors
///
/// [`HeaderError::ControlCharacter`] for a control character.
///
/// # Examples
///
/// ```
/// let mut out = String::new();
/// smtp_net::encode_word("Caf\u{e9}", &mut out)?;
/// assert_eq!(out, "=?UTF-8?Q?Caf=C3=A9?=");
/// out.clear();
/// smtp_net::encode_word("\u{4f1a}\u{8b70}\u{306e}\u{304a}\u{77e5}\u{3089}\u{305b}", &mut out)?;
/// assert_eq!(out, "=?UTF-8?B?5Lya6K2w44Gu44GK55+l44KJ44Gb?=");
/// # Ok::<(), smtp_net::HeaderError>(())
/// ```
pub fn encode_word(text: &str, out: &mut String) -> Result<(), HeaderError> {
    check_header_value("encoded word", text)?;
    let mut buf = Vec::new();
    encode_shorter(text, MAX_ENCODED_WORD, &mut buf).map_err(|e| map_write("encoded word", e))?;
    out.push_str(&String::from_utf8_lossy(&buf));
    Ok(())
}

/// RFC 2047 words: `B` when most of the text's octets are not ASCII and `B`
/// comes out shorter (a Japanese or Russian subject), otherwise `Q`, which
/// stays readable for mostly ASCII text such as `José` even where `B` would
/// save an octet (D-082). The two forms are counted, not written twice.
pub(crate) fn encode_shorter(
    text: &str,
    room_first_line: usize,
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    let non_ascii = text.bytes().filter(|b| !b.is_ascii()).count();
    if non_ascii * 2 <= text.len() {
        return mail::encode_words(text, room_first_line, out);
    }
    let mut q = CountSink::new();
    mail::encode_words(text, room_first_line, &mut q)?;
    let mut b = CountSink::new();
    mail::encode_words_b(text, room_first_line, &mut b)?;
    if b.count() < q.count() {
        mail::encode_words_b(text, room_first_line, out)
    } else {
        mail::encode_words(text, room_first_line, out)
    }
}

/// Writes `Name: value` into `out`, folded at whitespace so lines stay within
/// 78 columns where the words allow and never pass 998 octets. No CRLF is
/// written at the end.
///
/// # Errors
///
/// [`HeaderError::InvalidName`], [`HeaderError::ControlCharacter`],
/// [`HeaderError::LineTooLong`] for a word that fits on no line.
///
/// # Examples
///
/// ```
/// let mut out = Vec::new();
/// smtp_net::fold_header("X-Note", &"word ".repeat(30), &mut out)?;
/// assert!(out.split(|&b| b == b'\n').all(|line| line.len() <= 79));
/// # Ok::<(), smtp_net::HeaderError>(())
/// ```
pub fn fold_header(name: &str, value: &str, out: &mut Vec<u8>) -> Result<(), HeaderError> {
    HeaderName::new(name)?;
    check_header_value("header", value)?;
    mail::fold(name, value.as_bytes(), out).map_err(|e| map_write("header", e))
}

fn map_write(field: &'static str, e: WriteError) -> HeaderError {
    match e {
        WriteError::Forbidden { at } => HeaderError::ControlCharacter {
            field,
            position: at as usize,
        },
        WriteError::NotToken => HeaderError::InvalidName,
        _ => HeaderError::LineTooLong,
    }
}

/// True when `text` can be written as a sequence of atoms (RFC 5322 3.2.3).
fn is_atom_phrase(text: &str) -> bool {
    !text.is_empty()
        && !text.contains("=?")
        && !text.starts_with(' ')
        && !text.ends_with(' ')
        && !text.contains("  ")
        && text
            .bytes()
            .all(|b| b == b' ' || parse_net::class::is_atext(b))
}

/// Appends the header form of `m` to `out`, starting at column `col` (used
/// to size the first encoded word).
pub(crate) fn write_mailbox(m: &Mailbox, out: &mut String, col: usize) {
    let addr = m.address().as_str();
    let Some(name) = m.display_name() else {
        out.push_str(addr);
        return;
    };
    if is_atom_phrase(name) {
        out.push_str(name);
    } else if name.is_ascii() && !name.contains("=?") {
        let mut buf = Vec::new();
        // The name passed the control check when the mailbox was made.
        if write::write_quoted(name.as_bytes(), &mut buf).is_ok() {
            out.push_str(&String::from_utf8_lossy(&buf));
        }
    } else {
        let mut buf = Vec::new();
        let room = RECOMMENDED_HEADER_LINE
            .saturating_sub(col)
            .max(MAX_ENCODED_WORD.min(16));
        if encode_shorter(name, room, &mut buf).is_ok() {
            out.push_str(&String::from_utf8_lossy(&buf));
        }
    }
    out.push_str(" <");
    out.push_str(addr);
    out.push('>');
}

/// Names the crate writes itself: kept as `&'static str`, not copied. The
/// ones every message has come first.
const WRITTEN: &[&str] = &[
    "Date",
    "From",
    "To",
    "Subject",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
    "Sender",
    "Reply-To",
    "Cc",
    "In-Reply-To",
    "References",
    "List-Unsubscribe",
    "List-Unsubscribe-Post",
    "Auto-Submitted",
    "Content-ID",
    "Content-Disposition",
];

/// Builds the header block line by line.
pub(crate) struct HeaderBlock {
    pub(crate) bytes: Vec<u8>,
    pub(crate) headers: Headers,
    /// False for a part's headers, which nothing looks up.
    index: bool,
    /// Reused for parameters, mailboxes, and ids.
    pub(crate) scratch: Vec<u8>,
    scratch_text: String,
}

impl Default for HeaderBlock {
    fn default() -> HeaderBlock {
        HeaderBlock::with_capacity(0)
    }
}

impl HeaderBlock {
    /// A block whose fields are recorded for `Message::headers`.
    pub(crate) fn with_capacity(capacity: usize) -> HeaderBlock {
        HeaderBlock {
            bytes: Vec::with_capacity(capacity),
            headers: Headers::default(),
            index: true,
            scratch: Vec::new(),
            scratch_text: String::new(),
        }
    }

    /// A block written only as bytes (a part's headers).
    pub(crate) fn unindexed(capacity: usize) -> HeaderBlock {
        HeaderBlock {
            index: false,
            ..HeaderBlock::with_capacity(capacity)
        }
    }

    /// `Name: value` for a field the crate writes with a fixed, short,
    /// printable value (`MIME-Version: 1.0`, `Content-Transfer-Encoding:
    /// 7bit`): no folding or checks needed.
    pub(crate) fn literal(&mut self, name: &str, value: &str) {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.extend_from_slice(b": ");
        self.bytes.extend_from_slice(value.as_bytes());
        self.finish_line(name, start);
    }

    /// `Name: <id>`, the id between angle brackets.
    pub(crate) fn angle(&mut self, name: &str, id: &str) -> Result<(), HeaderError> {
        let mut v = core::mem::take(&mut self.scratch_text);
        v.clear();
        v.reserve(id.len() + 2);
        v.push('<');
        v.push_str(id);
        v.push('>');
        let r = self.folded(name, &v);
        self.scratch_text = v;
        r
    }

    /// An unstructured field (Subject, custom headers): folded ASCII, or RFC
    /// 2047 words when the text is not printable ASCII or contains `=?` (T-23).
    pub(crate) fn unstructured(
        &mut self,
        name: &str,
        field: &'static str,
        text: &str,
    ) -> Result<(), HeaderError> {
        check_header_value(field, text)?;
        let plain =
            !text.contains("=?") && text.bytes().all(|b| b == b'\t' || (32..127).contains(&b));
        let start = self.bytes.len();
        if plain {
            mail::fold(name, text.as_bytes(), &mut self.bytes).map_err(|e| map_write(field, e))?;
        } else {
            self.bytes.extend_from_slice(name.as_bytes());
            self.bytes.extend_from_slice(b": ");
            let room = RECOMMENDED_HEADER_LINE.saturating_sub(name.len() + 2);
            encode_shorter(text, room, &mut self.bytes).map_err(|e| map_write(field, e))?;
        }
        self.finish_line(name, start);
        Ok(())
    }

    /// A structured ASCII value that may fold at its spaces.
    pub(crate) fn folded(&mut self, name: &str, value: &str) -> Result<(), HeaderError> {
        let start = self.bytes.len();
        mail::fold(name, value.as_bytes(), &mut self.bytes).map_err(|e| map_write("header", e))?;
        self.finish_line(name, start);
        Ok(())
    }

    /// An address list, folded between mailboxes.
    pub(crate) fn mailboxes(&mut self, name: &str, list: &[Mailbox]) {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.push(b':');
        let mut col = name.len() + 1;
        let mut item = core::mem::take(&mut self.scratch_text);
        item.reserve(128);
        for (i, m) in list.iter().enumerate() {
            item.clear();
            write_mailbox(m, &mut item, col + 1);
            let first_line = item.find('\r').unwrap_or(item.len());
            let sep = usize::from(i + 1 < list.len());
            if i > 0 && col + 1 + first_line + sep > RECOMMENDED_HEADER_LINE {
                self.bytes.extend_from_slice(b"\r\n");
                col = 0;
                item.clear();
                write_mailbox(m, &mut item, 1);
            }
            self.bytes.push(b' ');
            self.bytes.extend_from_slice(item.as_bytes());
            col += 1 + item.rsplit('\n').next().map_or(item.len(), str::len);
            if sep == 1 {
                self.bytes.push(b',');
                col += 1;
            }
        }
        self.scratch_text = item;
        self.finish_line(name, start);
    }

    /// Appends CRLF and records the unfolded value.
    pub(crate) fn finish_line(&mut self, name: &str, start: usize) {
        if self.index {
            let line = self.bytes.get(start + name.len() + 1..).unwrap_or(&[]);
            self.headers.push_unfolded(name, line);
        }
        self.bytes.extend_from_slice(b"\r\n");
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::address::Address;

    fn mb(name: Option<&str>, addr: &str) -> Mailbox {
        Mailbox::new(name, Address::parse(addr).unwrap()).unwrap()
    }

    #[test]
    fn test_check_header_value_refuses_every_control() {
        for (s, pos) in [
            ("a\rb", 1),
            ("a\nb", 1),
            ("\0", 0),
            ("x\u{85}", 1),
            ("x\u{2028}", 1),
            ("x\u{2029}", 1),
            ("x\u{7f}", 1),
            ("x\u{1b}[31m", 1),
        ] {
            assert_eq!(
                check_header_value("Subject", s),
                Err(HeaderError::ControlCharacter {
                    field: "Subject",
                    position: pos
                }),
                "{s:?}"
            );
        }
        assert!(check_header_value("Subject", "tab\tok caf\u{e9}").is_ok());
    }

    #[test]
    fn test_header_name_rules() {
        assert!(HeaderName::new("X-Mailer").is_ok());
        assert!(HeaderName::new("").is_err());
        assert!(HeaderName::new("X Bad").is_err());
        assert!(HeaderName::new("X:Bad").is_err());
        assert!(HeaderName::new("X-\u{e9}").is_err());
        assert!(HeaderName::new(&"a".repeat(76)).is_ok());
        assert!(HeaderName::new(&"a".repeat(77)).is_err());
        for r in [
            "FROM",
            "bcc",
            "Content-Type",
            "content-transfer-encoding",
            "DKIM-Signature",
            "Message-Id",
        ] {
            assert!(HeaderName::new(r).unwrap().is_reserved(), "{r}");
        }
        assert!(!HeaderName::new("X-Content").unwrap().is_reserved());
    }

    #[test]
    fn test_unstructured_plain_folds_and_encoded_words_split() {
        let mut b = HeaderBlock::default();
        b.unstructured("Subject", "Subject", &"word ".repeat(40))
            .unwrap();
        let s = core::str::from_utf8(&b.bytes).unwrap();
        assert!(s.lines().all(|l| l.len() <= 78), "{s}");
        assert!(s.ends_with("\r\n"));
        let mut b = HeaderBlock::default();
        b.unstructured("Subject", "Subject", &"\u{e9}t\u{e9} ".repeat(20))
            .unwrap();
        let s = core::str::from_utf8(&b.bytes).unwrap();
        for word in s.split_whitespace().filter(|w| w.starts_with("=?")) {
            assert!(word.len() <= 75, "{word}");
        }
        assert!(s.lines().all(|l| l.len() <= 78), "{s}");
    }

    #[test]
    fn test_unstructured_encoded_word_lookalike_is_encoded() {
        let mut b = HeaderBlock::default();
        b.unstructured("Subject", "Subject", "=?utf-8?q?Bank_alert?=")
            .unwrap();
        let v = b.headers.get("subject").unwrap();
        assert!(v.starts_with("=?UTF-8?Q?"), "{v}");
        assert!(!v.contains("=?utf-8?q?Bank"));
    }

    #[test]
    fn test_unstructured_unbreakable_over_998_refused() {
        let mut b = HeaderBlock::default();
        assert_eq!(
            b.unstructured("Subject", "Subject", &"x".repeat(2000)),
            Err(HeaderError::LineTooLong)
        );
        let mut b = HeaderBlock::default();
        assert!(
            b.unstructured("Subject", "Subject", &"x".repeat(990))
                .is_ok()
        );
    }

    #[test]
    fn test_mailbox_list_folds_between_items() {
        let list: Vec<Mailbox> = (0..10)
            .map(|i| {
                mb(
                    Some("Some Person"),
                    &alloc::format!("person{i}@example.com"),
                )
            })
            .collect();
        let mut b = HeaderBlock::default();
        b.mailboxes("To", &list);
        let s = core::str::from_utf8(&b.bytes).unwrap();
        assert!(s.lines().all(|l| l.len() <= 78), "{s}");
        assert_eq!(s.matches(',').count(), 9);
        let v = b.headers.get("To").unwrap();
        assert!(v.starts_with("Some Person <person0@example.com>,"), "{v}");
    }

    #[test]
    fn test_write_mailbox_forms() {
        assert_eq!(mb(None, "a@b.example").to_string(), "a@b.example");
        assert_eq!(
            mb(Some("Jane Q. Doe"), "a@b.example").to_string(),
            "\"Jane Q. Doe\" <a@b.example>"
        );
        assert_eq!(
            mb(Some("A&B"), "a@b.example").to_string(),
            "A&B <a@b.example>"
        );
    }

    #[test]
    fn test_shorter_of_q_and_b_is_chosen() {
        // Mostly non-ASCII: B. Mostly ASCII: Q. Both decode to the text.
        let cases = [
            (
                "\u{4f1a}\u{8b70}\u{306e}\u{304a}\u{77e5}\u{3089}\u{305b}\u{3067}\u{3059}",
                "B",
            ),
            (
                "\u{41f}\u{440}\u{438}\u{432}\u{435}\u{442}, \u{43c}\u{438}\u{440}",
                "B",
            ),
            ("Caf\u{e9} au lait, ready at 9", "Q"),
            ("Bank alert =? check", "Q"),
        ];
        for (text, form) in cases {
            let mut b = HeaderBlock::default();
            b.unstructured("Subject", "Subject", text).unwrap();
            let v = b.headers.get("subject").unwrap();
            assert!(
                v.starts_with(&alloc::format!("=?UTF-8?{form}?")),
                "{text}: {v}"
            );
            let (mut q, mut bb) = (CountSink::new(), CountSink::new());
            mail::encode_words(text, 69, &mut q).unwrap();
            mail::encode_words_b(text, 69, &mut bb).unwrap();
            assert!(v.len() <= q.count().min(bb.count()) + 8, "{text}");
            let mut out = [0u8; 512];
            let decoded =
                mail::decode_words(v.as_bytes(), &parse_net::Limits::DEFAULT, &mut out).unwrap();
            assert_eq!(decoded, text);
        }
        // A long Japanese subject: B words, each at most 75, lines within 78.
        let long = "\u{30a2}\u{30ab}\u{30a6}\u{30f3}\u{30c8}\u{306e}\u{78ba}\u{8a8d}".repeat(8);
        let mut b = HeaderBlock::default();
        b.unstructured("Subject", "Subject", &long).unwrap();
        let s = core::str::from_utf8(&b.bytes).unwrap();
        assert!(s.lines().all(|l| l.len() <= 78), "{s}");
        assert!(
            s.split_whitespace()
                .filter(|w| w.starts_with("=?"))
                .all(|w| w.starts_with("=?UTF-8?B?") && w.len() <= 75)
        );
        // Display names too.
        let m = mb(Some("\u{5c71}\u{7530}\u{592a}\u{90ce}"), "taro@example.jp").to_string();
        assert!(m.starts_with("=?UTF-8?B?"), "{m}");
    }

    #[test]
    fn test_encode_word_and_fold_header_public() {
        let mut out = String::new();
        encode_word("plain", &mut out).unwrap();
        assert_eq!(out, "plain");
        assert!(encode_word("a\nb", &mut String::new()).is_err());
        let mut v = Vec::new();
        assert_eq!(
            fold_header("Bad Name", "x", &mut v),
            Err(HeaderError::InvalidName)
        );
        assert!(fold_header("X-A", "x\r\nBcc: y", &mut v).is_err());
    }
}
