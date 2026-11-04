//! Header names, values, encoding, and folding.
//!
//! Every value that reaches the header block passes [`check_header_value`]
//! first; there is no other way in (PLAN 10.2). Folding and RFC 2047 words
//! come from parse-net (`mail::fold`, `mail::encode_words`).

use alloc::{string::String, vec::Vec};
use core::fmt;

use parse_net::{WriteError, mail, write};

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
    // Fast path: printable ASCII and TAB only.
    if value.bytes().all(|b| b == b'\t' || (32..127).contains(&b)) {
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
pub struct HeaderName(String);

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
        Ok(HeaderName(String::from(name)))
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_reserved(&self) -> bool {
        let lower = self.0.to_ascii_lowercase();
        RESERVED.contains(&lower.as_str()) || lower.starts_with("content-")
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
    list: Vec<(HeaderName, String)>,
}

impl Headers {
    /// The first value of `name`, compared without ASCII case.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.list
            .iter()
            .find(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every field in order.
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &str)> {
        self.list.iter().map(|(n, v)| (n, v.as_str()))
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

    pub(crate) fn push(&mut self, name: &str, value: String) {
        // Names written by the crate itself are constants in ftext.
        self.list.push((HeaderName(String::from(name)), value));
    }
}

/// Appends `text` as RFC 2047 encoded words (`=?UTF-8?Q?...?=`, at most 75
/// characters each, split only between characters, separated by CRLF SP) to
/// `out`. Printable ASCII without `=?` is appended as it is.
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
/// # Ok::<(), smtp_net::HeaderError>(())
/// ```
pub fn encode_word(text: &str, out: &mut String) -> Result<(), HeaderError> {
    check_header_value("encoded word", text)?;
    let mut buf = Vec::new();
    mail::encode_words(text, MAX_ENCODED_WORD, &mut buf)
        .map_err(|e| map_write("encoded word", e))?;
    out.push_str(&String::from_utf8_lossy(&buf));
    Ok(())
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
        && text.bytes().all(|b| b == b' ' || is_atext(b))
}

fn is_atext(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b)
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
        if mail::encode_words(name, room, &mut buf).is_ok() {
            out.push_str(&String::from_utf8_lossy(&buf));
        }
    }
    out.push_str(" <");
    out.push_str(addr);
    out.push('>');
}

/// Builds the header block line by line.
#[derive(Default)]
pub(crate) struct HeaderBlock {
    pub(crate) bytes: Vec<u8>,
    pub(crate) headers: Headers,
}

impl HeaderBlock {
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
            mail::encode_words(text, room, &mut self.bytes).map_err(|e| map_write(field, e))?;
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
        for (i, m) in list.iter().enumerate() {
            let mut item = String::new();
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
        self.finish_line(name, start);
    }

    /// Appends CRLF and records the unfolded value.
    pub(crate) fn finish_line(&mut self, name: &str, start: usize) {
        let line = self.bytes.get(start + name.len() + 1..).unwrap_or(&[]);
        let mut value = String::with_capacity(line.len());
        let text = String::from_utf8_lossy(line);
        for (i, piece) in text.split("\r\n").enumerate() {
            if i == 0 {
                value.push_str(piece.strip_prefix(' ').unwrap_or(piece));
            } else {
                value.push_str(piece);
            }
        }
        self.headers.push(name, value);
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
