//! MIME parts: content types, attachments, inline parts, transfer-encoding
//! choice, and streaming serialization.

use alloc::{string::String, vec, vec::Vec};
use core::fmt;

use parse_net::{Limits, class, mail};

use super::{
    header::{HeaderBlock, RECOMMENDED_HEADER_LINE, check_header_value},
    sink::Sink,
};
use crate::{
    encode::{self, B64_LINE_INPUT, MIME_LINE_LENGTH, QpState, base64_encoded_len},
    error::{Error, HeaderError, SinkError},
};

/// Longest attachment file name, in octets.
const MAX_FILE_NAME: usize = 255;

/// A validated MIME content type: `type/subtype` and parameters.
///
/// # Examples
///
/// ```
/// let ct = smtp_net::ContentType::parse("text/CSV; header=present")?;
/// assert_eq!(ct.essence(), "text/csv");
/// assert_eq!(ct.parameter("header"), Some("present"));
/// assert!(smtp_net::ContentType::parse("text/").is_err());
/// # Ok::<(), smtp_net::HeaderError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct ContentType {
    essence: String,
    params: Vec<(String, String)>,
}

impl ContentType {
    /// Parses `type/subtype` with optional RFC 2045 parameters (RFC 2231
    /// sections and charsets are decoded).
    ///
    /// # Errors
    ///
    /// [`HeaderError::InvalidContentType`], [`HeaderError::ControlCharacter`].
    pub fn parse(input: &str) -> Result<ContentType, HeaderError> {
        check_header_value("Content-Type", input)?;
        let input = input.trim();
        let semi = input.find(';').unwrap_or(input.len());
        let essence = input.get(..semi).unwrap_or("").trim_end();
        let (ty, sub) = essence
            .split_once('/')
            .ok_or(HeaderError::InvalidContentType)?;
        let token = |s: &str| !s.is_empty() && s.bytes().all(class::is_mime_token_char);
        if !token(ty) || !token(sub) {
            return Err(HeaderError::InvalidContentType);
        }
        let mut ct = ContentType {
            essence: essence.to_ascii_lowercase(),
            params: Vec::new(),
        };
        let rest = input.get(semi..).unwrap_or("");
        if rest.is_empty() {
            return Ok(ct);
        }
        let (params, used) = mail::parse_mime_params(rest.as_bytes(), &Limits::DEFAULT)
            .map_err(|_| HeaderError::InvalidContentType)?;
        if used != rest.len() {
            return Err(HeaderError::InvalidContentType);
        }
        for (raw_name, _) in params.iter() {
            let base = raw_name.split(|&b| b == b'*').next().unwrap_or(raw_name);
            let name = core::str::from_utf8(base).map_err(|_| HeaderError::InvalidContentType)?;
            if ct.params.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
                continue;
            }
            let mut buf = vec![0u8; rest.len()];
            let value = params
                .decode_into(name, &mut buf)
                .map_err(|_| HeaderError::InvalidContentType)?
                .ok_or(HeaderError::InvalidContentType)?;
            ct.params
                .push((name.to_ascii_lowercase(), String::from(value)));
        }
        Ok(ct)
    }

    /// Adds or replaces a parameter. Non-ASCII and long values are written
    /// with RFC 2231 encoding.
    ///
    /// # Errors
    ///
    /// [`HeaderError::InvalidContentType`] for a name that is not a token;
    /// [`HeaderError::ControlCharacter`] for a control in the value.
    pub fn with_parameter(mut self, name: &str, value: &str) -> Result<ContentType, HeaderError> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| class::is_mime_token_char(b) && b != b'*' && b != b'\'' && b != b'%')
        {
            return Err(HeaderError::InvalidContentType);
        }
        check_header_value("Content-Type", value)?;
        let name = name.to_ascii_lowercase();
        self.params.retain(|(n, _)| *n != name);
        self.params.push((name, String::from(value)));
        Ok(self)
    }

    /// `type/subtype`, lowercase.
    #[must_use]
    pub fn essence(&self) -> &str {
        &self.essence
    }

    /// A parameter value, by name without ASCII case.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn is_text(&self) -> bool {
        self.essence.starts_with("text/")
    }
}

impl fmt::Debug for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentType")
            .field("essence", &self.essence)
            .field("params", &self.params)
            .finish()
    }
}

/// How a part's body is encoded for transport (RFC 2045 section 6).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransferEncoding {
    /// ASCII lines of at most 998 octets, sent as they are.
    SevenBit,
    /// UTF-8 lines of at most 998 octets (only with `allow_8bit`).
    EightBit,
    /// Quoted-printable: mostly ASCII text.
    QuotedPrintable,
    /// Base64: binary data and text that is mostly not ASCII.
    Base64,
}

impl TransferEncoding {
    fn name(self) -> &'static str {
        match self {
            TransferEncoding::SevenBit => "7bit",
            TransferEncoding::EightBit => "8bit",
            TransferEncoding::QuotedPrintable => "quoted-printable",
            TransferEncoding::Base64 => "base64",
        }
    }
}

fn check_file_name(name: &str) -> Result<(), HeaderError> {
    if name.is_empty()
        || name.len() > MAX_FILE_NAME
        || name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control() || c == '\u{2028}' || c == '\u{2029}')
    {
        return Err(HeaderError::InvalidFileName);
    }
    Ok(())
}

/// A file attached to the message (`multipart/mixed`, always base64).
///
/// # Examples
///
/// ```
/// let a = smtp_net::Attachment::new("report.pdf", "application/pdf", vec![0x25, 0x50, 0x44, 0x46])?;
/// assert_eq!(a.file_name(), "report.pdf");
/// assert!(smtp_net::Attachment::new("../../.bashrc", "text/plain", vec![]).is_err());
/// # Ok::<(), smtp_net::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Attachment {
    file_name: String,
    content_type: ContentType,
    bytes: Vec<u8>,
}

impl Attachment {
    /// An attachment named `file_name` (1 to 255 octets, no `/`, `\`, or
    /// controls) of `content_type`.
    ///
    /// # Errors
    ///
    /// [`HeaderError::InvalidFileName`], [`HeaderError::InvalidContentType`].
    pub fn new(file_name: &str, content_type: &str, bytes: Vec<u8>) -> Result<Attachment, Error> {
        check_file_name(file_name)?;
        let content_type = ContentType::parse(content_type)?;
        Ok(Attachment {
            file_name: String::from(file_name),
            content_type,
            bytes,
        })
    }

    /// The file name.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// The content.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Attachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attachment")
            .field("file_name", &self.file_name)
            .field("content_type", &self.content_type.essence)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// A part the HTML body shows inline, referenced as `cid:<content id>`
/// (`multipart/related`, RFC 2392).
///
/// # Examples
///
/// ```
/// let logo = smtp_net::Inline::new("logo@example.com", "image/png", vec![0x89, b'P', b'N', b'G'])?;
/// assert_eq!(logo.content_id(), "logo@example.com");
/// # Ok::<(), smtp_net::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Inline {
    content_id: String,
    content_type: ContentType,
    bytes: Vec<u8>,
}

impl Inline {
    /// An inline part with `content_id` (`left@right`, angle brackets optional).
    ///
    /// # Errors
    ///
    /// [`HeaderError::InvalidContentId`], [`HeaderError::InvalidContentType`].
    pub fn new(content_id: &str, content_type: &str, bytes: Vec<u8>) -> Result<Inline, Error> {
        let (l, r) = super::id::split_msg_id(content_id).ok_or(HeaderError::InvalidContentId)?;
        let content_type = ContentType::parse(content_type)?;
        let mut id = String::with_capacity(l.len() + r.len() + 1);
        id.push_str(l);
        id.push('@');
        id.push_str(r);
        Ok(Inline {
            content_id: id,
            content_type,
            bytes,
        })
    }

    /// The content id, without angle brackets.
    #[must_use]
    pub fn content_id(&self) -> &str {
        &self.content_id
    }
}

impl fmt::Debug for Inline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inline")
            .field("content_id", &self.content_id)
            .field("content_type", &self.content_type.essence)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// The multipart kinds the builder produces.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Multipart {
    /// `multipart/mixed`: a body and attachments.
    Mixed,
    /// `multipart/alternative`: the same content as text and HTML.
    Alternative,
    /// `multipart/related`: HTML and the inline parts it refers to.
    Related,
}

impl Multipart {
    fn essence(self) -> &'static str {
        match self {
            Multipart::Mixed => "multipart/mixed",
            Multipart::Alternative => "multipart/alternative",
            Multipart::Related => "multipart/related",
        }
    }
}

/// A part of the built tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Part {
    pub(crate) content_type: ContentType,
    /// `Content-Disposition` value and parameters.
    pub(crate) disposition: Option<(&'static str, Vec<(String, String)>)>,
    pub(crate) content_id: Option<String>,
    pub(crate) body: Body,
    /// The rendered header fields of a child part (empty for the root, whose
    /// fields go into the message header block).
    pub(crate) head: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Body {
    /// Text with LF line endings (CRLF is written on output).
    Text {
        text: String,
        encoding: TransferEncoding,
    },
    /// Binary content, always base64.
    Bytes(Vec<u8>),
    Multipart {
        kind: Multipart,
        boundary: String,
        parts: Vec<Part>,
    },
}

impl Part {
    pub(crate) fn text(essence: &str, text: String, allow_8bit: bool) -> Part {
        let encoding = choose_text_encoding(&text, allow_8bit);
        let content_type = ContentType {
            essence: String::from(essence),
            params: vec![(String::from("charset"), String::from("utf-8"))],
        };
        Part {
            content_type,
            disposition: None,
            content_id: None,
            body: Body::Text { text, encoding },
            head: Vec::new(),
        }
    }

    pub(crate) fn attachment(a: Attachment) -> Part {
        let mut content_type = a.content_type;
        content_type.params.retain(|(n, _)| n != "name");
        content_type
            .params
            .push((String::from("name"), a.file_name.clone()));
        Part {
            content_type,
            disposition: Some(("attachment", vec![(String::from("filename"), a.file_name)])),
            content_id: None,
            body: Body::Bytes(a.bytes),
            head: Vec::new(),
        }
    }

    pub(crate) fn inline(i: Inline) -> Part {
        let body = if i.content_type.is_text() {
            match String::from_utf8(i.bytes) {
                Ok(t) => {
                    let text = t.replace("\r\n", "\n");
                    let encoding = choose_text_encoding(&text, false);
                    Body::Text { text, encoding }
                }
                Err(e) => Body::Bytes(e.into_bytes()),
            }
        } else {
            Body::Bytes(i.bytes)
        };
        Part {
            content_type: i.content_type,
            disposition: Some(("inline", Vec::new())),
            content_id: Some(i.content_id),
            body,
            head: Vec::new(),
        }
    }

    pub(crate) fn multipart(kind: Multipart, parts: Vec<Part>) -> Part {
        let content_type = ContentType {
            essence: String::from(kind.essence()),
            params: Vec::new(),
        };
        Part {
            content_type,
            disposition: None,
            content_id: None,
            body: Body::Multipart {
                kind,
                boundary: String::new(),
                parts,
            },
            head: Vec::new(),
        }
    }

    pub(crate) fn encoding(&self) -> Option<TransferEncoding> {
        match &self.body {
            Body::Text { encoding, .. } => Some(*encoding),
            Body::Bytes(_) => Some(TransferEncoding::Base64),
            Body::Multipart { .. } => None,
        }
    }

    pub(crate) fn count(&self) -> usize {
        match &self.body {
            Body::Multipart { parts, .. } => 1 + parts.iter().map(Part::count).sum::<usize>(),
            _ => 1,
        }
    }

    pub(crate) fn depth(&self) -> usize {
        match &self.body {
            Body::Multipart { parts, .. } => 1 + parts.iter().map(Part::depth).max().unwrap_or(0),
            _ => 1,
        }
    }

    pub(crate) fn has_8bit(&self) -> bool {
        match &self.body {
            Body::Text { encoding, .. } => *encoding == TransferEncoding::EightBit,
            Body::Bytes(_) => false,
            Body::Multipart { parts, .. } => parts.iter().any(Part::has_8bit),
        }
    }

    /// Writes the content header fields (each ending CRLF) into `block`.
    pub(crate) fn write_headers(&self, block: &mut HeaderBlock) -> Result<(), HeaderError> {
        let mut params: Vec<(&str, &str)> = self
            .content_type
            .params
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        if let Body::Multipart { boundary, .. } = &self.body {
            params.push(("boundary", boundary.as_str()));
        }
        block.with_params("Content-Type", &self.content_type.essence, &params)?;
        if let Some(enc) = self.encoding() {
            block.folded("Content-Transfer-Encoding", enc.name())?;
        }
        if let Some(id) = &self.content_id {
            let mut v = String::with_capacity(id.len() + 2);
            v.push('<');
            v.push_str(id);
            v.push('>');
            block.folded("Content-ID", &v)?;
        }
        if let Some((kind, params)) = &self.disposition {
            let params: Vec<(&str, &str)> = params
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            block.with_params("Content-Disposition", kind, &params)?;
        }
        Ok(())
    }

    /// Renders the header fields of every child part into its `head`.
    pub(crate) fn render_children(&mut self) -> Result<(), HeaderError> {
        if let Body::Multipart { parts, .. } = &mut self.body {
            for p in parts.iter_mut() {
                let mut block = HeaderBlock::default();
                p.write_headers(&mut block)?;
                p.head = block.bytes;
                p.render_children()?;
            }
        }
        Ok(())
    }

    /// Visits every text body that is written without encoding.
    pub(crate) fn plain_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
        match &self.body {
            Body::Text {
                text,
                encoding: TransferEncoding::SevenBit | TransferEncoding::EightBit,
            } => out.push(text),
            Body::Multipart { parts, .. } => parts.iter().for_each(|p| p.plain_texts(out)),
            _ => {}
        }
    }

    /// Exact serialized length of this part's body (after its headers and blank line).
    pub(crate) fn body_len(&self) -> u64 {
        match &self.body {
            Body::Text { text, encoding } => text_len(text, *encoding),
            Body::Bytes(b) => base64_encoded_len(b.len() as u64),
            Body::Multipart {
                boundary, parts, ..
            } => {
                let b = boundary.len() as u64;
                let mut n = 0u64;
                for p in parts {
                    // "--" boundary CRLF headers CRLF body CRLF
                    n += 2 + b + 2 + p.head.len() as u64 + 2 + p.body_len() + 2;
                }
                n + 2 + b + 2 + 2
            }
        }
    }

    /// Writes this part's body.
    pub(crate) fn write_body<S: Sink>(&self, sink: &mut S) -> Result<(), SinkError> {
        match &self.body {
            Body::Text { text, encoding } => write_text(text, *encoding, sink),
            Body::Bytes(b) => write_base64(b, sink),
            Body::Multipart {
                boundary, parts, ..
            } => {
                for p in parts {
                    sink.write(b"--")?;
                    sink.write(boundary.as_bytes())?;
                    sink.write(b"\r\n")?;
                    sink.write(&p.head)?;
                    sink.write(b"\r\n")?;
                    p.write_body(sink)?;
                    sink.write(b"\r\n")?;
                }
                sink.write(b"--")?;
                sink.write(boundary.as_bytes())?;
                sink.write(b"--\r\n")
            }
        }
    }
}

impl HeaderBlock {
    /// `Name: essence; p1=v1; p2=v2`, folding before a parameter that would
    /// pass 78 columns; parameter values through parse-net's
    /// `write_mime_param` (RFC 2231 for non-ASCII or long values).
    pub(crate) fn with_params(
        &mut self,
        name: &str,
        essence: &str,
        params: &[(&str, &str)],
    ) -> Result<(), HeaderError> {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.extend_from_slice(b": ");
        self.bytes.extend_from_slice(essence.as_bytes());
        let mut col = name.len() + 2 + essence.len();
        for (pname, value) in params {
            let mut p = Vec::new();
            mail::write_mime_param(pname, value, &mut p)
                .map_err(|_| HeaderError::InvalidContentType)?;
            let first = p.iter().position(|&b| b == b'\r').unwrap_or(p.len());
            if col + first > RECOMMENDED_HEADER_LINE && p.starts_with(b"; ") {
                self.bytes.extend_from_slice(b";\r\n ");
                self.bytes.extend_from_slice(p.get(2..).unwrap_or(&[]));
            } else {
                self.bytes.extend_from_slice(&p);
            }
            col = match self.bytes.iter().rposition(|&b| b == b'\n') {
                Some(nl) if nl >= start => self.bytes.len() - nl - 1,
                _ => self.bytes.len() - start,
            };
        }
        self.finish_line(name, start);
        Ok(())
    }
}

/// The share of printable ASCII (with TAB and LF) above which text is
/// quoted-printable rather than base64 (PLAN 7.9) **[est.]**.
const QP_THRESHOLD_PERCENT: usize = 80;

pub(crate) fn choose_text_encoding(text: &str, allow_8bit: bool) -> TransferEncoding {
    let mut line = 0usize;
    let mut long = false;
    let mut controls = false;
    let mut printable = 0usize;
    for &b in text.as_bytes() {
        if b == b'\n' {
            line = 0;
            printable += 1;
            continue;
        }
        line += 1;
        if line > 998 {
            long = true;
        }
        match b {
            b'\t' | 32..=126 => printable += 1,
            0..=31 | 127 => controls = true,
            _ => {}
        }
    }
    if !long && !controls {
        if text.is_ascii() {
            return TransferEncoding::SevenBit;
        }
        if allow_8bit {
            return TransferEncoding::EightBit;
        }
    }
    if printable * 100 >= text.len() * QP_THRESHOLD_PERCENT {
        TransferEncoding::QuotedPrintable
    } else {
        TransferEncoding::Base64
    }
}

fn lf_count(text: &str) -> u64 {
    text.bytes().filter(|&b| b == b'\n').count() as u64
}

fn text_len(text: &str, encoding: TransferEncoding) -> u64 {
    match encoding {
        TransferEncoding::SevenBit | TransferEncoding::EightBit => {
            text.len() as u64 + lf_count(text)
        }
        TransferEncoding::QuotedPrintable => encode::qp_encoded_len(text.as_bytes()),
        TransferEncoding::Base64 => base64_encoded_len(text.len() as u64 + lf_count(text)),
    }
}

fn write_text<S: Sink>(
    text: &str,
    encoding: TransferEncoding,
    sink: &mut S,
) -> Result<(), SinkError> {
    match encoding {
        TransferEncoding::SevenBit | TransferEncoding::EightBit => {
            let mut first = true;
            for line in text.split('\n') {
                if !first {
                    sink.write(b"\r\n")?;
                }
                first = false;
                sink.write(line.as_bytes())?;
            }
            Ok(())
        }
        TransferEncoding::QuotedPrintable => {
            let mut state = QpState::new();
            let mut err = None;
            let mut emit = |b: &[u8]| {
                if err.is_none() {
                    if let Err(e) = sink.write(b) {
                        err = Some(e);
                    }
                }
            };
            encode::qp_push(&mut state, text.as_bytes(), &mut emit);
            encode::qp_finish(&mut state, &mut emit);
            err.map_or(Ok(()), Err)
        }
        TransferEncoding::Base64 => {
            let mut b = B64Stream::new();
            let mut first = true;
            for line in text.split('\n') {
                if !first {
                    b.push(b"\r\n", sink)?;
                }
                first = false;
                b.push(line.as_bytes(), sink)?;
            }
            b.finish(sink)
        }
    }
}

fn write_base64<S: Sink>(bytes: &[u8], sink: &mut S) -> Result<(), SinkError> {
    let mut buf = [0u8; MIME_LINE_LENGTH];
    let mut first = true;
    for chunk in bytes.chunks(B64_LINE_INPUT) {
        if !first {
            sink.write(b"\r\n")?;
        }
        first = false;
        let n = encode::base64_line(chunk, &mut buf);
        sink.write(buf.get(..n).unwrap_or(&[]))?;
    }
    Ok(())
}

/// Base64 over bytes that arrive in pieces, in 76-character lines.
struct B64Stream {
    held: [u8; B64_LINE_INPUT],
    n: usize,
    lines: u64,
}

impl B64Stream {
    fn new() -> B64Stream {
        B64Stream {
            held: [0; B64_LINE_INPUT],
            n: 0,
            lines: 0,
        }
    }

    fn push<S: Sink>(&mut self, mut bytes: &[u8], sink: &mut S) -> Result<(), SinkError> {
        while !bytes.is_empty() {
            let take = (B64_LINE_INPUT - self.n).min(bytes.len());
            if let (Some(dst), Some(src)) =
                (self.held.get_mut(self.n..self.n + take), bytes.get(..take))
            {
                dst.copy_from_slice(src);
            }
            self.n += take;
            bytes = bytes.get(take..).unwrap_or(&[]);
            if self.n == B64_LINE_INPUT {
                self.emit(sink)?;
            }
        }
        Ok(())
    }

    fn emit<S: Sink>(&mut self, sink: &mut S) -> Result<(), SinkError> {
        if self.lines > 0 {
            sink.write(b"\r\n")?;
        }
        let mut buf = [0u8; MIME_LINE_LENGTH];
        let n = encode::base64_line(self.held.get(..self.n).unwrap_or(&[]), &mut buf);
        sink.write(buf.get(..n).unwrap_or(&[]))?;
        self.lines += 1;
        self.n = 0;
        Ok(())
    }

    fn finish<S: Sink>(mut self, sink: &mut S) -> Result<(), SinkError> {
        if self.n > 0 { self.emit(sink) } else { Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_choose_encoding_decisions() {
        assert_eq!(
            choose_text_encoding("hello\nworld", false),
            TransferEncoding::SevenBit
        );
        assert_eq!(
            choose_text_encoding("caf\u{e9} au lait", false),
            TransferEncoding::QuotedPrintable
        );
        assert_eq!(
            choose_text_encoding("caf\u{e9}", true),
            TransferEncoding::EightBit
        );
        assert_eq!(
            choose_text_encoding(&"\u{65e5}\u{672c}".repeat(10), false),
            TransferEncoding::Base64
        );
        assert_eq!(
            choose_text_encoding(&"x".repeat(998), false),
            TransferEncoding::SevenBit
        );
        assert_eq!(
            choose_text_encoding(&"x".repeat(999), false),
            TransferEncoding::QuotedPrintable
        );
        assert_eq!(
            choose_text_encoding("bell\u{7}", true),
            TransferEncoding::QuotedPrintable
        );
        assert_eq!(choose_text_encoding("", false), TransferEncoding::SevenBit);
    }

    #[test]
    fn test_text_len_matches_written_bytes() {
        for (t, a) in [
            ("a\nb\n", false),
            ("caf\u{e9} \n.x\nFrom y", false),
            (&*"\u{65e5}\n".repeat(100), false),
            ("\u{e9}\n", true),
            ("", false),
        ] {
            let enc = choose_text_encoding(t, a);
            let mut out = Vec::new();
            write_text(t, enc, &mut out).unwrap();
            assert_eq!(out.len() as u64, text_len(t, enc), "{t:?} {enc:?}");
            assert!(!out.windows(2).any(|w| w[1] == b'\n' && w[0] != b'\r'));
        }
    }

    #[test]
    fn test_base64_text_uses_crlf_canonical_form() {
        let mut out = Vec::new();
        write_text("\u{65e5}\n\u{65e5}", TransferEncoding::Base64, &mut out).unwrap();
        // Base64 of E6 97 A5 0D 0A E6 97 A5.
        assert_eq!(out, b"5pelDQrml6U=");
    }

    #[test]
    fn test_file_name_rules() {
        for bad in ["", "a/b", "a\\b", "a\0b", "a\x1b[1m", &"n".repeat(256)] {
            assert_eq!(
                check_file_name(bad),
                Err(HeaderError::InvalidFileName),
                "{bad:?}"
            );
        }
        for good in [
            "report.pdf",
            "my file \"v2\".txt",
            "caf\u{e9}.txt",
            "..",
            &"n".repeat(255),
        ] {
            assert!(check_file_name(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn test_content_type_parse_and_params() {
        assert!(ContentType::parse("text").is_err());
        assert!(ContentType::parse("/plain").is_err());
        assert!(ContentType::parse("text/plain; charset=\"utf\r\n-8\"").is_err());
        let ct = ContentType::parse("Application/PDF").unwrap();
        assert_eq!(ct.essence(), "application/pdf");
        let ct = ContentType::parse("text/plain; charset=\"utf-8\"; format=flowed").unwrap();
        assert_eq!(ct.parameter("CHARSET"), Some("utf-8"));
        assert_eq!(ct.parameter("format"), Some("flowed"));
        let ct = ct.with_parameter("format", "fixed").unwrap();
        assert_eq!(ct.parameter("format"), Some("fixed"));
        assert!(
            ContentType::parse("text/plain")
                .unwrap()
                .with_parameter("a b", "x")
                .is_err()
        );
    }

    #[test]
    fn test_with_params_folds_and_encodes_non_ascii() {
        let mut b = HeaderBlock::default();
        b.with_params(
            "Content-Disposition",
            "attachment",
            &[(
                "filename",
                "caf\u{e9} r\u{e9}sum\u{e9} with a long name.pdf",
            )],
        )
        .unwrap();
        let s = core::str::from_utf8(&b.bytes).unwrap();
        assert!(s.contains("filename*"), "{s}");
        assert!(s.lines().all(|l| l.len() <= 78), "{s}");
        assert!(s.is_ascii());
    }
}
