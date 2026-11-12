//! Capabilities from the EHLO reply (RFC 5321 4.1.1.1).

use alloc::vec::Vec;

use crate::error::{Extension, ProtocolError};

/// Most unknown keywords kept (more are counted, not kept).
const MAX_UNKNOWN: usize = 32;
/// Longest unknown keyword line kept, in octets.
const MAX_UNKNOWN_LEN: usize = 64;
/// Most AUTH mechanism names kept.
const MAX_MECHANISMS: usize = 16;
/// Largest SIZE value accepted (2^53).
const MAX_SIZE: u64 = 1 << 53;

/// What the server offered in its EHLO reply.
///
/// # Examples
///
/// ```
/// use smtp_net::{Capabilities, Extension};
/// use smtp_net::protocol::{ReplyLimits, ReplyParser};
/// let mut p = ReplyParser::new(ReplyLimits::default(), false);
/// let (_, ehlo) = p.push(b"250-mx.example.com\r\n250-SIZE 10240000\r\n250-PIPELINING\r\n250 8BITMIME\r\n")?;
/// let caps = Capabilities::parse(&ehlo.unwrap())?;
/// assert!(caps.has(Extension::Pipelining));
/// assert_eq!(caps.size_limit(), Some(10_240_000));
/// assert!(!caps.has(Extension::Chunking));
/// # Ok::<(), smtp_net::ProtocolError>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    flags: u32,
    size: Option<u64>,
    /// AUTH mechanism names, uppercase, each followed by a space: one
    /// allocation for the whole list.
    mechanisms: Vec<u8>,
    mechanism_count: usize,
    unknown: Vec<Vec<u8>>,
    unknown_count: usize,
}

fn bit(ext: Extension) -> u32 {
    1 << match ext {
        Extension::Pipelining => 0,
        Extension::Size => 1,
        Extension::EightBitMime => 2,
        Extension::Smtputf8 => 3,
        Extension::Chunking => 4,
        Extension::BinaryMime => 5,
        Extension::Dsn => 6,
        Extension::EnhancedStatusCodes => 7,
        Extension::StartTls => 8,
        Extension::Auth => 9,
        Extension::RequireTls => 10,
    }
}

const KNOWN: [Extension; 11] = [
    Extension::Pipelining,
    Extension::Size,
    Extension::EightBitMime,
    Extension::Smtputf8,
    Extension::Chunking,
    Extension::BinaryMime,
    Extension::Dsn,
    Extension::EnhancedStatusCodes,
    Extension::StartTls,
    Extension::Auth,
    Extension::RequireTls,
];

impl Capabilities {
    /// Parses an EHLO reply: the first line is the server's name and greeting;
    /// each further line is one keyword with parameters, case-insensitive.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::MalformedCapability`] for a keyword outside the
    /// grammar or a SIZE value that is not a number up to 2^53.
    pub fn parse(ehlo: &super::Reply) -> Result<Capabilities, ProtocolError> {
        Capabilities::from_lines(ehlo.lines())
    }

    pub(crate) fn from_text(text: &[u8]) -> Result<Capabilities, ProtocolError> {
        let body = text.strip_suffix(b"\n").unwrap_or(text);
        Capabilities::from_lines(body.split(|&b| b == b'\n'))
    }

    fn from_lines<'a>(
        lines: impl Iterator<Item = &'a [u8]>,
    ) -> Result<Capabilities, ProtocolError> {
        let mut caps = Capabilities::default();
        for line in lines.skip(1) {
            caps.line(line)?;
        }
        Ok(caps)
    }

    fn line(&mut self, line: &[u8]) -> Result<(), ProtocolError> {
        let end = line
            .iter()
            .position(|&b| b == b' ' || b == b'=')
            .unwrap_or(line.len());
        let keyword = line.get(..end).unwrap_or(&[]);
        let legacy_auth = line.get(end) == Some(&b'=');
        let valid = keyword.first().is_some_and(u8::is_ascii_alphanumeric)
            && keyword
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'-');
        let params = line.get(end + 1..).unwrap_or(&[]);
        // A keyword outside the RFC 5321 grammar (servers send `X_PIPE_CONNECT`
        // and the like) is never acted on: it is counted and kept like any
        // unknown keyword, so it cannot change what the client does.
        let known = if valid && (!legacy_auth || keyword.eq_ignore_ascii_case(b"AUTH")) {
            KNOWN
                .iter()
                .copied()
                .find(|e| e.keyword().as_bytes().eq_ignore_ascii_case(keyword))
        } else {
            None
        };
        match known {
            Some(Extension::Size) => {
                let v = params.split(|&b| b == b' ').next().unwrap_or(&[]);
                let size = if v.is_empty() {
                    0
                } else {
                    if v.len() > 16 || !v.iter().all(u8::is_ascii_digit) {
                        return Err(ProtocolError::MalformedCapability);
                    }
                    let n = v.iter().fold(0u64, |n, &d| n * 10 + u64::from(d - b'0'));
                    if n > MAX_SIZE {
                        return Err(ProtocolError::MalformedCapability);
                    }
                    n
                };
                self.size = Some(size);
                self.flags |= bit(Extension::Size);
            }
            Some(Extension::Auth) => {
                self.flags |= bit(Extension::Auth);
                for name in params.split(|&b| b == b' ').filter(|n| !n.is_empty()) {
                    if self.mechanism_count < MAX_MECHANISMS
                        && !self
                            .auth_mechanism_names()
                            .any(|m| m.eq_ignore_ascii_case(name))
                    {
                        self.mechanisms.reserve(params.len() + 1);
                        self.mechanisms
                            .extend(name.iter().map(u8::to_ascii_uppercase));
                        self.mechanisms.push(b' ');
                        self.mechanism_count += 1;
                    }
                }
            }
            Some(ext) => self.flags |= bit(ext),
            None => {
                self.unknown_count += 1;
                if self.unknown.len() < MAX_UNKNOWN {
                    let kept = line.get(..line.len().min(MAX_UNKNOWN_LEN)).unwrap_or(&[]);
                    self.unknown.push(kept.to_vec());
                }
            }
        }
        Ok(())
    }

    /// True when the server offered `extension`.
    #[must_use]
    pub fn has(&self, extension: Extension) -> bool {
        self.flags & bit(extension) != 0
    }

    /// The SIZE limit: `None` when not advertised, `Some(0)` for no fixed limit.
    #[must_use]
    pub fn size_limit(&self) -> Option<u64> {
        self.size
    }

    /// The AUTH mechanism names offered, uppercase, in the server's order.
    pub fn auth_mechanism_names(&self) -> impl Iterator<Item = &[u8]> + Clone + '_ {
        self.mechanisms
            .split(|&b| b == b' ')
            .filter(|n| !n.is_empty())
    }

    /// Unknown keyword lines kept (at most 32, each at most 64 octets).
    pub fn unknown(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.unknown.iter().map(Vec::as_slice)
    }

    /// How many unknown keyword lines there were, kept or not.
    #[must_use]
    pub fn unknown_count(&self) -> usize {
        self.unknown_count
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    fn caps(lines: &[&str]) -> Result<Capabilities, ProtocolError> {
        let mut text = alloc::string::String::from("mx.example.com hello\n");
        for l in lines {
            text.push_str(l);
            text.push('\n');
        }
        Capabilities::from_text(text.as_bytes())
    }

    #[test]
    fn test_ehlo_with_no_extensions() {
        let c = Capabilities::from_text(b"mx.example.com\n").unwrap();
        assert!(!c.has(Extension::Pipelining));
        assert_eq!(c.size_limit(), None);
    }

    #[test]
    fn test_ehlo_keywords_case_insensitive_and_duplicates() {
        let c = caps(&[
            "pipelining",
            "PIPELINING",
            "8bitmime",
            "SmtpUtf8",
            "STARTTLS",
            "ENHANCEDSTATUSCODES",
            "CHUNKING",
            "DSN",
        ])
        .unwrap();
        for e in [
            Extension::Pipelining,
            Extension::EightBitMime,
            Extension::Smtputf8,
            Extension::StartTls,
            Extension::EnhancedStatusCodes,
            Extension::Chunking,
            Extension::Dsn,
        ] {
            assert!(c.has(e), "{e:?}");
        }
    }

    #[test]
    fn test_ehlo_size_values() {
        assert_eq!(caps(&["SIZE"]).unwrap().size_limit(), Some(0));
        assert_eq!(caps(&["SIZE 0"]).unwrap().size_limit(), Some(0));
        assert_eq!(
            caps(&["SIZE 35882577"]).unwrap().size_limit(),
            Some(35_882_577)
        );
        for bad in [
            "SIZE 18446744073709551615",
            "SIZE -1",
            "SIZE 1e9",
            "SIZE 9007199254740993",
        ] {
            assert_eq!(
                caps(&[bad]),
                Err(ProtocolError::MalformedCapability),
                "{bad}"
            );
        }
    }

    #[test]
    fn test_ehlo_auth_lists() {
        let c = caps(&["AUTH PLAIN LOGIN XOAUTH2", "AUTH=PLAIN LOGIN"]).unwrap();
        assert!(c.has(Extension::Auth));
        assert_eq!(c.auth_mechanism_names().count(), 3);
        let many = format!(
            "AUTH {}",
            (0..50)
                .map(|i| format!("M{i}"))
                .collect::<alloc::vec::Vec<_>>()
                .join(" ")
        );
        assert_eq!(
            caps(&[&many]).unwrap().auth_mechanism_names().count(),
            MAX_MECHANISMS
        );
        assert!(caps(&["AUTH"]).unwrap().has(Extension::Auth));
    }

    #[test]
    fn test_ehlo_unknown_keywords_bounded() {
        let lines: alloc::vec::Vec<alloc::string::String> =
            (0..33).map(|i| format!("X-EXT{i} a b c")).collect();
        let refs: alloc::vec::Vec<&str> = lines.iter().map(alloc::string::String::as_str).collect();
        let c = caps(&refs).unwrap();
        assert_eq!(c.unknown().count(), 32);
        assert_eq!(c.unknown_count(), 33);
    }

    #[test]
    fn test_ehlo_keywords_outside_grammar_kept_as_unknown() {
        let c = caps(&["-X", "X_PIPE_CONNECT", "", "X=Y", "SIZE=5"]).unwrap();
        assert_eq!(c.unknown_count(), 5);
        assert!(!c.has(Extension::Size));
    }
}
