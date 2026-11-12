//! Command formatting from validated types (PLAN 10.2: no caller string is
//! formatted into a command without its type's validation, and every line is
//! scanned again before it is queued).

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    address::{Address, Domain},
    error::{AddressError, BuildError, Error},
    message::prepared::xtext,
};

/// Longest command line, including CRLF (RFC 5321 4.5.3.1.4).
pub const MAX_COMMAND_LINE: usize = 512;
/// Longest text line, including CRLF (RFC 5321 4.5.3.1.6).
pub const MAX_TEXT_LINE: usize = 1000;

/// The EHLO argument.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientName {
    /// A fully qualified domain name.
    Domain(Domain),
    /// An address literal, `[192.0.2.1]` or `[IPv6:2001:db8::1]` (D-011).
    AddressLiteral(IpAddr),
}

impl ClientName {
    /// Parses an EHLO name: a domain (`mail.example.com`), or an IP address,
    /// bare (`192.0.2.1`, `2001:db8::1`) or as an RFC 5321 literal
    /// (`[192.0.2.1]`, `[IPv6:2001:db8::1]`).
    ///
    /// # Errors
    ///
    /// As [`Domain::parse`] for a name; `AddressLiteralNotAllowed` for a
    /// bracketed literal that is not an IPv4 address or `IPv6:` and an IPv6
    /// address.
    ///
    /// # Examples
    ///
    /// ```
    /// use smtp_net::protocol::ClientName;
    /// assert!(matches!(ClientName::parse("mail.example.com")?, ClientName::Domain(_)));
    /// assert!(matches!(ClientName::parse("[IPv6:2001:db8::1]")?, ClientName::AddressLiteral(_)));
    /// assert!(ClientName::parse("[IPv6:192.0.2.1]").is_err());
    /// assert!(ClientName::parse("not a name").is_err());
    /// # Ok::<(), smtp_net::AddressError>(())
    /// ```
    pub fn parse(text: &str) -> Result<ClientName, AddressError> {
        if let Some(inner) = text.strip_prefix('[') {
            let inner = inner
                .strip_suffix(']')
                .ok_or(AddressError::AddressLiteralNotAllowed)?;
            let ip = match inner.strip_prefix("IPv6:") {
                Some(v6) => v6.parse::<Ipv6Addr>().map(IpAddr::V6).ok(),
                None => inner.parse::<Ipv4Addr>().map(IpAddr::V4).ok(),
            };
            return ip
                .map(ClientName::AddressLiteral)
                .ok_or(AddressError::AddressLiteralNotAllowed);
        }
        if let Ok(ip) = text.parse::<IpAddr>() {
            return Ok(ClientName::AddressLiteral(ip));
        }
        Domain::parse(text).map(ClientName::Domain)
    }
}

impl Default for ClientName {
    fn default() -> ClientName {
        ClientName::AddressLiteral(IpAddr::V4(core::net::Ipv4Addr::LOCALHOST))
    }
}

/// Appends one command line to `out`, checking it holds no CR or LF before
/// its CRLF and fits in 512 octets (T-2).
pub(crate) struct Line<'a> {
    out: &'a mut Vec<u8>,
    start: usize,
}

impl<'a> Line<'a> {
    pub(crate) fn new(out: &'a mut Vec<u8>) -> Line<'a> {
        let start = out.len();
        Line { out, start }
    }

    pub(crate) fn put(&mut self, bytes: &[u8]) -> &mut Self {
        self.out.extend_from_slice(bytes);
        self
    }

    pub(crate) fn decimal(&mut self, mut n: u64) -> &mut Self {
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        loop {
            i -= 1;
            if let Some(d) = buf.get_mut(i) {
                *d = b'0' + (n % 10) as u8;
            }
            n /= 10;
            if n == 0 {
                break;
            }
        }
        self.out.extend_from_slice(buf.get(i..).unwrap_or(&[]));
        self
    }

    pub(crate) fn client_name(&mut self, name: &ClientName) -> &mut Self {
        match name {
            ClientName::Domain(d) => self.put(d.as_str().as_bytes()),
            ClientName::AddressLiteral(IpAddr::V4(a)) => {
                self.put(b"[");
                for (i, o) in a.octets().iter().enumerate() {
                    if i > 0 {
                        self.put(b".");
                    }
                    self.decimal(u64::from(*o));
                }
                self.put(b"]")
            }
            ClientName::AddressLiteral(IpAddr::V6(a)) => {
                let mut s = alloc::string::String::new();
                let _ = core::fmt::Write::write_fmt(&mut s, format_args!("[IPv6:{a}]"));
                self.put(s.as_bytes())
            }
        }
    }

    /// Appends `bytes` as RFC 3461 xtext, written straight into the line.
    pub(crate) fn xtext(&mut self, bytes: &[u8]) -> &mut Self {
        xtext(bytes, self.out);
        self
    }

    pub(crate) fn path(&mut self, a: Option<&Address>) -> &mut Self {
        self.put(b"<");
        if let Some(a) = a {
            self.put(a.as_str().as_bytes());
        }
        self.put(b">")
    }

    /// Ends the line with CRLF after the shadow check; on failure the line
    /// is removed and nothing is queued.
    ///
    /// # Errors
    ///
    /// `Build(CommandHasControl)` when the line holds CR, LF, or NUL;
    /// `Build(CommandTooLong)` when it passes 512 octets. Both permanent.
    pub(crate) fn end(self) -> Result<(), Error> {
        let line = self.out.get(self.start..).unwrap_or(&[]);
        let refused = if line.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0) {
            Some(BuildError::CommandHasControl)
        } else if line.len() + 2 > MAX_COMMAND_LINE {
            Some(BuildError::CommandTooLong)
        } else {
            None
        };
        if let Some(b) = refused {
            self.out.truncate(self.start);
            return Err(Error::from(b).with_disposition(crate::Disposition::Permanent));
        }
        self.out.extend_from_slice(b"\r\n");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_name_literals() {
        let mut out = Vec::new();
        let mut l = Line::new(&mut out);
        l.put(b"EHLO ").client_name(&ClientName::default());
        l.end().unwrap();
        assert_eq!(out, b"EHLO [127.0.0.1]\r\n");
        let mut out = Vec::new();
        let mut l = Line::new(&mut out);
        l.put(b"EHLO ")
            .client_name(&ClientName::AddressLiteral("2001:db8::1".parse().unwrap()));
        l.end().unwrap();
        assert_eq!(out, b"EHLO [IPv6:2001:db8::1]\r\n");
    }

    #[test]
    fn test_line_shadow_check_refuses_embedded_crlf_and_overlength() {
        let mut out = b"KEEP\r\n".to_vec();
        let mut l = Line::new(&mut out);
        l.put(b"MAIL FROM:<a@b>\r\nRCPT TO:<c@d>");
        assert!(l.end().is_err());
        assert_eq!(out, b"KEEP\r\n");
        let mut l = Line::new(&mut out);
        l.put(&[b'x'; 511]);
        assert!(l.end().is_err());
        let mut l = Line::new(&mut out);
        l.put(&[b'x'; 510]);
        assert!(l.end().is_ok());
    }

    #[test]
    fn test_shadow_check_over_arbitrary_path_bytes() {
        // T-2: bytes that never passed the Address grammar, put where a path
        // goes; the line is queued exactly when it has no CR, LF, or NUL and
        // fits, and a refused line leaves nothing behind.
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..50_000 {
            let len = (next() % 600) as usize;
            let path: Vec<u8> = (0..len)
                .map(|_| match next() % 16 {
                    0 => b'\r',
                    1 => b'\n',
                    2 => 0,
                    3 => b'>',
                    _ => (next() % 256) as u8,
                })
                .collect();
            let mut out = b"EHLO [127.0.0.1]\r\n".to_vec();
            let mut l = Line::new(&mut out);
            l.put(b"RCPT TO:<").put(&path).put(b">");
            let clean = !path.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0);
            let fits = 10 + path.len() + 2 <= MAX_COMMAND_LINE;
            assert_eq!(l.end().is_ok(), clean && fits);
            if clean && fits {
                assert_eq!(out.len(), 18 + 10 + path.len() + 2);
                assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 2);
            } else {
                assert_eq!(out, b"EHLO [127.0.0.1]\r\n");
            }
        }
    }

    #[test]
    fn test_client_name_parse_accepts_names_and_addresses() {
        assert!(matches!(
            ClientName::parse("mail.example.com"),
            Ok(ClientName::Domain(_))
        ));
        for (text, ip) in [
            ("192.0.2.1", "192.0.2.1"),
            ("[192.0.2.1]", "192.0.2.1"),
            ("2001:db8::1", "2001:db8::1"),
            ("[IPv6:2001:db8::1]", "2001:db8::1"),
        ] {
            let want: IpAddr = ip.parse().unwrap();
            assert_eq!(
                ClientName::parse(text),
                Ok(ClientName::AddressLiteral(want)),
                "{text}"
            );
        }
    }

    #[test]
    fn test_client_name_parse_refuses_bad_literals_and_names() {
        for text in [
            "",
            "[2001:db8::1]",
            "[IPv6:192.0.2.1]",
            "[192.0.2.1",
            "[]",
            "[mail.example.com]",
            "not a name",
            "mail.example.com\r\nMAIL FROM:<x>",
        ] {
            assert!(ClientName::parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn test_parsed_client_name_formats_as_ehlo_argument() {
        for (text, wire) in [
            ("mail.example.com", "mail.example.com"),
            ("192.0.2.1", "[192.0.2.1]"),
            ("[IPv6:2001:db8::1]", "[IPv6:2001:db8::1]"),
        ] {
            let mut out = Vec::new();
            Line::new(&mut out).client_name(&ClientName::parse(text).unwrap());
            assert_eq!(out, wire.as_bytes(), "{text}");
        }
    }

    #[test]
    fn test_decimal_formatting() {
        let mut out = Vec::new();
        Line::new(&mut out)
            .decimal(0)
            .decimal(1234567890)
            .decimal(u64::MAX);
        assert_eq!(out, b"0123456789018446744073709551615");
    }
}
