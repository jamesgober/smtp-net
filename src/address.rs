//! Addresses, mailboxes, and domains.
//!
//! The RFC 5322 grammar comes from parse-net (`mail::parse_addr_spec`,
//! `mail::parse_mailbox`); this module adds the rules RFC 5321 puts on an SMTP
//! path: LDH domain labels of at most 63 octets, a domain of at most 255
//! octets, a path of at most 256 octets, no domain literals unless asked for,
//! and no control character anywhere (D-014, T-2).

use alloc::string::String;
use core::{fmt, str::FromStr};

use parse_net::{ErrorKind as PnKind, Limits, ParseError, mail};

use crate::error::{AddressError, AddressPart};

/// Longest local part, in octets (RFC 5321 4.5.3.1.1).
pub const MAX_LOCAL_PART: usize = 64;
/// Longest domain, in octets (RFC 5321 4.5.3.1.2).
pub const MAX_DOMAIN: usize = 255;
/// Longest path including `<` and `>`, in octets (RFC 5321 4.5.3.1.3).
pub const MAX_PATH: usize = 256;

/// A validated domain: LDH labels (or UTF-8 labels, which need SMTPUTF8).
///
/// # Examples
///
/// ```
/// let d = smtp_net::Domain::parse("mail.example.com")?;
/// assert!(d.is_ascii());
/// assert!(smtp_net::Domain::parse("-bad.example").is_err());
/// # Ok::<(), smtp_net::AddressError>(())
/// ```
#[derive(Clone)]
pub struct Domain {
    /// The full text the domain lives in (the address, for an address's domain).
    text: String,
    /// Where the domain starts in `text`.
    start: usize,
    ascii: bool,
    literal: bool,
}

impl Domain {
    /// Parses and validates a domain name (no address literal).
    ///
    /// # Errors
    ///
    /// [`AddressError::Empty`], `InvalidDomain`, `LabelTooLong`, `TooLong`,
    /// `ControlCharacter`, `AddressLiteralNotAllowed`.
    pub fn parse(input: &str) -> Result<Domain, AddressError> {
        if input.is_empty() {
            return Err(AddressError::Empty);
        }
        check_controls(input, 0)?;
        if input.starts_with('[') {
            return Err(AddressError::AddressLiteralNotAllowed);
        }
        let ascii = check_domain_labels(input.as_bytes(), 0)?;
        Ok(Domain {
            text: String::from(input),
            start: 0,
            ascii,
            literal: false,
        })
    }

    /// True when every octet is ASCII (no SMTPUTF8 needed).
    #[must_use]
    pub fn is_ascii(&self) -> bool {
        self.ascii
    }

    /// True for a domain literal such as `[192.0.2.1]`.
    #[must_use]
    pub fn is_literal(&self) -> bool {
        self.literal
    }

    /// The domain as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.text.get(self.start..).unwrap_or("")
    }

    /// True when the domains are equal ignoring ASCII case.
    #[must_use]
    pub fn eq_ignore_case(&self, other: &Domain) -> bool {
        self.as_str().eq_ignore_ascii_case(other.as_str())
    }
}

impl PartialEq for Domain {
    fn eq(&self, other: &Domain) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for Domain {}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Domain").field(&self.as_str()).finish()
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated `addr-spec` that can be used as an SMTP path.
///
/// One allocation holds the whole address; the local part and the domain are
/// views into it.
///
/// # Examples
///
/// ```
/// let a = smtp_net::Address::parse("user@example.com")?;
/// assert_eq!(a.local_part(), "user");
/// assert_eq!(a.domain().as_str(), "example.com");
/// assert!(!a.needs_smtputf8());
/// assert!(smtp_net::Address::parse("a@b>\r\nRCPT TO:<c@d").is_err());
/// # Ok::<(), smtp_net::AddressError>(())
/// ```
#[derive(Clone)]
pub struct Address {
    domain: Domain,
}

impl Address {
    /// Parses an `addr-spec`: a dot-atom or quoted-string local part, `@`, and
    /// a domain name. Comments, folding whitespace, obsolete syntax, and domain
    /// literals are refused. Leading and trailing spaces are ignored.
    ///
    /// # Errors
    ///
    /// The [`AddressError`] variants.
    pub fn parse(input: &str) -> Result<Address, AddressError> {
        parse_address(input, false)
    }

    /// As [`parse`](Address::parse), but also accepts a domain literal
    /// (`user@[192.0.2.1]`, `user@[IPv6:2001:db8::1]`).
    ///
    /// # Errors
    ///
    /// The [`AddressError`] variants except `AddressLiteralNotAllowed`.
    pub fn parse_allowing_literal(input: &str) -> Result<Address, AddressError> {
        parse_address(input, true)
    }

    /// Builds an address from its parts with the same checks as `parse`.
    ///
    /// # Errors
    ///
    /// The [`AddressError`] variants.
    pub fn new(local_part: &str, domain: &str) -> Result<Address, AddressError> {
        let mut s = String::with_capacity(local_part.len() + 1 + domain.len());
        s.push_str(local_part);
        s.push('@');
        s.push_str(domain);
        let a = parse_address(&s, false)?;
        if a.local_part() != local_part {
            return Err(AddressError::InvalidLocalPart { position: 0 });
        }
        Ok(a)
    }

    /// The local part, as written (a quoted local part keeps its quotes).
    #[must_use]
    pub fn local_part(&self) -> &str {
        let at = self.domain.start.saturating_sub(1);
        self.domain.text.get(..at).unwrap_or("")
    }

    /// The domain.
    #[must_use]
    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    /// True when the local part or the domain has a non-ASCII octet.
    #[must_use]
    pub fn needs_smtputf8(&self) -> bool {
        !self.domain.text.is_ascii()
    }

    /// The address as written on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.domain.text
    }

    /// True when the addresses name the same mailbox for deduplication: the
    /// local parts are equal and the domains are equal ignoring ASCII case.
    #[must_use]
    pub fn same_mailbox(&self, other: &Address) -> bool {
        self.local_part() == other.local_part() && self.domain.eq_ignore_case(&other.domain)
    }
}

/// Equal when the whole addresses are equal as written (local part and
/// domain); [`same_mailbox`](Address::same_mailbox) ignores domain case.
impl PartialEq for Address {
    fn eq(&self, other: &Address) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for Address {}

impl core::hash::Hash for Address {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Address").field(&self.as_str()).finish()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Address {
    type Err = AddressError;
    fn from_str(s: &str) -> Result<Address, AddressError> {
        Address::parse(s)
    }
}

impl TryFrom<&str> for Address {
    type Error = AddressError;
    fn try_from(s: &str) -> Result<Address, AddressError> {
        Address::parse(s)
    }
}

fn check_controls(input: &str, offset: usize) -> Result<(), AddressError> {
    for (i, c) in input.char_indices() {
        if c.is_control() || c == '\u{2028}' || c == '\u{2029}' {
            return Err(AddressError::ControlCharacter {
                position: offset + i,
            });
        }
    }
    Ok(())
}

/// Validates dot-separated domain labels; returns whether all are ASCII.
fn check_domain_labels(d: &[u8], offset: usize) -> Result<bool, AddressError> {
    if d.len() > MAX_DOMAIN {
        return Err(AddressError::TooLong {
            part: AddressPart::Domain,
            length: d.len(),
            limit: MAX_DOMAIN,
        });
    }
    let mut ascii = true;
    let mut pos = offset;
    for (index, label) in d.split(|&b| b == b'.').enumerate() {
        if label.is_empty() {
            return Err(AddressError::InvalidDomain { position: pos });
        }
        if label.len() > 63 {
            return Err(AddressError::LabelTooLong { label: index });
        }
        if label.is_ascii() {
            for (i, &b) in label.iter().enumerate() {
                let edge = i == 0 || i + 1 == label.len();
                let ok = b.is_ascii_alphanumeric() || (b == b'-' && !edge);
                if !ok {
                    return Err(AddressError::InvalidDomain { position: pos + i });
                }
            }
        } else {
            ascii = false;
            // A U-label: no ASCII punctuation other than '-', no edge hyphen.
            for (i, &b) in label.iter().enumerate() {
                let edge = i == 0 || i + 1 == label.len();
                if b < 0x80 && !(b.is_ascii_alphanumeric() || (b == b'-' && !edge)) {
                    return Err(AddressError::InvalidDomain { position: pos + i });
                }
            }
        }
        pos += label.len() + 1;
    }
    Ok(ascii)
}

fn map_parse_error(e: ParseError, at: usize, input_len: usize) -> AddressError {
    let position = e.offset();
    match e.kind() {
        PnKind::Empty => AddressError::Empty,
        PnKind::TooLong => {
            if at > MAX_LOCAL_PART {
                AddressError::TooLong {
                    part: AddressPart::LocalPart,
                    length: at,
                    limit: MAX_LOCAL_PART,
                }
            } else {
                AddressError::TooLong {
                    part: AddressPart::Path,
                    length: input_len + 2,
                    limit: MAX_PATH,
                }
            }
        }
        PnKind::BareCr | PnKind::LineFeed | PnKind::Nul | PnKind::Control => {
            AddressError::ControlCharacter { position }
        }
        _ if at == usize::MAX => AddressError::MissingAt,
        _ if position > at => AddressError::InvalidDomain { position },
        _ => AddressError::InvalidLocalPart { position },
    }
}

fn parse_address(input: &str, allow_literal: bool) -> Result<Address, AddressError> {
    let trimmed = input.trim_matches(|c| c == ' ' || c == '\t');
    let lead = input.len() - input.trim_start_matches([' ', '\t']).len();
    if trimmed.is_empty() {
        return Err(AddressError::Empty);
    }
    check_controls(trimmed, lead)?;
    let at = trimmed.rfind('@').unwrap_or(usize::MAX);
    let spec = mail::parse_addr_spec(trimmed.as_bytes())
        .map_err(|e| map_parse_error(e, at, trimmed.len()).shift(lead))?;
    if at == usize::MAX {
        return Err(AddressError::MissingAt);
    }
    let local_len = match spec.local {
        mail::LocalPart::DotAtom(a) => a.len(),
        mail::LocalPart::Quoted(q) => q.raw().len() + 2,
    };
    if local_len > MAX_LOCAL_PART {
        return Err(AddressError::TooLong {
            part: AddressPart::LocalPart,
            length: local_len,
            limit: MAX_LOCAL_PART,
        });
    }
    if trimmed.len() + 2 > MAX_PATH {
        return Err(AddressError::TooLong {
            part: AddressPart::Path,
            length: trimmed.len() + 2,
            limit: MAX_PATH,
        });
    }
    // The domain starts after the '@' that ends the local part.
    let start = local_len + 1;
    let (ascii, literal) = match spec.domain {
        mail::Domain::DotAtom(d) => (check_domain_labels(d, lead + start)?, false),
        mail::Domain::Literal(_) if !allow_literal => {
            return Err(AddressError::AddressLiteralNotAllowed);
        }
        mail::Domain::Literal(d) => {
            check_literal(d)?;
            (true, true)
        }
    };
    Ok(Address {
        domain: Domain {
            text: String::from(trimmed),
            start,
            ascii,
            literal,
        },
    })
}

/// An RFC 5321 address literal: an IPv4 address, `IPv6:` and an IPv6
/// address. General address literals are refused.
fn check_literal(d: &[u8]) -> Result<(), AddressError> {
    let s = core::str::from_utf8(d).map_err(|_| AddressError::AddressLiteralNotAllowed)?;
    let ok = if let Some(v6) = s.strip_prefix("IPv6:") {
        v6.parse::<core::net::Ipv6Addr>().is_ok()
    } else {
        s.parse::<core::net::Ipv4Addr>().is_ok()
    };
    if ok {
        Ok(())
    } else {
        Err(AddressError::AddressLiteralNotAllowed)
    }
}

trait Shift {
    fn shift(self, by: usize) -> Self;
}

impl Shift for AddressError {
    fn shift(self, by: usize) -> AddressError {
        match self {
            AddressError::InvalidLocalPart { position } => AddressError::InvalidLocalPart {
                position: position + by,
            },
            AddressError::InvalidDomain { position } => AddressError::InvalidDomain {
                position: position + by,
            },
            AddressError::ControlCharacter { position } => AddressError::ControlCharacter {
                position: position + by,
            },
            AddressError::DisplayNameInvalid { position } => AddressError::DisplayNameInvalid {
                position: position + by,
            },
            other => other,
        }
    }
}

/// A mailbox: an optional display name and an address.
///
/// The display name is stored as text (quotes and escapes removed) and is
/// quoted or RFC 2047 encoded only when written into a header.
///
/// # Examples
///
/// ```
/// let m = smtp_net::Mailbox::parse("\"Doe, Jane\" <jane@example.com>")?;
/// assert_eq!(m.display_name(), Some("Doe, Jane"));
/// assert_eq!(m.address().as_str(), "jane@example.com");
/// assert_eq!(m.to_string(), "\"Doe, Jane\" <jane@example.com>");
/// # Ok::<(), smtp_net::AddressError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Mailbox {
    display_name: Option<String>,
    address: Address,
}

impl Mailbox {
    /// Parses `display-name <addr-spec>` or a bare `addr-spec`. The display
    /// name may be a phrase or a quoted string; comments are refused, and
    /// RFC 2047 encoded words in the input are kept as text, not decoded.
    ///
    /// # Errors
    ///
    /// The [`AddressError`] variants.
    pub fn parse(input: &str) -> Result<Mailbox, AddressError> {
        check_controls(input, 0)?;
        let bytes = input.as_bytes();
        if !bytes.contains(&b'<') {
            return Ok(Mailbox {
                display_name: None,
                address: Address::parse(input)?,
            });
        }
        let parsed = mail::parse_mailbox(bytes, &Limits::DEFAULT).map_err(|e| {
            let lt = bytes.iter().position(|&b| b == b'<').unwrap_or(0);
            if e.offset() < lt {
                AddressError::DisplayNameInvalid {
                    position: e.offset(),
                }
            } else {
                let inner = input.get(lt + 1..).unwrap_or("");
                let at = inner.rfind('@').unwrap_or(usize::MAX);
                map_parse_error(e, at.saturating_add(lt + 1), inner.len()).shift(0)
            }
        })?;
        let lt = bytes.iter().position(|&b| b == b'<').unwrap_or(0);
        let gt = bytes
            .iter()
            .rposition(|&b| b == b'>')
            .unwrap_or(bytes.len());
        let inner = input.get(lt + 1..gt).unwrap_or("");
        let address = Address::parse(inner).map_err(|e| e.shift(lt + 1))?;
        let display_name = match parsed.display_name {
            None => None,
            Some(raw) => Some(unquote_phrase(raw)?),
        };
        Ok(Mailbox {
            display_name,
            address,
        })
    }

    /// A mailbox from a display name (text, written as given) and an address.
    ///
    /// # Errors
    ///
    /// [`AddressError::ControlCharacter`] for a control in the display name.
    pub fn new(display_name: Option<&str>, address: Address) -> Result<Mailbox, AddressError> {
        if let Some(name) = display_name {
            check_controls(name, 0)?;
        }
        Ok(Mailbox {
            display_name: display_name
                .filter(|n| !n.trim().is_empty())
                .map(String::from),
            address,
        })
    }

    /// The display name, as text.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// The address.
    #[must_use]
    pub fn address(&self) -> &Address {
        &self.address
    }
}

/// Turns a raw RFC 5322 phrase into text: quoted strings unquoted, quoted
/// pairs unescaped, runs of whitespace between words made one space.
fn unquote_phrase(raw: &[u8]) -> Result<String, AddressError> {
    let raw =
        core::str::from_utf8(raw).map_err(|_| AddressError::DisplayNameInvalid { position: 0 })?;
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.char_indices().peekable();
    let mut in_quote = false;
    let mut space = false;
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => in_quote = !in_quote,
            '\\' if in_quote => {
                if let Some((_, n)) = chars.next() {
                    out.push(n);
                }
            }
            '(' if !in_quote => return Err(AddressError::DisplayNameInvalid { position: i }),
            ' ' | '\t' if !in_quote => {
                space = !out.is_empty();
            }
            _ => {
                if space {
                    out.push(' ');
                    space = false;
                }
                out.push(c);
            }
        }
    }
    Ok(out)
}

impl fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mailbox")
            .field("display_name", &self.display_name)
            .field("address", &self.address)
            .finish()
    }
}

/// The header form: the display name as an atom phrase, a quoted string, or
/// (for non-ASCII text) RFC 2047 encoded words, then `<address>`.
impl fmt::Display for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        crate::message::header::write_mailbox(self, &mut s, 0);
        f.write_str(&s)
    }
}

impl FromStr for Mailbox {
    type Err = AddressError;
    fn from_str(s: &str) -> Result<Mailbox, AddressError> {
        Mailbox::parse(s)
    }
}

impl TryFrom<&str> for Mailbox {
    type Error = AddressError;
    fn try_from(s: &str) -> Result<Mailbox, AddressError> {
        Mailbox::parse(s)
    }
}

impl From<Address> for Mailbox {
    fn from(address: Address) -> Mailbox {
        Mailbox {
            display_name: None,
            address,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::ToString};

    use super::*;

    #[test]
    fn test_address_parse_valid_forms() {
        for s in [
            "a@b.example",
            "first.last@example.com",
            "\"john doe\"@example.com",
            "\"a@b\"@example.com",
            "user+tag@sub.example.co.uk",
            "x@123.example",
            "x@xn--bcher-kva.example",
        ] {
            let a = Address::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"));
            assert_eq!(a.as_str(), s);
        }
        let q = Address::parse("\"john doe\"@example.com").unwrap();
        assert_eq!(q.local_part(), "\"john doe\"");
        assert_eq!(q.domain().as_str(), "example.com");
    }

    #[test]
    fn test_address_trims_surrounding_spaces() {
        assert_eq!(
            Address::parse("  a@b.example ").unwrap().as_str(),
            "a@b.example"
        );
    }

    #[test]
    fn test_address_injection_attempts_refused() {
        for s in [
            "a@b>\r\nRCPT TO:<c@d",
            "\"a\r\n\"@b",
            "a@b\0c",
            "a\n@b",
            "a@b\u{85}",
            "a@b\u{2028}",
        ] {
            assert!(
                matches!(
                    Address::parse(s),
                    Err(AddressError::ControlCharacter { .. })
                ),
                "{s:?} -> {:?}",
                Address::parse(s)
            );
        }
        assert!(Address::parse("a@b>c").is_err());
        assert!(Address::parse("a b@c").is_err());
    }

    #[test]
    fn test_address_lengths_at_limits() {
        let l64 = "a".repeat(64);
        let l65 = "a".repeat(65);
        assert!(Address::parse(&format!("{l64}@example.com")).is_ok());
        assert!(matches!(
            Address::parse(&format!("{l65}@example.com")),
            Err(AddressError::TooLong {
                part: AddressPart::LocalPart,
                ..
            })
        ));
        let label63 = "b".repeat(63);
        let label64 = "b".repeat(64);
        assert!(Address::parse(&format!("a@{label63}.example")).is_ok());
        assert!(matches!(
            Address::parse(&format!("a@{label64}.example")),
            Err(AddressError::LabelTooLong { label: 0 })
        ));
        // Path: 254 octets of address + 2 angle brackets = 256.
        let dom = format!(
            "{}.{}.{}.{}",
            "c".repeat(63),
            "c".repeat(63),
            "c".repeat(63),
            "c".repeat(60)
        );
        let ok = format!("a@{dom}");
        assert_eq!(ok.len(), 254);
        assert!(Address::parse(&ok).is_ok(), "{:?}", Address::parse(&ok));
        let long = format!("ab@{dom}");
        assert!(matches!(
            Address::parse(&long),
            Err(AddressError::TooLong { .. })
        ));
    }

    #[test]
    fn test_address_dots_and_hyphens() {
        for s in [
            ".a@b.example",
            "a.@b.example",
            "a..b@c.example",
            "a@-b.example",
            "a@b-.example",
            "a@b..example",
            "a@b.example.",
        ] {
            assert!(Address::parse(s).is_err(), "{s}");
        }
        assert!(Address::parse("a@b-c.example").is_ok());
    }

    #[test]
    fn test_address_literals_refused_by_default() {
        assert_eq!(
            Address::parse("a@[192.0.2.1]"),
            Err(AddressError::AddressLiteralNotAllowed)
        );
        let a = Address::parse_allowing_literal("a@[192.0.2.1]").unwrap();
        assert!(a.domain().is_literal());
        assert!(Address::parse_allowing_literal("a@[IPv6:2001:db8::1]").is_ok());
        assert!(Address::parse_allowing_literal("a@[999.0.2.1]").is_err());
        assert!(Address::parse_allowing_literal("a@[tag:x]").is_err());
    }

    #[test]
    fn test_address_utf8_flags_smtputf8() {
        let a = Address::parse("j\u{f6}rg@example.com").unwrap();
        assert!(a.needs_smtputf8());
        let d = Address::parse("a@b\u{fc}cher.example").unwrap();
        assert!(!d.domain().is_ascii());
    }

    #[test]
    fn test_address_errors_missing_at_and_empty() {
        assert_eq!(Address::parse(""), Err(AddressError::Empty));
        assert_eq!(Address::parse("   "), Err(AddressError::Empty));
        assert!(matches!(
            Address::parse("nobody"),
            Err(AddressError::MissingAt) | Err(AddressError::InvalidLocalPart { .. })
        ));
        assert!(Address::parse("a(comment)@b.example").is_err());
        assert!(Address::parse("<@a:b@c.example>").is_err());
    }

    #[test]
    fn test_address_equality_compares_the_whole_address() {
        let b = Address::parse("b@example.org").unwrap();
        let d = Address::parse("d@example.org").unwrap();
        assert_ne!(b, d, "same domain, different local part");
        assert_eq!(b, Address::parse("b@example.org").unwrap());
        assert_ne!(b, Address::parse("b@example.net").unwrap());
    }

    #[test]
    fn test_address_new_and_same_mailbox() {
        let a = Address::new("user", "Example.COM").unwrap();
        let b = Address::parse("user@example.com").unwrap();
        assert!(a.same_mailbox(&b));
        assert!(a != b);
        assert!(!Address::parse("User@example.com").unwrap().same_mailbox(&b));
        assert!(Address::new("a@b", "c.example").is_err());
    }

    #[test]
    fn test_domain_parse() {
        assert!(Domain::parse("example.com").unwrap().is_ascii());
        assert_eq!(Domain::parse(""), Err(AddressError::Empty));
        assert_eq!(
            Domain::parse("[1.2.3.4]"),
            Err(AddressError::AddressLiteralNotAllowed)
        );
        assert!(Domain::parse(&"a.".repeat(128)).is_err());
    }

    #[test]
    fn test_mailbox_forms() {
        let m = Mailbox::parse("Example <no-reply@example.com>").unwrap();
        assert_eq!(m.display_name(), Some("Example"));
        let m = Mailbox::parse("  Jane   Q.  Doe <j@example.com>").unwrap();
        assert_eq!(m.display_name(), Some("Jane Q. Doe"));
        let m = Mailbox::parse("\"Doe \\\"JD\\\" Jane\" <j@example.com>").unwrap();
        assert_eq!(m.display_name(), Some("Doe \"JD\" Jane"));
        let m = Mailbox::parse("j@example.com").unwrap();
        assert_eq!(m.display_name(), None);
        let m = Mailbox::parse("<j@example.com>").unwrap();
        assert_eq!(m.display_name(), None);
        let m = Mailbox::parse("Jos\u{e9} <j@example.com>").unwrap();
        assert_eq!(m.display_name(), Some("Jos\u{e9}"));
    }

    #[test]
    fn test_mailbox_refusals() {
        assert!(Mailbox::parse("Doe, Jane <j@example.com>").is_err());
        assert!(Mailbox::parse("Jane (x) <j@example.com>").is_err());
        assert!(matches!(
            Mailbox::parse("Jane\r\nBcc: v@x <j@example.com>"),
            Err(AddressError::ControlCharacter { .. })
        ));
        assert!(Mailbox::parse("Jane <j@example.com").is_err());
        assert!(Mailbox::parse("Jane <j@example.com> trailing").is_err());
        assert!(Mailbox::new(Some("a\nb"), Address::parse("a@b.example").unwrap()).is_err());
    }

    #[test]
    fn test_mailbox_display_quotes_and_encodes() {
        let a = Address::parse("j@example.com").unwrap();
        assert_eq!(
            Mailbox::new(Some("Jane Doe"), a.clone())
                .unwrap()
                .to_string(),
            "Jane Doe <j@example.com>"
        );
        assert_eq!(
            Mailbox::new(Some("Doe, Jane"), a.clone())
                .unwrap()
                .to_string(),
            "\"Doe, Jane\" <j@example.com>"
        );
        assert_eq!(
            Mailbox::new(Some("a\"b"), a.clone()).unwrap().to_string(),
            "\"a\\\"b\" <j@example.com>"
        );
        assert_eq!(
            Mailbox::new(Some("Jos\u{e9}"), a.clone())
                .unwrap()
                .to_string(),
            "=?UTF-8?Q?Jos=C3=A9?= <j@example.com>"
        );
        assert!(
            Mailbox::new(Some("=?utf-8?q?x?="), a.clone())
                .unwrap()
                .to_string()
                .starts_with("=?UTF-8?Q?")
        );
        assert_eq!(
            Mailbox::new(None, a.clone()).unwrap().to_string(),
            "j@example.com"
        );
        assert_eq!(Mailbox::new(Some("  "), a).unwrap().display_name(), None);
    }
}
