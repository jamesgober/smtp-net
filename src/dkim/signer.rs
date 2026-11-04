//! The DKIM signer (RFC 6376 sections 3.5, 3.7, and 5; RFC 8463).

use alloc::string::String;
use alloc::vec::Vec;

use crypt_io::hash::Sha256Hasher;

use super::canon::{BodyCanonicalizer, Canonicalization, HeaderCanonicalizer};
use super::key::DkimKey;
use crate::address::{Address, Domain};
use crate::encode::base64_append;
use crate::error::DkimError;

/// Headers signed when present, in this order (PLAN 7.10).
const DEFAULT_HEADERS: [&str; 14] = [
    "from",
    "to",
    "cc",
    "subject",
    "date",
    "message-id",
    "reply-to",
    "in-reply-to",
    "references",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "list-unsubscribe",
    "list-unsubscribe-post",
];

/// Headers listed once more than they occur, so one added in transit breaks
/// the signature (RFC 6376 section 5.4.2; T-20).
const DEFAULT_OVERSIGN: [&str; 7] = [
    "from",
    "to",
    "cc",
    "subject",
    "date",
    "reply-to",
    "message-id",
];

/// Largest header block signed (64 KiB) **[budget]**.
pub(crate) const MAX_HEADER_BLOCK: usize = 64 * 1024;

/// Lines of the signature header are kept to this many characters.
const WIDTH: usize = 78;

/// Signs messages for one domain and selector.
///
/// Defaults: relaxed/relaxed canonicalization; the headers of PLAN 7.10
/// signed when present (From always); From, To, Cc, Subject, Date, Reply-To,
/// and Message-ID oversigned; `t=` set; no `x=`, no `i=`. `l=` (body
/// length) is never written, nor `rsa-sha1` (RFC 8301 section 3.1).
///
/// # Examples
///
/// ```
/// use smtp_net::{DkimKey, DkimSigner};
/// let key = DkimKey::ed25519_from_seed(&[7; 32])?;
/// let signer = DkimSigner::new("example.com", "mail2026", key)?;
/// let header = signer.sign(b"From: a@example.com\r\nSubject: hi\r\n\r\nHello.\r\n", 1_700_000_000)?;
/// assert!(header.starts_with("DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;"));
/// assert!(header.ends_with("\r\n"));
/// # Ok::<(), smtp_net::DkimError>(())
/// ```
#[derive(Clone, Debug)]
pub struct DkimSigner {
    domain: String,
    selector: String,
    key: DkimKey,
    header_canon: Canonicalization,
    body_canon: Canonicalization,
    headers: Vec<String>,
    oversign: Vec<String>,
    expiry: Option<u32>,
    identity: Option<String>,
}

impl DkimSigner {
    /// A signer for `domain` (`d=`) and `selector` (`s=`); the public key
    /// is published at `<selector>._domainkey.<domain>`.
    ///
    /// # Errors
    ///
    /// [`DkimError::InvalidDomain`] (not an ASCII domain name; publish IDNs
    /// in their `xn--` form), [`DkimError::InvalidSelector`].
    pub fn new(domain: &str, selector: &str, key: DkimKey) -> Result<DkimSigner, DkimError> {
        let d = Domain::parse(domain).map_err(|_| DkimError::InvalidDomain)?;
        if !d.is_ascii() || d.is_literal() {
            return Err(DkimError::InvalidDomain);
        }
        if !valid_selector(selector) {
            return Err(DkimError::InvalidSelector);
        }
        Ok(DkimSigner {
            domain: domain.to_ascii_lowercase(),
            selector: String::from(selector),
            key,
            header_canon: Canonicalization::Relaxed,
            body_canon: Canonicalization::Relaxed,
            headers: DEFAULT_HEADERS.iter().map(|s| String::from(*s)).collect(),
            oversign: DEFAULT_OVERSIGN.iter().map(|s| String::from(*s)).collect(),
            expiry: None,
            identity: None,
        })
    }

    /// Header and body canonicalization (`c=`).
    #[must_use]
    pub fn canonicalization(mut self, header: Canonicalization, body: Canonicalization) -> Self {
        self.header_canon = header;
        self.body_canon = body;
        self
    }

    /// Replaces the list of headers signed when present. From is always
    /// signed, even when left out.
    ///
    /// # Errors
    ///
    /// [`DkimError::InvalidHeaderName`].
    pub fn headers(mut self, names: &[&str]) -> Result<Self, DkimError> {
        let mut list = header_list(names)?;
        if !list.iter().any(|n| n == "from") {
            list.insert(0, String::from("from"));
        }
        self.headers = list;
        Ok(self)
    }

    /// Replaces the list of oversigned headers (an empty list turns
    /// oversigning off).
    ///
    /// # Errors
    ///
    /// [`DkimError::InvalidHeaderName`].
    pub fn oversign(mut self, names: &[&str]) -> Result<Self, DkimError> {
        self.oversign = header_list(names)?;
        Ok(self)
    }

    /// Adds `x=`: the signature expires `seconds` after it is made. Zero
    /// removes the tag.
    #[must_use]
    pub fn expiry(mut self, seconds: u32) -> Self {
        self.expiry = (seconds > 0).then_some(seconds);
        self
    }

    /// Adds `i=`, the identity the signer acts for; its domain must be
    /// `d=` or a subdomain of it (RFC 6376 section 3.5).
    ///
    /// # Errors
    ///
    /// [`DkimError::IdentityOutsideDomain`].
    pub fn identity(mut self, address: &Address) -> Result<Self, DkimError> {
        let domain = address.domain().as_str();
        let d = &self.domain;
        let inside = domain.eq_ignore_ascii_case(d)
            || (domain.len() > d.len() + 1
                && domain
                    .get(domain.len() - d.len()..)
                    .is_some_and(|tail| tail.eq_ignore_ascii_case(d))
                && domain.as_bytes().get(domain.len() - d.len() - 1) == Some(&b'.'));
        if !inside || !domain.is_ascii() {
            return Err(DkimError::IdentityOutsideDomain);
        }
        // dkim-quoted-printable (RFC 6376 section 2.11) for the local part.
        let mut value = String::new();
        for &b in address.local_part().as_bytes() {
            if (0x21..=0x7e).contains(&b) && b != b';' && b != b'=' {
                value.push(char::from(b));
            } else {
                value.push('=');
                value.push(hex_digit(b >> 4));
                value.push(hex_digit(b & 15));
            }
        }
        value.push('@');
        value.push_str(domain);
        self.identity = Some(value);
        Ok(self)
    }

    /// The signing domain (`d=`).
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The selector (`s=`).
    #[must_use]
    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// The key.
    #[must_use]
    pub fn key(&self) -> &DkimKey {
        &self.key
    }

    /// Signs `message` (RFC 5322 bytes with CRLF line ends, as they will be
    /// sent) and returns the `DKIM-Signature` header line, CRLF included,
    /// to put in front of it. `now_unix` is the `t=` time.
    ///
    /// # Errors
    ///
    /// [`DkimError::MissingFrom`], [`DkimError::HeaderBlockTooLarge`],
    /// [`DkimError::MalformedMessage`], [`DkimError::Signing`].
    pub fn sign(&self, message: &[u8], now_unix: u64) -> Result<String, DkimError> {
        let mut out = Vec::new();
        self.sign_into(message, now_unix, &mut out)?;
        Ok(String::from_utf8(out).unwrap_or_default())
    }

    /// As [`sign`](Self::sign), appending the header line to `out`.
    ///
    /// # Errors
    ///
    /// As [`sign`](Self::sign).
    pub fn sign_into(
        &self,
        message: &[u8],
        now_unix: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), DkimError> {
        let parsed = Parsed::new(message)?;
        let bh = body_hash(parsed.body(message), self.body_canon);
        self.sign_parsed(message, &parsed, &bh, now_unix, out)
    }

    fn sign_parsed(
        &self,
        message: &[u8],
        parsed: &Parsed,
        bh: &[u8; 32],
        now_unix: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), DkimError> {
        if parsed.count(message, "from") == 0 {
            return Err(DkimError::MissingFrom);
        }
        let mut h: Vec<&str> = Vec::new();
        for name in &self.headers {
            for _ in 0..parsed.count(message, name) {
                h.push(name);
            }
        }
        h.extend(self.oversign.iter().map(String::as_str));

        let start = out.len();
        let mut f = Folder::new(out, b"DKIM-Signature: ");
        f.piece(b"", b"v=1");
        f.tag(b"a=", self.key.algorithm().name().as_bytes());
        let mut c = String::from(self.header_canon.name());
        c.push('/');
        c.push_str(self.body_canon.name());
        f.tag(b"c=", c.as_bytes());
        f.tag(b"d=", self.domain.as_bytes());
        if let Some(i) = &self.identity {
            f.tag(b"i=", i.as_bytes());
        }
        f.tag(b"s=", self.selector.as_bytes());
        let mut num = itoa(now_unix);
        f.tag(b"t=", num.as_bytes());
        if let Some(x) = self.expiry {
            num = itoa(now_unix.saturating_add(u64::from(x)));
            f.tag(b"x=", num.as_bytes());
        }
        let mut first = true;
        for name in &h {
            if first {
                let mut t = Vec::with_capacity(2 + name.len());
                t.extend_from_slice(b"h=");
                t.extend_from_slice(name.as_bytes());
                f.piece(b"; ", &t);
                first = false;
            } else {
                f.piece(b":", name.as_bytes());
            }
        }
        let mut b64 = Vec::with_capacity(44);
        base64_append(bh, &mut b64);
        f.tag(b"bh=", &b64);
        // b= starts its own line; under either canonicalization the signed
        // form is everything up to and including "b=" (RFC 6376 section 3.7).
        f.out.extend_from_slice(b";\r\n b=");
        let prefix_end = f.out.len();

        let canon = HeaderCanonicalizer::new(self.header_canon);
        let mut data = Vec::with_capacity(1024);
        let mut used = alloc::vec![false; parsed.fields.len()];
        for name in &h {
            if let Some(i) = parsed.last_unused(message, name, &used) {
                if let Some(u) = used.get_mut(i) {
                    *u = true;
                }
                canon.canonicalize(parsed.field(message, i), &mut data);
            }
            // A listed name with no instance left is hashed as nothing.
        }
        canon.canonicalize(f.out.get(start..prefix_end).unwrap_or(&[]), &mut data);
        data.truncate(data.len() - 2);
        let signature = self.key.sign(&data)?;

        b64.clear();
        base64_append(&signature, &mut b64);
        let out = f.out;
        let mut col = 3;
        let mut rest = &b64[..];
        loop {
            let take = rest.len().min(WIDTH - col);
            out.extend_from_slice(rest.get(..take).unwrap_or(&[]));
            rest = rest.get(take..).unwrap_or(&[]);
            if rest.is_empty() {
                break;
            }
            out.extend_from_slice(b"\r\n ");
            col = 1;
        }
        out.extend_from_slice(b"\r\n");
        Ok(())
    }
}

/// Signs `message` with every signer and returns their headers, in the
/// order given, to put in front of it. The signatures are independent; a
/// body hash is computed once per body canonicalization.
pub(crate) fn sign_all(
    signers: &[DkimSigner],
    message: &[u8],
    now_unix: u64,
) -> Result<Vec<u8>, DkimError> {
    let parsed = Parsed::new(message)?;
    let mut hashes: [Option<[u8; 32]>; 2] = [None, None];
    let mut out = Vec::with_capacity(signers.len() * 512);
    for s in signers {
        let slot = usize::from(s.body_canon == Canonicalization::Relaxed);
        let bh = match hashes.get(slot).copied().flatten() {
            Some(bh) => bh,
            None => {
                let bh = body_hash(parsed.body(message), s.body_canon);
                if let Some(h) = hashes.get_mut(slot) {
                    *h = Some(bh);
                }
                bh
            }
        };
        s.sign_parsed(message, &parsed, &bh, now_unix, &mut out)?;
    }
    Ok(out)
}

fn hex_digit(n: u8) -> char {
    char::from(
        b"0123456789ABCDEF"
            .get(usize::from(n))
            .copied()
            .unwrap_or(b'0'),
    )
}

fn itoa(n: u64) -> String {
    let mut s = String::new();
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{n}"));
    s
}

fn body_hash(body: &[u8], mode: Canonicalization) -> [u8; 32] {
    let mut h = Sha256Hasher::new();
    let mut c = BodyCanonicalizer::new(mode);
    c.update(body, &mut |b| {
        h.update(b);
    });
    c.finish(&mut |b| {
        h.update(b);
    });
    h.finalize()
}

fn valid_selector(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
                && b.first() != Some(&b'-')
                && b.last() != Some(&b'-')
        })
}

fn valid_field_name(n: &[u8]) -> bool {
    !n.is_empty() && n.len() <= 76 && n.iter().all(|&c| (33..=126).contains(&c) && c != b':')
}

fn header_list(names: &[&str]) -> Result<Vec<String>, DkimError> {
    let mut list: Vec<String> = Vec::with_capacity(names.len());
    for n in names {
        if !valid_field_name(n.as_bytes()) {
            return Err(DkimError::InvalidHeaderName);
        }
        let n = n.to_ascii_lowercase();
        if !list.contains(&n) {
            list.push(n);
        }
    }
    Ok(list)
}

/// Writes tags, folding with CRLF SP before a piece that would pass WIDTH.
struct Folder<'a> {
    out: &'a mut Vec<u8>,
    col: usize,
}

impl<'a> Folder<'a> {
    fn new(out: &'a mut Vec<u8>, name: &[u8]) -> Folder<'a> {
        out.extend_from_slice(name);
        Folder {
            out,
            col: name.len(),
        }
    }

    fn tag(&mut self, name: &[u8], value: &[u8]) {
        let mut t = Vec::with_capacity(name.len() + value.len());
        t.extend_from_slice(name);
        t.extend_from_slice(value);
        self.piece(b"; ", &t);
    }

    fn piece(&mut self, sep: &[u8], text: &[u8]) {
        // One column stays free for the separator that may follow.
        if self.col + sep.len() + text.len() + 1 > WIDTH && self.col > 1 {
            self.out
                .extend_from_slice(sep.strip_suffix(b" ").unwrap_or(sep));
            self.out.extend_from_slice(b"\r\n ");
            self.col = 1;
        } else {
            self.out.extend_from_slice(sep);
            self.col += sep.len();
        }
        self.out.extend_from_slice(text);
        self.col += text.len();
    }
}

/// The header fields of a message: byte ranges, each with its CRLF.
pub(crate) struct Parsed {
    fields: Vec<(usize, usize)>,
    body_start: usize,
}

impl Parsed {
    pub(crate) fn new(message: &[u8]) -> Result<Parsed, DkimError> {
        let mut fields: Vec<(usize, usize)> = Vec::new();
        let mut pos = 0usize;
        let mut line = 1usize;
        loop {
            if pos > MAX_HEADER_BLOCK {
                return Err(DkimError::HeaderBlockTooLarge);
            }
            let rest = message.get(pos..).unwrap_or(&[]);
            let window = rest
                .get(..rest.len().min(MAX_HEADER_BLOCK + 2 - pos))
                .unwrap_or(rest);
            let Some(nl) = window.iter().position(|&c| c == b'\n') else {
                return Err(if rest.len() > window.len() {
                    DkimError::HeaderBlockTooLarge
                } else {
                    DkimError::MalformedMessage { line }
                });
            };
            if nl == 0 || rest.get(nl - 1) != Some(&b'\r') {
                return Err(DkimError::MalformedMessage { line });
            }
            let text = rest.get(..nl - 1).unwrap_or(&[]);
            let next = pos + nl + 1;
            match text.first() {
                None => {
                    return Ok(Parsed {
                        fields,
                        body_start: next,
                    });
                }
                Some(b' ' | b'\t') => match fields.last_mut() {
                    Some(last) => last.1 = next,
                    None => return Err(DkimError::MalformedMessage { line }),
                },
                Some(_) => {
                    if text.contains(&b'\r') || !valid_field_name(name_of(text)) {
                        return Err(DkimError::MalformedMessage { line });
                    }
                    fields.push((pos, next));
                }
            }
            pos = next;
            line += 1;
        }
    }

    fn body<'m>(&self, message: &'m [u8]) -> &'m [u8] {
        message.get(self.body_start..).unwrap_or(&[])
    }

    fn field<'m>(&self, message: &'m [u8], i: usize) -> &'m [u8] {
        self.fields
            .get(i)
            .and_then(|&(s, e)| message.get(s..e))
            .unwrap_or(&[])
    }

    fn count(&self, message: &[u8], name: &str) -> usize {
        (0..self.fields.len())
            .filter(|&i| name_of(self.field(message, i)).eq_ignore_ascii_case(name.as_bytes()))
            .count()
    }

    /// The bottom-most instance of `name` not signed yet (RFC 6376 5.4.2).
    fn last_unused(&self, message: &[u8], name: &str, used: &[bool]) -> Option<usize> {
        (0..self.fields.len()).rev().find(|&i| {
            used.get(i) == Some(&false)
                && name_of(self.field(message, i)).eq_ignore_ascii_case(name.as_bytes())
        })
    }
}

/// The field name: the text before the colon, without trailing whitespace
/// (RFC 5322 obsolete syntax allows `Subject :`). No colon gives the empty name.
fn name_of(field: &[u8]) -> &[u8] {
    let Some(colon) = field.iter().position(|&c| c == b':') else {
        return &[];
    };
    let name = field.get(..colon).unwrap_or(&[]);
    let end = name
        .iter()
        .rposition(|c| !matches!(c, b' ' | b'\t'))
        .map_or(0, |p| p + 1);
    name.get(..end).unwrap_or(&[])
}

#[cfg(test)]
mod tests;
