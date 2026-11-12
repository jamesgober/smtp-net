//! Envelopes and prepared messages: the bytes that are sent, with the SMTP
//! envelope they are sent under.

use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::{
    address::Address,
    error::{BuildError, Error, PayloadError},
};

/// Default most recipients in an envelope (RFC 5321 4.5.3.1.8).
const DEFAULT_MAX_RECIPIENTS: u16 = 100;

/// The SMTP envelope: the reverse-path (`MAIL FROM`) and the forward-paths
/// (`RCPT TO`).
///
/// # Examples
///
/// ```
/// use smtp_net::{Address, Envelope};
/// let to = [Address::parse("a@example.org")?, Address::parse("A@EXAMPLE.ORG")?, Address::parse("a@Example.org")?];
/// let env = Envelope::new(Address::parse("bounces@example.com")?, &to)?;
/// assert_eq!(env.recipients().len(), 2); // the same mailbox once, local parts compared exactly
/// # Ok::<(), smtp_net::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Shared: the session and each transaction clone the envelope, which
    /// is then a reference-count increment, not a copy of every address.
    data: alloc::sync::Arc<EnvelopeData>,
}

#[derive(Clone, PartialEq, Eq)]
struct EnvelopeData {
    from: Option<Address>,
    recipients: Vec<Address>,
    dsn: Option<Dsn>,
}

/// What a delivery status notification returns (RFC 3461 4.3).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DsnReturn {
    /// The whole message (`RET=FULL`).
    Full,
    /// The headers only (`RET=HDRS`).
    Headers,
}

/// When notifications are wanted (RFC 3461 4.1): never, or any of success,
/// failure, delay.
///
/// # Examples
///
/// ```
/// use smtp_net::DsnNotify;
/// let n = DsnNotify::FAILURE | DsnNotify::DELAY;
/// assert!(n.failure() && n.delay() && !n.success());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DsnNotify(u8);

impl DsnNotify {
    /// `NOTIFY=NEVER`.
    pub const NEVER: DsnNotify = DsnNotify(0);
    /// Notify on success.
    pub const SUCCESS: DsnNotify = DsnNotify(1);
    /// Notify on failure.
    pub const FAILURE: DsnNotify = DsnNotify(2);
    /// Notify on delay.
    pub const DELAY: DsnNotify = DsnNotify(4);

    /// True for success notifications.
    #[must_use]
    pub const fn success(self) -> bool {
        self.0 & 1 != 0
    }

    /// True for failure notifications.
    #[must_use]
    pub const fn failure(self) -> bool {
        self.0 & 2 != 0
    }

    /// True for delay notifications.
    #[must_use]
    pub const fn delay(self) -> bool {
        self.0 & 4 != 0
    }

    pub(crate) const fn bits(self) -> u8 {
        self.0
    }
}

impl core::ops::BitOr for DsnNotify {
    type Output = DsnNotify;
    fn bitor(self, rhs: DsnNotify) -> DsnNotify {
        DsnNotify(self.0 | rhs.0)
    }
}

/// Whether DSN parameters are required or sent only when offered.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum DsnPolicy {
    /// Send the parameters when the server offers DSN, omit them otherwise.
    #[default]
    IfSupported,
    /// Refuse to send (permanent `ExtensionRequired(Dsn)`) when DSN is not offered.
    Required,
}

/// RFC 3461 delivery status notification parameters.
///
/// # Examples
///
/// ```
/// use smtp_net::{Dsn, DsnNotify, DsnReturn};
/// let dsn = Dsn::new(DsnNotify::FAILURE | DsnNotify::DELAY).with_return_content(DsnReturn::Headers).with_envelope_id("order-1234")?;
/// assert_eq!(dsn.envelope_id(), Some("order-1234"));
/// assert!(Dsn::new(DsnNotify::NEVER).with_envelope_id(&"x".repeat(101)).is_err());
/// # Ok::<(), smtp_net::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dsn {
    ret: Option<DsnReturn>,
    envelope_id: Option<String>,
    notify: DsnNotify,
    policy: DsnPolicy,
}

/// Recipients up to this many are deduplicated by a scan (no allocation);
/// more go through a sorted set.
const SCAN_DEDUP: usize = 32;

/// Longest ENVID on the wire, in characters, after xtext encoding (RFC
/// 3461 4.4: "The ENVID parameter MAY be up to 100 characters").
const MAX_ENVID: usize = 100;

/// The length of `value` as xtext: `+XX` for `+`, `=`, and octets outside
/// 33 to 126, one character for every other octet.
pub(crate) fn xtext_len(value: &[u8]) -> usize {
    value
        .iter()
        .map(|&b| {
            if (33..=126).contains(&b) && b != b'+' && b != b'=' {
                1
            } else {
                3
            }
        })
        .sum()
}

impl Dsn {
    /// DSN parameters with `notify` on every recipient, no `RET`, no `ENVID`,
    /// policy `IfSupported`.
    #[must_use]
    pub fn new(notify: DsnNotify) -> Dsn {
        Dsn {
            ret: None,
            envelope_id: None,
            notify,
            policy: DsnPolicy::IfSupported,
        }
    }

    /// Sets `RET`: what a failure notice carries.
    #[must_use]
    pub fn with_return_content(mut self, ret: DsnReturn) -> Dsn {
        self.ret = Some(ret);
        self
    }

    /// Sets `ENVID`: printable ASCII, at most 100 characters as sent. The
    /// value goes out as xtext, where `+`, `=`, and a space take three
    /// characters each, so an id of 100 characters with any of them is
    /// refused (RFC 3461 4.4).
    ///
    /// # Errors
    ///
    /// `Build(InvalidDsn)`.
    pub fn with_envelope_id(mut self, id: &str) -> Result<Dsn, Error> {
        if id.is_empty()
            || xtext_len(id.as_bytes()) > MAX_ENVID
            || !id.bytes().all(|b| (32..127).contains(&b))
        {
            return Err(BuildError::InvalidDsn.into());
        }
        self.envelope_id = Some(String::from(id));
        Ok(self)
    }

    /// Sets the policy: [`DsnPolicy::Required`] fails the send when the
    /// server does not offer DSN, instead of sending without it.
    #[must_use]
    pub fn with_policy(mut self, policy: DsnPolicy) -> Dsn {
        self.policy = policy;
        self
    }

    /// The `RET` value.
    #[must_use]
    pub fn return_content(&self) -> Option<DsnReturn> {
        self.ret
    }

    /// The `ENVID` value.
    #[must_use]
    pub fn envelope_id(&self) -> Option<&str> {
        self.envelope_id.as_deref()
    }

    /// The `NOTIFY` value.
    #[must_use]
    pub fn notify(&self) -> DsnNotify {
        self.notify
    }

    /// The policy.
    #[must_use]
    pub fn policy(&self) -> DsnPolicy {
        self.policy
    }
}

/// Appends `value` as RFC 3461 xtext: `+XX` for `+`, `=`, and octets outside 33 to 126.
pub(crate) fn xtext(value: &[u8], out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in value {
        if (33..=126).contains(&b) && b != b'+' && b != b'=' {
            out.push(b);
        } else {
            out.push(b'+');
            out.push(HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'));
            out.push(HEX.get(usize::from(b & 15)).copied().unwrap_or(b'0'));
        }
    }
}

impl Envelope {
    /// An explicit envelope; recipients deduplicated (exact local part,
    /// ASCII-case-insensitive domain), at most 100.
    ///
    /// # Errors
    ///
    /// `Build(NoRecipients)`, `Build(TooManyRecipients)`.
    pub fn new(from: Address, to: &[Address]) -> Result<Envelope, Error> {
        Envelope::with_limit(Some(from), to, DEFAULT_MAX_RECIPIENTS)
    }

    pub(crate) fn with_limit(
        from: Option<Address>,
        to: &[Address],
        limit: u16,
    ) -> Result<Envelope, Error> {
        Envelope::from_refs(from, to.iter(), limit)
    }

    /// Deduplicates `to` (by mailbox, as `Address::same_mailbox`) while
    /// copying each address once.
    pub(crate) fn from_refs<'a>(
        from: Option<Address>,
        to: impl ExactSizeIterator<Item = &'a Address>,
        limit: u16,
    ) -> Result<Envelope, Error> {
        if to.len() == 0 {
            return Err(BuildError::NoRecipients.into());
        }
        let mut recipients: Vec<Address> = Vec::with_capacity(to.len());
        if to.len() <= SCAN_DEDUP {
            for a in to {
                if !recipients.iter().any(|r| r.same_mailbox(a)) {
                    recipients.push(a.clone());
                }
            }
        } else {
            // Many recipients (a decoded payload may hold 65,535): a sorted
            // set keeps this O(n log n), where the scan would be O(n^2).
            let mut seen = alloc::collections::BTreeSet::new();
            for a in to {
                let key = (
                    String::from(a.local_part()),
                    a.domain().as_str().to_ascii_lowercase(),
                );
                if seen.insert(key) {
                    recipients.push(a.clone());
                }
            }
        }
        if recipients.len() > usize::from(limit) {
            return Err(BuildError::TooManyRecipients { limit }.into());
        }
        Ok(Envelope {
            data: alloc::sync::Arc::new(EnvelopeData {
                from,
                recipients,
                dsn: None,
            }),
        })
    }

    /// The reverse-path, where bounces go; `None` is the null sender `<>`.
    #[must_use]
    pub fn return_path(&self) -> Option<&Address> {
        self.data.from.as_ref()
    }

    /// The forward-paths, in order.
    #[must_use]
    pub fn recipients(&self) -> &[Address] {
        &self.data.recipients
    }

    /// Replaces the reverse-path: the address bounces go to, distinct from From.
    #[must_use]
    pub fn with_return_path(mut self, address: Address) -> Envelope {
        alloc::sync::Arc::make_mut(&mut self.data).from = Some(address);
        self
    }

    /// The null reverse-path `MAIL FROM:<>`, for bounces and auto-replies
    /// (never derived from a message).
    ///
    /// # Errors
    ///
    /// `Build(NoRecipients)`, `Build(TooManyRecipients)`.
    pub fn null_sender(to: &[Address]) -> Result<Envelope, Error> {
        Envelope::with_limit(None, to, DEFAULT_MAX_RECIPIENTS)
    }

    /// Adds DSN parameters (RFC 3461).
    #[must_use]
    pub fn with_dsn(mut self, dsn: Dsn) -> Envelope {
        alloc::sync::Arc::make_mut(&mut self.data).dsn = Some(dsn);
        self
    }

    /// The DSN parameters, when set.
    #[must_use]
    pub fn dsn(&self) -> Option<&Dsn> {
        self.data.dsn.as_ref()
    }

    /// A copy with only the recipients at `indices` (a further transaction
    /// for recipients the server deferred).
    #[cfg_attr(not(feature = "client"), allow(dead_code))]
    pub(crate) fn subset(&self, indices: &[usize]) -> Envelope {
        Envelope {
            data: alloc::sync::Arc::new(EnvelopeData {
                from: self.data.from.clone(),
                recipients: indices
                    .iter()
                    .filter_map(|&i| self.data.recipients.get(i).cloned())
                    .collect(),
                dsn: self.data.dsn.clone(),
            }),
        }
    }

    /// True when an envelope address is not ASCII (needs SMTPUTF8).
    #[must_use]
    pub fn needs_smtputf8(&self) -> bool {
        self.data.from.as_ref().is_some_and(Address::needs_smtputf8)
            || self.data.recipients.iter().any(Address::needs_smtputf8)
    }
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("from", &self.data.from)
            .field("recipients", &self.data.recipients)
            .field("dsn", &self.data.dsn)
            .finish()
    }
}

/// An envelope and the final message bytes, sent as they are (never
/// re-serialized or re-signed).
///
/// # Examples
///
/// ```
/// use smtp_net::{Address, Envelope, PreparedMessage};
/// let env = Envelope::new(Address::parse("a@example.com")?, &[Address::parse("b@example.org")?])?;
/// let raw = b"From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n".to_vec();
/// let p = PreparedMessage::from_raw(env.clone(), raw)?;
/// assert!(!p.has_8bit());
/// assert!(PreparedMessage::from_raw(env, b"From: a@example.com\n\nbare LF\n".to_vec()).is_err());
/// # Ok::<(), smtp_net::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedMessage {
    envelope: Envelope,
    bytes: Vec<u8>,
    message_id: Option<String>,
    smtputf8: bool,
    eight_bit: bool,
}

impl PreparedMessage {
    pub(crate) fn from_parts(
        envelope: Envelope,
        bytes: Vec<u8>,
        message_id: Option<String>,
        smtputf8: bool,
        eight_bit: bool,
    ) -> PreparedMessage {
        PreparedMessage {
            envelope,
            bytes,
            message_id,
            smtputf8,
            eight_bit,
        }
    }

    /// Wraps RFC 5322 bytes not built by smtp-net after checking them: CRLF
    /// line endings only (no bare CR or LF, T-4), every line at most 998
    /// octets, a header block ending in an empty line, a From header. The
    /// flags (8-bit content, UTF-8 headers) are computed in the same scan.
    ///
    /// # Errors
    ///
    /// `Build(BareLineFeed)`, `Build(BareCarriageReturn)`, `Build(LineTooLong)`,
    /// `Build(NoHeaderBlock)`, `Build(MissingFrom)`.
    pub fn from_raw(envelope: Envelope, rfc5322: Vec<u8>) -> Result<PreparedMessage, Error> {
        let mut line = 1u64;
        let mut line_start = 0usize;
        let mut header_end = None;
        let mut from = false;
        let mut message_id = None;
        let mut eight_bit = false;
        let mut header_8bit = false;
        let b = &rfc5322;
        let mut i = 0usize;
        // Line by line: the next CR or LF and the 8-bit check are word-at-a-
        // time scans (PLAN 11.3 item 4).
        while let Some(rest) = b.get(i..).filter(|r| !r.is_empty()) {
            let k = crate::scan::find_line_end(rest).unwrap_or(rest.len());
            let text = rest.get(..k).unwrap_or(&[]);
            if !crate::scan::is_ascii(text) {
                eight_bit = true;
                if header_end.is_none() {
                    header_8bit = true;
                }
            }
            match rest.get(k) {
                None => break,
                Some(b'\n') => {
                    return Err(BuildError::BareLineFeed {
                        position: (i + k) as u64,
                    }
                    .into());
                }
                Some(_) if rest.get(k + 1) != Some(&b'\n') => {
                    return Err(BuildError::BareCarriageReturn {
                        position: (i + k) as u64,
                    }
                    .into());
                }
                Some(_) => {}
            }
            if text.len() > 998 {
                return Err(BuildError::LineTooLong { line }.into());
            }
            if header_end.is_none() {
                if text.is_empty() {
                    header_end = Some(i + k + 2);
                } else {
                    if starts_with_name(text, b"from") {
                        from = true;
                    }
                    if message_id.is_none() && starts_with_name(text, b"message-id") {
                        message_id = extract_id(text);
                    }
                }
            }
            line += 1;
            i += k + 2;
            line_start = i;
        }
        if b.len() - line_start > 998 {
            return Err(BuildError::LineTooLong { line }.into());
        }
        if header_end.is_none() || line_start == 0 && header_end.is_none() {
            return Err(BuildError::NoHeaderBlock.into());
        }
        if !from {
            return Err(BuildError::MissingFrom.into());
        }
        let smtputf8 = header_8bit || envelope.needs_smtputf8();
        Ok(PreparedMessage {
            envelope,
            bytes: rfc5322,
            message_id,
            smtputf8,
            eight_bit,
        })
    }

    /// The envelope.
    #[must_use]
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// The message bytes, as sent (before dot-stuffing).
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The `Message-ID` without angle brackets, when the message has one.
    #[must_use]
    pub fn message_id(&self) -> Option<&str> {
        self.message_id.as_deref()
    }

    /// True when an address or a header needs SMTPUTF8.
    #[must_use]
    pub fn needs_smtputf8(&self) -> bool {
        self.smtputf8
    }

    /// True when the message has octets above 127 (needs 8BITMIME or SMTPUTF8).
    #[must_use]
    pub fn has_8bit(&self) -> bool {
        self.eight_bit
    }

    /// Adds a `DKIM-Signature` header from each signer, in the order given,
    /// in front of the message. Works on any bytes [`from_raw`](Self::from_raw)
    /// accepted, not only on messages this crate built (FR-53). The
    /// signatures are independent of each other (RFC 8463 section 6: one
    /// RSA and one Ed25519 signature is the usual pair). `now_unix` is the
    /// `t=` time. Sign once, before the payload is stored: retries send the
    /// same signed bytes.
    ///
    /// # Errors
    ///
    /// `Dkim(...)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use smtp_net::{DkimKey, DkimSigner, Message};
    /// let signer = DkimSigner::new("example.com", "s2026", DkimKey::ed25519_from_seed(&[7; 32])?)?;
    /// let msg = Message::text("no-reply@example.com", "user@example.org", "Hi", "Hello.")?;
    /// let signed = msg.prepare()?.sign(&[signer], 1_700_000_000)?;
    /// assert!(signed.bytes().starts_with(b"DKIM-Signature: v=1; a=ed25519-sha256;"));
    /// # Ok::<(), smtp_net::Error>(())
    /// ```
    ///
    /// Raw bytes from elsewhere:
    ///
    /// ```
    /// use smtp_net::{Address, DkimKey, DkimSigner, Envelope, PreparedMessage};
    /// let signer = DkimSigner::new("example.com", "s2026", DkimKey::ed25519_from_seed(&[7; 32])?)?;
    /// let env = Envelope::new(Address::parse("a@example.com")?, &[Address::parse("b@example.org")?])?;
    /// let raw = b"From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n".to_vec();
    /// let signed = PreparedMessage::from_raw(env, raw)?.sign(&[signer], 1_700_000_000)?;
    /// assert!(signed.bytes().starts_with(b"DKIM-Signature: "));
    /// # Ok::<(), smtp_net::Error>(())
    /// ```
    #[cfg(feature = "dkim")]
    pub fn sign(
        mut self,
        signers: &[crate::DkimSigner],
        now_unix: u64,
    ) -> Result<PreparedMessage, Error> {
        if signers.is_empty() {
            return Ok(self);
        }
        let mut bytes = crate::dkim::sign_all(signers, &self.bytes, now_unix)?;
        bytes.extend_from_slice(&self.bytes);
        self.bytes = bytes;
        Ok(self)
    }
}

/// Magic at the start of every job payload.
const MAGIC: &[u8; 8] = b"SMTPNET1";
/// The payload format this version writes and reads.
const FORMAT_VERSION: u8 = 1;
/// Largest message accepted from a payload (64 MiB) **[budget]**.
const MAX_PAYLOAD_MESSAGE: usize = 64 * 1024 * 1024;
/// Longest address field in a payload (an SMTP path is at most 256 octets).
const MAX_PAYLOAD_ADDRESS: usize = 256;

const FLAG_NULL_SENDER: u8 = 1;
const FLAG_DSN: u8 = 2;

impl PreparedMessage {
    /// The job payload: `SMTPNET1`, a version byte, flags, the envelope as
    /// length-prefixed fields, the message bytes, and a CRC-32C trailer.
    /// Deterministic: the same message gives the same payload.
    ///
    /// # Examples
    ///
    /// ```
    /// use smtp_net::{Address, Envelope, PreparedMessage};
    /// let env = Envelope::new(Address::parse("a@example.com")?, &[Address::parse("b@example.org")?])?;
    /// let p = PreparedMessage::from_raw(env, b"From: a@example.com\r\n\r\nhi\r\n".to_vec())?;
    /// let payload = p.encode();
    /// assert_eq!(PreparedMessage::decode(&payload)?, p);
    /// let mut bad = payload.clone();
    /// bad[20] ^= 1;
    /// assert!(PreparedMessage::decode(&bad).is_err());
    /// # Ok::<(), smtp_net::Error>(())
    /// ```
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let env = &self.envelope;
        let mut n = MAGIC.len() + 2 + 2 + 2 + 4 + 4 + self.bytes.len();
        n += env.data.from.as_ref().map_or(0, |a| a.as_str().len());
        n += env
            .data
            .recipients
            .iter()
            .map(|a| 2 + a.as_str().len())
            .sum::<usize>();
        n += env
            .data
            .dsn
            .as_ref()
            .map_or(0, |d| 4 + d.envelope_id.as_ref().map_or(0, String::len));
        let mut out = Vec::with_capacity(n);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        let mut flags = 0u8;
        if env.data.from.is_none() {
            flags |= FLAG_NULL_SENDER;
        }
        if env.data.dsn.is_some() {
            flags |= FLAG_DSN;
        }
        out.push(flags);
        put_short(
            &mut out,
            env.data
                .from
                .as_ref()
                .map_or(&b""[..], |a| a.as_str().as_bytes()),
        );
        // Envelopes hold at most u16::MAX recipients (MessageLimits is u16).
        out.extend_from_slice(
            &u16::try_from(env.data.recipients.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        for a in env.data.recipients.iter().take(usize::from(u16::MAX)) {
            put_short(&mut out, a.as_str().as_bytes());
        }
        if let Some(d) = &env.data.dsn {
            out.push(match d.ret {
                None => 0,
                Some(DsnReturn::Full) => 1,
                Some(DsnReturn::Headers) => 2,
            });
            out.push(d.notify.bits());
            out.push(u8::from(d.policy == DsnPolicy::Required));
            let id = d.envelope_id.as_deref().unwrap_or("").as_bytes();
            out.push(u8::try_from(id.len()).unwrap_or(0));
            out.extend_from_slice(
                id.get(..usize::from(u8::try_from(id.len()).unwrap_or(0)))
                    .unwrap_or(&[]),
            );
        }
        out.extend_from_slice(
            &u32::try_from(self.bytes.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.bytes);
        let crc = crate::encode::crc32c(&out);
        out.extend_from_slice(&crc.to_be_bytes());
        out
    }

    /// Reads a job payload back. Checks the magic and version, then the
    /// CRC-32C over everything before it, then every length against its
    /// budget before allocating, then validates the addresses and the
    /// message bytes again (as [`from_raw`](PreparedMessage::from_raw)
    /// does). A damaged payload is refused, never sent (T-33).
    ///
    /// # Errors
    ///
    /// `Payload(Corrupt)`, `Payload(UnknownVersion)`, `Payload(TooLarge)`,
    /// `Payload(Truncated)`, address and raw-message errors.
    pub fn decode(payload: &[u8]) -> Result<PreparedMessage, Error> {
        if payload.len() < MAGIC.len() + 2 + 4 {
            return Err(PayloadError::Truncated.into());
        }
        if payload.get(..MAGIC.len()) != Some(&MAGIC[..]) {
            return Err(PayloadError::Corrupt.into());
        }
        let version = payload.get(MAGIC.len()).copied().unwrap_or(0);
        if version != FORMAT_VERSION {
            return Err(PayloadError::UnknownVersion { version }.into());
        }
        let (body, trailer) = payload.split_at(payload.len() - 4);
        let mut crc = [0u8; 4];
        crc.copy_from_slice(trailer);
        if crate::encode::crc32c(body) != u32::from_be_bytes(crc) {
            return Err(PayloadError::Corrupt.into());
        }
        let mut r = Reader {
            b: body,
            at: MAGIC.len() + 1,
        };
        let flags = r.byte()?;
        if flags & !(FLAG_NULL_SENDER | FLAG_DSN) != 0 {
            return Err(PayloadError::Corrupt.into());
        }
        let from_raw = r.short(MAX_PAYLOAD_ADDRESS)?;
        let from = if flags & FLAG_NULL_SENDER != 0 {
            if !from_raw.is_empty() {
                return Err(PayloadError::Corrupt.into());
            }
            None
        } else {
            Some(address_of(from_raw)?)
        };
        let count = usize::from(u16::from_be_bytes([r.byte()?, r.byte()?]));
        // Each recipient needs at least 3 bytes: refuse a count the rest cannot hold.
        if count.saturating_mul(3) > r.left() {
            return Err(PayloadError::TooLarge.into());
        }
        let mut recipients = Vec::with_capacity(count);
        for _ in 0..count {
            recipients.push(address_of(r.short(MAX_PAYLOAD_ADDRESS)?)?);
        }
        let dsn = if flags & FLAG_DSN != 0 {
            let ret = match r.byte()? {
                0 => None,
                1 => Some(DsnReturn::Full),
                2 => Some(DsnReturn::Headers),
                _ => return Err(PayloadError::Corrupt.into()),
            };
            let notify = r.byte()?;
            if notify & !7 != 0 {
                return Err(PayloadError::Corrupt.into());
            }
            let policy = match r.byte()? {
                0 => DsnPolicy::IfSupported,
                1 => DsnPolicy::Required,
                _ => return Err(PayloadError::Corrupt.into()),
            };
            let id_len = usize::from(r.byte()?);
            let id = r.take(id_len)?;
            let mut d = Dsn {
                ret,
                envelope_id: None,
                notify: DsnNotify(notify),
                policy,
            };
            if !id.is_empty() {
                let id = core::str::from_utf8(id).map_err(|_| PayloadError::Corrupt)?;
                d = d.with_envelope_id(id)?;
            }
            Some(d)
        } else {
            None
        };
        let len = r.word()?;
        if len > MAX_PAYLOAD_MESSAGE {
            return Err(PayloadError::TooLarge.into());
        }
        if len != r.left() {
            return Err(if len > r.left() {
                PayloadError::Truncated
            } else {
                PayloadError::Corrupt
            }
            .into());
        }
        let bytes = r.take(len)?.to_vec();
        let mut envelope = Envelope::with_limit(from, &recipients, u16::MAX)?;
        alloc::sync::Arc::make_mut(&mut envelope.data).dsn = dsn;
        if envelope.data.recipients.len() != recipients.len() {
            return Err(PayloadError::Corrupt.into());
        }
        PreparedMessage::from_raw(envelope, bytes)
    }
}

fn put_short(out: &mut Vec<u8>, b: &[u8]) {
    let n = u16::try_from(b.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b.get(..usize::from(n)).unwrap_or(&[]));
}

fn address_of(b: &[u8]) -> Result<Address, Error> {
    let s = core::str::from_utf8(b).map_err(|_| PayloadError::Corrupt)?;
    // Literals were accepted when the envelope was made, if the caller allowed them.
    Ok(Address::parse_allowing_literal(s)?)
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn left(&self) -> usize {
        self.b.len().saturating_sub(self.at)
    }

    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        let end = self.at.checked_add(n).ok_or(PayloadError::TooLarge)?;
        let s = self.b.get(self.at..end).ok_or(PayloadError::Truncated)?;
        self.at = end;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?.first().copied().unwrap_or(0))
    }

    fn short(&mut self, max: usize) -> Result<&[u8], Error> {
        let n = usize::from(u16::from_be_bytes([self.byte()?, self.byte()?]));
        if n > max {
            return Err(PayloadError::TooLarge.into());
        }
        self.take(n)
    }

    fn word(&mut self) -> Result<usize, Error> {
        let b = self.take(4)?;
        let mut w = [0u8; 4];
        w.copy_from_slice(b);
        usize::try_from(u32::from_be_bytes(w)).map_err(|_| PayloadError::TooLarge.into())
    }
}

impl fmt::Debug for PreparedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedMessage")
            .field("envelope", &self.envelope)
            .field("len", &self.bytes.len())
            .field("message_id", &self.message_id)
            .finish()
    }
}

fn starts_with_name(line: &[u8], name: &[u8]) -> bool {
    line.len() > name.len()
        && line
            .get(..name.len())
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
        && line.get(name.len()) == Some(&b':')
}

fn extract_id(line: &[u8]) -> Option<String> {
    let lt = line.iter().position(|&b| b == b'<')?;
    let gt = line.iter().rposition(|&b| b == b'>')?;
    let inner = core::str::from_utf8(line.get(lt + 1..gt)?).ok()?;
    super::id::split_msg_id(inner).map(|_| String::from(inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Envelope {
        Envelope::new(
            Address::parse("a@example.com").unwrap(),
            &[Address::parse("b@example.org").unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn test_from_raw_smuggling_sequences_refused() {
        for raw in [
            &b"From: a@x\r\n\r\nx\n.\nmore\r\n"[..],
            b"From: a@x\r\n\r\nx\r.\rmore\r\n",
            b"From: a@x\r\n\r\nx\r\n.\nmore\r\n",
            b"From: a@x\r\n\r\nx\n.\r\nmore\r\n",
        ] {
            assert!(
                PreparedMessage::from_raw(env(), raw.to_vec()).is_err(),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn test_from_raw_structure_checks() {
        assert!(matches!(
            PreparedMessage::from_raw(env(), b"Subject: x\r\n\r\nbody".to_vec())
                .unwrap_err()
                .kind(),
            crate::ErrorKind::Build(BuildError::MissingFrom)
        ));
        assert!(matches!(
            PreparedMessage::from_raw(env(), b"From: a@x\r\nno blank line".to_vec())
                .unwrap_err()
                .kind(),
            crate::ErrorKind::Build(BuildError::NoHeaderBlock)
        ));
        let long = [&b"From: a@x\r\n\r\n"[..], &[b'x'; 999]].concat();
        assert!(matches!(
            PreparedMessage::from_raw(env(), long).unwrap_err().kind(),
            crate::ErrorKind::Build(BuildError::LineTooLong { line: 3 })
        ));
        let ok = [&b"From: a@x\r\n\r\n"[..], &[b'x'; 998]].concat();
        assert!(PreparedMessage::from_raw(env(), ok).is_ok());
    }

    #[test]
    fn test_from_raw_flags_and_message_id() {
        let p = PreparedMessage::from_raw(
            env(),
            b"FROM: a@x\r\nMessage-ID: <id.1@x.example>\r\n\r\ncaf\xc3\xa9\r\n".to_vec(),
        )
        .unwrap();
        assert_eq!(p.message_id(), Some("id.1@x.example"));
        assert!(p.has_8bit());
        assert!(!p.needs_smtputf8());
        let p =
            PreparedMessage::from_raw(env(), b"From: J\xc3\xb6rg <a@x>\r\n\r\nx".to_vec()).unwrap();
        assert!(p.needs_smtputf8());
    }

    #[test]
    fn test_envelope_dedup_and_limits() {
        let a = Address::parse("x@example.org").unwrap();
        assert!(Envelope::new(a.clone(), &[]).is_err());
        let many: Vec<Address> = (0..101)
            .map(|i| Address::parse(&alloc::format!("u{i}@example.org")).unwrap())
            .collect();
        assert!(Envelope::new(a.clone(), &many).is_err());
        assert!(Envelope::new(a.clone(), &many[..100]).is_ok());
        let e = Envelope::new(a.clone(), core::slice::from_ref(&a))
            .unwrap()
            .with_return_path(Address::parse("bounce@example.com").unwrap());
        assert_eq!(e.return_path().unwrap().as_str(), "bounce@example.com");
    }

    fn sample() -> PreparedMessage {
        let to = [
            Address::parse("b@example.org").unwrap(),
            Address::parse("c@example.org").unwrap(),
        ];
        let env = Envelope::new(Address::parse("a@example.com").unwrap(), &to)
            .unwrap()
            .with_dsn(
                Dsn::new(DsnNotify::FAILURE)
                    .with_return_content(DsnReturn::Full)
                    .with_envelope_id("x")
                    .unwrap(),
            );
        PreparedMessage::from_raw(
            env,
            b"From: a@example.com\r\nMessage-ID: <m.1@example.com>\r\n\r\nhi\r\n".to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn test_payload_round_trip_is_identity_and_deterministic() {
        let p = sample();
        let a = p.encode();
        assert_eq!(a, p.encode());
        assert_eq!(PreparedMessage::decode(&a).unwrap(), p);
        let null = PreparedMessage::from_raw(
            Envelope::null_sender(&[Address::parse("b@example.org").unwrap()]).unwrap(),
            b"From: x@y\r\n\r\n".to_vec(),
        )
        .unwrap();
        assert_eq!(PreparedMessage::decode(&null.encode()).unwrap(), null);
    }

    #[test]
    fn test_payload_every_bit_flip_refused() {
        // T-33: a damaged job payload is refused, never sent.
        let payload = sample().encode();
        for byte in 0..payload.len() {
            for bit in 0..8 {
                let mut bad = payload.clone();
                bad[byte] ^= 1 << bit;
                assert!(
                    PreparedMessage::decode(&bad).is_err(),
                    "byte {byte} bit {bit}"
                );
            }
        }
    }

    #[test]
    fn test_payload_truncated_at_every_byte_and_bad_headers() {
        let payload = sample().encode();
        for n in 0..payload.len() {
            assert!(
                PreparedMessage::decode(&payload[..n]).is_err(),
                "truncated at {n}"
            );
        }
        assert!(matches!(
            PreparedMessage::decode(b"").unwrap_err().kind(),
            crate::ErrorKind::Payload(PayloadError::Truncated)
        ));
        let mut wrong_magic = payload.clone();
        wrong_magic[0] = b'X';
        assert!(matches!(
            PreparedMessage::decode(&wrong_magic).unwrap_err().kind(),
            crate::ErrorKind::Payload(PayloadError::Corrupt)
        ));
        let mut v2 = payload.clone();
        v2[8] = 2;
        assert!(matches!(
            PreparedMessage::decode(&v2).unwrap_err().kind(),
            crate::ErrorKind::Payload(PayloadError::UnknownVersion { version: 2 })
        ));
    }

    #[test]
    fn test_payload_oversized_lengths_refused_before_allocation() {
        // A recipient count the payload cannot hold, with a valid checksum.
        let mut body = MAGIC.to_vec();
        body.push(FORMAT_VERSION);
        body.push(0);
        put_short(&mut body, b"a@example.com");
        body.extend_from_slice(&u16::MAX.to_be_bytes());
        let crc = crate::encode::crc32c(&body);
        body.extend_from_slice(&crc.to_be_bytes());
        assert!(matches!(
            PreparedMessage::decode(&body).unwrap_err().kind(),
            crate::ErrorKind::Payload(PayloadError::TooLarge)
        ));
    }

    #[test]
    fn test_many_recipients_dedup_like_the_scan_and_round_trip() {
        // Past 32 recipients the set is used; it must agree with the
        // scan (local part exact, domain case ignored), and a payload of
        // 20,000 recipients decodes.
        let mut to: Vec<Address> = (0..20_000)
            .map(|i| Address::parse(&alloc::format!("u{i}@example.org")).unwrap())
            .collect();
        to.push(Address::parse("u7@EXAMPLE.org").unwrap());
        to.push(Address::parse("U7@example.org").unwrap());
        let from = Address::parse("a@example.com").unwrap();
        let env = Envelope::with_limit(Some(from.clone()), &to, u16::MAX).unwrap();
        assert_eq!(env.recipients().len(), 20_001);
        assert!(
            env.recipients()
                .iter()
                .any(|a| a.as_str() == "U7@example.org")
        );
        let few = [to[7].clone(), to[20_000].clone(), to[20_001].clone()];
        let small = Envelope::with_limit(Some(from), &few, u16::MAX).unwrap();
        assert_eq!(small.recipients().len(), 2);
        let raw = b"From: a@example.com\r\nSubject: x\r\n\r\nbody\r\n".to_vec();
        let p = PreparedMessage::from_raw(env, raw).unwrap();
        let back = PreparedMessage::decode(&p.encode()).unwrap();
        assert_eq!(back.envelope().recipients().len(), 20_001);
    }

    #[test]
    fn test_xtext_encoding() {
        let mut out = Vec::new();
        xtext(b"a+b=c d\x01~", &mut out);
        assert_eq!(out, b"a+2Bb+3Dc+20d+01~");
        assert_eq!(xtext_len(b"a+b=c d\x01~"), out.len());
    }

    #[test]
    fn test_dsn_envelope_id_rules() {
        assert!(Dsn::new(DsnNotify::NEVER).with_envelope_id("").is_err());
        assert!(
            Dsn::new(DsnNotify::NEVER)
                .with_envelope_id(&"x".repeat(100))
                .is_ok()
        );
        assert!(
            Dsn::new(DsnNotify::NEVER)
                .with_envelope_id(&"x".repeat(101))
                .is_err()
        );
        // Measured as sent: 34 plus signs are 102 characters of xtext.
        assert!(
            Dsn::new(DsnNotify::NEVER)
                .with_envelope_id(&"+".repeat(33))
                .is_ok()
        );
        assert!(
            Dsn::new(DsnNotify::NEVER)
                .with_envelope_id(&"+".repeat(34))
                .is_err()
        );
        assert!(
            Dsn::new(DsnNotify::NEVER)
                .with_envelope_id("caf\u{e9}")
                .is_err()
        );
        assert!(
            Dsn::new(DsnNotify::NEVER)
                .with_envelope_id("a\r\nb")
                .is_err()
        );
    }
}
