//! Envelopes and prepared messages: the bytes that are sent, with the SMTP
//! envelope they are sent under.

use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::{
    address::Address,
    error::{BuildError, Error},
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
    from: Option<Address>,
    recipients: Vec<Address>,
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
        if to.is_empty() {
            return Err(BuildError::NoRecipients.into());
        }
        let mut recipients: Vec<Address> = Vec::with_capacity(to.len());
        for a in to {
            if !recipients.iter().any(|r| r.same_mailbox(a)) {
                recipients.push(a.clone());
            }
        }
        if recipients.len() > usize::from(limit) {
            return Err(BuildError::TooManyRecipients { limit }.into());
        }
        Ok(Envelope { from, recipients })
    }

    /// The reverse-path; `None` is the null sender `<>`.
    #[must_use]
    pub fn from(&self) -> Option<&Address> {
        self.from.as_ref()
    }

    /// The forward-paths, in order.
    #[must_use]
    pub fn recipients(&self) -> &[Address] {
        &self.recipients
    }

    /// Replaces the reverse-path: the address bounces go to, distinct from From.
    #[must_use]
    pub fn return_path(mut self, address: Address) -> Envelope {
        self.from = Some(address);
        self
    }

    /// True when an envelope address is not ASCII (needs SMTPUTF8).
    #[must_use]
    pub fn needs_smtputf8(&self) -> bool {
        self.from.as_ref().is_some_and(Address::needs_smtputf8)
            || self.recipients.iter().any(Address::needs_smtputf8)
    }
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("from", &self.from)
            .field("recipients", &self.recipients)
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
        while i < b.len() {
            let c = b.get(i).copied().unwrap_or(0);
            match c {
                b'\r' => {
                    if b.get(i + 1) != Some(&b'\n') {
                        return Err(BuildError::BareCarriageReturn { position: i as u64 }.into());
                    }
                    let text = b.get(line_start..i).unwrap_or(&[]);
                    if text.len() > 998 {
                        return Err(BuildError::LineTooLong { line }.into());
                    }
                    if header_end.is_none() {
                        if text.is_empty() {
                            header_end = Some(i + 2);
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
                    i += 2;
                    line_start = i;
                    continue;
                }
                b'\n' => return Err(BuildError::BareLineFeed { position: i as u64 }.into()),
                0x80..=0xff => {
                    eight_bit = true;
                    if header_end.is_none() {
                        header_8bit = true;
                    }
                }
                _ => {}
            }
            i += 1;
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
            .return_path(Address::parse("bounce@example.com").unwrap());
        assert_eq!(e.from().unwrap().as_str(), "bounce@example.com");
    }
}
