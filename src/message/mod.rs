//! Building messages: RFC 5322 headers and RFC 2045 to 2049 MIME bodies.

pub(crate) mod header;
pub(crate) mod id;
pub(crate) mod part;
pub(crate) mod prepared;
pub(crate) mod sink;

use alloc::{string::String, vec, vec::Vec};
use core::{convert::Infallible, fmt};

use header::{HeaderBlock, HeaderName, Headers, check_header_value};
use id::RandomSource;
use part::{Attachment, Inline, Multipart, Part};
use prepared::{Envelope, PreparedMessage};
use sink::Sink;

use crate::{
    address::{Address, Mailbox},
    error::{BuildError, Error, HeaderError},
};

/// Budgets checked before allocation or encoding (T-26).
///
/// # Examples
///
/// ```
/// let mut limits = smtp_net::MessageLimits::default();
/// limits.max_recipients = 10;
/// let builder = smtp_net::Message::builder().limits(limits);
/// # let _ = builder;
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageLimits {
    /// Largest encoded message, in octets (default 25 MiB).
    pub max_message_size: u64,
    /// Most MIME parts (default 100).
    pub max_parts: u16,
    /// Deepest MIME nesting (default 8).
    pub max_depth: u8,
    /// Most custom headers (default 100).
    pub max_headers: u16,
    /// Longest header value before encoding, in octets (default 16 KiB).
    pub max_header_value: u32,
    /// Most recipients in To, Cc, and Bcc together (default 100; RFC 5321
    /// 4.5.3.1.8 requires servers to accept at least 100).
    pub max_recipients: u16,
    /// Most ids in `References` (default 50) **[est. budget]**.
    pub max_references: u16,
}

impl Default for MessageLimits {
    fn default() -> MessageLimits {
        MessageLimits {
            max_message_size: 25 * 1024 * 1024,
            max_parts: 100,
            max_depth: 8,
            max_headers: 100,
            max_header_value: 16 * 1024,
            max_recipients: 100,
            max_references: 50,
        }
    }
}

/// A validated, immutable message ready to send. `Send + Sync`.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "std")] {
/// let msg = smtp_net::Message::text(
///     "Example <no-reply@example.com>",
///     "user@example.org",
///     "Confirm your email address",
///     "Open this link to confirm: https://example.com/confirm/abc123",
/// )?;
/// let bytes = msg.to_bytes()?;
/// assert!(bytes.starts_with(b"Date: "));
/// assert_eq!(bytes.len() as u64, msg.encoded_len());
/// # }
/// # Ok::<(), smtp_net::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    head: Vec<u8>,
    headers: Headers,
    body: Part,
    message_id: String,
    from: Mailbox,
    sender: Option<Mailbox>,
    recipients: Vec<Mailbox>,
    needs_smtputf8: bool,
    has_8bit: bool,
    encoded_len: u64,
    max_recipients: u16,
}

impl Message {
    /// An empty builder with default [`MessageLimits`].
    #[must_use]
    pub fn builder() -> MessageBuilder {
        MessageBuilder::default()
    }

    /// A single-part `text/plain; charset=utf-8` message from one mailbox to
    /// one mailbox, with a generated `Date` and `Message-ID`.
    ///
    /// # Errors
    ///
    /// `Address` for an invalid mailbox, `Header` for a control character in
    /// the subject, `Build` for a budget, `Random` if the OS random source failed.
    #[cfg(feature = "std")]
    pub fn text(from: &str, to: &str, subject: &str, body: &str) -> Result<Message, Error> {
        Message::builder()
            .from(from)?
            .to(to)?
            .subject(subject)?
            .text(body)?
            .build()
    }

    /// A `multipart/alternative` message with the text first and the HTML
    /// last (RFC 2046: the last part is the preferred one).
    ///
    /// # Errors
    ///
    /// As [`Message::text`].
    #[cfg(feature = "std")]
    pub fn html(
        from: &str,
        to: &str,
        subject: &str,
        html: &str,
        text: &str,
    ) -> Result<Message, Error> {
        Message::builder()
            .from(from)?
            .to(to)?
            .subject(subject)?
            .text(text)?
            .html(html)?
            .build()
    }

    /// The `Message-ID`, without angle brackets.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// The header fields as written (Bcc is never among them).
    #[must_use]
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// The envelope derived from the headers (PLAN 7.11): the reverse-path is
    /// the Sender address if set, else the From address; the recipients are
    /// To, Cc, and Bcc in that order, deduplicated.
    ///
    /// # Errors
    ///
    /// `Build(NoRecipients)`, `Build(TooManyRecipients)`.
    pub fn envelope(&self) -> Result<Envelope, Error> {
        let from = self.sender.as_ref().unwrap_or(&self.from).address().clone();
        let to: Vec<Address> = self
            .recipients
            .iter()
            .map(|m| m.address().clone())
            .collect();
        Envelope::with_limit(Some(from), &to, self.max_recipients)
    }

    /// True when an address needs SMTPUTF8 (RFC 6531).
    #[must_use]
    pub fn needs_smtputf8(&self) -> bool {
        self.needs_smtputf8
    }

    /// True when a part is sent as `8bit` (needs 8BITMIME).
    #[must_use]
    pub fn has_8bit(&self) -> bool {
        self.has_8bit
    }

    /// The exact length of [`write_to`](Message::write_to) output.
    #[must_use]
    pub fn encoded_len(&self) -> u64 {
        self.encoded_len
    }

    /// Writes the message (CRLF line endings, deterministic) into `sink`.
    ///
    /// # Errors
    ///
    /// `Sink` errors.
    pub fn write_to<S: Sink>(&self, sink: &mut S) -> Result<(), Error> {
        sink.write(&self.head)?;
        sink.write(b"\r\n")?;
        self.body.write_body(sink)?;
        Ok(())
    }

    /// The message as bytes, in one allocation of `encoded_len` octets.
    ///
    /// # Errors
    ///
    /// `Build(TooLarge)` when the length does not fit in memory.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let len = usize::try_from(self.encoded_len).map_err(|_| BuildError::TooLarge {
            size: self.encoded_len,
            limit: usize::MAX as u64,
        })?;
        let mut out = Vec::with_capacity(len);
        self.write_to(&mut out)?;
        Ok(out)
    }

    /// The envelope (from [`envelope`](Message::envelope)) and the serialized
    /// bytes, as they will be sent.
    ///
    /// # Errors
    ///
    /// As `envelope` and `to_bytes`.
    pub fn prepare(&self) -> Result<PreparedMessage, Error> {
        let envelope = self.envelope()?;
        let bytes = self.to_bytes()?;
        // UTF-8 addresses are written raw into the header block (RFC 6532), so
        // such a message is 8-bit on the wire too.
        let eight_bit = self.has_8bit || self.needs_smtputf8;
        Ok(PreparedMessage::from_parts(
            envelope,
            bytes,
            Some(self.message_id.clone()),
            self.needs_smtputf8,
            eight_bit,
        ))
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("message_id", &self.message_id)
            .field("headers", &self.headers.len())
            .field("encoded_len", &self.encoded_len)
            .finish()
    }
}

impl From<Infallible> for Error {
    fn from(e: Infallible) -> Error {
        match e {}
    }
}

/// Accumulates a message; every setter validates its input at once.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "std")] {
/// use smtp_net::{Attachment, Message};
/// let msg = Message::builder()
///     .from("Billing <billing@example.com>")?
///     .to("customer@example.org")?
///     .bcc("archive@example.com")?
///     .subject("Your receipt")?
///     .text("Thank you for your order.")?
///     .attachment(Attachment::new("receipt.pdf", "application/pdf", b"%PDF-1.7".to_vec())?)?
///     .build()?;
/// assert!(msg.headers().get("Bcc").is_none());
/// assert_eq!(msg.envelope()?.recipients().len(), 2);
/// # }
/// # Ok::<(), smtp_net::Error>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct MessageBuilder {
    from: Option<Mailbox>,
    sender: Option<Mailbox>,
    reply_to: Vec<Mailbox>,
    to: Vec<Mailbox>,
    cc: Vec<Mailbox>,
    bcc: Vec<Mailbox>,
    subject: Option<String>,
    text: Option<String>,
    html: Option<String>,
    attachments: Vec<Attachment>,
    inlines: Vec<Inline>,
    custom: Vec<(HeaderName, String)>,
    message_id: Option<String>,
    message_id_domain: Option<String>,
    date: Option<u64>,
    in_reply_to: Option<String>,
    references: Vec<String>,
    allow_8bit: bool,
    limits: MessageLimits,
}

fn mailbox<M>(m: M) -> Result<Mailbox, Error>
where
    M: TryInto<Mailbox>,
    M::Error: Into<Error>,
{
    m.try_into().map_err(Into::into)
}

impl MessageBuilder {
    fn recipient_count(&self) -> usize {
        self.to.len() + self.cc.len() + self.bcc.len()
    }

    fn add_recipient(mut self, which: u8, m: Mailbox) -> Result<Self, Error> {
        if self.recipient_count() >= usize::from(self.limits.max_recipients) {
            return Err(BuildError::TooManyRecipients {
                limit: self.limits.max_recipients,
            }
            .into());
        }
        match which {
            0 => self.to.push(m),
            1 => self.cc.push(m),
            _ => self.bcc.push(m),
        }
        Ok(self)
    }

    /// Sets the single From mailbox; a second call replaces it.
    ///
    /// # Errors
    ///
    /// `Address`.
    pub fn from<M>(mut self, mailbox_: M) -> Result<Self, Error>
    where
        M: TryInto<Mailbox>,
        M::Error: Into<Error>,
    {
        self.from = Some(mailbox(mailbox_)?);
        Ok(self)
    }

    /// Sets the RFC 5322 Sender, used as the reverse-path when set.
    ///
    /// # Errors
    ///
    /// `Address`.
    pub fn sender<M>(mut self, mailbox_: M) -> Result<Self, Error>
    where
        M: TryInto<Mailbox>,
        M::Error: Into<Error>,
    {
        self.sender = Some(mailbox(mailbox_)?);
        Ok(self)
    }

    /// Adds a Reply-To mailbox.
    ///
    /// # Errors
    ///
    /// `Address`, `Build(TooMany)` beyond `max_recipients`.
    pub fn reply_to<M>(mut self, mailbox_: M) -> Result<Self, Error>
    where
        M: TryInto<Mailbox>,
        M::Error: Into<Error>,
    {
        let m = mailbox(mailbox_)?;
        if self.reply_to.len() >= usize::from(self.limits.max_recipients) {
            return Err(BuildError::TooMany {
                what: "Reply-To mailboxes",
                limit: u32::from(self.limits.max_recipients),
            }
            .into());
        }
        self.reply_to.push(m);
        Ok(self)
    }

    /// Adds a To recipient.
    ///
    /// # Errors
    ///
    /// `Address`, `Build(TooManyRecipients)`.
    pub fn to<M>(self, mailbox_: M) -> Result<Self, Error>
    where
        M: TryInto<Mailbox>,
        M::Error: Into<Error>,
    {
        let m = mailbox(mailbox_)?;
        self.add_recipient(0, m)
    }

    /// Adds a Cc recipient.
    ///
    /// # Errors
    ///
    /// `Address`, `Build(TooManyRecipients)`.
    pub fn cc<M>(self, mailbox_: M) -> Result<Self, Error>
    where
        M: TryInto<Mailbox>,
        M::Error: Into<Error>,
    {
        let m = mailbox(mailbox_)?;
        self.add_recipient(1, m)
    }

    /// Adds a Bcc recipient: in the envelope only, never in the message (T-28).
    ///
    /// # Errors
    ///
    /// `Address`, `Build(TooManyRecipients)`.
    pub fn bcc<M>(self, mailbox_: M) -> Result<Self, Error>
    where
        M: TryInto<Mailbox>,
        M::Error: Into<Error>,
    {
        let m = mailbox(mailbox_)?;
        self.add_recipient(2, m)
    }

    fn check_value(&self, field: &'static str, value: &str) -> Result<(), Error> {
        check_header_value(field, value)?;
        if value.len() > self.limits.max_header_value as usize {
            return Err(BuildError::TooLarge {
                size: value.len() as u64,
                limit: u64::from(self.limits.max_header_value),
            }
            .into());
        }
        Ok(())
    }

    /// Sets the subject (text; encoded on output when needed).
    ///
    /// # Errors
    ///
    /// `Header(ControlCharacter { field: "Subject", .. })`, `Build(TooLarge)`.
    pub fn subject(mut self, text: &str) -> Result<Self, Error> {
        self.check_value("Subject", text)?;
        self.subject = Some(String::from(text));
        Ok(self)
    }

    fn body_text(&self, body: &str) -> Result<String, Error> {
        if body.len() as u64 > self.limits.max_message_size {
            return Err(BuildError::TooLarge {
                size: body.len() as u64,
                limit: self.limits.max_message_size,
            }
            .into());
        }
        let bytes = body.as_bytes();
        let mut out = String::with_capacity(body.len());
        let mut start = 0;
        let mut i = 0;
        while let Some(&b) = bytes.get(i) {
            if b == b'\r' {
                if bytes.get(i + 1) != Some(&b'\n') {
                    return Err(BuildError::BareCarriageReturn { position: i as u64 }.into());
                }
                out.push_str(body.get(start..i).unwrap_or(""));
                start = i + 1;
                i += 1;
            }
            i += 1;
        }
        out.push_str(body.get(start..).unwrap_or(""));
        Ok(out)
    }

    /// Sets the plain-text body. LF and CRLF line endings are accepted (CRLF
    /// is written); a bare CR is refused.
    ///
    /// # Errors
    ///
    /// `Build(BareCarriageReturn)`, `Build(TooLarge)`.
    pub fn text(mut self, body: &str) -> Result<Self, Error> {
        self.text = Some(self.body_text(body)?);
        Ok(self)
    }

    /// Sets the HTML body, with the same line-ending rules as [`text`](MessageBuilder::text).
    ///
    /// # Errors
    ///
    /// `Build(BareCarriageReturn)`, `Build(TooLarge)`.
    pub fn html(mut self, body: &str) -> Result<Self, Error> {
        self.html = Some(self.body_text(body)?);
        Ok(self)
    }

    /// Adds an attachment (`multipart/mixed`).
    ///
    /// # Errors
    ///
    /// `Build(TooManyParts)`, `Build(TooLarge)`.
    pub fn attachment(mut self, attachment: Attachment) -> Result<Self, Error> {
        if self.attachments.len() + self.inlines.len() + 4 > usize::from(self.limits.max_parts) {
            return Err(BuildError::TooManyParts.into());
        }
        let size = attachment.bytes().len() as u64;
        if size > self.limits.max_message_size {
            return Err(BuildError::TooLarge {
                size,
                limit: self.limits.max_message_size,
            }
            .into());
        }
        self.attachments.push(attachment);
        Ok(self)
    }

    /// Adds an inline part beside the HTML body (`multipart/related`).
    ///
    /// # Errors
    ///
    /// `Build(TooManyParts)`, `Build(DuplicateContentId)`, `Build(TooLarge)`.
    pub fn inline(mut self, inline: Inline) -> Result<Self, Error> {
        if self.attachments.len() + self.inlines.len() + 4 > usize::from(self.limits.max_parts) {
            return Err(BuildError::TooManyParts.into());
        }
        if self
            .inlines
            .iter()
            .any(|i| i.content_id() == inline.content_id())
        {
            return Err(BuildError::DuplicateContentId.into());
        }
        self.inlines.push(inline);
        Ok(self)
    }

    /// Adds a custom header. The name must be `ftext` of at most 76 octets
    /// and not one the builder sets itself; the value is unstructured text.
    ///
    /// # Errors
    ///
    /// `Header(InvalidName)`, `Header(Reserved)`, `Header(ControlCharacter)`,
    /// `Build(TooManyHeaders)`.
    pub fn header(mut self, name: &str, value: &str) -> Result<Self, Error> {
        let name = HeaderName::new(name)?;
        if name.is_reserved() {
            return Err(HeaderError::Reserved.into());
        }
        self.check_value("header", value)?;
        if self.custom.len() >= usize::from(self.limits.max_headers) {
            return Err(BuildError::TooManyHeaders.into());
        }
        self.custom.push((name, String::from(value)));
        Ok(self)
    }

    /// Sets the `Message-ID` (`left@right`, angle brackets optional).
    ///
    /// # Errors
    ///
    /// `Header(InvalidMessageId)`.
    pub fn message_id(mut self, id: &str) -> Result<Self, Error> {
        let (l, r) = id::split_msg_id(id).ok_or(HeaderError::InvalidMessageId)?;
        let mut s = String::with_capacity(l.len() + r.len() + 1);
        s.push_str(l);
        s.push('@');
        s.push_str(r);
        self.message_id = Some(s);
        Ok(self)
    }

    /// The domain for a generated `Message-ID`, instead of the From domain.
    ///
    /// # Errors
    ///
    /// `Address` for a domain that is not a valid ASCII name.
    pub fn message_id_domain(mut self, domain: &str) -> Result<Self, Error> {
        let d = crate::address::Domain::parse(domain)?;
        if !d.is_ascii() {
            return Err(crate::error::AddressError::InternationalDomainUnsupported.into());
        }
        self.message_id_domain = Some(String::from(domain));
        Ok(self)
    }

    /// Fixes the `Date` header (Unix seconds, written in UTC).
    #[must_use]
    pub fn date_unix(mut self, seconds: u64) -> Self {
        self.date = Some(seconds);
        self
    }

    /// Sets `In-Reply-To`.
    ///
    /// # Errors
    ///
    /// `Header(InvalidMessageId)`.
    pub fn in_reply_to(mut self, id: &str) -> Result<Self, Error> {
        let (l, r) = id::split_msg_id(id).ok_or(HeaderError::InvalidMessageId)?;
        self.in_reply_to = Some(alloc::format!("<{l}@{r}>"));
        Ok(self)
    }

    /// Sets `References` (replacing earlier ids).
    ///
    /// # Errors
    ///
    /// `Header(InvalidMessageId)`, `Build(TooMany)` beyond `max_references`.
    pub fn references(mut self, ids: &[&str]) -> Result<Self, Error> {
        if ids.len() > usize::from(self.limits.max_references) {
            return Err(BuildError::TooMany {
                what: "References ids",
                limit: u32::from(self.limits.max_references),
            }
            .into());
        }
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let (l, r) = id::split_msg_id(id).ok_or(HeaderError::InvalidMessageId)?;
            out.push(alloc::format!("<{l}@{r}>"));
        }
        self.references = out;
        Ok(self)
    }

    /// Allows `8bit` for UTF-8 text parts (D-012). Off by default: output is
    /// 7-bit clean, which keeps DKIM signatures valid through relays.
    #[must_use]
    pub fn allow_8bit(mut self, allow: bool) -> Self {
        self.allow_8bit = allow;
        self
    }

    /// Replaces the budgets.
    #[must_use]
    pub fn limits(mut self, limits: MessageLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Builds the message with the OS random source and the system clock.
    ///
    /// # Errors
    ///
    /// `Build(MissingFrom)`, `Build(NoRecipients)`, `Build(InlineWithoutHtml)`,
    /// every budget, `Header(InvalidMessageId)` when no ASCII domain is
    /// available for the id, `Random`.
    #[cfg(feature = "std")]
    pub fn build(self) -> Result<Message, Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.build_with(&mut id::OsRandom, now)
    }

    /// Builds the message with caller-supplied randomness and time (`no_std`,
    /// tests, deterministic output).
    ///
    /// # Errors
    ///
    /// As [`build`](MessageBuilder::build).
    pub fn build_with(
        self,
        random: &mut dyn RandomSource,
        now_unix: u64,
    ) -> Result<Message, Error> {
        let from = self.from.clone().ok_or(BuildError::MissingFrom)?;
        if self.recipient_count() == 0 {
            return Err(BuildError::NoRecipients.into());
        }
        if !self.inlines.is_empty() && self.html.is_none() {
            return Err(BuildError::InlineWithoutHtml.into());
        }
        let mut body = self.body_tree();
        if body.count() > usize::from(self.limits.max_parts) {
            return Err(BuildError::TooManyParts.into());
        }
        if body.depth() > usize::from(self.limits.max_depth) {
            return Err(BuildError::DepthExceeded.into());
        }
        let message_id = match &self.message_id {
            Some(id) => id.clone(),
            None => {
                let domain = match &self.message_id_domain {
                    Some(d) => d.as_str(),
                    None if from.address().domain().is_ascii()
                        && !from.address().domain().is_literal() =>
                    {
                        from.address().domain().as_str()
                    }
                    None => return Err(HeaderError::InvalidMessageId.into()),
                };
                id::generate(random, domain)?
            }
        };
        assign_boundaries(&mut body, random)?;
        body.render_children()?;

        let mut block = HeaderBlock::default();
        let date = parse_net::MailDate::new(
            i64::try_from(now_unix).map_err(|_| HeaderError::InvalidDate)?,
            0,
        )
        .map_err(|_| HeaderError::InvalidDate)?;
        let (d, n) = date.format();
        block.folded(
            "Date",
            core::str::from_utf8(d.get(..n).unwrap_or(&[])).unwrap_or(""),
        )?;
        block.mailboxes("From", core::slice::from_ref(&from));
        if let Some(s) = &self.sender {
            block.mailboxes("Sender", core::slice::from_ref(s));
        }
        if !self.reply_to.is_empty() {
            block.mailboxes("Reply-To", &self.reply_to);
        }
        if !self.to.is_empty() {
            block.mailboxes("To", &self.to);
        }
        if !self.cc.is_empty() {
            block.mailboxes("Cc", &self.cc);
        }
        if let Some(s) = &self.subject {
            block.unstructured("Subject", "Subject", s)?;
        }
        block.folded("Message-ID", &alloc::format!("<{message_id}>"))?;
        if let Some(r) = &self.in_reply_to {
            block.folded("In-Reply-To", r)?;
        }
        if !self.references.is_empty() {
            block.folded("References", &self.references.join(" "))?;
        }
        for (name, value) in &self.custom {
            block.unstructured(name.as_str(), "header", value)?;
        }
        block.folded("MIME-Version", "1.0")?;
        body.write_headers(&mut block)?;

        let encoded_len = block.bytes.len() as u64 + 2 + body.body_len();
        if encoded_len > self.limits.max_message_size {
            return Err(BuildError::TooLarge {
                size: encoded_len,
                limit: self.limits.max_message_size,
            }
            .into());
        }
        let needs_smtputf8 = core::iter::once(&from)
            .chain(self.sender.iter())
            .chain(self.reply_to.iter())
            .chain(self.to.iter())
            .chain(self.cc.iter())
            .chain(self.bcc.iter())
            .any(|m| m.address().needs_smtputf8());
        let has_8bit = body.has_8bit();
        let mut recipients = self.to;
        recipients.extend(self.cc);
        recipients.extend(self.bcc);
        Ok(Message {
            head: block.bytes,
            headers: block.headers,
            body,
            message_id,
            from,
            sender: self.sender,
            recipients,
            needs_smtputf8,
            has_8bit,
            encoded_len,
            max_recipients: self.limits.max_recipients,
        })
    }

    /// The MIME tree: mixed > related > alternative (PLAN FR-3).
    fn body_tree(&self) -> Part {
        let text = self
            .text
            .as_ref()
            .map(|t| Part::text("text/plain", t.clone(), self.allow_8bit));
        let html = self
            .html
            .as_ref()
            .map(|h| Part::text("text/html", h.clone(), self.allow_8bit));
        let mut core = match (text, html) {
            (Some(t), Some(h)) => Part::multipart(Multipart::Alternative, vec![t, h]),
            (Some(t), None) => t,
            (None, Some(h)) => h,
            (None, None) => Part::text("text/plain", String::new(), false),
        };
        if !self.inlines.is_empty() {
            let mut parts = vec![core];
            parts.extend(self.inlines.iter().cloned().map(Part::inline));
            core = Part::multipart(Multipart::Related, parts);
        }
        if !self.attachments.is_empty() {
            let mut parts = vec![core];
            parts.extend(self.attachments.iter().cloned().map(Part::attachment));
            core = Part::multipart(Multipart::Mixed, parts);
        }
        core
    }
}

/// Draws a boundary for every multipart; redraws when a part sent without
/// encoding has a line that starts with `--` and the boundary (T-15).
fn assign_boundaries(part: &mut Part, random: &mut dyn RandomSource) -> Result<(), Error> {
    if let part::Body::Multipart { .. } = &part.body {
        let mut texts = Vec::new();
        part.plain_texts(&mut texts);
        let mut chosen = None;
        for _ in 0..8 {
            let b = id::boundary(random)?;
            if !texts.iter().any(|t| collides(t, &b)) {
                chosen = Some(b);
                break;
            }
        }
        let b = chosen.ok_or(Error::new(crate::ErrorKind::Random))?;
        if let part::Body::Multipart {
            boundary, parts, ..
        } = &mut part.body
        {
            *boundary = b;
            for p in parts.iter_mut() {
                assign_boundaries(p, random)?;
            }
        }
    }
    Ok(())
}

fn collides(text: &str, boundary: &str) -> bool {
    text.split('\n').any(|line| {
        line.strip_prefix("--")
            .is_some_and(|rest| rest.starts_with(boundary))
    })
}

#[cfg(test)]
mod tests;
