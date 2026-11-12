//! SASL for SMTP AUTH (RFC 4954): credentials, the mechanism allowlist, the
//! client side of PLAIN (RFC 4616), LOGIN, XOAUTH2, and SCRAM-SHA-256
//! (RFC 7677, feature `scram`), and the [`Mechanism`] trait for others.

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::fmt;

use crypt_io::Zeroizing;

use crate::encode::{base64_append, base64_decode};
use crate::error::{ConfigError, Error};

/// Longest AUTH command or response line, including CRLF (RFC 4954 4).
pub const MAX_AUTH_LINE: usize = 12_288;
/// Most challenge-response steps an exchange takes before it is refused as a
/// protocol error.
pub(crate) const MAX_STEPS: u8 = 8;
/// Most mechanisms in an allowlist.
const MAX_MECHANISMS: usize = 8;
/// Largest XOAUTH2 error document kept (1 KiB).
const MAX_OAUTH_ERROR: usize = 1024;

/// A password or token: wiped from memory on drop (crypt-io's `Zeroizing`),
/// never shown by `Debug` or `Display` (T-9).
///
/// # Examples
///
/// ```
/// let s = smtp_net::Secret::from("hunter2");
/// assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
/// assert!(!format!("{s}").contains("hunter2"));
/// ```
#[derive(Clone)]
pub struct Secret(Zeroizing<Vec<u8>>);

/// Compared in time that depends only on the lengths, not on where the
/// contents differ.
impl PartialEq for Secret {
    fn eq(&self, other: &Secret) -> bool {
        let (a, b) = (self.expose(), other.expose());
        if a.len() != b.len() {
            return false;
        }
        let diff = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
        core::hint::black_box(diff) == 0
    }
}
impl Eq for Secret {}

#[cfg(test)]
mod secret_tests {
    use super::Secret;
    use alloc::vec;

    #[test]
    fn test_secret_equality_compares_whole_contents() {
        let a = Secret::new(vec![1, 2, 3]);
        assert!(a == Secret::new(vec![1, 2, 3]));
        assert!(a != Secret::new(vec![1, 2, 4]));
        assert!(a != Secret::new(vec![0, 2, 3]));
        assert!(a != Secret::new(vec![1, 2]));
        assert!(Secret::new(vec![]) == Secret::new(vec![]));
    }
}

impl Secret {
    /// A secret holding `bytes`.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Secret {
        Secret(Zeroizing::new(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Its length in octets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Secret {
        Secret::new(s.into_bytes())
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Secret {
        Secret::new(s.as_bytes().to_vec())
    }
}

impl From<Vec<u8>> for Secret {
    fn from(v: Vec<u8>) -> Secret {
        Secret::new(v)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// What to authenticate with.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub enum Credentials {
    /// A user name and a password (SCRAM-SHA-256, PLAIN, LOGIN).
    Password {
        /// The user name.
        user: String,
        /// The password.
        password: Secret,
    },
    /// A user name and an OAuth 2.0 access token (XOAUTH2). Getting and
    /// refreshing the token is the caller's job.
    OAuth2 {
        /// The user name (the mailbox address).
        user: String,
        /// The access token.
        token: Secret,
    },
    /// A mechanism this crate does not implement.
    Custom(CustomMechanism),
}

impl Credentials {
    /// A user name and password.
    #[must_use]
    pub fn password(user: &str, password: impl Into<Secret>) -> Credentials {
        Credentials::Password {
            user: String::from(user),
            password: password.into(),
        }
    }

    /// A user name and an OAuth 2.0 access token, for XOAUTH2 (Gmail,
    /// Microsoft 365).
    #[must_use]
    pub fn oauth2(user: &str, token: impl Into<Secret>) -> Credentials {
        Credentials::OAuth2 {
            user: String::from(user),
            token: token.into(),
        }
    }

    /// The user name (empty for a custom mechanism).
    #[must_use]
    pub fn user(&self) -> &str {
        match self {
            Credentials::Password { user, .. } | Credentials::OAuth2 { user, .. } => user,
            Credentials::Custom(_) => "",
        }
    }

    /// True when `mechanism` can use these credentials.
    fn fits(&self, mechanism: MechanismName) -> bool {
        matches!(
            (self, mechanism),
            (
                Credentials::Password { .. },
                MechanismName::Plain | MechanismName::Login | MechanismName::ScramSha256
            ) | (Credentials::OAuth2 { .. }, MechanismName::XOAuth2)
                | (Credentials::Custom(_), MechanismName::Other)
        )
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credentials::Password { user, .. } => f
                .debug_struct("Password")
                .field("user", user)
                .field("password", &"<redacted>")
                .finish(),
            Credentials::OAuth2 { user, .. } => f
                .debug_struct("OAuth2")
                .field("user", user)
                .field("token", &"<redacted>")
                .finish(),
            Credentials::Custom(m) => f.debug_tuple("Custom").field(m).finish(),
        }
    }
}

/// A SASL mechanism name.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MechanismName {
    /// PLAIN (RFC 4616).
    Plain,
    /// LOGIN (draft-murchison-sasl-login).
    Login,
    /// XOAUTH2 (Google's OAuth 2.0 mechanism, also used by Microsoft 365).
    XOAuth2,
    /// SCRAM-SHA-256 (RFC 7677): the password never leaves the client, and
    /// the server proves it knows it too. Needs the `scram` feature.
    ScramSha256,
    /// The [`CustomMechanism`] in the credentials, under its own name.
    Other,
}

impl MechanismName {
    /// The name the server advertises (empty for [`MechanismName::Other`],
    /// whose name the custom mechanism gives).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            MechanismName::Plain => "PLAIN",
            MechanismName::Login => "LOGIN",
            MechanismName::XOAuth2 => "XOAUTH2",
            MechanismName::ScramSha256 => "SCRAM-SHA-256",
            MechanismName::Other => "",
        }
    }
}

impl fmt::Display for MechanismName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The ordered allowlist the client chooses from (FR-35): the first one the
/// server offers and the credentials fit wins; the server's order is
/// ignored and there is no fallback outside the list (T-10).
///
/// # Examples
///
/// ```
/// use smtp_net::MechanismName;
/// use smtp_net::protocol::MechanismList;
/// let list = MechanismList::new(&[MechanismName::Login])?;
/// assert_eq!(list.iter().count(), 1);
/// assert!(MechanismList::default().iter().any(|m| m == MechanismName::Plain));
/// # Ok::<(), smtp_net::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MechanismList(Vec<MechanismName>);

impl MechanismList {
    /// A list in the caller's order, duplicates removed, at most 8.
    ///
    /// # Errors
    ///
    /// `Config(TooManyMechanisms)`, and `Config(TooManyMechanisms)` for an
    /// empty list too (nothing could be chosen).
    pub fn new(list: &[MechanismName]) -> Result<MechanismList, Error> {
        if list.is_empty() || list.len() > MAX_MECHANISMS {
            return Err(ConfigError::TooManyMechanisms.into());
        }
        let mut v: Vec<MechanismName> = Vec::with_capacity(list.len());
        for m in list {
            if !v.contains(m) {
                v.push(*m);
            }
        }
        Ok(MechanismList(v))
    }

    /// The names in order.
    pub fn iter(&self) -> impl Iterator<Item = MechanismName> + '_ {
        self.0.iter().copied()
    }
}

impl Default for MechanismList {
    /// `[ScramSha256 (with the scram feature), Plain, Login, XOAuth2,
    /// Other]`: each credential kind meets only the mechanisms it fits, so
    /// a password uses SCRAM when the server offers it, then PLAIN, then
    /// LOGIN.
    fn default() -> MechanismList {
        let mut v = Vec::with_capacity(5);
        if cfg!(feature = "scram") {
            v.push(MechanismName::ScramSha256);
        }
        v.extend([
            MechanismName::Plain,
            MechanismName::Login,
            MechanismName::XOAuth2,
            MechanismName::Other,
        ]);
        MechanismList(v)
    }
}

/// Credentials and the mechanism allowlist for a session.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Auth {
    /// What to authenticate with.
    pub credentials: Credentials,
    /// Which mechanisms may be used, in order of preference.
    pub mechanisms: MechanismList,
    scram_nonce: Option<String>,
}

impl Auth {
    /// `credentials` with the default allowlist.
    #[must_use]
    pub fn new(credentials: Credentials) -> Auth {
        Auth {
            credentials,
            mechanisms: MechanismList::default(),
            scram_nonce: None,
        }
    }

    /// Replaces the allowlist.
    #[must_use]
    pub fn mechanisms(mut self, list: MechanismList) -> Auth {
        self.mechanisms = list;
        self
    }

    /// The SCRAM client nonce for the next exchange: at least 16 printable
    /// ASCII characters without commas, from a CSPRNG, new for every
    /// session. With `std` the session draws one from the OS when none is
    /// set; without it SCRAM needs this. Tests use it to replay RFC 7677.
    ///
    /// # Errors
    ///
    /// `Sasl(InvalidCredential)` for a nonce that is too short, too long
    /// (over 64), or has other characters.
    pub fn scram_nonce(mut self, nonce: &str) -> Result<Auth, Error> {
        let ok = (16..=64).contains(&nonce.len())
            && nonce
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && b != b',');
        if !ok {
            return Err(SaslError::InvalidCredential.into());
        }
        self.scram_nonce = Some(String::from(nonce));
        Ok(self)
    }
}

/// A SASL exchange was refused on the client side.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SaslError {
    /// A user name, password, or token holds a character the mechanism
    /// cannot carry (NUL for PLAIN, 0x01 for XOAUTH2).
    InvalidCredential,
    /// The server's challenge is not valid base64.
    InvalidChallenge,
    /// The exchange took more steps than the mechanism has.
    TooManySteps,
    /// SCRAM: the server's message does not follow RFC 5802.
    InvalidServerMessage,
    /// SCRAM: the server nonce does not extend the client's.
    ServerNonceMismatch,
    /// SCRAM: the iteration count is under 4,096 (RFC 7677) or over
    /// 1,000,000 (this crate's budget).
    IterationsOutOfRange,
    /// SCRAM: the server's signature is wrong or missing: it did not prove
    /// it knows the password.
    ServerSignatureMismatch,
    /// SCRAM: the server reported an error (`e=`).
    ServerError,
    /// SCRAM needs ASCII credentials until SASLprep is available (O-12),
    /// and the allowlist had no other mechanism the server offers.
    NonAsciiCredential,
    /// SCRAM without `std` needs [`Auth::scram_nonce`].
    NonceMissing,
    /// A response would pass the 12,288-octet AUTH line limit.
    ResponseTooLong,
    /// A custom mechanism name is not 1 to 20 of `A-Z`, `0-9`, `-`, `_`.
    InvalidMechanismName,
    /// A custom mechanism refused, with its reason.
    Custom(&'static str),
}

impl fmt::Display for SaslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SaslError::InvalidCredential => {
                "the user name, password, or token holds a character the AUTH mechanism cannot send"
            }
            SaslError::InvalidChallenge => "the server's AUTH challenge is not valid base64",
            SaslError::TooManySteps => {
                "the server asked for more AUTH steps than the mechanism has"
            }
            SaslError::InvalidServerMessage => "the server's SCRAM message is malformed",
            SaslError::ServerNonceMismatch => {
                "the server's SCRAM nonce does not extend the client's"
            }
            SaslError::IterationsOutOfRange => {
                "the server's SCRAM iteration count is outside 4096 to 1000000"
            }
            SaslError::ServerSignatureMismatch => {
                "the server did not prove it knows the password (SCRAM server signature wrong or missing)"
            }
            SaslError::ServerError => "the server reported a SCRAM error",
            SaslError::NonAsciiCredential => {
                "SCRAM needs ASCII credentials, and no other allowed mechanism is offered"
            }
            SaslError::NonceMissing => "SCRAM without std needs a nonce (Auth::scram_nonce)",
            SaslError::ResponseTooLong => "an AUTH response is longer than 12288 octets",
            SaslError::InvalidMechanismName => {
                "a SASL mechanism name must be 1 to 20 of A-Z, 0-9, '-', '_'"
            }
            SaslError::Custom(reason) => reason,
        })
    }
}

/// What a [`Mechanism`] step left to do.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// More challenges may follow.
    Continue,
    /// This was the last response.
    Done,
}

/// A SASL mechanism this crate does not implement (Tier 3).
///
/// The session base64-encodes what the mechanism writes, decodes the
/// server's challenges before passing them in, enforces the line limit, and
/// stops after 8 steps. A client-side error closes the connection.
pub trait Mechanism: Send {
    /// The mechanism name, as the server advertises it.
    fn name(&self) -> &'static str;
    /// Writes the initial response into `out`; returns false to send none.
    ///
    /// # Errors
    ///
    /// Any [`SaslError`]; the exchange ends.
    fn initial_response(&mut self, out: &mut Vec<u8>) -> Result<bool, SaslError>;
    /// Answers a decoded challenge into `out`.
    ///
    /// # Errors
    ///
    /// Any [`SaslError`]; the exchange ends.
    fn step(&mut self, challenge: &[u8], out: &mut Vec<u8>) -> Result<Step, SaslError>;
    /// Called on the server's `235`. SMTP carries no data with success, so
    /// `final_data` is `None`; a mechanism that needs a final server proof
    /// must have received it in a challenge.
    ///
    /// # Errors
    ///
    /// Any [`SaslError`]: the client refuses the success.
    fn verify_success(&mut self, final_data: Option<&[u8]>) -> Result<(), SaslError>;
}

type MakeMechanism = dyn Fn() -> Box<dyn Mechanism> + Send + Sync;

/// A factory for a custom [`Mechanism`]: each session gets a fresh one.
#[derive(Clone)]
pub struct CustomMechanism {
    name: &'static str,
    make: Arc<MakeMechanism>,
}

impl CustomMechanism {
    /// A custom mechanism advertised as `name`.
    ///
    /// # Errors
    ///
    /// `Sasl(InvalidMechanismName)`.
    pub fn new(
        name: &'static str,
        make: impl Fn() -> Box<dyn Mechanism> + Send + Sync + 'static,
    ) -> Result<CustomMechanism, Error> {
        let ok = (1..=20).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !ok {
            return Err(SaslError::InvalidMechanismName.into());
        }
        Ok(CustomMechanism {
            name,
            make: Arc::new(make),
        })
    }

    /// The mechanism name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl PartialEq for CustomMechanism {
    fn eq(&self, other: &CustomMechanism) -> bool {
        self.name == other.name && Arc::ptr_eq(&self.make, &other.make)
    }
}
impl Eq for CustomMechanism {}

impl fmt::Debug for CustomMechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomMechanism")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

enum Kind {
    /// PLAIN and LOGIN: responses still to send, last first, as base64.
    Fixed(Vec<Zeroizing<Vec<u8>>>),
    XOAuth2 {
        /// The initial response when it did not fit on the AUTH line.
        pending: Option<Zeroizing<Vec<u8>>>,
        /// The `status` of the server's error document.
        status: Option<String>,
    },
    #[cfg(feature = "scram")]
    Scram(super::scram::Scram),
    Custom {
        mechanism: Box<dyn Mechanism>,
        done: bool,
    },
}

/// The client side of one SASL exchange.
pub(crate) struct Exchange {
    pub(crate) mechanism: MechanismName,
    kind: Kind,
    pub(crate) steps: u8,
}

impl fmt::Debug for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchange")
            .field("mechanism", &self.mechanism)
            .field("steps", &self.steps)
            .finish_non_exhaustive()
    }
}

fn b64(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len().div_ceil(3) * 4));
    base64_append(bytes, &mut out);
    out
}

/// True when SCRAM can carry the credentials before SASLprep exists (O-12).
fn scram_fits(credentials: &Credentials) -> bool {
    let printable = |b: &[u8]| b.iter().all(|c| (0x20..=0x7e).contains(c));
    match credentials {
        Credentials::Password { user, password } => {
            !user.is_empty() && printable(user.as_bytes()) && printable(password.expose())
        }
        _ => false,
    }
}

impl Exchange {
    /// Picks the first mechanism of `auth`'s list the server offers and the
    /// credentials fit. `Err(NonAsciiCredential)` when only SCRAM matched
    /// and the credentials are not ASCII.
    pub(crate) fn choose<'a>(
        auth: &Auth,
        offered: impl Iterator<Item = &'a [u8]> + Clone,
    ) -> Result<Option<MechanismName>, SaslError> {
        let custom = match &auth.credentials {
            Credentials::Custom(c) => c.name,
            _ => "",
        };
        let mut skipped_scram = false;
        for m in auth.mechanisms.iter() {
            if !auth.credentials.fits(m) {
                continue;
            }
            let name = if m == MechanismName::Other {
                custom
            } else {
                m.as_str()
            };
            if !offered
                .clone()
                .any(|o| o.eq_ignore_ascii_case(name.as_bytes()))
            {
                continue;
            }
            if m == MechanismName::ScramSha256
                && (!cfg!(feature = "scram") || !scram_fits(&auth.credentials))
            {
                skipped_scram |= cfg!(feature = "scram");
                continue;
            }
            return Ok(Some(m));
        }
        if skipped_scram {
            return Err(SaslError::NonAsciiCredential);
        }
        Ok(None)
    }

    /// The AUTH command line (without CRLF) and the exchange that follows it.
    pub(crate) fn start(
        auth: &Auth,
        mechanism: MechanismName,
    ) -> Result<(Zeroizing<Vec<u8>>, Exchange), SaslError> {
        let mut line = Zeroizing::new(Vec::with_capacity(64));
        line.extend_from_slice(b"AUTH ");
        let kind = match (&auth.credentials, mechanism) {
            (Credentials::Password { user, password }, MechanismName::Plain) => {
                line.extend_from_slice(b"PLAIN");
                if user.as_bytes().contains(&0) || password.expose().contains(&0) {
                    return Err(SaslError::InvalidCredential);
                }
                // authzid (empty) NUL authcid NUL passwd
                let mut msg = Zeroizing::new(Vec::with_capacity(user.len() + password.len() + 2));
                msg.push(0);
                msg.extend_from_slice(user.as_bytes());
                msg.push(0);
                msg.extend_from_slice(password.expose());
                let b = b64(&msg);
                let mut responses = Vec::new();
                if line.len() + 1 + b.len() + 2 <= MAX_AUTH_LINE {
                    line.push(b' ');
                    line.extend_from_slice(&b);
                } else {
                    // Too long for an initial response: sent after the 334 (RFC 4954 4).
                    responses.push(b);
                }
                Kind::Fixed(responses)
            }
            (Credentials::Password { user, password }, MechanismName::Login) => {
                line.extend_from_slice(b"LOGIN");
                Kind::Fixed(alloc::vec![b64(password.expose()), b64(user.as_bytes())])
            }
            (Credentials::OAuth2 { user, token }, MechanismName::XOAuth2) => {
                line.extend_from_slice(b"XOAUTH2");
                if user.as_bytes().contains(&1) || token.expose().contains(&1) {
                    return Err(SaslError::InvalidCredential);
                }
                // "user=" user ^A "auth=Bearer " token ^A ^A
                let mut msg = Zeroizing::new(Vec::with_capacity(user.len() + token.len() + 20));
                msg.extend_from_slice(b"user=");
                msg.extend_from_slice(user.as_bytes());
                msg.extend_from_slice(b"\x01auth=Bearer ");
                msg.extend_from_slice(token.expose());
                msg.extend_from_slice(b"\x01\x01");
                let b = b64(&msg);
                let pending = if line.len() + 1 + b.len() + 2 <= MAX_AUTH_LINE {
                    line.push(b' ');
                    line.extend_from_slice(&b);
                    None
                } else {
                    Some(b)
                };
                Kind::XOAuth2 {
                    pending,
                    status: None,
                }
            }
            #[cfg(feature = "scram")]
            (Credentials::Password { user, password }, MechanismName::ScramSha256) => {
                line.extend_from_slice(b"SCRAM-SHA-256 ");
                let nonce = match &auth.scram_nonce {
                    Some(n) => Zeroizing::new(n.as_bytes().to_vec()),
                    None => super::scram::fresh_nonce()?,
                };
                let (scram, first) = super::scram::Scram::new(user, password, &nonce)?;
                line.extend_from_slice(&b64(&first));
                Kind::Scram(scram)
            }
            (Credentials::Custom(c), MechanismName::Other) => {
                line.extend_from_slice(c.name.as_bytes());
                let mut mechanism = (c.make)();
                let mut out = Zeroizing::new(Vec::new());
                if mechanism.initial_response(&mut out)? {
                    line.push(b' ');
                    if out.is_empty() {
                        // A zero-length initial response (RFC 4954 4).
                        line.push(b'=');
                    } else {
                        line.extend_from_slice(&b64(&out));
                    }
                }
                Kind::Custom {
                    mechanism,
                    done: false,
                }
            }
            _ => return Err(SaslError::InvalidCredential),
        };
        if line.len() + 2 > MAX_AUTH_LINE {
            return Err(SaslError::ResponseTooLong);
        }
        Ok((
            line,
            Exchange {
                mechanism,
                kind,
                steps: 0,
            },
        ))
    }

    /// The response to a `334` challenge (base64, possibly empty), or
    /// `None` when the mechanism has nothing more to send.
    pub(crate) fn respond(
        &mut self,
        challenge: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SaslError> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > MAX_STEPS {
            return Err(SaslError::TooManySteps);
        }
        let mut decoded = Zeroizing::new(Vec::with_capacity(challenge.len() / 4 * 3));
        if base64_decode(challenge, &mut decoded).is_err() {
            return Err(SaslError::InvalidChallenge);
        }
        match &mut self.kind {
            // PLAIN and LOGIN challenges are informational.
            Kind::Fixed(responses) => Ok(responses.pop()),
            Kind::XOAuth2 { pending, status } => {
                if let Some(p) = pending.take() {
                    return Ok(Some(p));
                }
                // An error document: keep its status, answer with an empty
                // line, and the server replies 535.
                if status.is_none() && decoded.len() <= MAX_OAUTH_ERROR {
                    *status = oauth_status(&decoded);
                }
                Ok(Some(Zeroizing::new(Vec::new())))
            }
            #[cfg(feature = "scram")]
            Kind::Scram(s) => s.on_challenge(&decoded).map(|r| Some(b64(&r))),
            Kind::Custom { mechanism, done } => {
                if *done {
                    return Err(SaslError::TooManySteps);
                }
                let mut out = Zeroizing::new(Vec::new());
                *done = mechanism.step(&decoded, &mut out)? == Step::Done;
                Ok(Some(b64(&out)))
            }
        }
    }

    /// The server said 235: true when the client accepts that.
    pub(crate) fn finish(&mut self) -> Result<bool, SaslError> {
        match &mut self.kind {
            Kind::Fixed(responses) => Ok(responses.is_empty()),
            Kind::XOAuth2 { pending, .. } => Ok(pending.is_none()),
            #[cfg(feature = "scram")]
            Kind::Scram(s) => {
                if s.verified() {
                    Ok(true)
                } else {
                    Err(SaslError::ServerSignatureMismatch)
                }
            }
            Kind::Custom { mechanism, .. } => mechanism.verify_success(None).map(|()| true),
        }
    }

    /// The XOAUTH2 error status the server sent, if any.
    pub(crate) fn detail(&self) -> Option<&str> {
        match &self.kind {
            Kind::XOAuth2 { status, .. } => status.as_deref(),
            _ => None,
        }
    }
}

/// The `status` member of an XOAUTH2 error document, when it is a short
/// printable string or number. Nothing else of the document is read.
fn oauth_status(doc: &[u8]) -> Option<String> {
    let text = core::str::from_utf8(doc).ok()?;
    let at = text.find("\"status\"")?;
    let rest = text
        .get(at + 8..)?
        .trim_start()
        .strip_prefix(':')?
        .trim_start();
    let value = match rest.strip_prefix('"') {
        Some(s) => s.get(..s.find('"')?)?,
        None => rest.get(
            ..rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len()),
        )?,
    };
    let ok =
        !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| (0x20..=0x7e).contains(&b));
    ok.then(|| String::from(value))
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    fn offered(names: &[&'static str]) -> Vec<&'static [u8]> {
        names.iter().map(|n| n.as_bytes()).collect()
    }

    #[test]
    fn test_secret_never_formatted() {
        let c = Credentials::password("user@example.com", "s3cr3t-value");
        let a = Auth::new(c);
        let o = Credentials::oauth2("user@example.com", "ya29.token-value");
        for s in [
            format!("{a:?}"),
            format!("{:?}", a.credentials),
            format!("{}", Secret::from("s3cr3t-value")),
            format!("{o:?}"),
        ] {
            assert!(
                !s.contains("s3cr3t-value") && !s.contains("token-value"),
                "{s}"
            );
        }
        assert!(format!("{a:?}").contains("user@example.com"));
    }

    #[test]
    fn test_plain_initial_response_rfc4616() {
        let auth = Auth::new(Credentials::password("tim", "tanstaaftanstaaf"));
        let (line, mut ex) = Exchange::start(&auth, MechanismName::Plain).unwrap();
        assert_eq!(&line[..], b"AUTH PLAIN AHRpbQB0YW5zdGFhZnRhbnN0YWFm");
        assert_eq!(ex.finish(), Ok(true));
    }

    #[test]
    fn test_plain_refuses_nul_and_long_goes_after_334() {
        let auth = Auth::new(Credentials::password("a\0b", "x"));
        assert_eq!(
            Exchange::start(&auth, MechanismName::Plain).unwrap_err(),
            SaslError::InvalidCredential
        );
        let long = "p".repeat(10_000);
        let auth = Auth::new(Credentials::password("u", long.as_str()));
        let (line, mut ex) = Exchange::start(&auth, MechanismName::Plain).unwrap();
        assert_eq!(&line[..], b"AUTH PLAIN");
        assert_eq!(ex.finish(), Ok(false));
        let r = ex.respond(b"").unwrap().unwrap();
        assert!(r.len() > 12_000);
        assert_eq!(ex.finish(), Ok(true));
    }

    #[test]
    fn test_login_two_steps_then_too_many() {
        let auth = Auth::new(Credentials::password("user", "pass"));
        let (line, mut ex) = Exchange::start(&auth, MechanismName::Login).unwrap();
        assert_eq!(&line[..], b"AUTH LOGIN");
        assert_eq!(
            &ex.respond(b"VXNlcm5hbWU6").unwrap().unwrap()[..],
            b"dXNlcg=="
        );
        assert_eq!(
            &ex.respond(b"UGFzc3dvcmQ6").unwrap().unwrap()[..],
            b"cGFzcw=="
        );
        assert_eq!(ex.finish(), Ok(true));
        assert_eq!(ex.respond(b"").unwrap(), None);
        assert_eq!(
            ex.respond(b"not base64!").unwrap_err(),
            SaslError::InvalidChallenge
        );
        for _ in 0..8 {
            let _ = ex.respond(b"");
        }
        assert_eq!(ex.respond(b"").unwrap_err(), SaslError::TooManySteps);
    }

    #[test]
    fn test_choose_follows_client_order_and_credential_kind() {
        let auth = Auth::new(Credentials::password("u", "p"));
        let o = offered(&["LOGIN", "CRAM-MD5", "plain", "XOAUTH2"]);
        assert_eq!(
            Exchange::choose(&auth, o.iter().copied()),
            Ok(Some(MechanismName::Plain))
        );
        let login_only = auth
            .clone()
            .mechanisms(MechanismList::new(&[MechanismName::Login]).unwrap());
        let plain = offered(&["PLAIN"]);
        assert_eq!(
            Exchange::choose(&login_only, plain.iter().copied()),
            Ok(None)
        );
        // A token never goes to PLAIN, a password never to XOAUTH2.
        let oauth = Auth::new(Credentials::oauth2("u", "t"));
        assert_eq!(
            Exchange::choose(&oauth, o.iter().copied()),
            Ok(Some(MechanismName::XOAuth2))
        );
        assert_eq!(Exchange::choose(&oauth, plain.iter().copied()), Ok(None));
        let xo = offered(&["XOAUTH2"]);
        assert_eq!(Exchange::choose(&auth, xo.iter().copied()), Ok(None));
        assert!(MechanismList::new(&[]).is_err());
        assert!(MechanismList::new(&[MechanismName::Plain; 9]).is_err());
        assert_eq!(
            MechanismList::new(&[MechanismName::Plain, MechanismName::Plain])
                .unwrap()
                .iter()
                .count(),
            1
        );
    }

    #[test]
    fn test_xoauth2_google_example_and_error_document() {
        // Google's documented example (user and token from the XOAUTH2 page).
        let auth = Auth::new(Credentials::oauth2(
            "someuser@example.com",
            "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg",
        ));
        let (line, mut ex) = Exchange::start(&auth, MechanismName::XOAuth2).unwrap();
        assert_eq!(
            &line[..],
            &b"AUTH XOAUTH2 dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ=="[..]
        );
        assert_eq!(ex.finish(), Ok(true));
        let doc =
            b64(br#"{"status":"401","schemes":"bearer mac","scope":"https://mail.google.com/"}"#);
        assert_eq!(&ex.respond(&doc).unwrap().unwrap()[..], b"");
        assert_eq!(ex.detail(), Some("401"));
        assert!(
            Exchange::start(
                &Auth::new(Credentials::oauth2("u\x01", "t")),
                MechanismName::XOAuth2
            )
            .is_err()
        );
    }

    #[test]
    fn test_oauth_status_is_bounded() {
        assert_eq!(oauth_status(br#"{"status": 400}"#).as_deref(), Some("400"));
        assert_eq!(
            oauth_status(br#"{"status":"invalid_request"}"#).as_deref(),
            Some("invalid_request")
        );
        assert_eq!(oauth_status(b"\xff\xfe"), None);
        assert_eq!(oauth_status(b"{\"status\":\"\x01\"}"), None);
        assert_eq!(oauth_status(b"not json"), None);
        let long = format!("{{\"status\":\"{}\"}}", "x".repeat(65));
        assert_eq!(oauth_status(long.as_bytes()), None);
        // Over 1 KiB: the document is not read at all.
        let auth = Auth::new(Credentials::oauth2("u", "t"));
        let (_, mut ex) = Exchange::start(&auth, MechanismName::XOAuth2).unwrap();
        let big = format!("{{\"status\":\"401\",\"pad\":\"{}\"}}", "y".repeat(1100));
        ex.respond(&b64(big.as_bytes())).unwrap();
        assert_eq!(ex.detail(), None);
    }

    struct Echo(u8);
    impl Mechanism for Echo {
        fn name(&self) -> &'static str {
            "X-ECHO"
        }
        fn initial_response(&mut self, out: &mut Vec<u8>) -> Result<bool, SaslError> {
            out.extend_from_slice(b"hello");
            Ok(true)
        }
        fn step(&mut self, challenge: &[u8], out: &mut Vec<u8>) -> Result<Step, SaslError> {
            self.0 += 1;
            out.extend_from_slice(challenge);
            Ok(if self.0 == 2 {
                Step::Done
            } else {
                Step::Continue
            })
        }
        fn verify_success(&mut self, final_data: Option<&[u8]>) -> Result<(), SaslError> {
            assert!(final_data.is_none());
            if self.0 == 2 {
                Ok(())
            } else {
                Err(SaslError::Custom("not finished"))
            }
        }
    }

    #[test]
    fn test_custom_mechanism() {
        assert!(CustomMechanism::new("bad name", || Box::new(Echo(0))).is_err());
        assert!(CustomMechanism::new("X\r\nQUIT", || Box::new(Echo(0))).is_err());
        let m = CustomMechanism::new("X-ECHO", || Box::new(Echo(0))).unwrap();
        let auth = Auth::new(Credentials::Custom(m));
        let o = offered(&["PLAIN", "X-ECHO"]);
        assert_eq!(
            Exchange::choose(&auth, o.iter().copied()),
            Ok(Some(MechanismName::Other))
        );
        let (line, mut ex) = Exchange::start(&auth, MechanismName::Other).unwrap();
        assert_eq!(&line[..], b"AUTH X-ECHO aGVsbG8=");
        assert_eq!(ex.finish(), Err(SaslError::Custom("not finished")));
        assert_eq!(&ex.respond(b"YWJj").unwrap().unwrap()[..], b"YWJj");
        assert_eq!(&ex.respond(b"").unwrap().unwrap()[..], b"");
        assert_eq!(ex.respond(b"").unwrap_err(), SaslError::TooManySteps);
        assert_eq!(ex.finish(), Ok(true));
    }
}
