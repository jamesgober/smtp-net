//! SASL for SMTP AUTH (RFC 4954): credentials, the mechanism allowlist, and
//! the client side of PLAIN (RFC 4616) and LOGIN.

use alloc::{string::String, vec::Vec};
use core::fmt;

use crypt_io::Zeroizing;

use crate::error::{ConfigError, Error};

/// Longest AUTH command or response line, including CRLF (RFC 4954 4).
pub const MAX_AUTH_LINE: usize = 12_288;
/// Most challenge-response steps a built-in mechanism takes before the
/// exchange is refused as a protocol error.
pub(crate) const MAX_STEPS: u8 = 8;
/// Most mechanisms in an allowlist.
const MAX_MECHANISMS: usize = 8;

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
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<Vec<u8>>);

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
    /// A user name and a password (PLAIN, LOGIN).
    Password {
        /// The user name.
        user: String,
        /// The password.
        password: Secret,
    },
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

    /// The user name.
    #[must_use]
    pub fn user(&self) -> &str {
        match self {
            Credentials::Password { user, .. } => user,
        }
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
}

impl MechanismName {
    /// The name the server advertises.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            MechanismName::Plain => "PLAIN",
            MechanismName::Login => "LOGIN",
        }
    }
}

impl fmt::Display for MechanismName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The ordered allowlist the client chooses from (FR-35): the first one the
/// server offers wins; the server's order is ignored and there is no
/// fallback outside the list (T-10).
///
/// # Examples
///
/// ```
/// use smtp_net::{MechanismList, MechanismName};
/// let list = MechanismList::new(&[MechanismName::Login])?;
/// assert_eq!(list.iter().count(), 1);
/// assert_eq!(MechanismList::default().iter().next(), Some(MechanismName::Plain));
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
    /// `[Plain, Login]`.
    fn default() -> MechanismList {
        MechanismList(alloc::vec![MechanismName::Plain, MechanismName::Login])
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
}

impl Auth {
    /// `credentials` with the default allowlist.
    #[must_use]
    pub fn new(credentials: Credentials) -> Auth {
        Auth {
            credentials,
            mechanisms: MechanismList::default(),
        }
    }

    /// Replaces the allowlist.
    #[must_use]
    pub fn mechanisms(mut self, list: MechanismList) -> Auth {
        self.mechanisms = list;
        self
    }
}

/// A SASL exchange was refused on the client side.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SaslError {
    /// A user name or password holds a NUL, which PLAIN cannot carry.
    InvalidCredential,
    /// The server's challenge is not valid base64.
    InvalidChallenge,
    /// The exchange took more steps than the mechanism has.
    TooManySteps,
}

impl fmt::Display for SaslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SaslError::InvalidCredential => {
                "the user name or password holds a NUL character, which AUTH PLAIN cannot send"
            }
            SaslError::InvalidChallenge => "the server's AUTH challenge is not valid base64",
            SaslError::TooManySteps => {
                "the server asked for more AUTH steps than the mechanism has"
            }
        })
    }
}

/// The client side of one SASL exchange.
#[derive(Clone, Debug)]
pub(crate) struct Exchange {
    pub(crate) mechanism: MechanismName,
    /// Responses still to send, in order, as base64 (already encoded).
    responses: Vec<Zeroizing<Vec<u8>>>,
    pub(crate) steps: u8,
}

impl Exchange {
    /// Picks the first mechanism of `auth`'s list the server offers.
    pub(crate) fn choose<'a>(
        auth: &Auth,
        offered: impl Iterator<Item = &'a [u8]> + Clone,
    ) -> Option<MechanismName> {
        auth.mechanisms.iter().find(|m| {
            offered
                .clone()
                .any(|o| o.eq_ignore_ascii_case(m.as_str().as_bytes()))
        })
    }

    /// The AUTH command line (without CRLF) and the exchange that follows it.
    pub(crate) fn start(
        auth: &Auth,
        mechanism: MechanismName,
    ) -> Result<(Zeroizing<Vec<u8>>, Exchange), SaslError> {
        let Credentials::Password { user, password } = &auth.credentials;
        let mut line = Zeroizing::new(Vec::with_capacity(64));
        line.extend_from_slice(b"AUTH ");
        line.extend_from_slice(mechanism.as_str().as_bytes());
        let mut responses = Vec::new();
        match mechanism {
            MechanismName::Plain => {
                if user.as_bytes().contains(&0) || password.expose().contains(&0) {
                    return Err(SaslError::InvalidCredential);
                }
                // authzid (empty) NUL authcid NUL passwd
                let mut msg = Zeroizing::new(Vec::with_capacity(user.len() + password.len() + 2));
                msg.push(0);
                msg.extend_from_slice(user.as_bytes());
                msg.push(0);
                msg.extend_from_slice(password.expose());
                let mut b64 = Zeroizing::new(Vec::with_capacity(msg.len() * 4 / 3 + 4));
                crate::encode::base64_append(&msg, &mut b64);
                if line.len() + 1 + b64.len() + 2 <= MAX_AUTH_LINE {
                    line.push(b' ');
                    line.extend_from_slice(&b64);
                } else {
                    // Too long for an initial response: sent after the 334 (RFC 4954 4).
                    responses.push(b64);
                }
            }
            MechanismName::Login => {
                for value in [user.as_bytes(), password.expose()] {
                    let mut b64 = Zeroizing::new(Vec::new());
                    crate::encode::base64_append(value, &mut b64);
                    responses.push(b64);
                }
            }
        }
        responses.reverse();
        Ok((
            line,
            Exchange {
                mechanism,
                responses,
                steps: 0,
            },
        ))
    }

    /// The response to a `334` challenge, or `None` when the mechanism has
    /// nothing more to send.
    pub(crate) fn respond(
        &mut self,
        challenge: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SaslError> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > MAX_STEPS {
            return Err(SaslError::TooManySteps);
        }
        // PLAIN and LOGIN challenges are informational; they must still be base64.
        let mut scratch = Vec::new();
        if crate::encode::base64_decode(challenge, &mut scratch).is_err() {
            return Err(SaslError::InvalidChallenge);
        }
        Ok(self.responses.pop())
    }

    /// True when every response was sent.
    pub(crate) fn complete(&self) -> bool {
        self.responses.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn test_secret_never_formatted() {
        let c = Credentials::password("user@example.com", "s3cr3t-value");
        let a = Auth::new(c);
        for s in [
            format!("{a:?}"),
            format!("{:?}", a.credentials),
            format!("{}", Secret::from("s3cr3t-value")),
        ] {
            assert!(!s.contains("s3cr3t-value"), "{s}");
        }
        assert!(format!("{a:?}").contains("user@example.com"));
    }

    #[test]
    fn test_plain_initial_response_rfc4616() {
        let auth = Auth::new(Credentials::password("tim", "tanstaaftanstaaf"));
        let (line, ex) = Exchange::start(&auth, MechanismName::Plain).unwrap();
        assert_eq!(&line[..], b"AUTH PLAIN AHRpbQB0YW5zdGFhZnRhbnN0YWFm");
        assert!(ex.complete());
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
        assert!(!ex.complete());
        let r = ex.respond(b"").unwrap().unwrap();
        assert!(r.len() > 12_000);
        assert!(ex.complete());
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
        assert!(ex.complete());
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
    fn test_choose_follows_client_order_not_server_order() {
        let auth = Auth::new(Credentials::password("u", "p"));
        let offered: [&[u8]; 3] = [b"LOGIN", b"CRAM-MD5", b"plain"];
        assert_eq!(
            Exchange::choose(&auth, offered.iter().copied()),
            Some(MechanismName::Plain)
        );
        let login_only = auth
            .clone()
            .mechanisms(MechanismList::new(&[MechanismName::Login]).unwrap());
        assert_eq!(
            Exchange::choose(&login_only, [&b"PLAIN"[..]].iter().copied()),
            None
        );
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
}
