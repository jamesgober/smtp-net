//! Stage timeouts (RFC 5321 4.5.3.2) and the caller's monotonic clock.

use core::time::Duration;

/// A point on the caller's monotonic clock, in milliseconds. The session
/// never reads a clock itself; the driver passes the time in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Millis(pub u64);

impl Millis {
    /// `self + d`, saturating.
    #[must_use]
    pub fn after(self, d: Duration) -> Millis {
        Millis(
            self.0
                .saturating_add(u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        )
    }
}

/// Timeouts for each stage of the conversation.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// let t = smtp_net::Timeouts::rfc5321();
/// assert_eq!(t.data_end, Duration::from_secs(600));
/// assert!(smtp_net::Timeouts::local().data_end < t.data_end);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// TCP connect, per attempt budget across all addresses (30 s) **[est.]**.
    pub connect: Duration,
    /// The `220` greeting (5 min, RFC 5321 4.5.3.2.1).
    pub greeting: Duration,
    /// EHLO, HELO, STARTTLS, AUTH, RSET, NOOP, QUIT replies (5 min).
    pub command: Duration,
    /// The TLS handshake (60 s) **[est.]**.
    pub tls_handshake: Duration,
    /// The MAIL reply (5 min, 4.5.3.2.2).
    pub mail: Duration,
    /// Each RCPT reply (5 min, 4.5.3.2.3).
    pub rcpt: Duration,
    /// The `354` reply to DATA (2 min, 4.5.3.2.4).
    pub data_init: Duration,
    /// Each block of body data written (3 min, 4.5.3.2.5): the deadline is
    /// renewed for every block, so a slow but steady upload is not cut off.
    pub data_block: Duration,
    /// The reply to the end of the data (10 min, 4.5.3.2.6).
    pub data_end: Duration,
    /// How long a reused connection may sit idle before it is closed (60 s,
    /// below the server's 5 min of 4.5.3.2.7).
    pub idle: Duration,
    /// An optional bound on a whole send (connect, TLS, AUTH, and every
    /// transaction; for a `Pool`, from before the connect); `None` by
    /// default. When it runs out first the error is `Timeout` at
    /// `Stage::Total`. The blocking client applies it; a sans-IO driver
    /// applies its own.
    pub total: Option<Duration>,
}

impl Timeouts {
    /// The RFC 5321 values (the default, D-010).
    #[must_use]
    pub const fn rfc5321() -> Timeouts {
        Timeouts {
            connect: Duration::from_secs(30),
            greeting: Duration::from_secs(300),
            command: Duration::from_secs(300),
            tls_handshake: Duration::from_secs(60),
            mail: Duration::from_secs(300),
            rcpt: Duration::from_secs(300),
            data_init: Duration::from_secs(120),
            data_block: Duration::from_secs(180),
            data_end: Duration::from_secs(600),
            idle: Duration::from_secs(60),
            total: None,
        }
    }

    /// Shorter values for submission to a mail server on the same machine:
    /// connect 2 s, replies 30 s, end of data 120 s **[est.]**. These are
    /// below what RFC 5321 recommends; a slow content scan past 120 s turns
    /// into a `possibly_delivered` error and a possible duplicate on retry.
    #[must_use]
    pub const fn local() -> Timeouts {
        Timeouts {
            connect: Duration::from_secs(2),
            greeting: Duration::from_secs(30),
            command: Duration::from_secs(30),
            tls_handshake: Duration::from_secs(10),
            mail: Duration::from_secs(30),
            rcpt: Duration::from_secs(30),
            data_init: Duration::from_secs(30),
            data_block: Duration::from_secs(30),
            data_end: Duration::from_secs(120),
            idle: Duration::from_secs(60),
            total: None,
        }
    }
}

impl Default for Timeouts {
    fn default() -> Timeouts {
        Timeouts::rfc5321()
    }
}
