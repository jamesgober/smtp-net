//! `Message-ID` and `Content-ID` values (RFC 5322 3.6.4, RFC 2392).

use alloc::string::String;

use parse_net::{CountSink, mail};

use crate::{encode, error::Error};

/// Random octets in a generated id: 128 bits, 26 base32 characters.
pub(crate) const ID_RANDOM: usize = 16;

/// Splits `left@right` (angle brackets optional) after checking both sides
/// are ASCII `dot-atom-text`. A `no-fold-literal` right side is refused.
pub(crate) fn split_msg_id(input: &str) -> Option<(&str, &str)> {
    let inner = input
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or(input);
    let (left, right) = inner.rsplit_once('@')?;
    if right.starts_with('[') {
        return None;
    }
    // write_msg_id validates both sides without writing (CountSink).
    mail::write_msg_id(left, right, &mut CountSink::new()).ok()?;
    Some((left, right))
}

/// Source of the random octets for `Message-ID` and MIME boundaries.
///
/// `MessageBuilder::build` uses the OS CSPRNG (feature `std`);
/// `build_with` takes any source, so `no_std` callers and tests can supply
/// their own. A source must never fall back to weaker randomness: return an
/// error instead (T-16).
pub trait RandomSource {
    /// Fills `buf` with random octets.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Random`](crate::ErrorKind::Random) when the source failed.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// The operating system's CSPRNG (`mod_rand::tier3`).
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

#[cfg(feature = "std")]
impl RandomSource for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        mod_rand::tier3::fill_bytes(buf).map_err(|_| Error::new(crate::ErrorKind::Random))
    }
}

/// `<26 base32 characters>@domain`, without brackets.
pub(crate) fn generate(random: &mut dyn RandomSource, domain: &str) -> Result<String, Error> {
    let mut bytes = [0u8; ID_RANDOM];
    random.fill(&mut bytes)?;
    let mut text = [0u8; 26];
    let n = encode::base32(&bytes, &mut text);
    let mut id = String::with_capacity(n + 1 + domain.len());
    id.push_str(core::str::from_utf8(text.get(..n).unwrap_or(&[])).unwrap_or(""));
    id.push('@');
    id.push_str(domain);
    Ok(id)
}

/// `=_` and 32 base32 characters of 160 random bits.
pub(crate) fn boundary(random: &mut dyn RandomSource) -> Result<String, Error> {
    let mut bytes = [0u8; 20];
    random.fill(&mut bytes)?;
    let mut text = [0u8; 32];
    let n = encode::base32(&bytes, &mut text);
    let mut b = String::with_capacity(2 + n);
    b.push_str("=_");
    b.push_str(core::str::from_utf8(text.get(..n).unwrap_or(&[])).unwrap_or(""));
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_msg_id_forms() {
        assert_eq!(
            split_msg_id("a.b@example.com"),
            Some(("a.b", "example.com"))
        );
        assert_eq!(split_msg_id("<a@b>"), Some(("a", "b")));
        assert_eq!(split_msg_id("a b@c"), None);
        assert_eq!(split_msg_id("a@[1.2.3.4]"), None);
        assert_eq!(split_msg_id("noat"), None);
        assert_eq!(split_msg_id("a@b\r\nX: y"), None);
        assert_eq!(split_msg_id(".a@b"), None);
    }

    struct Fixed(u8);
    impl RandomSource for Fixed {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
            buf.fill(self.0);
            Ok(())
        }
    }

    #[test]
    fn test_generated_id_and_boundary_shapes() {
        let id = generate(&mut Fixed(0), "example.com").unwrap();
        assert_eq!(id, "aaaaaaaaaaaaaaaaaaaaaaaaaa@example.com");
        let b = boundary(&mut Fixed(0xff)).unwrap();
        assert_eq!(b.len(), 34);
        assert!(b.starts_with("=_"));
    }
}
