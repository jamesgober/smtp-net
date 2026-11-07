//! SCRAM-SHA-256 client (RFC 5802, RFC 7677), without channel binding.
//!
//! The password never leaves the client; the server proves it holds the
//! stored key by its signature, checked in constant time (T-29).

use alloc::vec::Vec;

use crypt_io::Zeroizing;
use crypt_io::hash::sha256;
use crypt_io::kdf::pbkdf2_hmac_sha256;
use crypt_io::mac::{hmac_sha256, hmac_sha256_check};

use super::sasl::{SaslError, Secret};
use crate::encode::{base64_append, base64_decode};

/// Fewest iterations accepted: the RFC 7677 section 4 minimum.
pub(crate) const MIN_ITERATIONS: u32 = 4096;
/// Most iterations accepted, so a hostile server cannot pin the CPU
/// (about 1 s of PBKDF2) **[budget]**.
pub(crate) const MAX_ITERATIONS: u32 = 1_000_000;
/// Longest salt accepted after decoding.
const MAX_SALT: usize = 1024;

enum State {
    /// client-first sent; waiting for server-first.
    First,
    /// client-final sent; waiting for server-final.
    Final {
        auth_message: Vec<u8>,
        server_key: Zeroizing<[u8; 32]>,
    },
    /// The server's signature checked out.
    Verified,
    /// A server message was refused; nothing more is accepted.
    Failed,
}

pub(crate) struct Scram {
    password: Secret,
    nonce: Zeroizing<Vec<u8>>,
    client_first_bare: Vec<u8>,
    state: State,
}

/// 24 bytes from the OS CSPRNG, base64: 32 characters.
#[cfg(feature = "std")]
pub(crate) fn fresh_nonce() -> Result<Zeroizing<Vec<u8>>, SaslError> {
    let mut raw = Zeroizing::new([0u8; 24]);
    mod_rand::tier3::fill_bytes(&mut raw[..]).map_err(|_| SaslError::NonceMissing)?;
    let mut out = Zeroizing::new(Vec::with_capacity(32));
    base64_append(&raw[..], &mut out);
    Ok(out)
}

#[cfg(not(feature = "std"))]
pub(crate) fn fresh_nonce() -> Result<Zeroizing<Vec<u8>>, SaslError> {
    Err(SaslError::NonceMissing)
}

impl Scram {
    /// The exchange and its client-first message (`n,,n=user,r=nonce`).
    pub(crate) fn new(
        user: &str,
        password: &Secret,
        nonce: &[u8],
    ) -> Result<(Scram, Vec<u8>), SaslError> {
        let mut bare = Vec::with_capacity(user.len() + nonce.len() + 8);
        bare.extend_from_slice(b"n=");
        // saslname: '=' and ',' escaped (RFC 5802 section 5.1).
        for &b in user.as_bytes() {
            match b {
                b'=' => bare.extend_from_slice(b"=3D"),
                b',' => bare.extend_from_slice(b"=2C"),
                _ => bare.push(b),
            }
        }
        bare.extend_from_slice(b",r=");
        bare.extend_from_slice(nonce);
        let mut first = Vec::with_capacity(bare.len() + 3);
        first.extend_from_slice(b"n,,");
        first.extend_from_slice(&bare);
        Ok((
            Scram {
                password: password.clone(),
                nonce: Zeroizing::new(nonce.to_vec()),
                client_first_bare: bare,
                state: State::First,
            },
            first,
        ))
    }

    pub(crate) fn verified(&self) -> bool {
        matches!(self.state, State::Verified)
    }

    /// Answers server-first with client-final, or checks server-final and
    /// answers with an empty response.
    pub(crate) fn on_challenge(&mut self, message: &[u8]) -> Result<Vec<u8>, SaslError> {
        // Taken out as Failed: only a check that passes moves it on, so a
        // refused message can never leave the exchange looking verified.
        match core::mem::replace(&mut self.state, State::Failed) {
            State::First => self.on_server_first(message),
            State::Final {
                auth_message,
                server_key,
            } => {
                on_server_final(message, &auth_message, &server_key)?;
                self.state = State::Verified;
                Ok(Vec::new())
            }
            State::Verified => {
                self.state = State::Verified;
                Err(SaslError::TooManySteps)
            }
            State::Failed => Err(SaslError::TooManySteps),
        }
    }

    fn on_server_first(&mut self, message: &[u8]) -> Result<Vec<u8>, SaslError> {
        let mut parts = message.split(|&b| b == b',');
        let server_nonce = parts
            .next()
            .and_then(|p| p.strip_prefix(b"r="))
            .ok_or(SaslError::InvalidServerMessage)?;
        let salt_b64 = parts
            .next()
            .and_then(|p| p.strip_prefix(b"s="))
            .ok_or(SaslError::InvalidServerMessage)?;
        let iterations = parts
            .next()
            .and_then(|p| p.strip_prefix(b"i="))
            .ok_or(SaslError::InvalidServerMessage)?;
        // Extensions after i= are allowed and ignored; a mandatory one (m=)
        // would come first and fails the r= check above.
        if server_nonce.is_empty()
            || !server_nonce
                .iter()
                .all(|b| (0x21..=0x7e).contains(b) && *b != b',')
        {
            return Err(SaslError::InvalidServerMessage);
        }
        if server_nonce.len() <= self.nonce.len() || !server_nonce.starts_with(&self.nonce) {
            return Err(SaslError::ServerNonceMismatch);
        }
        let iterations = parse_u32(iterations).ok_or(SaslError::InvalidServerMessage)?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(SaslError::IterationsOutOfRange);
        }
        let mut salt = Vec::with_capacity(salt_b64.len() / 4 * 3);
        if salt_b64.len() > MAX_SALT * 2
            || base64_decode(salt_b64, &mut salt).is_err()
            || salt.is_empty()
        {
            return Err(SaslError::InvalidServerMessage);
        }

        let mut salted = Zeroizing::new([0u8; 32]);
        pbkdf2_hmac_sha256(self.password.expose(), &salt, iterations, &mut salted[..])
            .map_err(|_| SaslError::IterationsOutOfRange)?;
        let client_key = Zeroizing::new(mac(&salted[..], b"Client Key")?);
        let stored_key = Zeroizing::new(sha256(&client_key[..]));
        let server_key = Zeroizing::new(mac(&salted[..], b"Server Key")?);

        // c=biws is base64("n,,"): no channel binding, no authzid.
        let mut without_proof = Vec::with_capacity(server_nonce.len() + 9);
        without_proof.extend_from_slice(b"c=biws,r=");
        without_proof.extend_from_slice(server_nonce);
        let mut auth_message = Vec::with_capacity(
            self.client_first_bare.len() + message.len() + without_proof.len() + 2,
        );
        auth_message.extend_from_slice(&self.client_first_bare);
        auth_message.push(b',');
        auth_message.extend_from_slice(message);
        auth_message.push(b',');
        auth_message.extend_from_slice(&without_proof);

        let signature = Zeroizing::new(mac(&stored_key[..], &auth_message)?);
        let mut proof = Zeroizing::new([0u8; 32]);
        for ((p, k), s) in proof
            .iter_mut()
            .zip(client_key.iter())
            .zip(signature.iter())
        {
            *p = k ^ s;
        }
        let mut out = without_proof;
        out.extend_from_slice(b",p=");
        base64_append(&proof[..], &mut out);
        self.state = State::Final {
            auth_message,
            server_key,
        };
        Ok(out)
    }
}

fn on_server_final(
    message: &[u8],
    auth_message: &[u8],
    server_key: &[u8; 32],
) -> Result<(), SaslError> {
    let first = message.split(|&b| b == b',').next().unwrap_or(&[]);
    if first.starts_with(b"e=") {
        return Err(SaslError::ServerError);
    }
    let v = first
        .strip_prefix(b"v=")
        .ok_or(SaslError::InvalidServerMessage)?;
    let mut signature = Vec::with_capacity(32);
    if v.len() > 64 || base64_decode(v, &mut signature).is_err() {
        return Err(SaslError::InvalidServerMessage);
    }
    // Constant time (T-29): crypt-io compares the whole tag.
    hmac_sha256_check(server_key, auth_message, &signature)
        .map_err(|_| SaslError::ServerSignatureMismatch)
}

fn mac(key: &[u8], data: &[u8]) -> Result<[u8; 32], SaslError> {
    hmac_sha256(key, data).map_err(|_| SaslError::InvalidServerMessage)
}

fn parse_u32(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    digits.iter().try_fold(0u32, |n, d| {
        n.checked_mul(10)?.checked_add(u32::from(d - b'0'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7677 section 3.
    const NONCE: &[u8] = b"rOprNGfwEbeRWgbNEkqO";
    const SERVER_FIRST: &[u8] =
        b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const CLIENT_FINAL: &[u8] =
        b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const SERVER_FINAL: &[u8] = b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    fn client() -> Scram {
        let (s, first) = Scram::new("user", &Secret::from("pencil"), NONCE).unwrap();
        assert_eq!(first, b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        s
    }

    #[test]
    fn test_rfc7677_example_exchange() {
        let mut s = client();
        assert_eq!(s.on_challenge(SERVER_FIRST).unwrap(), CLIENT_FINAL);
        assert!(!s.verified());
        assert_eq!(s.on_challenge(SERVER_FINAL).unwrap(), b"");
        assert!(s.verified());
        assert_eq!(s.on_challenge(b"").unwrap_err(), SaslError::TooManySteps);
    }

    #[test]
    fn test_server_signature_checked_both_ways() {
        // T-29: the mismatch path, one bit off, and the e= path.
        let mut s = client();
        s.on_challenge(SERVER_FIRST).unwrap();
        assert_eq!(
            s.on_challenge(b"v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
                .unwrap_err(),
            SaslError::ServerSignatureMismatch
        );
        assert!(!s.verified());
        let mut s = client();
        s.on_challenge(SERVER_FIRST).unwrap();
        assert_eq!(
            s.on_challenge(b"e=invalid-proof").unwrap_err(),
            SaslError::ServerError
        );
        let mut s = client();
        s.on_challenge(SERVER_FIRST).unwrap();
        assert_eq!(
            s.on_challenge(b"x=1").unwrap_err(),
            SaslError::InvalidServerMessage
        );
    }

    #[test]
    fn test_server_first_checks() {
        let cases: &[(&[u8], SaslError)] = &[
            // Nonce equal to ours, shorter, not starting with ours.
            (
                b"r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
                SaslError::ServerNonceMismatch,
            ),
            (
                b"r=rOprNG,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
                SaslError::ServerNonceMismatch,
            ),
            (
                b"r=XOprNGfwEbeRWgbNEkqOabc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
                SaslError::ServerNonceMismatch,
            ),
            // Salt not base64, empty.
            (
                b"r=rOprNGfwEbeRWgbNEkqOabc,s=!!!!,i=4096",
                SaslError::InvalidServerMessage,
            ),
            (
                b"r=rOprNGfwEbeRWgbNEkqOabc,s=,i=4096",
                SaslError::InvalidServerMessage,
            ),
            // Iterations: 0, 4095, 1000001, not a number, overflow.
            (
                b"r=rOprNGfwEbeRWgbNEkqOabc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0",
                SaslError::IterationsOutOfRange,
            ),
            (
                b"r=rOprNGfwEbeRWgbNEkqOabc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4095",
                SaslError::IterationsOutOfRange,
            ),
            (
                b"r=rOprNGfwEbeRWgbNEkqOabc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=1000001",
                SaslError::IterationsOutOfRange,
            ),
            (
                b"r=rOprNGfwEbeRWgbNEkqOabc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4k",
                SaslError::InvalidServerMessage,
            ),
            (
                b"r=rOprNGfwEbeRWgbNEkqOabc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=99999999999",
                SaslError::InvalidServerMessage,
            ),
            // A mandatory extension, missing attributes, wrong order.
            (
                b"m=x,r=rOprNGfwEbeRWgbNEkqOabc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
                SaslError::InvalidServerMessage,
            ),
            (
                b"r=rOprNGfwEbeRWgbNEkqOabc",
                SaslError::InvalidServerMessage,
            ),
            (
                b"s=W22ZaJ0SNY7soEsUEjb6gQ==,r=rOprNGfwEbeRWgbNEkqOabc,i=4096",
                SaslError::InvalidServerMessage,
            ),
        ];
        for (msg, want) in cases {
            assert_eq!(
                client().on_challenge(msg).unwrap_err(),
                *want,
                "{}",
                String::from_utf8_lossy(msg)
            );
        }
        // 4096 exactly and an extension after i= are fine.
        let ok = b"r=rOprNGfwEbeRWgbNEkqOabc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=ext";
        assert!(client().on_challenge(ok).is_ok());
    }

    #[test]
    fn test_a_refused_message_never_leaves_it_verified() {
        let mut s = client();
        assert!(
            s.on_challenge(b"r=nope,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
                .is_err()
        );
        assert!(!s.verified());
        assert_eq!(
            s.on_challenge(SERVER_FIRST).unwrap_err(),
            SaslError::TooManySteps
        );
        let mut s = client();
        s.on_challenge(SERVER_FIRST).unwrap();
        assert!(s.on_challenge(b"v=AAAA").is_err());
        assert!(!s.verified());
        assert_eq!(
            s.on_challenge(SERVER_FINAL).unwrap_err(),
            SaslError::TooManySteps
        );
        assert!(!s.verified());
    }

    #[test]
    fn test_user_name_escaping() {
        let (_, first) = Scram::new("a=b,c", &Secret::from("p"), NONCE).unwrap();
        assert_eq!(first, b"n,,n=a=3Db=2Cc,r=rOprNGfwEbeRWgbNEkqO");
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_fresh_nonces_differ() {
        let a = fresh_nonce().unwrap();
        let b = fresh_nonce().unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    /// T-29, dudect style: checking a wrong server signature takes the same
    /// time whether it differs from the right one in its first octet or its
    /// last; an early-exit comparison would be faster for the first. The
    /// check runs on the decoded signature, the step `on_server_final` hands
    /// to crypt-io: the base64 before it reads only bytes the server sent.
    /// The two classes are interleaved at random, each sample times 8
    /// checks, the slowest 10% of each class is cropped, and Welch's t must
    /// stay under 4.5 (dudect's threshold). Timing depends on the machine,
    /// so it runs on request, in release:
    /// `cargo test --release --features scram --lib scram::tests::timing -- --ignored --nocapture`.
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "timing; run in release on request"]
    fn timing_server_signature_check() {
        use std::time::Instant;

        const SAMPLES: usize = 200_000;
        const BATCH: usize = 8;
        let key = [0x5au8; 32];
        let auth = b"n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
        let good = mac(&key, auth).unwrap();
        let wrong = |octet: usize| {
            let mut s = good;
            s[octet] ^= 1;
            s
        };
        let classes = [wrong(0), wrong(31)];
        let mut times: [Vec<u64>; 2] = [Vec::with_capacity(SAMPLES), Vec::with_capacity(SAMPLES)];
        let mut x = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..2 * SAMPLES {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let c = (x & 1) as usize;
            let sig = core::hint::black_box(&classes[c]);
            let t = Instant::now();
            for _ in 0..BATCH {
                let r = hmac_sha256_check(&key, auth, core::hint::black_box(sig));
                assert!(core::hint::black_box(r).is_err());
            }
            times[c].push(t.elapsed().as_nanos() as u64);
        }
        let stats = |v: &mut Vec<u64>| {
            v.sort_unstable();
            v.truncate(v.len() * 9 / 10);
            let n = v.len() as f64;
            let mean = v.iter().map(|&t| t as f64).sum::<f64>() / n;
            let var = v.iter().map(|&t| (t as f64 - mean).powi(2)).sum::<f64>() / (n - 1.0);
            (n, mean, var)
        };
        let [mut a, mut b] = times;
        let (na, ma, va) = stats(&mut a);
        let (nb, mb, vb) = stats(&mut b);
        let t = (ma - mb) / (va / na + vb / nb).sqrt();
        std::println!(
            "{BATCH} checks, first octet wrong: {ma:.1} ns, last octet wrong: {mb:.1} ns, Welch t = {t:.2} ({na} and {nb} samples)"
        );
        assert!(t.abs() < 4.5, "timing differs: t = {t:.2}");
    }
}
