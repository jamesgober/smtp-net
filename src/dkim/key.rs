//! DKIM private keys: Ed25519 and RSA through crypt-io (T-21, T-22).

use alloc::sync::Arc;
use core::fmt;

use crypt_io::Zeroizing;
use crypt_io::sign::{Ed25519SigningKey, RsaSigningKey};

use crate::encode::{base64_append, base64_decode};
use crate::error::DkimError;

/// Smallest RSA modulus accepted, in bits (RFC 8301 section 3.2 SHOULD;
/// crypt-io refuses anything smaller, D-066).
pub const DKIM_RSA_MIN_BITS: u32 = 2048;
/// Largest RSA modulus accepted, in bits: the most every verifier must
/// handle (RFC 8301 section 3.2).
pub const DKIM_RSA_MAX_BITS: u32 = 4096;

/// The signing algorithm a key produces (the `a=` tag).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DkimAlgorithm {
    /// `ed25519-sha256` (RFC 8463).
    Ed25519Sha256,
    /// `rsa-sha256` (RFC 6376, RFC 8301).
    RsaSha256,
}

impl DkimAlgorithm {
    /// The value of the `a=` tag.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            DkimAlgorithm::Ed25519Sha256 => "ed25519-sha256",
            DkimAlgorithm::RsaSha256 => "rsa-sha256",
        }
    }
}

enum Inner {
    Ed25519(Ed25519SigningKey),
    Rsa(RsaSigningKey),
}

/// A DKIM private key.
///
/// The key material lives inside crypt-io's signing types, which wipe it on
/// drop; this type keeps no copy, its `Debug` prints only the algorithm and
/// size, and no error ever carries key bytes (T-22). Cloning shares the one
/// key. The bytes a key is parsed from stay in the caller's buffer: wipe it
/// once the key is built.
///
/// # Examples
///
/// ```
/// use smtp_net::{DkimAlgorithm, DkimKey};
/// // RFC 8032 section 7.1, test 1 (the key in RFC 8463's example).
/// let seed = [
///     0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
///     0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
/// ];
/// let key = DkimKey::ed25519_from_seed(&seed)?;
/// assert_eq!(key.algorithm(), DkimAlgorithm::Ed25519Sha256);
/// assert_eq!(key.dns_record(), "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=");
/// # Ok::<(), smtp_net::DkimError>(())
/// ```
#[derive(Clone)]
pub struct DkimKey {
    inner: Arc<Inner>,
}

impl DkimKey {
    /// An Ed25519 key from a `-----BEGIN PRIVATE KEY-----` PEM document
    /// (PKCS#8, what `openssl genpkey -algorithm ed25519` writes).
    ///
    /// # Errors
    ///
    /// [`DkimError::KeyFormat`].
    pub fn ed25519_from_pkcs8_pem(pem: &str) -> Result<DkimKey, DkimError> {
        let (label, der) = pem_decode(pem)?;
        if label != "PRIVATE KEY" {
            return Err(DkimError::KeyFormat);
        }
        DkimKey::ed25519_from_pkcs8_der(&der)
    }

    /// An Ed25519 key from PKCS#8 DER (RFC 5208 v1 or RFC 5958 v2).
    ///
    /// # Errors
    ///
    /// [`DkimError::KeyFormat`].
    pub fn ed25519_from_pkcs8_der(der: &[u8]) -> Result<DkimKey, DkimError> {
        let key = Ed25519SigningKey::from_pkcs8_der(der).map_err(|_| DkimError::KeyFormat)?;
        Ok(DkimKey::wrap(Inner::Ed25519(key)))
    }

    /// An Ed25519 key from its 32-byte seed (RFC 8032 section 5.1.5), for
    /// keys kept in a vault or a KMS.
    ///
    /// # Errors
    ///
    /// [`DkimError::KeyFormat`] if the backend cannot build the key.
    pub fn ed25519_from_seed(seed: &[u8; 32]) -> Result<DkimKey, DkimError> {
        let key = Ed25519SigningKey::from_seed(seed).map_err(|_| DkimError::KeyFormat)?;
        Ok(DkimKey::wrap(Inner::Ed25519(key)))
    }

    /// An RSA key from PEM: `-----BEGIN PRIVATE KEY-----` (PKCS#8) or
    /// `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1). Encrypted keys are
    /// refused; decrypt them before loading.
    ///
    /// # Errors
    ///
    /// [`DkimError::KeyFormat`], [`DkimError::KeyTooSmall`] (under 2048
    /// bits), [`DkimError::KeyTooLarge`] (over 4096 bits).
    pub fn rsa_from_pem(pem: &str) -> Result<DkimKey, DkimError> {
        let (label, der) = pem_decode(pem)?;
        match label {
            "PRIVATE KEY" => DkimKey::rsa(&der, Form::Pkcs8),
            "RSA PRIVATE KEY" => DkimKey::rsa(&der, Form::Pkcs1),
            _ => Err(DkimError::KeyFormat),
        }
    }

    /// An RSA key from DER, PKCS#8 or PKCS#1 (told apart by structure).
    ///
    /// # Errors
    ///
    /// As [`rsa_from_pem`](Self::rsa_from_pem).
    pub fn rsa_from_der(der: &[u8]) -> Result<DkimKey, DkimError> {
        let form = der_form(der).ok_or(DkimError::KeyFormat)?;
        DkimKey::rsa(der, form)
    }

    fn rsa(der: &[u8], form: Form) -> Result<DkimKey, DkimError> {
        // Measure first, so a short key gets a precise error instead of the
        // backend's generic refusal.
        let bits = modulus_bits(der, form).ok_or(DkimError::KeyFormat)?;
        if bits < DKIM_RSA_MIN_BITS {
            return Err(DkimError::KeyTooSmall {
                bits,
                minimum: DKIM_RSA_MIN_BITS,
            });
        }
        if bits > DKIM_RSA_MAX_BITS {
            return Err(DkimError::KeyTooLarge { bits });
        }
        let key = match form {
            Form::Pkcs8 => RsaSigningKey::from_pkcs8_der(der),
            Form::Pkcs1 => RsaSigningKey::from_pkcs1_der(der),
        }
        .map_err(|_| DkimError::KeyFormat)?;
        Ok(DkimKey::wrap(Inner::Rsa(key)))
    }

    fn wrap(inner: Inner) -> DkimKey {
        DkimKey {
            inner: Arc::new(inner),
        }
    }

    /// Which `a=` value the key produces.
    #[must_use]
    pub fn algorithm(&self) -> DkimAlgorithm {
        match *self.inner {
            Inner::Ed25519(_) => DkimAlgorithm::Ed25519Sha256,
            Inner::Rsa(_) => DkimAlgorithm::RsaSha256,
        }
    }

    /// The RSA modulus length in bits; `None` for Ed25519.
    #[must_use]
    pub fn rsa_bits(&self) -> Option<u32> {
        match &*self.inner {
            Inner::Ed25519(_) => None,
            Inner::Rsa(k) => Some(k.modulus_bits()),
        }
    }

    /// The TXT record value to publish at `<selector>._domainkey.<domain>`:
    /// `v=DKIM1; k=ed25519; p=<44 characters>` (RFC 8463 section 4.2) or
    /// `v=DKIM1; k=rsa; p=<base64 SubjectPublicKeyInfo>`. An RSA record is
    /// longer than 255 octets; DNS publishes it as several strings of one
    /// TXT record, which the DNS host's interface usually does on its own.
    #[must_use]
    pub fn dns_record(&self) -> String {
        let mut out = Vec::with_capacity(32 + 4 * 600 / 3);
        match &*self.inner {
            Inner::Ed25519(k) => {
                out.extend_from_slice(b"v=DKIM1; k=ed25519; p=");
                base64_append(&k.public_key(), &mut out);
            }
            Inner::Rsa(k) => {
                out.extend_from_slice(b"v=DKIM1; k=rsa; p=");
                base64_append(k.public_key_der(), &mut out);
            }
        }
        String::from_utf8(out).unwrap_or_default()
    }

    /// Signs the canonicalized header data: PKCS#1 v1.5 over SHA-256 for
    /// RSA; PureEdDSA over the SHA-256 of the data for Ed25519 (RFC 8463
    /// section 3).
    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DkimError> {
        match &*self.inner {
            Inner::Ed25519(k) => Ok(k.sign(&crypt_io::hash::sha256(data)).to_vec()),
            Inner::Rsa(k) => k.sign_pkcs1v15_sha256(data).map_err(|_| DkimError::Signing),
        }
    }
}

impl fmt::Debug for DkimKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("DkimKey");
        d.field("algorithm", &self.algorithm());
        if let Some(bits) = self.rsa_bits() {
            d.field("bits", &bits);
        }
        d.finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum Form {
    Pkcs8,
    Pkcs1,
}

/// Longest PEM document read (an 8192-bit RSA key is about 6.5 KB).
const MAX_PEM: usize = 16 * 1024;

/// The label and the decoded body of the first PEM block in `pem`.
fn pem_decode(pem: &str) -> Result<(&str, Zeroizing<Vec<u8>>), DkimError> {
    if pem.len() > MAX_PEM {
        return Err(DkimError::KeyFormat);
    }
    let begin = pem.find("-----BEGIN ").ok_or(DkimError::KeyFormat)?;
    let rest = pem.get(begin + 11..).ok_or(DkimError::KeyFormat)?;
    let label_end = rest.find("-----").ok_or(DkimError::KeyFormat)?;
    let label = rest.get(..label_end).ok_or(DkimError::KeyFormat)?;
    let body = rest.get(label_end + 5..).ok_or(DkimError::KeyFormat)?;
    let end = body.find("-----END ").ok_or(DkimError::KeyFormat)?;
    let tail = body.get(end + 9..).ok_or(DkimError::KeyFormat)?;
    if tail.get(..label.len()) != Some(label)
        || tail.get(label.len()..label.len() + 5) != Some("-----")
    {
        return Err(DkimError::KeyFormat);
    }
    let text = body.get(..end).ok_or(DkimError::KeyFormat)?;
    // The base64 text is key material too: gather it in wiped buffers sized
    // up front, so no reallocation leaves a copy behind.
    let mut b64 = Zeroizing::new(Vec::with_capacity(text.len()));
    b64.extend(text.bytes().filter(|c| !c.is_ascii_whitespace()));
    let mut der = Zeroizing::new(Vec::with_capacity(b64.len() / 4 * 3));
    base64_decode(&b64, &mut der).map_err(|()| DkimError::KeyFormat)?;
    Ok((label, der))
}

/// One DER element: (tag, contents, the bytes after it).
fn der_next(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *buf.first()?;
    let first = *buf.get(1)?;
    let (len, start) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 3 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*buf.get(2 + i)?);
        }
        (len, 2 + n)
    };
    let contents = buf.get(start..start.checked_add(len)?)?;
    Some((tag, contents, buf.get(start + len..)?))
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;

/// PKCS#8 has an AlgorithmIdentifier SEQUENCE second; PKCS#1 an INTEGER.
fn der_form(der: &[u8]) -> Option<Form> {
    let (tag, seq, _) = der_next(der)?;
    if tag != SEQUENCE {
        return None;
    }
    let (_, _, rest) = der_next(seq)?;
    match der_next(rest)?.0 {
        SEQUENCE => Some(Form::Pkcs8),
        INTEGER => Some(Form::Pkcs1),
        _ => None,
    }
}

/// The modulus length of an RSA private key, read from its DER structure.
fn modulus_bits(der: &[u8], form: Form) -> Option<u32> {
    let (tag, seq, _) = der_next(der)?;
    if tag != SEQUENCE {
        return None;
    }
    let pkcs1 = match form {
        Form::Pkcs1 => seq,
        Form::Pkcs8 => {
            // version, AlgorithmIdentifier, privateKey OCTET STRING.
            let (_, _, rest) = der_next(seq)?;
            let (_, _, rest) = der_next(rest)?;
            let (tag, inner, _) = der_next(rest)?;
            if tag != OCTET_STRING {
                return None;
            }
            let (tag, inner, _) = der_next(inner)?;
            if tag != SEQUENCE {
                return None;
            }
            inner
        }
    };
    // RSAPrivateKey: version, modulus, ...
    let (_, _, rest) = der_next(pkcs1)?;
    let (tag, modulus, _) = der_next(rest)?;
    if tag != INTEGER {
        return None;
    }
    let skip = modulus.iter().position(|&b| b != 0)?;
    let m = modulus.get(skip..)?;
    let top = u32::from(*m.first()?);
    u32::try_from(m.len() - 1)
        .ok()?
        .checked_mul(8)?
        .checked_add(32 - top.leading_zeros())
}
