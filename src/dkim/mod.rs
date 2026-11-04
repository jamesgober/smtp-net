//! DKIM signing (RFC 6376, RFC 8463, RFC 8301).
//!
//! The canonicalizers are always built and `no_std`; keys and the signer
//! need the `dkim` feature.

mod canon;
#[cfg(feature = "dkim")]
mod key;
#[cfg(feature = "dkim")]
mod signer;

pub use canon::{BodyCanonicalizer, Canonicalization, HeaderCanonicalizer};
#[cfg(feature = "dkim")]
pub use key::{DKIM_RSA_MAX_BITS, DKIM_RSA_MIN_BITS, DkimAlgorithm, DkimKey};
#[cfg(feature = "dkim")]
pub use signer::DkimSigner;
#[cfg(feature = "dkim")]
pub(crate) use signer::sign_all;
