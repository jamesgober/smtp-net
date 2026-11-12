//! DKIM canonicalization (RFC 6376 section 3.4), for code that hashes or
//! verifies DKIM itself (Tier 3).
//!
//! Signing needs none of this: build a `DkimSigner` (feature `dkim`) and
//! add it to the server with `ServerBuilder::dkim`, or sign a prepared
//! message with `PreparedMessage::sign`. The canonicalizers are always
//! built and `no_std`.

pub(crate) mod canon;
#[cfg(feature = "dkim")]
pub(crate) mod key;
#[cfg(feature = "dkim")]
pub(crate) mod signer;

pub use canon::{BodyCanonicalizer, HeaderCanonicalizer};
#[cfg(feature = "dkim")]
pub(crate) use signer::sign_all;
