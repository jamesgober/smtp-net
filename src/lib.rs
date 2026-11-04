//! # smtp_net
//!
//! SMTP client for Rust: message submission over STARTTLS or implicit TLS, authentication, pipelining, MIME message building, DKIM signing, and a sans-IO core.
//!
//! ## Status
//!
//! Design lock (`0.2.0`). The public API is written down in `docs/API.md`,
//! the design and decisions in `dev/PLAN.md`, and the schedule in
//! `dev/ROADMAP.md` (all in the
//! [repository](https://github.com/jamesgober/smtp-net)). The first
//! functional release is `0.3.0`; this release contains only [`VERSION`].

#![doc(html_root_url = "https://docs.rs/smtp-net")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
