<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>smtp-net</b>
    <br>
    <sub><sup>OUTGOING EMAIL</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/smtp-net"><img alt="Crates.io" src="https://img.shields.io/crates/v/smtp-net"></a>
    <a href="https://crates.io/crates/smtp-net"><img alt="Downloads" src="https://img.shields.io/crates/d/smtp-net?color=%230099ff"></a>
    <a href="https://docs.rs/smtp-net"><img alt="docs.rs" src="https://img.shields.io/docsrs/smtp-net"></a>
    <a href="https://github.com/jamesgober/smtp-net/actions"><img alt="CI" src="https://github.com/jamesgober/smtp-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>smtp-net</strong> sends email: account verification, password resets, alerts, and anything else a service needs to deliver. It builds standards-compliant MIME messages, signs them with DKIM so receiving servers trust them, and submits them over TLS.
    </p>
    <p>
        The protocol core is sans-IO, like http-net: the SMTP conversation is a state machine fed by bytes, so it is testable without a mail server. The transport runs over net-io and tls-net.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>.
    </p>
    <blockquote>
        <strong>Status: design lock (<code>0.2.0</code>).</strong> The public API is written down in <a href="./docs/API.md"><code>docs/API.md</code></a>, the design and every decision in <a href="./dev/PLAN.md"><code>dev/PLAN.md</code></a>, and the schedule in <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>. No functional code yet: <code>0.3.0</code> is the first release that sends mail.
    </blockquote>
</div>

<hr>
<br>

## Planned API

The simple path is one call. This is the contract from the design lock; it ships in `0.3.0` (local submission) and `0.4.0` (TLS relays).

```rust
// Send a plain-text email through the local mail server (for example Exim on 127.0.0.1:25).
let msg = smtp_net::Message::text(
    "Example <no-reply@example.com>",
    "user@example.org",
    "Confirm your email address",
    "Open this link to confirm: https://example.com/confirm/abc123",
)?;
let report = smtp_net::send_local(&msg)?;
println!("accepted as {}", report.message_id());

// Text plus HTML through a remote relay with STARTTLS on 587 and AUTH.
let msg = smtp_net::Message::html(from, to, "Reset your password", html, text)?;
let server = smtp_net::Server::starttls("mail.example.com").login("no-reply@example.com", password);
smtp_net::send(&server, &msg)?;
```

Every error says whether it is **temporary** (retry later) or **permanent** (do not retry), and whether the message was **possibly delivered**, so a job system can retry, dead-letter, or flag a possible duplicate without reading SMTP reply codes.

## Scope

SMTP submission (RFC 6409) with STARTTLS or implicit TLS (RFC 8314); AUTH PLAIN, LOGIN, XOAUTH2, and SCRAM-SHA-256; PIPELINING, CHUNKING, SIZE, 8BITMIME, SMTPUTF8, DSN, and enhanced status codes; MIME building (text, HTML, attachments, inline images, quoted-printable and base64, RFC 2047 and RFC 2231 encoding) with header injection refused, never stripped; DKIM signing (Ed25519 and RSA-SHA256); a versioned, checksummed job payload; a pacing gate for host limits; and a test server with fault injection. It does not receive mail, run a queue, or spawn a `sendmail` binary.

See [`dev/PLAN.md`](./dev/PLAN.md) for the full scope, what is deliberately left to other crates, and the decision log.

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b> &mdash; <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b> &mdash; <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
