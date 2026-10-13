# smtp-net - Project Plan

> The design, strategy, and decision record for `smtp-net`. A living document: every design decision, idea, or open question about smtp-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md).
>
> **Status:** scaffold, `0.1.0`. Design lock is `0.2.0`.

---

## 1. Purpose

smtp-net sends email for services: account verification, password resets, alerts, receipts. It builds the message, signs it, and submits it to a mail server. It does not receive mail.

## 2. How mail leaves (first run)

On the cPanel server, the simplest reliable path is submission to the server's own mail service (Exim) on `localhost:587` with authentication; Exim handles delivery, retries, and the DNS side. smtp-net can also submit to any external relay over the internet.

## 3. The protocol core (sans-IO)

- A client state machine for the SMTP conversation: greeting, `EHLO`, `STARTTLS` and re-`EHLO`, `AUTH`, `MAIL FROM`, `RCPT TO`, `DATA` with dot-stuffing, `RSET`, `QUIT`.
- Reply parsing including multi-line replies, with budgets.
- Extensions: `PIPELINING` (RFC 2920), `SIZE`, `8BITMIME`, `SMTPUTF8`, `ENHANCEDSTATUSCODES`.
- Fed bytes, emits bytes; testable without a server.

## 4. Transport

- Over net-io (TCP) and tls-net: implicit TLS on 465 or `STARTTLS` on 587; plaintext only for `localhost` and only when configured explicitly.
- Server certificate verification on by default.
- Connection reuse for batches.

## 5. Messages (MIME)

- RFC 5322 headers with encoded words (RFC 2047) for non-ASCII; `Message-ID` and `Date` generated.
- Bodies: text, HTML, `multipart/alternative` for both, attachments (`multipart/mixed`), inline images (`multipart/related`); quoted-printable or base64 transfer encoding chosen per part; line length limits respected.
- **Header injection refused:** CR or LF in any header value, address, or subject is an error, never stripped.
- Address parsing and validation (RFC 5322 mailbox syntax, internationalized addresses with `SMTPUTF8`).

## 6. Authentication of our mail

| Mechanism | Who does it |
|---|---|
| **DKIM** signature (RFC 6376), relaxed/relaxed canonicalization | smtp-net, with Ed25519 (RFC 8463) and RSA-SHA256; keys from key-vault |
| SPF and DMARC | DNS records published for the domain (documented in the guide, not code) |

RSA signing needs RSA in crypt-io; to be confirmed at design lock (Ed25519 alone is not yet accepted everywhere, so both are signed).

## 7. Sending model

- `send(message)` submits now and reports the server's verdict per recipient.
- Queuing, retries with backoff, and dead letters live in the service's job system (task-io or the stack's jobs crate); smtp-net provides the hook and classifies failures as temporary or permanent.

## 8. Threats

| Threat | Defence |
|---|---|
| header injection (a user's name in a subject line adding a `Bcc:`) | CR and LF refused everywhere |
| credential exposure | `AUTH` only after TLS; credentials from key-vault, zeroized |
| downgrade (a server that drops `STARTTLS`) | TLS required by default; refusal, not fallback |
| spoofing of our domain | DKIM, with SPF and DMARC documented |
| oversized messages | budgets and the server's `SIZE` |

## 9. Architecture

```
src/
  lib.rs       crate docs, Tier-1 entry points (send)
  proto.rs     sans-IO client state machine, reply parsing
  transport.rs net-io and tls-net transport
  message/     builder, headers, encoded words, MIME parts, transfer encodings
  address.rs   mailbox parsing and validation
  dkim.rs      canonicalization and signing
  error.rs     SmtpError (#[non_exhaustive])
```

## 10. Testing

Conversation transcripts as data (normal, every extension, every failure reply); a scripted test server; RFC 6376 DKIM test vectors; header-injection attempts in every field; property tests for MIME round trips through a reference parser.

## 11. Open decisions

| Id | Question | Recommendation |
|---|---|---|
| O-1 | RSA signing in crypt-io for DKIM? | add it to crypt-io (audited primitive) |
| O-2 | XOAUTH2 (Gmail, Microsoft relays) in 1.0? | after 1.0 |
| O-3 | Publish `0.1.0` to crates.io to claim the name? | yes |

## 12. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Client only; no mail server | services send mail; receiving is a different product |
| D-002 | 2026-10-13 | Sans-IO core | testable without a server; same core over any transport |
| D-003 | 2026-10-13 | TLS required by default; plaintext only to localhost by explicit configuration | no silent downgrade |
| D-004 | 2026-10-13 | Retries belong to the job system | smtp-net stays a sender, not a queue |
