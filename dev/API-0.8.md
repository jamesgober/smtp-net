# smtp-net - The 0.8 API and why it changed

Before the field test I went through every public item of 0.7.1 with four
questions:

1. Can you send one email, locally or through a relay, in a line or two of
   obvious code with plain `?`?
2. Is every name a plain word that says what it means? RFC keywords keep
   their spelling.
3. Is there one way to do each thing?
4. Does `docs/API.md` cover every public item, with examples that compile
   and run?

What changed is below. The renames are mapped in
[`docs/release/v0.8.0.md`](../docs/release/v0.8.0.md).

---

## What changed

| Was | Now, and why |
|---|---|
| The crate root exported 132 names. The 20 an application needs (`Message`, `send`, `Server`, `Error`) sat in one list next to the base64 encoder, the header folder, the sans-IO session, the DKIM canonicalizers, and the test server. | The root keeps what an application uses. The rest moved to `protocol` (the sans-IO session), `mime` (parts, encoders, sinks, randomness), `dkim` (the canonicalizers), and `testing`. Each item has one path. |
| `SendGate` had two pairs of methods, one taking a count and one taking the envelope. `DomainLimit` let everything through the count pair, because a count has no domains, and nothing said so. | One pair, `admit(&Envelope, now)` and `refund(&Envelope, admitted)`. A count-based gate reads `envelope.recipients().len()`. |
| Two ways to set the TLS engine, `tls(tls_net::TlsClient)` and `tls_connector(impl TlsConnector)`. | One method, `tls(impl TlsConnector)`. |
| Two ways to sign: `Message::prepare_signed(signers, now)` was `prepare()?.sign(signers, now)`. | `prepare_signed` is gone. |
| A refused recipient had two shapes: a tuple from `Report::rejected()` and a `RecipientFailure` alias from `Error::recipients()`. | One struct, `RejectedRecipient`, from both `Report::rejected()` and `Error::rejected()`; `Report::accepted()` gives `&[Address]` to match. |
| `PORT_SUBMISSION` (587) and `PORT_SUBMISSIONS` (465) differed by one letter. | `PORT_STARTTLS` and `PORT_IMPLICIT_TLS`, the words `Server::starttls` and `Security` already use. |
| Setters and getters of one field had different names (`Dsn::ret` and `return_content`, `Envelope::return_path` and `from`). | The getter takes the field's name and the setter is `with_` plus that name. |
| `DomainLimit::per_domain(n)` didn't say what it counts; `ReplyCode::is_transient` used another word for temporary; `QpState` was an abbreviation. | `DomainLimit::recipients`, `ReplyCode::is_temporary`, `QuotedPrintableState`. |
| `ServerBuilder::mechanisms` returned a `Result` in the middle of the chain, and `client_name` needed `ClientName::Domain(Domain::parse(..)?)`. | Both return `Self` and `build()` checks them. `ClientName::parse` is the one conversion from text. |
| The relay one-liner worked but no example showed it. XOAUTH2 had no one-line form. | The relay line sits next to `send_local` in the crate docs, the README, and `docs/API.md`; `Server::oauth2` sits next to `Server::login`. |
| `docs/API.md` was the old design list of signatures, not compiled. | A task-oriented reference of every public item; every Rust block runs as a doctest. |

## Checked and kept

| Item | Why it stays |
|---|---|
| `Server::starttls` beside `Security::StartTls` | STARTTLS is the RFC keyword; the function uses the command's own spelling, the enum variant is the Rust form of the same word (PLAN 6). |
| `Dsn`, `Ehlo`, `Bdat`, `Dkim`, `Smtputf8` | RFC words, kept so a reader of the RFC finds them. |
| `send`, `send_local`, `send_prepared`; `Client`; `Pool` | One job at three scales (one message, one connection, several connections), each with one name. `send` signs with the server's DKIM signers; `send_prepared` never re-signs. Merging the two would hide that difference. |
| `Message::text` and `Message::html` beside `Message::builder` | Tier 1 and Tier 2 of the same job. |
| `Server::login` and `Server::oauth2` beside `ServerBuilder::credentials` | Tier 1 for a password or a token, Tier 2 for custom mechanisms and other settings. |
| `Error::is_temporary`, `is_permanent`, `disposition` | The booleans read best at a call site; `disposition` is the value to store or forward. |
| `Address::parse` and `TryFrom<&str>` | The builder takes `impl TryInto<Mailbox>`; `TryFrom` is what makes a `&str` work there. |
| `Message::to_bytes` beside `Message::write_to` | `write_to` is the sink path, which does not allocate; `to_bytes` is the convenience. |
| `Millis`, `TextLossy` | Tier 3. `Millis` is a millisecond count, and `TextLossy` follows `String::from_utf8_lossy`. Both read without the docs. |
| Two flags to turn certificate verification off for a remote host | Deliberate: one call cannot do it by accident. |

## What the break touches

| Dependent | Uses | Effect |
|---|---|---|
| `smtp-net-bench` (competitor benchmarks, unpublished) | `QpState`, the base64 and quoted-printable functions, `RandomSource`, `TestServer`, `Fault` | Pins `smtp-net = "0.6"`, so nothing changes until it upgrades. On upgrade, the paths move to `smtp_net::mime` and `smtp_net::testing`, and `QpState` becomes `QuotedPrintableState`. |
| crates.io | no reverse dependencies | none |
| task-io and the first site | not yet using smtp-net | They start on the 0.8 API, which is the one the field test checks. |
