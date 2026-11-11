# smtp-net - Simplicity audit of the 0.7.1 API

Date: 2026-11-11. Scope: every public item of smtp-net 0.7.1, checked against
four rules:

1. Tier 1 sends one email, locally or through a relay, in a line or two of
   obvious code with plain `?`.
2. Names are plain words and say what they mean. RFC keywords keep their
   spelling (PLAN 6, "Names").
3. There is one way to do each thing.
4. `docs/API.md` covers every public item, as a task-oriented reference
   whose examples compile and run.

The fixes ship in 0.8.0 with a migration table in
[`docs/release/v0.8.0.md`](../docs/release/v0.8.0.md). Decisions D-109 to D-118
in `PLAN.md` section 19 record each one.

---

## Findings

| # | Rule | Finding | Fix in 0.8.0 | Decision |
|---|---|---|---|---|
| 1 | 4, 1 | The crate root exports 132 names. The 20 an application needs (`Message`, `send`, `Server`, `Error`) sit in one alphabetical list next to the base64 encoder, the header folder, the sans-IO session, the DKIM canonicalizers, and the test server. | The root keeps what an application uses. The Tier 3 surface moves to four modules: `protocol` (the sans-IO session), `mime` (parts, encoders, sinks, randomness), `dkim` (the canonicalizers), and `testing`. Each item has one path. | D-110 |
| 2 | 3 | `SendGate` has two pairs of methods: `admit` and `refund` take a count, `admit_envelope` and `refund_envelope` take the envelope. The client calls the envelope pair. `DomainLimit::admit(count)` admits everything, because a count has no domains, so a caller or combinator that uses the count pair gets no per-domain limit at all and nothing says so. | One pair, `admit(&Envelope, now)` and `refund(&Envelope, now)`. A count-based gate reads `envelope.recipients().len()`. | D-111 |
| 3 | 3 | Two ways to set the TLS engine: `ServerBuilder::tls(tls_net::TlsClient)` and `ServerBuilder::tls_connector(impl TlsConnector)`. `TlsClient` implements `TlsConnector`, so the first is the second with a narrower type. | One method, `tls(impl TlsConnector)`. | D-112 |
| 4 | 3 | Two ways to sign: `Message::prepare_signed(signers, now)` is `prepare()?.sign(signers, now)`. | `Message::prepare_signed` is removed. | D-113 |
| 5 | 2, 3 | A refused recipient has two shapes: `Report::rejected()` yields `(&Address, &Reply, Disposition)` and `Error::recipients()` returns `&[RecipientFailure]`, an alias for `(Address, Reply, Disposition)`. A tuple needs the docs to read, and the accessors have different names. | One struct, `RejectedRecipient`, with `address()`, `reply()`, `disposition()`, `is_temporary()`, and `is_permanent()`. `Report::rejected()` and `Error::rejected()` both give it as a slice, and `Report::accepted()` gives `&[Address]` to match. The alias is removed. | D-114 |
| 6 | 2 | `PORT_SUBMISSION` (587) and `PORT_SUBMISSIONS` (465) differ by one letter. | `PORT_STARTTLS` and `PORT_IMPLICIT_TLS`, the words `Server::starttls`, `Server::implicit_tls`, and `Security` already use. `PORT_SMTP` stays. | D-115 |
| 7 | 2 | Setters and getters of the same field have different names: `Dsn::ret` and `Dsn::return_content`, `Dsn::envelope_id` and `Dsn::envelope_id_value`, `Envelope::return_path` and `Envelope::from`, `Envelope::dsn` and `Envelope::dsn_parameters`. `Dsn::required` sets what `Dsn::policy` reads. | The getter takes the field's name and the setter is `with_` plus that name, as `ContentType::with_parameter` already is: `Dsn::{with_return_content, with_envelope_id, with_policy}`, `Envelope::{return_path, with_return_path, dsn, with_dsn}`. | D-116 |
| 8 | 2 | `DomainLimit::per_domain(n)` repeats the type name and does not say what is counted; `HourlyLimit::recipients(n)` does. `ReplyCode::is_transient` uses another word for what `Error::is_temporary` and `Disposition::Temporary` call temporary. `QpState` is an abbreviation. | `DomainLimit::recipients(per_hour)`, `ReplyCode::is_temporary`, `mime::QuotedPrintableState`. | D-117 |
| 9 | 1 | Two `ServerBuilder` methods break the chain: `mechanisms(&[MechanismName])` returns a `Result` in the middle of it, and `client_name` takes a `ClientName`, which needs `ClientName::Domain(Domain::parse(..)?)`. Every other option is checked once, by `build()`. | `mechanisms` and `client_name(&str)` return `Self`; `build()` checks them (`Config(TooManyMechanisms)`, new `Config(InvalidClientName)`). `ClientName::parse` is the one conversion from text. | D-118 |
| 10 | 1 | The relay line works today (`send(&Server::starttls(host).login(user, password), &msg)?`), but the crate docs, the README, and the `send` example show only `send_local` or a builder for a loopback port. A reader has to find it. | The relay line is the second Tier 1 example everywhere, next to `send_local`, in a `main` that returns `Box<dyn Error>` to show plain `?` works. | D-110 |
| 11 | 4 | `docs/API.md` is the 0.2 design-lock list of signatures (PLAN numbering, `/* ... */` bodies). Its code is not compiled, so it can drift from the crate. It has no per-item errors, and few examples per task. | Rewritten as a task-oriented reference covering every public item, with what it does, its parameters, and its errors. Every Rust block compiles and runs as a doctest (`#[doc = include_str!]` under `cfg(doctest)`). The design-lock change table moves to the end. | D-110 |

## Checked and kept

| Item | Why it stays |
|---|---|
| `Server::starttls` beside `Security::StartTls` | STARTTLS is the RFC keyword; the function uses the command's own spelling, the enum variant is the Rust form of the same word (PLAN 6). |
| `Dsn`, `Ehlo`, `Bdat`, `Dkim`, `Smtputf8` | RFC words, kept so a reader of the RFC finds them. |
| `send`, `send_local`, `send_prepared`; `Client`; `Pool` | One job at three scales (one message, one connection, several connections), each with one name. `send` signs with the server's DKIM signers; `send_prepared` never re-signs. Merging the two would hide that difference. |
| `Message::text` and `Message::html` beside `Message::builder` | Tier 1 and Tier 2 of the same job. |
| `Server::login` beside `ServerBuilder::credentials` | Tier 1 for a password, Tier 2 for OAuth 2.0 and custom mechanisms. |
| `Error::is_temporary`, `is_permanent`, `disposition` | The booleans read best at a call site; `disposition` is the value to store or forward. |
| `Address::parse` and `TryFrom<&str>` | The builder takes `impl TryInto<Mailbox>`; `TryFrom` is what makes a `&str` work there. |
| `Message::to_bytes` beside `Message::write_to` | `write_to` is the sink path, which does not allocate; `to_bytes` is the convenience. |
| `Millis`, `TextLossy` | Tier 3. `Millis` is a millisecond count, and `TextLossy` follows `String::from_utf8_lossy`. Both read without the docs. |
| Two flags to turn certificate verification off for a remote host | Deliberate (D-024): one call cannot do it by accident. |

## What the break touches

| Dependent | Uses | Effect |
|---|---|---|
| `smtp-net-bench` (competitor benchmarks, unpublished) | `QpState`, the base64 and quoted-printable functions, `RandomSource`, `TestServer`, `Fault` | Pins `smtp-net = "0.6"`, so nothing changes until it upgrades. On upgrade, the paths move to `smtp_net::mime` and `smtp_net::testing`, and `QpState` becomes `QuotedPrintableState`. |
| crates.io | no reverse dependencies | none |
| task-io and the first site | not yet using smtp-net | They start on the 0.8 API, which is the one the field test checks. |
