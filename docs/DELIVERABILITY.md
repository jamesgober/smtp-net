# Deliverability: what to publish so mail arrives

A correct client still lands in spam, or nowhere, when the sending domain's DNS is wrong. This guide covers what an operator sets up next to smtp-net. Values marked **[check]** depend on the host or the receiver and should be confirmed for yours.

## 1. What a `250` means

The submission server accepted the message. It has not been delivered yet: the server queues it and delivers it to the recipient's mail server later. A delivery failure after that point comes back as a bounce message (section 8), not as an smtp-net error.

On cPanel hosts, mail over the account's hourly limit is accepted at SMTP time and then queued or dropped by the host's settings **[check]**. smtp-net receives `250` for such a message, so pacing has to happen before submission: see section 9.

## 2. SPF (RFC 7208)

A TXT record at the sending domain lists the hosts allowed to send for it:

```
example.com.  TXT  "v=spf1 a mx ip4:203.0.113.10 -all"
```

Use `~all` while testing, `-all` once every legitimate sender is listed. A domain has exactly one SPF record, and evaluating it may take at most 10 DNS-querying mechanisms (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`).

## 3. DKIM (RFC 6376, RFC 8463)

smtp-net signs with `DkimSigner` (feature `dkim`). Each key is published as a TXT record at `<selector>._domainkey.<domain>`; `DkimKey::dns_record()` gives the value:

```rust
let key = smtp_net::DkimKey::rsa_from_pem(&std::fs::read_to_string("dkim-rsa.pem")?)?;
println!("rsa2026._domainkey.example.com. TXT \"{}\"", key.dns_record());
```

Or run the example: `cargo run --example dkim_dns_record --features dkim -- dkim-rsa.pem rsa2026 example.com`.

- **Keys.** Generate them with OpenSSL:

  ```
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out dkim-rsa.pem
  openssl genpkey -algorithm ed25519 -out dkim-ed25519.pem
  ```

  smtp-net accepts RSA keys of 2048 to 4096 bits (shorter keys are refused; RFC 8301 asks for at least 2048) and Ed25519 keys, as PKCS#8 or (RSA) PKCS#1, PEM or DER, unencrypted. Keep the files readable only by the sending service.
- **Two signatures.** Sign with RSA and Ed25519 under different selectors (RFC 8463 section 6): receivers that verify Ed25519 use it, the others use RSA. Add both signers to the `Server` (`ServerBuilder::dkim`, at most 4) or pass both to `PreparedMessage::sign`.
- **Long records.** An RSA 2048-bit record is longer than 255 octets, the limit of one DNS string. It is published as several quoted strings inside one TXT record; most DNS hosting interfaces split it on their own.
- **Rotation.** Publish the new selector's record, wait for it to be visible, switch the signer, keep the old record for about a week (mail in flight is still verified against it) **[check]**, then remove it.
- **Defaults.** Relaxed canonicalization for header and body; From, To, Cc, Subject, Date, Reply-To, and Message-ID oversigned, so adding one of them in transit breaks the signature; no `l=` tag, so nothing can be appended under a valid signature.
- **Sign once.** Sign before the message enters a job queue (`message.prepare()?.sign(..)`, then `PreparedMessage::encode`). `send_prepared` never re-signs, so retries send the same signed bytes.

## 4. cPanel's own DKIM

cPanel's Email Deliverability tool can create DKIM keys, and Exim can sign outgoing mail itself **[check]**. If Exim signs mail submitted on `127.0.0.1`, signing in smtp-net is optional for that path; a second signature does no harm as long as each uses its own selector.

## 5. DMARC (RFC 7489)

A TXT record at `_dmarc.<domain>` tells receivers what to do with mail that fails SPF and DKIM alignment, and where to send reports:

```
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```

Start with `p=none` and read the reports. Move to `p=quarantine`, then `p=reject`, once every legitimate source of mail for the domain passes. Alignment means the From domain matches the DKIM `d=` domain (or the SPF domain), so sign with `DkimSigner::new("<your From domain>", ...)`.

## 6. Reverse DNS

The sending IP address needs a PTR record whose name resolves back to the same address (forward-confirmed reverse DNS). Major receivers, Gmail among them, require it **[check]**. On shared hosting the host sets it.

## 7. Bulk sender rules

Gmail's sender guidelines (since February 2024) ask everyone sending more than about 5,000 messages a day to Gmail addresses for SPF and DKIM, a DMARC record, alignment, one-click unsubscribe (RFC 8058) for subscribed and marketing mail, and a reported spam rate below 0.3% (below 0.1% recommended) **[check current figures]**. Yahoo publishes similar rules.

Transactional mail (account verification, password resets) does not need List-Unsubscribe. Alerts and newsletters do: `MessageBuilder::list_unsubscribe(&[...], true)` writes both `List-Unsubscribe` and `List-Unsubscribe-Post: List-Unsubscribe=One-Click`, which needs an `https:` target that unsubscribes on a POST.

Mark automated mail with `MessageBuilder::auto_submitted` so auto-responders do not answer it (RFC 3834).

## 8. Bounces

A refusal during the SMTP conversation comes back as an smtp-net error: check `is_temporary()` and `is_permanent()`, and do not retry a permanent one. Most delivery failures arrive later, as a bounce message (a delivery status notification, RFC 3464) sent to the envelope return path.

- Use a dedicated return-path mailbox (`Envelope::with_return_path`) so bounces do not land in a person's inbox.
- A return path that identifies the message (`bounces+<token>@example.com`) lets the bounce processor match a bounce to the message and the recipient.
- Treat `5.1.1` (no such mailbox) as permanent and stop sending to that address; keep a suppression list.
- Ask for notifications only where they are read: `Dsn::new(DsnNotify::FAILURE)` asks the server for failure reports only, when it supports DSN.

Reading the bounce mailbox is outside smtp-net.

## 9. Rate limits

Shared hosts cap mail per hour per domain or account **[check the value and whether it counts messages or recipients]**. Put an `HourlyLimit` on the `Server` below that cap, counting the same unit, with headroom for mail the operator sends by hand:

```rust
let server = smtp_net::Server::local()
    .to_builder()
    .gate(smtp_net::HourlyLimit::messages(450))   // host cap 500 per hour
    .build()?;
```

A send over the limit fails with `Throttled` before anything is sent, and `Error::retry_after` says when to try again; a job system schedules the retry for then.

## 10. Not needed for submission

MTA-STS, TLS-RPT, DANE, and BIMI concern how other servers deliver to you or how your brand is shown; none of them is needed to submit mail. smtp-net always uses TLS with certificate verification to a relay, and plaintext only to the mail server on the same machine.
