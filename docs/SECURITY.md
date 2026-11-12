# smtp-net - Security

> What smtp-net defends against, how, what each defence costs, and the test that proves it. The numbers T-1 to T-36 are the threat table of [`../dev/PLAN.md`](../dev/PLAN.md) section 10.1. To report a vulnerability, open a private security advisory on the [repository](https://github.com/jamesgober/smtp-net/security/advisories/new).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Contents

- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Scope](#scope)
- [Assumptions](#assumptions)
- [Threats, defences, tests, costs](#threats-defences-tests-costs)
- [Hardening record (0.7)](#hardening-record-07)
- [What smtp-net does not defend against](#what-smtp-net-does-not-defend-against)
- [Operating guidance](#operating-guidance)

## Reporting a vulnerability

Use a private security advisory on GitHub (link above), not a public issue. Include the version, the smallest input or transcript that shows the problem, and what you expected. You will get an answer within 72 hours. A fix ships as a patch release with a RUSTSEC advisory when the flaw affects a published version.

## Scope

smtp-net builds MIME messages, signs them with DKIM, and submits them to one relay (a local MTA, or a submission server on 587 or 465). It is a client: it does not receive mail, look up MX records, verify DKIM, or relay for others. Everything a server sends is treated as hostile, and so is every string an application passes in, since applications fill headers from user input (names, subjects, file names).

## Assumptions

- The relay is the one configured. For TLS that is proven by the certificate (tls-net, verification always on); plaintext is allowed only when the connected peer address is loopback.
- DKIM private keys and SMTP credentials come from the application's configuration or a key vault, and the application does not log them.
- The application decides who may send to whom. smtp-net caps recipients per message and offers gates per hour and per domain, but it cannot tell a legitimate list from an abused one.
- Job payloads (`PreparedMessage::encode`) are stored encrypted at rest by the job runner (task-io's `Sealer`); the CRC-32C in the payload catches damage, not tampering.

## Threats, defences, tests, costs

Every row has at least one test that must fail to get through. Paths are relative to the repository root; `src/...` tests are unit tests, `tests/transcripts/*.txt` run whole and split at every byte. Costs marked **[est.]** are estimates until benchmarked.

| Id | Threat | Defence | Tests | Cost |
|---|---|---|---|---|
| T-1 | Header injection (`\r\nBcc:` in a name or subject) | every setter goes through `check_header_value`; CR, LF, NUL, C0 and C1 controls (TAB allowed in text), U+2028 and U+2029 refused, never stripped | `src/message/tests.rs` `test_header_injection_refused_in_every_field`, `test_header_count_matches_builder_input`; `src/message/header.rs` `test_check_header_value_refuses_every_control`; `tests/threats.rs` `t01_list_unsubscribe_controls_refused`; `tests/properties.rs` `prop_builder_output_obeys_wire_rules`; fuzz `header_value` | one scan, 16 to 19 GB/s measured |
| T-2 | Envelope command injection (`a@b>\r\nRCPT TO:<c@d`) | addresses by grammar; every command line scanned again for CR, LF, NUL and length before its CRLF | `src/address.rs` `test_address_injection_attempts_refused`; `src/proto/command.rs` `test_line_shadow_check_refuses_embedded_crlf_and_overlength`, `test_shadow_check_over_arbitrary_path_bytes` (50,000 random paths that never passed the grammar); fuzz `address` | one scan per command, under 10 ns |
| T-3 | Dot-stuffing failure ends DATA early (RUSTSEC-2021-0069) | streaming stuffer keeps line-start state across chunks; BDAT needs no stuffing | `src/proto/stuff.rs` `test_dot_stuffer_dot_after_double_crlf_split_at_every_byte_stuffed`; `tests/properties.rs` `prop_body_dot_stuffing_round_trips_at_any_split`; `tests/threats.rs` `t03_dot_bodies_arrive_whole`; `tests/driver.rs` `test_send_delivers_exact_bytes_after_unstuffing` | none beyond the scan |
| T-4 | SMTP smuggling with bare LF or CR (CVE-2023-51764, 51765, 51766) | CRLF only out of the builder; raw input with bare CR or LF refused before any byte is written | `src/message/prepared.rs` `test_from_raw_smuggling_sequences_refused`; `src/proto/stuff.rs` `test_dot_stuffer_smuggling_sequences_refused`; `src/proto/session/tests.rs` `test_body_bare_lf_refused_and_session_closed`; fuzz `raw_message` | one scan |
| T-5 | STARTTLS stripped by a path attacker | `Security::StartTls` requires the extension; no fallback | `tests/extended.rs` `test_stripped_starttls_sends_nothing`; transcript `starttls_missing.txt` | none |
| T-6 | Plaintext replies injected after `220` to STARTTLS (NO STARTTLS) | the session stops reading after the 220; any further plaintext byte before the handshake is refused; capabilities discarded and EHLO sent again over TLS | `tests/extended.rs` `test_starttls_response_injection_refused` (refused either as `StartTlsInjection` or, when the bytes reach the TLS engine, as a TLS failure; no injected capability is used either way); transcript `starttls_injection.txt` | none |
| T-7 | A command pipelined after STARTTLS runs in plaintext | STARTTLS ends its group; no output until `tls_established` | `src/proto/session/tests.rs` `test_no_output_after_starttls_until_tls_established`; fuzz `session_server_bytes` | none |
| T-8 | Credentials in plaintext | AUTH only over TLS or to a verified loopback peer | `tests/extended.rs` `test_stripped_starttls_sends_nothing`; `src/proto/session/tests.rs` `test_auth_refused_over_unverified_plaintext`; `src/client/mod.rs` `test_plaintext_needs_a_loopback_peer_whatever_the_name` | none |
| T-9 | Credentials in `Debug`, errors, transcripts, logs | `Secret` redacts; AUTH payloads redacted in transcripts; errors carry codes, not AUTH bytes | `src/proto/sasl.rs` `test_secret_never_formatted`; `tests/threats.rs` `t09_no_secret_in_debug` (`ServerBuilder`, `Server`, `Client`, `Pool`, `Credentials`, `Secret`); `tests/extended.rs` `test_auth_plain_over_starttls_and_redacted_transcript`; `tests/auth.rs` `test_observer_sees_codes_and_outcomes_never_secrets` | none |
| T-10 | Authentication downgrade | caller allowlist, no fallback outside it | `tests/threats.rs` `t10_no_downgrade_outside_the_allowlist`; `tests/auth.rs` `test_password_never_goes_to_xoauth2`; transcript `auth_unavailable.txt` | none |
| T-11 | Certificate validation bypass or wrong name | tls-net verification always on; the name is the configured host; turning verification off is refused for non-loopback hosts | `tests/tls_real.rs` `test_untrusted_ca_is_certificate_rejected`, `test_self_signed_certificate_is_rejected`, `test_tls_net_never_turns_verification_off`; `tests/threats.rs` `t11_wrong_name_is_permanent`; `tests/extended.rs` `test_insecure_remote_needs_the_second_flag` | handshake only |
| T-12 | Reply flood exhausts memory | `ReplyLimits` checked per byte before storing | `tests/alloc.rs` `test_t12_reply_flood_stays_within_the_budget` (a 10 MiB line and 100,000 continuation lines, peak held at most 12 KiB); `tests/driver.rs` `test_hostile_reply_flood_refused_within_budget`; fuzz `reply`, `ehlo` | none |
| T-13 | Slow drip ties up a worker | stage deadlines from the command, not reset per byte | `tests/threats.rs` `t13_one_byte_a_second_times_out`; `tests/driver.rs` `test_slow_drip_ends_in_timeout_at_stage_deadline` | none |
| T-14 | Desynchronised replies under pipelining | replies matched by count and by class: a reply that cannot answer its command (250 to DATA, 354 to MAIL) is `Protocol(UnexpectedReply)` and closes the session | `tests/threats.rs` `t14_extra_reply_at_every_stage`; transcripts `unexpected_extra_reply.txt`, `data_answered_250.txt`, `mail_answered_354.txt`, `data_end_answered_354.txt`; `tests/driver.rs` `test_malformed_and_extra_replies_close_the_session` | one comparison per reply |
| T-15 | Boundary collision forges MIME parts | boundaries start `=_` (impossible in QP and base64) with 160 random bits; 7bit parts scanned and the boundary redrawn on a hit | `src/message/tests.rs` `test_boundary_redrawn_when_content_contains_it`; `tests/threats.rs` `t15_adversarial_text_and_boundaries` | one scan of 7bit parts |
| T-16 | Predictable Message-ID or boundary | OS CSPRNG; a failed source is an error, never a weaker fallback | `src/message/tests.rs` `test_random_failure_is_an_error_never_a_fallback` | about 1 µs per message **[est.]** |
| T-17 | Host name leaked in Message-ID or EHLO | Message-ID from the From domain; EHLO is a configured name or the socket's address literal | `tests/threats.rs` `t17_no_host_name_in_output` (reads the machine's name and searches everything sent); `src/message/tests.rs` `test_text_message_golden`; `src/proto/command.rs` `test_client_name_literals` | none |
| T-18 | Duplicate delivery after an ambiguous failure | `possibly_delivered`; a retry sends the same bytes and Message-ID | `tests/threats.rs` `t18_retry_sends_identical_bytes`; `tests/driver.rs` `test_close_after_data_end_is_possibly_delivered`; transcripts `eof_after_data_end.txt`, `data_end_answered_354.txt` | none |
| T-19 | Content appended under a DKIM signature (`l=`) | `l=` never written | `src/dkim/signer/tests.rs` `test_header_list_and_oversigning`; dkimpy in CI (`fail-appended`); fuzz `dkim` | none |
| T-20 | DKIM header addition (a second Subject) | From, To, Cc, Subject, Date, Reply-To, Message-ID oversigned | `tests/dkim.rs` `test_write_verifier_corpus` checked by dkimpy in CI; `src/dkim/signer/tests.rs` `test_added_header_changes_the_signed_data` | under 1 µs **[est.]** |
| T-21 | Weak DKIM keys | RSA 2048 to 4096 bits only; `rsa-sha1` never written; Ed25519 offered | `src/dkim/signer/tests.rs` `test_key_sizes_t21` (1023, 1024, 2047, 2048, 4096, 4098: OpenSSL cannot make 4097, D-071) | none |
| T-22 | DKIM private key exposure | keys in crypt-io types that wipe on drop; `Debug` redacts; error types are `Copy` codes that cannot hold key bytes | `src/dkim/signer/tests.rs` `test_debug_never_prints_key_material_t22`; the wipe is crypt-io's own test | none |
| T-23 | Encoded-word look-alike in user text | unstructured text containing `=?` is itself encoded | `tests/threats.rs` `t23_encoded_word_lookalike_reads_literally` (decoded by parse-net back to the literal text); `src/message/header.rs` `test_unstructured_encoded_word_lookalike_is_encoded` | one scan |
| T-24 | Path traversal or controls in a file name | `/`, `\`, controls, empty, and over 255 octets refused | `src/message/part.rs` `test_file_name_rules` | one scan |
| T-25 | Display-name spoofing (`"support@bank.example" <evil@...>`) | `MessageBuilder::refuse_address_like_display_names` refuses `@` in any shown display name (off by default) | `tests/threats.rs` `t25_address_like_display_names` | one scan per name |
| T-26 | Huge or many parts, deep nesting | `MessageLimits` checked before encoding; a streamed attachment's declared length counted when it is added | `tests/alloc.rs` `test_t26_huge_trees_refused_before_encoding` (10,000 parts, depth 100), `test_t26_gib_attachment_refused_when_added`; `src/message/tests.rs` `test_size_limit_checked_before_encoding` | none |
| T-27 | Spam cannon through user-chosen recipients | 100 recipients per message; `HourlyLimit` per hour and `DomainLimit` per recipient domain | `src/message/tests.rs` `test_recipient_limits`; `src/gate.rs` `test_never_over_admits_under_64_threads`, the loom models (CI job `loom`), the `DomainLimit` tests | 29 to 32 ns per admission (`HourlyLimit`); `DomainLimit` one lock and one hash **[est.]** |
| T-28 | Bcc disclosure | Bcc never serialized | `src/message/tests.rs` `test_bcc_never_serialized_but_in_envelope`; `tests/driver.rs` `test_bcc_only_in_envelope_on_the_wire` | none |
| T-29 | Timing leak in the SCRAM server-signature check | crypt-io's constant-time HMAC check | `src/proto/scram.rs` `test_server_signature_checked_both_ways`, `test_rfc7677_example_exchange`, `timing_server_signature_check` (dudect style, below) | none |
| T-30 | Terminal or log injection through reply text | `text_lossy` replaces controls with `?`; a CR inside a reply line is refused outright; the observer gets codes only | `src/proto/reply.rs` `test_text_lossy_sanitizes_terminal_escapes`, `test_reply_parser_line_endings` | one scan of kept text |
| T-31 | RSA signing timing (RUSTSEC-2023-0071) | crypt-io's RSA is aws-lc-rs (constant time, blinded) | CI job `security`: `cargo audit` and `cargo deny` with no ignores | none |
| T-32 | `PlaintextLoopback` aimed at a remote relay | needs a loopback host at build and a loopback peer at connect | `tests/driver.rs` `test_plaintext_to_remote_host_refused_at_build`; `src/client/mod.rs` `test_plaintext_needs_a_loopback_peer_whatever_the_name` | none |
| T-33 | Corrupted job payload sends another message | version, budgets, and CRC-32C checked before use | `src/message/prepared.rs` `test_payload_every_bit_flip_refused`; fuzz `prepared_decode` | CRC at about 8 GB/s **[est.]** |
| T-34 | Reset links in transcripts | the test server's transcript never holds a body | `tests/threats.rs` `t34_transcript_omits_bodies` | none |
| T-35 | Bidirectional overrides in Subject or names | U+202A to U+202E and U+2066 to U+2069 refused in the Subject and display names unless `allow_bidi_controls` | `tests/threats.rs` `t35_bidi_controls` | one scan |
| T-36 | Over-long header lines split by receivers | hard 998 limit; folding only at whitespace; refusal when impossible | `src/message/header.rs` `test_unstructured_unbreakable_over_998_refused`; `src/message/tests.rs` `test_subject_long_folds_and_unbreakable_refused` | none |
| T-37 | A refused transaction leaves commands queued, and the next message on the connection joins it (to the earlier recipients) | every MAIL and RCPT line is measured before the first is queued, and a refused `begin` restores the queue; a later refusal closes the session; a client reuses, or sends QUIT on, a connection only when nothing is queued or outstanding; `TestServer` keeps the open transaction on a nested MAIL, as Postfix does | `tests/crosstalk.rs` (client and pool, BDAT and DATA); `src/proto/session/tests.rs` `test_begin_refusing_a_long_rcpt_queues_nothing`, `test_begin_refusing_a_long_mail_line_queues_nothing` | each MAIL and RCPT line formatted twice: about 40 ns per line **[est.]**, no allocation |

## Hardening record (0.7)

Machine: AMD Ryzen 9 9950X3D (32 threads), WSL2 Linux 6.6, Rust stable 1.99 and nightly for fuzzing. The machine was shared with other builds throughout.

### Fuzzing

One hour per target, all eleven at once, libFuzzer through cargo-fuzz, corpora kept outside the repository. No crash, leak, or timeout in any target.

| Target | Executions | Coverage | Notes |
|---|---|---|---|
| `address` | 42.3 M | 1,102 | |
| `content_type` | 49.3 M | 1,488 | |
| `dkim` | 14.4 M | 517 | canonicalization split invariance; signing never panics |
| `ehlo` | 25.4 M | 288 | |
| `header_value` | 18.9 M | 534 | |
| `prepared_decode` | 100.3 M | 615 | second hour, with framed inputs (see below) |
| `raw_message` | 29.8 M | 379 | |
| `reply` | 47.3 M | 272 | |
| `sasl` | 12.5 M | 1,076 | SCRAM, XOAUTH2, PLAIN, LOGIN against arbitrary server bytes |
| `session_server_bytes` | 19.2 M | 965 | |
| `transcript` | 31.6 M | 186 | |

`prepared_decode` reached only 52 coverage points in its first hour: random payloads almost never carry a valid CRC-32C, so the fields behind the checksum were barely reached. The target now frames half its inputs with the header and a correct checksum, and its second hour reached 615.

Four targets ran a second hour on later code, again with no finding:

| Target | Code | Executions | Coverage |
|---|---|---|---|
| `session_server_bytes` | with the reply-class check (D-096) | 32.9 M | 1,135 |
| `transcript` | with the reply-class check (D-096) | 132.9 M | 189 |
| `address` | with parse-net 0.9.2 (D-104) | 108.6 M | 1,102 |
| `content_type` | with parse-net 0.9.2 (D-104) | 121.5 M | 1,497 |

The second runs shared the machine with two or three targets rather than ten, which is most of the difference in executions.

### Soak (NFR-14)

`tests/soak.rs`, 24 hours: one message every 10 ms over a reused connection through `(HourlyLimit, DomainLimit)` with recipients at 1,000 domains, two pooled threads beside it, and one send a second to a server with a fault (ten kinds in turn: close at DATA, close after the end of data, 451 to RCPT, 550 to MAIL, a refused recipient, a malformed reply, an extra reply, an oversized EHLO reply, a close after three messages, a 1 ms round trip). It fails on heap, descriptor, or thread growth between the first and last thirds of the run, on any fault ending another way than expected, and on any message reported sent that the server did not take.

The 0.7.0 run passed: 8,640,000 messages on the reused connection, 3,277,232 through the pool, and 86,400 fault sends, every one ending as expected. The highest live heap was 620 KB in the first third and 673 KB in the last; descriptors stayed at 29 and threads at 21.

### SCRAM timing (T-29)

`timing_server_signature_check`, dudect style: wrong server signatures that differ from the right one in the first octet or in the last, interleaved at random, 200,000 samples of 8 checks each per class, the slowest 10% cropped. Welch's t must stay under 4.5.

| Platform | Mean (8 checks) | t, three to five runs |
|---|---|---|
| Linux (WSL2) | 1,754 to 1,798 ns | 0.07, -1.76, -0.97 |
| Windows 11 (MSVC) | 1,968 to 2,055 ns | 1.19, 0.19, -0.15, -0.64, 0.91 |

The first version timed the whole server-final step, base64 decoding included, and showed a steady 0.3 to 0.7 ns difference (t up to -7.6 on Windows). That came from decoding different base64 characters, which the server chose and already knows; the comparison with the secret is the step measured now.

### Defects found and fixed in 0.7

- A reply whose class cannot answer its command was taken as a refusal. Under pipelining, an extra reply from a server put the replies out of step, and a `250` matched to DATA became a permanent `Rejected`, so a job queue would dead-letter a good message. It is now `Protocol(UnexpectedReply)`, temporary, the session closes, and after the end of data the message is possibly delivered (T-14).
- The loom models of `HourlyLimit` and the pool's slot bitmap were never run in CI. They are now (job `loom`).

### Fixed in 0.7.2

- A send refused while its MAIL and RCPT lines were being queued (DSN parameters that pushed an RCPT line past 512 octets) left the lines already queued. They went out with the next message on the same `Client` or `Pool` connection, and a server that keeps the open transaction on a nested MAIL, as Postfix does, delivered that message to the refused message's recipients as well, while the client reported it failed (T-37). `TestServer` reset the transaction on every MAIL, so the suite could not see it. Found by an independent review.

### Added in 0.7

- `MessageBuilder::allow_bidi_controls` (bidi controls refused by default) and `refuse_address_like_display_names` (T-25, T-35).
- `DomainLimit`, gate pairs, and `SendGate::admit`, which sees the whole envelope (PLAN 10.3).
- `TestServerBuilder::record(false)` and `TestServer::messages` for long runs.

## What smtp-net does not defend against

- **A compromised relay.** Once the relay has the message, smtp-net has no say in what it does with it. Verification proves only that it is the relay configured.
- **Message content.** smtp-net does not judge text, links, or attachments. An application that puts user text in a message (a contact form) is responsible for what it says.
- **DMARC alignment.** DKIM signs with the domain given; whether that domain aligns with the From domain is the application's configuration (see `docs/DELIVERABILITY.md`).
- **Plaintext job payloads at rest.** `PreparedMessage::encode` is integrity-checked, not encrypted. Encrypt payloads in the job store.
- **Memory disclosure of message bodies.** Bodies are not wiped after sending; only credentials and keys are.
- **Several processes sharing one budget.** `HourlyLimit` and `DomainLimit` count per process. Divide the cap between processes, or implement `SendGate` over a shared counter.

## Operating guidance

- Never put untrusted text in the From display name. If any display name comes from users, turn on `refuse_address_like_display_names`.
- Leave `allow_bidi_controls` off unless a known sender needs the controls.
- Combine the gates: `.gate((HourlyLimit::recipients(cap), DomainLimit::recipients(n)))`. `Throttled` errors are temporary and carry `retry_after`.
- Treat `possibly_delivered` errors as "do not resend automatically, or resend the same `PreparedMessage`": the receiver can then deduplicate on Message-ID.
- Watch `ObservedEvent::SecurityEvent` (STARTTLS missing or injected, protocol violations): a change on a relay that used to behave is worth an alert.
- Run on Linux in production (`docs/PERFORMANCE.md`): the signing backend is several times faster there.
