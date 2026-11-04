# smtp-net architecture

How the crate is put together, as of `0.5.0`. The design reasoning and every decision behind it are in [`dev/PLAN.md`](../dev/PLAN.md) (sections 7 and 19); the public API is in [`API.md`](./API.md).

## Layers

```
            Tier 1: send, send_local, send_prepared          (client)
            Tier 2: Message, MessageBuilder, Server, Client, Pool, DkimSigner
 ┌──────────────────────────────────────────────────────────────────────┐
 │ client/   blocking driver over net-io; TLS through the TlsConnector  │  std
 │           seam; Pool; Observer                                       │
 ├──────────────────────────────────────────────────────────────────────┤
 │ proto/    sans-IO Session: bytes in, bytes out, events, deadlines;   │  no_std + alloc
 │           ReplyParser, Capabilities, SASL, DotStuffer, classify      │
 │ message/  MIME building, serialization into a Sink, Envelope,        │  no_std + alloc
 │           PreparedMessage and its job payload                        │
 │ dkim/     canonicalizers (always); keys and signer (feature dkim)    │  canon: no_std
 │ address   Address, Mailbox, Domain on parse-net's grammar            │  no_std + alloc
 │ encode    base64, quoted-printable, CRC-32C, base32                  │  no_std
 │ gate      SendGate, HourlyLimit                                      │  no_std (atomics)
 └──────────────────────────────────────────────────────────────────────┘
```

Without default features everything below `client/` builds for a target with no operating system (CI builds it for `thumbv7em-none-eabi`, with and without `scram`). Time and randomness are passed in there; `std` adds the clock and the OS random source.

## Modules

| Path | What it holds |
|---|---|
| `src/lib.rs` | crate docs, re-exports, constants |
| `src/error.rs` | `Error` (one pointer wide), `ErrorKind`, `Disposition`, `Stage`, and the nested error enums; the default disposition of every kind |
| `src/address.rs` | `Address`, `Mailbox`, `Domain`: RFC 5321 paths and RFC 5322 mailboxes through parse-net, with SMTPUTF8 detection |
| `src/encode.rs` | base64 (strict decoding), quoted-printable with the dot and `From ` rules, CRC-32C, base32 |
| `src/message/mod.rs` | `Message`, `MessageBuilder`: validation at every setter, fixed header order, exact `encoded_len` |
| `src/message/header.rs` | header names and values, folding, RFC 2047 words, injection checks |
| `src/message/part.rs` | `Part`, `Attachment` (in memory or streamed from a `BodySource`), `Inline`, `ContentType`, transfer-encoding choice, streaming serialization |
| `src/message/prepared.rs` | `Envelope`, `Dsn`, `PreparedMessage`, `from_raw` checks, the versioned and checksummed job payload, DKIM signing of prepared bytes |
| `src/message/id.rs`, `sink.rs` | `Message-ID` and boundary generation, `RandomSource`; the `Sink` trait, `CountingSink`, `IoSink` |
| `src/proto/session.rs` | the `Session` state machine |
| `src/proto/reply.rs`, `capability.rs`, `command.rs`, `stuff.rs`, `timeouts.rs`, `classify.rs` | reply parsing with budgets, EHLO capabilities, command formatting, dot-stuffing, stage timeouts, reply-to-disposition rules |
| `src/proto/sasl.rs`, `scram.rs` | credentials, the mechanism allowlist, PLAIN, LOGIN, XOAUTH2, the `Mechanism` trait; SCRAM-SHA-256 (feature `scram`) |
| `src/dkim/` | `canon.rs` (simple and relaxed, streaming), `key.rs` (`DkimKey`, PEM and DER loading, DNS records), `signer.rs` (`DkimSigner`, header selection, the signature header) |
| `src/gate.rs` | `SendGate`, `HourlyLimit` (60 one-minute buckets, lock-free) |
| `src/client/mod.rs` | `Server`, `ServerBuilder`, `Client`, `Report`, `send`, `send_local`, `send_prepared` |
| `src/client/tls.rs` | `TlsConnector`, the tls-net connector, the TLS record pump over net-io |
| `src/client/pool.rs`, `slots.rs` | `Pool` and its lock-free slot bitmaps |
| `src/client/observe.rs` | `Observer`, `ObservedEvent`, `SecurityEventKind` |
| `src/testing.rs` | `Transcript`, `ScriptedServer` (sans-IO), `TestServer` (loopback SMTP server with faults, AUTH including SCRAM and XOAUTH2, BDAT, TLS) |

## Data flow

```
MessageBuilder ──▶ Message ──▶ prepare (serialize once) ──▶ [DKIM sign] ──▶ PreparedMessage
                                                                              │
                                                        encode() ──▶ job store ──▶ decode()
                                                                              │
send / Client / Pool ──▶ SendGate ──▶ connect ──▶ [TLS] ──▶ Session ◀──▶ socket
                                                              │
                                                Report  or  Error { disposition, possibly_delivered }
```

A message is serialized and signed once. Retries, reconnects, and deferred recipients all send the same bytes with the same `Message-ID`, so the signature stays valid and a receiver can spot a duplicate.

## The session

`Session` (in `proto/`) does no I/O and keeps no clock. The driver:

1. writes `transmit()` to the socket and reports how much went with `transmitted(n)`;
2. feeds bytes read with `receive(bytes, now)`;
3. drains `poll_event()` (`Ready`, `StartTls`, `BodyWanted`, `Delivered`, `Closed`, and others);
4. sleeps until `deadline()` at most, then calls `on_timeout(now)`.

States run from the greeting through EHLO, STARTTLS (where any byte after the `220` is refused as an injection), the TLS handshake (done by the driver), EHLO again, AUTH, and then transactions. Commands are pipelined when the server offers PIPELINING; the body goes as DATA with dot-stuffing or as BDAT chunks. Every reply is classified into a `Disposition`; a lost connection after the end of the data is reported as `possibly_delivered`.

The same session runs under `ScriptedServer` in the tests, whole and split at every byte, so the state machine is tested without sockets.

## TLS

The driver never touches rustls directly. `TlsConnector` gives it a net-io `TlsSession` (a sans-IO TLS engine); `client/tls.rs` moves records between the socket and the engine. With the `tls` feature the default connector is tls-net's client, which always verifies certificates; there is no way to turn verification off with it. Errors are classified as certificate rejection (permanent, a security event), protocol mismatch, or handshake and stream failures (temporary).

## DKIM

`DkimSigner::sign` parses the header block (64 KiB at most), streams the body through the body canonicalizer into SHA-256, selects headers bottom-up for `h=` (each present default header, then the oversign list), writes the `DKIM-Signature` header folded at 78 columns with `b=` on its own line, canonicalizes that header through `b=`, and signs: RSA with PKCS#1 v1.5 over SHA-256, Ed25519 over the SHA-256 of the header data (RFC 8463). Several signers sign the original message independently and their headers go in front in order; the body hash is computed once per body canonicalization. Keys live inside crypt-io's types (AWS-LC behind them), which wipe them on drop.

## SASL

`Exchange` (in `proto/sasl.rs`) picks the first mechanism of the caller's allowlist that the server offers and the credentials fit: a password goes to SCRAM-SHA-256, PLAIN, or LOGIN, a token to XOAUTH2, a custom mechanism to its own name. AUTH runs only over TLS or to a confirmed loopback peer. SCRAM checks that the server nonce extends the client's, bounds the iteration count, and refuses a success the server did not prove with its signature (checked in constant time). Responses are built in wiped buffers, and the session's output buffer is overwritten after an AUTH response leaves it.

## Concurrency

`Session` and `Client` are `Send` and not `Sync`: one connection, one owner. `Message`, `PreparedMessage`, `DkimSigner`, `Server`, `HourlyLimit`, and `Pool` are `Send + Sync`. The shared mutable state is in two places, both lock-free and both modelled with loom:

- `HourlyLimit`: 60 bucket words and a total; admission is a compare-and-swap on the total after expired buckets are retired.
- `Pool`: a busy bitmap and an open bitmap. Checkout claims a free slot by compare-and-swap (one with an open connection first) and then takes that slot's mutex, which no one else holds; a waiter sleeps on a condition variable until a slot is released or the wait limit passes (`PoolExhausted`).

No thread is spawned, and there is no timer: idle connections are replaced when they are next used.

## Memory

| Object | Bound |
|---|---|
| `Session` | an output buffer (16 KiB by default), a reply buffer within `ReplyLimits`, capabilities with at most 32 unknown keywords |
| `Client` | a 16 KiB read buffer and the TLS record buffers |
| `Message` | its parts and headers, checked against `MessageLimits` (25 MiB encoded by default) before encoding; a streamed attachment holds only its source until serialization |
| `DkimSigner::sign` | the canonicalized header data (header block at most 64 KiB); the body is hashed as it streams |
| `PreparedMessage` | the message bytes; a decoded payload is capped at 64 MiB |
| `Pool` | at most `max_connections` clients |

## Observability

smtp-net does not log. An `Observer` set on the `Server` receives structured events: connected, TLS up, each reply's codes (never its text), delivered, failed, and a security event after a failure that looks like an attack or a broken server. The session queues reply events only when an observer is set. `TestServer` transcripts replace AUTH payloads with `<redacted N octets>`.
