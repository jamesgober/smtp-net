<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>smtp-net performance</b>
</h1>

Measured for `0.6.0` on 2026-11-06. Every target comes from `dev/PLAN.md` section 11.1; every miss is recorded there and in `dev/ROADMAP.md` with its reason.

## Machine and method

- AMD Ryzen 9 9950X3D (16 cores, 32 threads), 62 GiB, Linux 6.6 under WSL 2 (Windows 11), Rust 1.99 for the competitor comparison and the targets, `--release` with the crate's default profile; the bench repository builds with fat LTO.
- The machine was shared with other work during the whole measurement (load average 70 to 490 on 32 threads). Each number is the minimum over many short batches (`benches/examples/targets.rs` here, `examples/report.rs` in [smtp-net-bench](https://github.com/jamesgober/smtp-net-bench)): preemption only adds time, so the minimum is the cleanest estimate under load (D-090). Every number is an upper bound. Where a quieter run during the 0.6 work gave a lower number, both are shown. `cargo bench` gives criterion's full distributions.
- **Linux is the production target.** Under Windows MSVC the crypto in crypt-io is several times slower: an Ed25519 DKIM signature of a 10 KiB message took 64 µs there against 20 µs under Linux on the same machine, and crypt-io reports up to about 10 times for Ed25519. The other numbers are within the noise of each other on both systems.

Reproduce:

```text
cargo run --release --example targets          # in benches/
cargo bench                                    # in benches/, criterion
scripts/run.sh                                 # in smtp-net-bench, the competitor table
```

## Targets (PLAN 11.1)

| Operation | Target | Measured | Result |
|---|---|---|---|
| Build and serialize a verification email (text plus HTML) | at most 5 µs | 3.5 to 4.1 µs | met |
| Allocations for that build | at most 8 | 21 (97 at 0.3) | missed, D-083 |
| Serialize a message with a 1 MiB attachment | at least 1.5 GB/s | 2.4 to 2.9 GB/s | met |
| base64, 76-column lines | at least 2 GB/s | 2.8 to 3.1 GB/s | met |
| quoted-printable | at least 800 MB/s | 0.53 to 0.63 GB/s under load; 0.91 GB/s in a quieter run | met only in the quieter run, D-093 |
| Header value check, 4 KiB | at least 4 GB/s | 16 to 19 GB/s | met |
| Reply parsing, single line | at most 50 ns, 0 allocations | 61 to 94 ns under load; 50 ns in a quieter run; 0 allocations | met only in the quieter run, D-093 |
| EHLO reply, 10 lines, parsed and turned into capabilities | at most 400 ns | 661 to 788 ns under load (the reply alone: 249 ns in a quieter run) | missed under load, D-093 |
| Dot-stuffing on the session's body path | at least 4 GB/s | 2.9 to 3.6 GB/s under load; about 6 GB/s in a quieter run | met only in the quieter run, D-093 |
| DKIM relaxed body canonicalization | at least 2 GB/s | 1.22 to 1.50 GB/s under load | missed, D-093 |
| DKIM Ed25519 signature, 10 KiB message | at most 40 µs | 20 µs | met |
| DKIM RSA-2048 signature, 10 KiB message | at most 1.6 ms | 217 to 230 µs | met |
| One message on a reused connection, 0 ms round trip | 20% less than lettre | 24 µs against 67 ms | met |
| Same, 1 ms round trip | 20% less than lettre | 2.1 ms against 101 ms | met |
| Same, 10 ms round trip | 20% less than lettre | 16.5 ms against 182 ms | met |
| Session memory, ready with one transaction | at most 16 KiB | 19,176 bytes (6,888 with a 4 KiB output buffer) | missed, D-085 |
| `HourlyLimit::admit`, uncontended | at most 30 ns | 29 to 32 ns | met within noise |

`Session::begin` and the whole body path allocate nothing; `tests/alloc.rs` holds that and the build count.

## Against other crates

Versions: lettre 0.11.23, mail-builder 2.0.1, mail-send 0.7.0, mail-auth 0.15.1, base64 0.22, quoted_printable 0.5. Time relative to smtp-net: above 1.00x is slower than smtp-net, below is faster.

| Workload | smtp-net | Others |
|---|---|---|
| Verification email, build and serialize | 3.54 µs | lettre 6.37 µs (1.80x), mail-builder 1.17 µs (0.33x) |
| 1 MiB attachment, build and serialize | 603 µs | lettre 1.89 ms (3.13x), mail-builder 82 µs (0.14x) |
| base64, 1 MiB | 483 µs, in 76-column lines | base64 crate 339 µs, one line (0.70x) |
| quoted-printable, 1 MiB | 1.84 ms | quoted_printable crate 8.50 ms (4.61x) |
| DKIM Ed25519, 10 KiB | 20.7 µs | mail-auth 18.6 µs (0.90x), lettre 34.5 µs (1.67x) |
| DKIM RSA-2048, 10 KiB | 230 µs | mail-auth 218 µs (0.95x), lettre 3.24 ms (14.06x) |
| One message on a reused connection, 0 ms round trip | 23.6 µs | lettre 67.0 ms, mail-send 64.6 ms |
| Same, 1 ms round trip | 2.13 ms | lettre 101 ms, mail-send 95.6 ms |
| Same, 10 ms round trip | 16.5 ms | lettre 182 ms, mail-send 160 ms |

Reading the table:

- **mail-builder is faster to build** because it does not check addresses or header values (smtp-net refuses header injection, bare CR or LF, and over-long lines at build time), and its base64 comes from a SIMD crate built on `unsafe` code. smtp-net keeps the checks and `#![forbid(unsafe_code)]` (D-091).
- **The send rows are mostly round trips.** smtp-net pipelines MAIL, RCPT, and DATA (or BDAT) and disables Nagle's algorithm on its socket. lettre and mail-send leave Nagle on, so on Linux a small write that follows another waits for the server's delayed acknowledgement (about 40 ms) before it is sent; that is most of their time at 0 ms. The same `TestServer`, with `TCP_NODELAY`, served every client.
- base64 and the base64 crate are not the same job: smtp-net writes 76-column lines with CRLF, the base64 crate one line.

## What changed in 0.6

| Change | Before | After |
|---|---|---|
| Dot-stuffing: copy whole runs up to the next line end, found eight octets at a time | 0.46 GB/s | about 6 GB/s in a quiet run |
| base64: six octets per step through a 12-bit pair table | 1.75 GB/s | 2.9 GB/s |
| quoted-printable: class table, literal runs copied mid-line | 0.31 GB/s | about 0.9 GB/s in a quiet run |
| Header value check: printable test eight octets at a time | 2.2 GB/s | 18 GB/s |
| Build: shared header text, static names, moved strings, inline boundaries | 97 allocations, 4.09 µs | 21 allocations, 3.5 µs |
| `Session::begin`: envelope shared behind an `Arc` | one allocation per address | none |
| Relaxed body canonicalization: prose lines in one piece, controls found eight octets at a time | Ed25519 signature 30 µs | 20 µs |

Each scan and encoder is checked against the loop it replaced at every offset and over a 3,000-case corpus (D-086).

## Not done, with reasons

- Unsigned mail is serialized once into a `PreparedMessage` rather than streamed from the message tree into the session (D-088): retries and deferred recipients need the bytes again, and the copy costs about a microsecond.
- `Event::Delivered` keeps its owned reply, one allocation per message after the end of data (D-087).
- The 0.9 polish pass re-measures every row on a quiet machine against the competitors' current versions and republishes this file.
