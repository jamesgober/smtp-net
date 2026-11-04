# smtp-net fuzz targets

One target per parser and decoder (dev/PLAN.md 12.4). Corpora live outside the
repository. Run a target with a nightly toolchain and cargo-fuzz:

```
cargo +nightly fuzz run reply -- -max_total_time=3600
```

Targets: `reply`, `ehlo`, `session_server_bytes`, `address`, `content_type`,
`header_value`, `raw_message`, `transcript`, `prepared_decode`, `dkim`, `sasl`. The
`dkim` target builds AWS-LC (C) through crypt-io; it needs a C compiler.
