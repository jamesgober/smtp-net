# smtp-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock
Exit: message builder, send API, and protocol state machine written in `docs/API.md` and approved; RSA signing in crypt-io confirmed (O-1).

## v0.3.0 - Submission
Exit: verification and reset emails are delivered through the cPanel server's Exim on localhost:587 and through one external relay.
- [ ] Sans-IO client state machine, extensions, reply parsing.
- [ ] Transport over net-io and tls-net (STARTTLS, implicit TLS).
- [ ] MIME builder with header-injection refusal; address validation.

## v0.4.0 - DKIM
Exit: messages pass DKIM verification at major receivers.
- [ ] Canonicalization and signing (Ed25519 and RSA-SHA256); DNS guide for SPF and DMARC.

## v1.0.0 - Stable
- [ ] Frozen after the first site has sent mail with it in production.
