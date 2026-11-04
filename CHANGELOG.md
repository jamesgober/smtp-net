<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>smtp-net</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.2.0] - 2026-11-04

The design lock. No functional code yet.

### Added

- `docs/API.md`: the public API for every version up to 1.0 (Tier 1 functions,
  addresses, the message builder, encoding primitives, sinks, envelopes and job
  payloads, the sans-IO session, replies and capabilities, SASL, DKIM, the
  blocking client and its TLS seam, pacing, timeouts, observability, errors,
  test support, constants), with grade, tier, version, and cost targets for
  each item.
- `dev/PLAN.md`: requirements, threat model with an attack test per threat,
  failure classification, timeouts, message model, DKIM design, performance
  targets, testing plan, and the answers to every open decision (D-005 to
  D-036).

### Changed

- `dev/ROADMAP.md` follows the standard version table (0.3 core, 0.4 extended,
  0.5 feature complete, 0.6 optimisation, 0.7 hardening, 0.8 alpha, 0.9 beta
  with a pre-1.0 polish pass, 1.0 stable) instead of the scaffold's
  submission-then-DKIM plan.

## [0.1.0] - 2026-10-13

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md` (purpose, scope, architecture, threats, ecosystem, open
  decisions, decision log), `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/smtp-net/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/smtp-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/smtp-net/releases/tag/v0.1.0
