# Changelog

All notable changes to `porte-rs` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow semver: while on
`v0`, a breaking change bumps the minor.

## [Unreleased]

## [0.2.0] - 2026-11-10

### Added

- **`oidc`, the Registre kit, ported from Go `porte/oidc` v0.16.1.** `Kit::new` runs discovery
  through `openidconnect` and fails at boot on a bad config, a manager built from another
  config, or a roles scope the provider does not offer. `Kit::routes` serves `/auth/config`,
  `/auth/oidc` (browser and `?flow=cli`), the callback, `/auth/oidc/exchange`,
  `/auth/oidc/device/exchange` (with `OIDC_CLI_AUDIENCE`), `/auth/sync-profile` and
  `/auth/backchannel-logout` with Go's answers. `Kit::provision_bearer` and
  `oidc::resolve_bearer` serve the bearer path.
- **`jwt`**, offline RS256 verification with a cached JWKS, as Go `porte/oidc/jwt`.
- **`http_client`**, the outbound HTTP behind a `Transport` trait so tests answer for a fake
  issuer.
- **Conformance.** Go's `routes`, `config_answer`, `pkce`, `scope_gate`, `jwt` and
  `backchannel_logout` vectors pass; the flow is walked end to end against an in-process fake
  provider that enforces PKCE, the redirect URI and client authentication.

### Changed

- The CLI code page draws no borders, per the suite UI rule; Go's page has them.

## [0.1.0] - 2026-11-10

### Added

- **Sessions, ported from Go `porte` v0.16.1.** `token` (`new_token`, `hash_token`,
  `secure_compare`), `Config`, `Identity`, the store traits, and `session::Manager`: issue, the
  cookie with the `__Host-` prefix whenever it is `Secure`, `require_auth` and `optional` as
  tower layers, the CSRF header rule, the idle window, coalesced `last_used_at`, and
  `POST /auth/logout`.
- **`Manager::check_origin`**, new in Rust: the CSRF rule for WebSocket upgrades, which are GETs.
- **`pg`**, the identity tables on sqlx: `SCHEMA` byte for byte Go's, the four stores in one
  `Store`, `erase_identity`, the verified-email linking rules, and `TokenSealer`
  (AES-256-GCM, HKDF-SHA256, `pv1:`) with `reseal_identities`.
- **Conformance.** `tests/conformance.rs` runs Go's `token`, `schema`, `cookie`, `csrf` and
  `sealer` vectors; `scripts/sync-vectors.sh` refreshes them from a local checkout.
