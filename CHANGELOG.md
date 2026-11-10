# Changelog

All notable changes to `porte-rs` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow semver: while on
`v0`, a breaking change bumps the minor.

## [Unreleased]

## [0.5.1] - 2026-11-10

### Changed

- tronc-rs is fetched from https://github.com/FacileStudio/tronc-rs instead of a local checkout.
- Licensed under MIT, like Go porte.

## [0.5.0] - 2026-11-10

### Changed

- **tronc v0.3.0.** porte-rs now depends on the tronc tag the apps use for MCP, so an app has
  one `tronc::Error` type and needs no `[patch]`. The `mcp` feature turns on tronc's `mcp`.

### Added

- **`mcpauth::Verifier` implements `tronc::mcp::Verifier`.** An app passes it to
  `tronc::mcp::Options` as is. `From<TokenInfo> for tronc::mcp::TokenInfo` puts `client_id` and
  `actor` in `extra` under `EXTRA_CLIENT_ID` and `EXTRA_ACTOR` and `exp` in `expires_at`;
  `InvalidToken` maps to `Invalid` (401) and `Unavailable` to `Unavailable` (500).
- **`pg::Store::find_by_user(provider, user_id)`** returns the `(provider, subject)` an account
  signs in with at one provider, or `StoreError::NotFound`. `Identity::subject` stays empty on
  a cookie session, as in Go porte v0.16.1; this is how an app reads the Registre subject.

### Documentation

- The `directory` docs warn that a snapshot is authoritative: an `Apply` moves the data of a
  space that disappeared to the trash and never hard-deletes it.

## [0.4.0] - 2026-11-10

### Added

- **`mcpauth`, ported from Go `porte/mcpauth` v0.2.0.** `Verifier` checks RS256 tokens whose
  `aud` names the resource byte for byte (the app's client id only on a delegated token),
  resolves them by `(iss, sub)`, optionally provisions the account through the OIDC kit, and
  answers every refusal as `invalid token` and a store or JWKS failure as unavailable.
  `RequireLayer` answers as the MCP Go SDK's `RequireBearerToken` with `error="invalid_token"`
  and `error="insufficient_scope"` challenges; `TokenInfo` is an extractor. Also
  `scopes_for`, `has_scope`, `third_party`, `identity`, `metadata_url`,
  `protected_resource_metadata` and `metadata_route`.

### Not ported

- `CheckPlan` and `PlanGate`: they need `forfait`, which no Rust app uses, and `/mcp` is never
  plan-gated.

## [0.3.0] - 2026-11-10

### Added

- **`directory`, ported from Go `porte/directory` v0.3.0.** `Client::snapshot` decodes as Go
  does (case-insensitive names, every field optional, 8 MiB cap). `Syncer` pulls at boot, every
  five minutes and two seconds after a nudge, applies a version once, and serves the nudge
  route. `Deletions` polls `/api/directory/deletions` page by page, calls the app then porte
  once per person, keeps the cursor before the earliest failure, and receives signed
  `secevent+jwt` pushes (202, 400, 503 inside the key refetch gap). `pg::Store` implements
  `IdentityEraser`.
- **`spaces`, ported from Go `porte/spaces`.** `Role`, `Ladder`, `Membership`, `Scope`,
  `Guard::{resolve, require, can_leave, spaces, assignable_by, assignable_over}`, the `Store`
  trait, `Memory`, and `spaces::conformance::run`, which fails against a store whose lookup
  ignores the space id.
- **Conformance.** Go's `directory_snapshot` and `spaces_ladder` vectors pass.

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
