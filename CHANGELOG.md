# Changelog

All notable changes to `porte-rs` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow semver: while on
`v0`, a breaking change bumps the minor.

## [Unreleased]

## [0.8.0] - 2026-11-14

Catches up with Go porte v0.20.1 (`mcpauth` v0.3.1, `directory` v0.5.0) and tronc-rs v0.5.0,
so Toile and Docs can drop their own confirm-page identity check and Bulle token source. No
migration, no route, CSRF or schema change.

**Upgrade note.** A browser login's session token now starts with `BROWSER_TOKEN_PREFIX`
(`b~`). A cookie minted before 0.8.0 keeps signing in for everything, but
`mcpauth::require_own_session` refuses it (403): each person signs in once in the browser before
they can confirm a pending MCP action. An app's e2e or seed script that writes a session row and
sets it as the cookie must prefix that token with `BROWSER_TOKEN_PREFIX` (and store the hash of
the prefixed token), or its confirm-page tests get 403.

### Breaking

- tronc-rs v0.5.0 (was v0.4.0). An app must move to tronc v0.5.0 in the same change, or it gets
  two `tronc` crates and `From<ExchangeError> for tronc::Error` stops matching. Read tronc-rs's
  own 0.5.0 breaking list (`Pending::create`, `Error::key`, `bulle::Error::NoActingFor`, ...).
- `Identity` gains `browser_session: bool`. A struct literal that names every field needs it or
  `..Identity::default()`.
- Feature `exchange` now enables `tronc/bulle`, for `Bound`'s `TokenSource` impl.

### Added

- **`mcpauth::require_own_session(&request)`, Go `RequireOwnSession`: only the person's own
  browser session confirms a pending MCP action.** It passes only `Identity::browser_session`
  with a session id and a user id, and no actor, subject or scopes, on a request without an
  `Authorization` header. It refuses every bearer (opaque session, named API token, JWT,
  delegated or not, machine token), a named API token or a CLI, device or mobile token sent as
  a cookie, and a cookie with a bearer next to it. No identity is 401 `missing auth`; every other
  refusal is the one 403 `tronc::mcp::delegated()`, "only the person's own session can confirm
  actions". Use it as `tronc::mcp::PendingPage::new`'s `user` hook. porte-rs has no
  `porte/keys`, so Go's API-key refusal has no Rust counterpart.
- `Identity::browser_session`, set by `session::Manager::authenticate` when the credential came
  in the session cookie, the row is not a named API token, and the token starts with
  `BROWSER_TOKEN_PREFIX`. The bearer-JWT path always clears it.
- `BROWSER_TOKEN_PREFIX` (`b~`), `new_browser_token()` and
  `session::Manager::issue_cookie_for(request, template)` (Go `IssueCookieFor`), which mints a
  browser token and returns its cookie. The OIDC browser callback uses it; the CLI code exchange,
  the device exchange and `issue`/`issue_for` keep plain tokens. The stored hash covers the
  prefix, so adding `b~` to a CLI token makes it fail its lookup (401). `~` is outside the
  base64url alphabet, so no plain token can carry the mark by chance (Go v0.20.0's `b-` matched
  one plain token in 4096, found in this release's review and fixed in Go v0.20.1), and
  `issue`/`issue_for` still redraw any token that starts with the prefix. A `b-` token is plain.
- `mcpauth::account_exists(info, lookup)` and `NoAccount`, Go `AccountExists`: reads the account
  a verified MCP token speaks for (`call.parts.extensions.get::<tronc::mcp::TokenInfo>()`), so a
  tool never runs for an account erased after the token was minted. A missing info, an id that
  is empty, zero or not a number, or a failed lookup is `NoAccount`, with the lookup's error as
  its source.
- `exchange::Exchanger::bound(user_id, target)` and `Bound`, a `tronc::bulle::TokenSource` for
  one user and one target. Its `forget` drops the cached token so the Bulle client retries a 401
  once. It replaces the `Tokens` struct Toile (`modules/ai/bulle.rs`) and Docs
  (`modules/assistant/mod.rs`) each copied. A zero user id is `ExchangeError::NoUser` (401).
- The MCP verifier puts `subject` in tronc's `TokenInfo::extra` under `EXTRA_SUBJECT`, as Go
  `mcpauth.ExtraSubject`.
- Conformance runners for the Go v0.20.1 vectors `exchange_errors`, `mcpauth_tokens`,
  `provision_bearer`, `directory_erased`, the `new_browser_token shape` and `browser_session` token cases and the two
  back-channel cases where the provider keys are unreachable or answer an error (503
  `could not fetch the provider keys`, which porte-rs already answered since 0.5.2).

### Changed

- `scripts/sync-vectors.sh <tag>` clones FacileStudio/porte at the tag (or reads a checkout with
  `<checkout> <tag>`), replaces the vector files as a set, and writes only the tag to
  `tests/vectors/SOURCE`. CI re-syncs from that tag and fails on any difference, new vector
  files included. Each vector keeps the `source` of its Go module (`porte`, `porte/mcpauth`,
  `porte/directory`).
- A token vector case of an unknown `kind` fails the suite instead of falling into the
  `new_token` shape check.

### Not ported

- `directory.Client.Invitations` and `kit.MountInvitations` (`GET /me/invitations`, Go
  v0.18.0): about 270 lines of Go with validation, a per-user cache and single-flight. A
  follow-up when a Rust app shows the invitation badge.

## [0.7.1] - 2026-11-13

No code change: consumers need not bump.

### Added

- `scripts/check.sh` refuses a `path =` or `file://` dependency in `Cargo.toml` or `Cargo.lock`.
- `douane.yml` permits CVE-2026-119375 on `libsqlite3-sys` until 2027-05-13. The crate is in
  the lockfile through `sqlx-macros-core`'s weak optional features and is never compiled.

### Documentation

- 0.4.0 and 0.5.0 are marked unbuildable from git: both depend on tronc through a local path.

## [0.7.0] - 2026-11-12

The erased-subject fix of Go porte v0.19.0 and `directory` v0.5.0. Opt-in: an app that only
bumps behaves as before, unless it matches `ProvisionError` exhaustively. No migration, no
route, cookie or schema change, and no conformance vector changed in Go.

### Fixed

- **`directory`: an account re-created after an erasure is erased again, without a restart.**
  `Deletions` skipped every notice for a subject it had handled, so an account that came back
  (a Bulle provisioning call, a bearer token minted before the erasure, an MCP first call)
  survived re-pushes and re-polls. `Deletions::with_holds(Arc<dyn IdentityHolder>)` asks the
  holder about every handled subject that arrives again; when an account holds it, the person
  is erased again (`PersonDeleted`, then `IdentityEraser`) and recorded again, on push and on
  poll. Only that subject is touched. A failed check fails the notice: the push answers 500 and
  the poll keeps its cursor before it. Re-running the callbacks for every repeat instead would
  re-erase each poll's one-minute overlap.

### Added

- `directory::IdentityHolder` and `pg::Store::holds_identity(provider, subject)`, which
  implements it, matching the provider exactly as `erase_identity` does.
- `directory::Deletions::erased(provider, subject)`. It reads the `StateStore` on every call,
  never the receiver's in-memory copy, so a replica that does not run the receiver answers the
  same. No `StateStore` method is added; no `StateStore` answers false.
- `porte::ErasedSubjects` (implemented by `Deletions`) and `porte::SubjectErased`, the cause of
  the refusal, with `SubjectErased::caused(&tronc::Error)` for Go's `errors.Is`.
- `oidc::Kit::with_erased(Arc<dyn ErasedSubjects>)`, Go's `oidc.Deps.Erased`: the login
  callback, `provision_bearer` and the profile sync refuse an erased identity before the user
  write with a 403 `permission_denied`. A ledger that cannot be read fails closed as internal.
  It is a setter shared by every clone of the kit rather than a `Deps` field, so existing
  `Deps` literals still compile and the kit can be built before `Deletions`.
- `oidc::ProvisionError::Erased`: provisioning refused for an erased subject. mcpauth answers
  an invalid token, as for `Refused`. A `match` on `ProvisionError` needs the new arm.

## [0.6.1] - 2026-11-11

### Changed

- **tronc-rs pinned at v0.4.0** (was v0.3.0). An app on tronc-rs v0.4.0 (for `bulle`) now builds
  one copy of `tronc`, so porte's `tronc::Error` mappings and the app's are the same type.

## [0.6.0] - 2026-11-11

### Added

- **`exchange` feature: RFC 8693 token exchange**, a port of Go `porte/exchange`. `Exchanger`
  turns the user's stored Registre refresh token into a short-lived token for another suite app
  (`Target { audience, scopes }`), caches it per user, audience and scopes until 30 s before it
  expires, serializes refreshes per user across audiences and saves each rotated refresh token.
  `call` retries once on a downstream 401, `Source` binds a target to the request's `Identity`,
  and `ExchangeError` maps `Reconnect` to a 412 and `NoUser` to a 401 `tronc::Error`.
- **`forfait` feature: plan enforcement**, a port of Go `porte/forfait`. `Store` reads the
  entitlements in the directory snapshot and answers `enabled`, `limit` and `check` for a space
  or a person, failing open only before the first authoritative snapshot. `export` and `import`
  keep that state across a restart, and `CheckError::Limit` becomes a 402 with the upgrade URL.

## [0.5.2] - 2026-11-11

### Fixed

- **ID and logout tokens follow go-oidc's key set.** They no longer share the bearer cache,
  whose keys expired after an hour and failed hard when the refetch failed. Cached keys never
  expire. A signature no cached key verifies refetches the JWKS, at most every 30 s, and a
  failed fetch keeps the old keys. A back-channel logout that cannot be checked because the
  JWKS is unreachable now answers `503 could not fetch the provider keys`, which Registre
  retries, instead of `401`.
- **Outbound response bodies are capped while they are read.** `HttpClient::new` stops one byte
  past 1 MiB (8 MiB for the directory) instead of buffering the whole body first.

### Removed

- **The `openidconnect` dependency.** Discovery goes through the `jwt` fetch. This drops rsa
  0.9.10 (RUSTSEC-2023-0071) and the duplicate `oauth2`, `hmac`, `rand` and `pkcs*` crates from
  every consumer's lockfile. With it goes `impl openidconnect::AsyncHttpClient for HttpClient`.
- **`oidc::IdToken` and `oidc::IdTokenError`.** No public function took or returned them.
- **The PKCE verifier lookup in `POST /auth/oidc/exchange`.** Only the mobile flow, which
  porte-rs does not port, binds a code to a verifier, so a request carrying one is refused
  outright, as before.

## [0.5.1] - 2026-11-10

### Changed

- tronc-rs is fetched from https://github.com/FacileStudio/tronc-rs instead of a local checkout.
- Licensed under MIT, like Go porte.

## [0.5.0] - 2026-11-10

**Unbuildable from git:** this tag depends on tronc through a local `file://` git source,
so it builds only on the machine that cut it. Use 0.5.1 or later.

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

**Unbuildable from git:** this tag depends on tronc through a local `file://` git source,
so it builds only on the machine that cut it. Use 0.5.1 or later.

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
