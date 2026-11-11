# porte-rs

[![ci](https://github.com/FacileStudio/porte-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/FacileStudio/porte-rs/actions/workflows/ci.yml)

The Rust auth kit for the [Facile Studio](https://facile.studio) suite: Registre sign-in,
sessions, spaces and MCP auth for the suite apps written in Rust, ported from Go
[`porte`](https://github.com/FacileStudio/porte).

Feuilles and Docs have Rust backends. A browser, a CLI or Registre must not be able to tell
them from a Go app, so this crate serves the same routes, cookie, tokens and tables, pinned by
test vectors generated from Go `porte` v0.16.1.

## What it does

- Issues opaque sessions, stores only their SHA-256, and reads them from the `session` cookie
  (`__Host-session` over https) or `Authorization: Bearer`
- Enforces the `X-Facile-CSRF` header on cookie-authenticated writes, an idle window, and an
  Origin check for WebSocket upgrades
- Signs users in through Registre: discovery, the authorization code flow with PKCE (S256) and
  a nonce, the CLI code and device exchanges, back-channel logout, profile sync and the roles claim
- Mirrors Registre's spaces through the directory snapshot, its nudge, and the account
  deletions it polls and receives signed
- Guards space membership with a rank ladder and a conformance suite for the app's store
- Verifies RS256 bearer JWTs offline against the issuer's JWKS, with an optional scope gate
- Guards an app's `/mcp` as an OAuth 2.1 resource server, with RFC 9728 metadata and
  first-call account provisioning
- Exchanges the signed-in user's stored Registre grant for a short-lived token to another
  suite app (RFC 8693), refreshing and rotating the refresh token safely (feature `exchange`)
- Enforces the plan a space or person pays for from the entitlements in the directory snapshot
  (feature `forfait`)
- Ships the identity tables (`porte_users`, `porte_identities`, `porte_sessions`, ...) byte for
  byte as Go writes them, with stores on `sqlx` and AES-256-GCM sealing of stored OIDC tokens

## Stack

| Layer | Tech |
|---|---|
| Runtime | Rust 1.98, edition 2024, axum 0.8, tower 0.5, [tronc-rs](https://github.com/FacileStudio/tronc-rs) 0.3 |
| Storage | PostgreSQL 16 through sqlx 0.9 (feature `pg`) |
| OIDC | hand-written to go-oidc's rules, reqwest 0.13 with rustls, RSA 0.10 (feature `oidc`) |

## Install

Pin a tag and pick features. Nothing is on by default.

```toml
[dependencies]
porte = { git = "https://github.com/FacileStudio/porte-rs", tag = "v0.6.1", features = ["pg", "oidc", "directory", "spaces", "mcp"] }
```

| Feature | Modules |
|---|---|
| always | root types, `token`, `store`, `session`, `wire` |
| `pg` | `pg`, the identity tables and their stores |
| `oidc` | `oidc` (the Registre kit), `jwt`, `http_client` |
| `directory` | `directory`: the snapshot client, `Syncer`, `Deletions`, `http_client` |
| `spaces` | `spaces`: `Guard`, `Ladder`, the `Store` trait and `spaces::conformance` |
| `exchange` | `exchange`: `Exchanger`, `Source`, `Target`, RFC 8693 against Registre's token endpoint |
| `forfait` | `forfait`: the entitlements `Store` over the directory snapshot (pulls in `directory`) |
| `mcp` | `mcpauth`: `Verifier` (also a `tronc::mcp::Verifier`), `RequireLayer`, the metadata route (pulls in `oidc` and tronc's `mcp`) |

The wiring every app writes, in its `auth` module, is in
[docs/architecture.md](docs/architecture.md#wiring-an-app). The core of it:

```rust
let store = porte::pg::Store::new(pool.clone()).with_token_sealer(porte::pg::TokenSealer::parse(&token_key)?);
let sessions = porte::session::Manager::new(&config, porte::session::Deps { sessions: store.sessions(), now: None });
let kit = porte::oidc::Kit::new(&config, porte::oidc::Deps {
    users: store.users(), identities: store.identities(), codes: store.login_codes(),
    sessions: sessions.clone(), config_extra: None, http: None, now: None,
}).await?;
let api = Router::new()
    .route("/me", get(|me: porte::Identity| async move { me.user_id.to_string() }))
    .route_layer(sessions.require_auth())
    .merge(sessions.routes())
    .merge(kit.routes());
```

The app's first migration carries `porte::pg::SCHEMA` verbatim.

## Documentation

| Doc | What's in it |
|---|---|
| [Architecture](docs/architecture.md) | Modules, request lifecycle, where Rust differs from Go |
| [Configuration](docs/configuration.md) | Every `Config` field, the variables it reads, and its traps |
| [Development](docs/development.md) | Local setup, the quality gate, vectors, versioning |
| [API](docs/api.md) | Every public item, module by module |

## License

porte-rs is licensed under the [MIT License](LICENSE), like Go porte.

---

Part of the [Facile Suite](https://facile.studio) — self-hosted tools for creative studios
and freelancers. One login, zero cloud dependency.
