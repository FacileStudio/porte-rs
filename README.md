# porte-rs

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
- Ships the identity tables (`porte_users`, `porte_identities`, `porte_sessions`, ...) byte for
  byte as Go writes them, with stores on `sqlx` and AES-256-GCM sealing of stored OIDC tokens

## Stack

| Layer | Tech |
|---|---|
| Runtime | Rust 1.98, edition 2024, axum 0.8, tower 0.5, [tronc-rs](https://github.com/FacileStudio/tronc-rs) 0.2 |
| Storage | PostgreSQL 16 through sqlx 0.9 (feature `pg`) |

## Install

Pin a tag and pick features. Nothing is on by default.

```toml
[dependencies]
porte = { git = "https://github.com/FacileStudio/porte-rs", tag = "v0.1.0", features = ["pg"] }
```

| Feature | Modules |
|---|---|
| always | root types, `token`, `store`, `session`, `wire` |
| `pg` | `pg`, the identity tables and their stores |

A session-only app, the shape every app starts from:

```rust
use porte::session::{Deps, Manager};

let store = porte::pg::Store::new(pool.clone());
let sessions = Manager::new(&config, Deps { sessions: store.sessions(), now: None });
let api = Router::new()
    .route("/me", get(|me: porte::Identity| async move { me.user_id.to_string() }))
    .route_layer(sessions.require_auth())
    .merge(sessions.routes());
```

The app's first migration carries `porte::pg::SCHEMA` verbatim.

## Documentation

| Doc | What's in it |
|---|---|
| [Architecture](docs/architecture.md) | Modules, request lifecycle, where Rust differs from Go |
| [Configuration](docs/configuration.md) | Every `Config` field, the variables it reads, and its traps |
| [Development](docs/development.md) | Local setup, the quality gate, vectors, versioning |
| [API](docs/api.md) | Every public item, module by module |

---

Part of the [Facile Suite](https://facile.studio) — self-hosted tools for creative studios
and freelancers. One login, zero cloud dependency.
