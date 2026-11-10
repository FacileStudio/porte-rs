# porte-rs — Architecture

How the crate is put together, what a request goes through, and where the Rust port differs
from Go `porte` v0.16.1.

## Topology

```
Browser / CLI ──▶ app router (axum) ──▶ Manager::require_auth layer ──▶ handler(Identity)
                        │                     │
                        │                     ├── cookie: __Host-session / session
                        │                     └── Authorization: Bearer
                        │
                        └── Manager::routes()  POST /auth/logout
                                              │
                                     porte::pg::Store (sqlx) ──▶ Postgres 16
                                       porte_users, porte_identities,
                                       porte_sessions, porte_login_codes
```

## Modules

| Module | What it is |
|---|---|
| root | `Config`, `Identity`, `Claims`, `TokenSet`, `StoredIdentity`, the constants and route paths |
| `token` | `new_token`, `hash_token`, `secure_compare` |
| `store` | `Session`, `LoginCode`, `StoreError` and the store traits an app implements or takes from `pg` |
| `session` | `Manager`: issue, cookies, the middleware, logout, `check_origin` |
| `wire` | The JSON bodies of the routes |
| `pg` | The tables and the stores over them, the token sealer |

The root depends on no database driver: an app's own stores compile against plain types.

## Request lifecycle

1. `require_auth` (or `optional`) splits the request and calls `Manager::authenticate`.
2. The credential is the session cookie if present, else `Authorization: Bearer`. Nothing
   else is read, never a query parameter.
3. A cookie on a method other than GET, HEAD or OPTIONS needs `X-Facile-CSRF` with any
   non-empty value, or the answer is 403 `permission_denied`.
4. The token is hashed and looked up once. An unknown token is 401 `invalid session`; an
   expired or idle one is 401 `session expired` and its row is deleted. Either way a cookie
   credential gets its cookie cleared on the response.
5. `last_used_at` is written at most once a minute.
6. The `Identity` lands in the request extensions, where the `Identity` extractor reads it.

## Data model

`porte::pg::SCHEMA` is Go `pg.Schema` byte for byte, pinned by `vectors/schema.json`. An app
ships it as its first migration and porte never applies it at boot.

| Table | Key | Holds |
|---|---|---|
| `porte_users` | `id` | One account: email, verified flag, name, locale |
| `porte_identities` | `(provider, subject)` | One way a human signs in, with the provider's tokens and cached roles |
| `porte_sessions` | `id`, `token_hash` | One session or named token. Only the hash is stored |
| `porte_login_codes` | `code_hash` | One-time CLI codes |

`(provider, subject)` is the matching key, never the email. `upsert_from_oidc` falls back to
the email only when the provider verified it, and a verified login that lands on an
unverified account purges that account's identities and sessions first.

## Where Rust differs from Go

- **`Manager::check_origin` is new.** A WebSocket upgrade is a GET, so the CSRF header rule
  does not cover it. A request carrying the session cookie must send an `Origin` matching its
  `Host` (or the success URL's origin). Bearer clients are exempt. Go porte has no WebSocket
  consumer yet; this is proposed upstream.
- **`SessionStore` is two traits.** The bulk deletes (`delete_by_user`, `delete_logins`,
  `delete_by_id`, `delete_expired`) sit in the supertrait `SessionRevocation`. The method set
  is Go's; only the grouping differs.
- **Cookies are returned, not written.** `set_cookie`, `clear_cookie` and `session_cookie`
  return `HeaderValue`s, and `Manager::authenticate` returns the ones the response must carry.
- **No local passwords, magic links, avatars, API keys, forfait or mobile login.** The
  columns stay in `SCHEMA` so the tables match Go's.
