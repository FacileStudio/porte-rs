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
| `oidc` | The Registre kit: discovery, the routes, roles, bearer provisioning |
| `jwt` | Offline RS256 verification against the issuer's JWKS |
| `http_client` | The outbound HTTP, behind a `Transport` a test can replace |

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

## Sign-in flow

```
browser ── GET /api/auth/oidc ──▶ kit: state, nonce, PKCE verifier into __Host-oidc_state (10 min)
        ◀── 302 sso.facile.studio/authorize?code_challenge=S256(verifier)&nonce=…&state=…
        ── GET /api/auth/oidc/callback?code&state ──▶ kit: state == cookie (constant time)
                                                      POST /oauth/token (Basic auth, code_verifier)
                                                      verify id_token: RS256, iss, aud, exp, nonce
                                                      UserStore::upsert_from_oidc, IdentityStore::save
        ◀── 302 success URL, Set-Cookie: __Host-session
```

A CLI passes `?flow=cli&port=N&cli_state=S`: the callback stores a one-time login code and
redirects to `http://127.0.0.1:N/?code=…&state=S`, or renders the code page without a port.
`POST /auth/oidc/exchange` trades the code for a session token once. With `OIDC_CLI_AUDIENCE`,
`POST /auth/oidc/device/exchange` trades a `facile-cli` device-grant access token for a session
instead, and that token never opens a `require_auth` route directly.

With `OIDC_MACHINE_AUDIENCE`, a bearer shaped as a JWT is verified offline and mapped to an
account by `(issuer, sub)` through `resolve_bearer`, and `OIDC_SCOPE_PREFIX` gates it on
`<prefix>.read` for GET, HEAD, OPTIONS and `<prefix>.write` for the rest.

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
- **ID tokens are verified by porte, not by `openidconnect`.** The crate runs discovery (and
  accepts the live `https://sso.facile.studio` document), but the code exchange, the refresh
  and the ID token checks are hand-written to go-oidc's rules: a logout token with no `sub` or
  a non-object `events` must reach porte's own checks and messages, which `openidconnect`'s
  typed claims refuse earlier. Only RS256 is accepted, as Registre advertises.
- **The token endpoint is called with HTTP Basic only.** Go's `oauth2` auto-detects and falls
  back to credentials in the form; Registre accepts Basic.
- **The CLI code page draws no borders**, per the suite UI rule.
- **No local passwords, magic links, avatars, API keys, forfait or mobile login.** The
  columns stay in `SCHEMA` so the tables match Go's.
