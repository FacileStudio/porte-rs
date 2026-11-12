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
| `directory` | The Registre snapshot, the sync loop, account deletions |
| `spaces` | The membership guard and its conformance suite |
| `mcpauth` | The resource server for an app's `/mcp` |
| `exchange` | RFC 8693 token exchange: a per-user token for another suite app |
| `forfait` | The entitlements store: plan limits and switches from the directory snapshot |

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

## Directory and deletions

```
Registre ── POST /api/registre/sync (empty) ──▶ Syncer::nudge ─┐ 2 s debounce
         ◀── GET /api/directory/snapshot (Basic client creds) ──┤ also at boot and every 5 min
                                                                 └▶ Apply::apply (app tables), once per version
Registre ── POST /api/registre/deletions (secevent+jwt) ──▶ Deletions: verify RS256, iss, aud, window
         ◀── GET /api/directory/deletions?since=cursor-1min ── Deletions::poll, page by page
                                                   each person: PersonDeleted (app) → IdentityEraser (porte)
                                                   handled before? only again if IdentityHolder says the account came back
```

The nudge carries nothing and is trusted for nothing. The cursor only moves past people
handled before the earliest failure, and handled subjects are remembered for the retention
window, so a retried page never erases twice, unless the account came back: with
`Deletions::with_holds`, a handled subject that an account holds again is erased again. With
`Kit::with_erased(deletions)`, the login callback, bearer provisioning and the profile sync
refuse a handled subject before the user write, so the account does not come back at all.

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

## Wiring an app

One `auth::Kits::new` per app builds everything once, at boot, in this order:

```rust
pub struct Kits { pub sessions: Manager, pub oidc: Kit, pub syncer: Syncer, pub deletions: Deletions, pub mcp: Arc<Verifier> }

impl Kits {
    pub async fn new(cfg: &porte::Config, pool: &PgPool, env: &Env) -> Result<Kits, Box<dyn Error>> {
        let store = pg::Store::new(pool.clone()).with_token_sealer(pg::TokenSealer::parse(&env.token_key)?);
        let sessions = session::Manager::new(cfg, session::Deps { sessions: store.sessions(), now: None });
        let oidc = oidc::Kit::new(cfg, oidc::Deps {
            users: store.users(), identities: store.identities(), codes: store.login_codes(),
            sessions: sessions.clone(), config_extra: None, http: None, now: None,
        }).await?;
        let http = HttpClient::new();
        let client = directory::Client { issuer: cfg.issuer.clone(), client_id: cfg.client_id.clone(),
            client_secret: cfg.client_secret.clone(), http: http.clone() };
        let syncer = directory::Syncer::new(client.clone(), Arc::new(SpacesApply::new(pool)), Duration::ZERO);
        let deletions = directory::Deletions::new(client, Arc::new(AppData::new(pool)),
            Some(Arc::new(store.clone())), Some(Arc::new(DeletionState::new(pool))), Duration::ZERO)
            .with_holds(Arc::new(store.clone()));
        let oidc = oidc.with_erased(Arc::new(deletions.clone()));
        let mcp = Arc::new(mcpauth::Verifier::new(mcpauth::Config {
            issuer: cfg.issuer.clone(), resource: env.mcp_resource.clone(), scope_prefix: "feuilles".into(),
            audience: cfg.client_id.clone(), identities: store.identities(), provision: true,
            accounts: Some(oidc.clone()), http,
        }).await?);
        Ok(Kits { sessions, oidc, syncer, deletions, mcp })
    }
}
```

Then the router: `sessions.routes()` and `oidc.routes()` under `/api`, the app's routes behind
`sessions.require_auth()`, `syncer.nudge_route()` at `/api/registre/sync`, `deletions.route()`
at `/api/registre/deletions`, and `/mcp` either through `tronc::mcp::mount` (hand it
`mcp` as the `Arc<dyn tronc::mcp::Verifier>`: porte's `Verifier` implements it, no adapter) or
behind `RequireLayer::new(mcp, …)` with `metadata_route` at `metadata_url(resource)`'s path. Spawn `syncer.run(token)` and
`deletions.run(token)` in exactly one replica. `SpacesApply`, `AppData` and `DeletionState`
are the app's: its spaces tables, its own erase, and its one-row state table. `SpacesApply`
moves the content of a space the snapshot dropped to the trash, never deletes it: a snapshot
is authoritative, and a space that vanished once can come back in the next one. A handler that
needs the caller's Registre subject on a cookie session calls `store.find_by_user(&cfg.issuer,
identity.user_id)`, because `Identity::subject` is empty there, as in Go. Every
WebSocket route calls `sessions.check_origin(&parts)` before upgrading.

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
- **No OIDC client crate.** Discovery, the code exchange, the refresh and the ID token checks
  are hand-written to go-oidc's rules: a logout token with no `sub` or a non-object `events`
  must reach porte's own checks and messages, which a typed client refuses earlier. Discovery
  shares the `jwt` fetch (1 MiB cap) and requires the issuer byte for byte, an
  `authorization_endpoint` and a `jwks_uri`, as go-oidc's `NewProvider` does. Only RS256 is
  accepted, as Registre advertises.
- **ID and logout tokens use go-oidc's key set, not the bearer cache.** Cached keys never
  expire. A signature no cached key verifies (an unknown kid, no kid, a key replaced under its
  kid) refetches the JWKS, at most every 30 s where go-oidc does not throttle. A failed fetch
  keeps the old keys. A back-channel logout that cannot be checked because the fetch failed
  answers `503`, so Registre retries it instead of dropping the revocation.
- **The token endpoint is called with HTTP Basic only.** Go's `oauth2` auto-detects and falls
  back to credentials in the form; Registre accepts Basic.
- **The CLI code page draws no borders**, per the suite UI rule.
- **`mcpauth` has no Go SDK under it.** `RequireLayer` reproduces `RequireBearerToken`'s
  answers and porte's challenge codes itself. `CheckPlan` and `PlanGate` are not ported:
  `/mcp` is never plan-gated.
- **No `pg` spaces store.** Go `porte/pg` owns no space tables: membership is app data. The
  conformance suite runs in this repo against `spaces::Memory` and an unscoped store; Feuilles
  and Docs run it against their own `Store` over their own tables.
- **The deletion state blob is not Go's.** It is JSON with a unix-seconds cursor; the blob is
  opaque to the app and never shared with a Go app.
- **`exchange` refreshes on its own task.** Go detaches the refresh from the caller's context
  with `context.WithoutCancel`; Rust spawns it, so a dropped request future still persists the
  rotated refresh token. `Exchanger::call` is Go's `Do` (`do` is a Rust keyword), and `Source`
  takes the request's `Identity` instead of a context.
- **`forfait` logs through `tracing`** and takes its issuer with `Store::with_issuer`. Its
  export document is the same JSON Go writes.
- **No local passwords, magic links, avatars, API keys, mobile login or `porte/kit`.** An exchange request carrying a PKCE `verifier` is
  refused, since only the mobile flow binds one. The
  columns stay in `SCHEMA` so the tables match Go's.
