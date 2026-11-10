# porte-rs — API

Every public item, module by module, with the feature that turns it on. `cargo doc
--all-features --open` renders the same surface with full doc comments. porte serves its
routes inside the app's router, so the live `/docs` reference is the app's.

## Root (always)

```rust
pub const SESSION_COOKIE_NAME: &str = "session";
pub const CSRF_HEADER_NAME: &str = "X-Facile-CSRF";
pub const DEFAULT_SESSION_TTL, DEFAULT_LOGIN_CODE_TTL, DEFAULT_CLAIMS_TTL,
    DEFAULT_PROFILE_SYNC_INTERVAL, DEFAULT_SESSION_IDLE_TTL: Duration;
pub const DEFAULT_APP_NAME: &str = "Sign-in";
pub const DEFAULT_LOCALE: &str = "en";
pub mod routes { CONFIG, LOGIN, CALLBACK, EXCHANGE, DEVICE_EXCHANGE, LOGOUT, SYNC_PROFILE, BACKCHANNEL_LOGOUT }

pub struct Config { issuer, client_id, client_secret, redirect_url, success_url, failure_url,
    app_name, logo_url, sso_only, machine_audience, scope_prefix, cli_audience,
    trust_email_without_verified_claim, claims_scope, extra_scopes, extra_claims,
    session_ttl, claims_ttl, login_code_ttl, session_idle_ttl: Option<Duration>, accept_legacy_cookie }
impl Config { from_vars(&tronc::env::Vars), enabled, claims_enabled, https, idle_timeout, scopes,
    resolved, validate -> Result<(), ConfigError>, login_failure(reason), app_label, logo }
pub struct ConfigError(pub String);

pub struct Identity { user_id: i64, subject, email, email_verified: bool, name, roles: Vec<String>,
    scopes: Vec<String>, actor: String, session_id: i64, roles_synced_at: Option<OffsetDateTime> }
impl Identity { has_role(&str), has_any_role(&[&str]) }
impl FromRequestParts, OptionalFromRequestParts for Identity   // 401 "missing auth"
pub struct Claims { provider, subject, email, email_verified, name, preferred_username, given_name,
    family_name, picture, locale, avatar_url, roles: Option<Vec<String>>, extra: BTreeMap<String, Value>, tokens }
impl Claims { display_name() }
pub struct TokenSet { access_token, refresh_token, expiry: Option<OffsetDateTime> }
pub struct StoredIdentity { user_id, provider, subject, password_hash, tokens, roles: Option<Vec<String>>,
    roles_synced_at, synced_at }
impl StoredIdentity { roles_stale(now, ttl) }
pub fn normalize_locale(tag: &str) -> String;
pub type Clock = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;
pub fn system_clock() -> Clock;
```

## `token` (always)

```rust
pub fn new_token() -> Result<String, getrandom::Error>;  // 32 random bytes, base64url, 43 chars
pub fn hash_token(token: &str) -> String;                 // lowercase hex SHA-256
pub fn secure_compare(a: &str, b: &str) -> bool;          // constant time
```

## `store` (always)

```rust
pub enum StoreError { NotFound, CodeConsumed, Refused(tronc::Error), Other(Box<dyn Error + Send + Sync>) }
pub struct Session { id, token_hash, user_id, label, created_at, last_used_at, expires_at: Option<_>,
    provider, subject, issued_by }   // the last three bind an issue; they are not stored
impl Session { expired(now), is_api_token() }
pub struct LoginCode { code_hash, user_id, expires_at, provider, subject }

#[async_trait] pub trait UserStore { upsert_from_oidc(&Claims) -> Result<i64, StoreError> }
#[async_trait] pub trait IdentityStore { find(provider, subject), save(&StoredIdentity),
    mark_roles_synced(provider, subject, at), list_by_user(user_id) }
#[async_trait] pub trait SessionStore: SessionRevocation { create(Session) -> Session, find(hash),
    touch(hash, at), delete(hash), list_by_user(user_id) }
#[async_trait] pub trait SessionRevocation { delete_by_user, delete_logins(user, except),
    delete_by_id(user, id), delete_expired(now) }
#[async_trait] pub trait LoginCodeStore { create(&LoginCode), consume(hash), delete_expired(now) }
```

`SessionStore::find` does not filter on expiry. `LoginCodeStore::consume` returns
`CodeConsumed` on a replay and `NotFound` for a code that never existed.

## `session` (always)

```rust
pub struct Deps { pub sessions: Arc<dyn SessionStore>, pub now: Option<Clock> }
pub struct Manager;  // Clone
impl Manager {
    pub fn new(cfg: &Config, deps: Deps) -> Self;
    pub fn with_claims(&self, Arc<dyn ClaimsSource>); pub fn with_jwt(&self, Arc<dyn JwtVerifier>);
    pub fn config(&self) -> &Config; pub fn store(&self) -> &Arc<dyn SessionStore>;
    pub async fn issue(&self, user_id, label) -> Result<(String, Session), tronc::Error>;
    pub async fn issue_for(&self, caller: Option<&Identity>, template: Session) -> Result<(String, Session), tronc::Error>;
    pub async fn end(&self, &Identity) -> Result<(), tronc::Error>;
    pub async fn list / revoke / revoke_user / revoke_logins / sweep;
    pub async fn authenticate(&self, req: &impl RequestView) -> Authentication;
    pub fn require_auth(&self) -> AuthLayer; pub fn optional(&self) -> AuthLayer;
    pub fn routes<S>(&self) -> axum::Router<S>;   // POST /auth/logout
    pub fn check_origin(&self, req: &impl RequestView) -> Result<(), tronc::Error>;
    pub fn secure(&self, req) -> bool; pub fn read_cookie(&self, req, base) -> Option<String>;
    pub fn set_cookie(&self, req, base, value, max_age) -> HeaderValue;
    pub fn clear_cookie(&self, req, base) -> Vec<HeaderValue>;
    pub fn session_cookie(&self, req, token) -> HeaderValue;
}
pub struct Authentication { pub result: Result<Identity, tronc::Error>, pub set_cookies: Vec<HeaderValue> }
pub fn append_cookies(out: &mut HeaderMap, values: impl IntoIterator<Item = HeaderValue>);
pub trait RequestView { fn view(&self) -> View<'_> }  // http::Request<B>, http::request::Parts
pub struct View<'a> { pub headers, pub extensions, pub method }
#[async_trait] pub trait ClaimsSource { async fn attach(&self, &mut Identity) }
#[async_trait] pub trait JwtVerifier { async fn verify_jwt(&self, raw) -> Result<Identity, Box<dyn Error>> }
```

| Route | Answer |
|---|---|
| `POST /auth/logout` | `200 {"logged_out":true}`, both cookie spellings expired; `403` with a cookie and no CSRF header |

| Refusal | Status | Message |
|---|---|---|
| no credential | 401 | `missing auth` |
| cookie write without `X-Facile-CSRF` | 403 | `missing X-Facile-CSRF header` |
| unknown token | 401 | `invalid session` |
| expired or idle | 401 | `session expired` |
| WebSocket upgrade with a cookie and no Origin | 403 | `missing Origin header` |
| WebSocket upgrade from another origin | 403 | `cross-origin WebSocket refused` |

## `wire` (always)

`ConfigResponse { sso_only, oidc_enabled }`, `ExchangeRequest { code, verifier }`,
`DeviceExchangeRequest { access_token }`, `ExchangeResponse { user_id: String, token }`,
`LogoutResponse { logged_out }`, `SyncProfileResponse { synced }`. Request types refuse unknown
fields.

## `pg` (`pg`)

```rust
pub const SCHEMA: &str;   // Go pg.Schema at v0.16.1, byte for byte
pub async fn ensure_schema(pool: &PgPool) -> Result<(), sqlx::Error>;   // tests only
pub struct Store;  // Clone; implements UserStore, IdentityStore, SessionStore, SessionRevocation, LoginCodeStore
impl Store {
    pub fn new(pool: PgPool) -> Self;
    pub fn with_token_sealer(self, Option<TokenSealer>) -> Self;
    pub fn pool(&self) -> &PgPool;
    pub fn users / identities / sessions / login_codes(&self) -> Arc<dyn Trait>;
    pub async fn erase_identity(&self, provider, subject) -> Result<(), StoreError>;
    pub async fn reseal_identities(&self) -> Result<u64, StoreError>;
}
pub struct TokenSealer;
impl TokenSealer { new(&[[u8; 32]]), parse(spec) -> Result<Option<Self>, ConfigError>, seal(plain), open(stored) }
pub struct TokenUnreadable;
```
