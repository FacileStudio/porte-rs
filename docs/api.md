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

## `oidc` (`oidc`)

```rust
pub type ConfigExtra = Arc<dyn Fn() -> serde_json::Map<String, Value> + Send + Sync>;
pub struct Deps { users: Arc<dyn UserStore>, identities: Arc<dyn IdentityStore>,
    codes: Arc<dyn LoginCodeStore>, sessions: Manager, config_extra: Option<ConfigExtra>,
    http: Option<HttpClient>, now: Option<Clock> }
pub struct Kit;  // Clone; implements session::ClaimsSource
impl Kit {
    pub async fn new(cfg: &Config, deps: Deps) -> Result<Kit, ConfigError>;
    pub fn routes<S>(&self) -> axum::Router<S>;
    pub fn config(&self) -> &Config; pub fn enabled(&self) -> bool; pub fn sessions(&self) -> &Manager;
    pub async fn provision_bearer(&self, token: &jwt::Claims) -> Result<Identity, ProvisionError>;
}
pub async fn resolve_bearer(identities: &dyn IdentityStore, issuer: &str, claims: &jwt::Claims) -> Result<Identity, StoreError>;
pub fn pkce_challenge(verifier: &str) -> String;
pub enum ProvisionError { Refused(String), Store(String) }
pub struct IdToken { subject, nonce, claims: Value }   pub struct IdTokenError(pub String);
```

`Kit::new` arms the bearer-JWT path of the session manager when `machine_audience` is set,
and attaches itself as the claims source when `claims_scope` is set.

| Route | Mounted | Answer |
|---|---|---|
| `GET /auth/config` | always | `200 {"sso_only","oidc_enabled"}`, plus the `ConfigExtra` keys sorted, porte's two written last |
| `GET /auth/oidc` | OIDC on | `302` to the authorize endpoint with `__Host-oidc_state` (10 min); `?flow=cli&port=N&cli_state=S` for a CLI; `?flow=mobile` is a `302` to the failure URL; `?ui_locales=fr` is forwarded |
| `GET /auth/oidc/callback` | OIDC on | `302` to the success URL with the session cookie, to `127.0.0.1:N/?code=&state=` for a CLI with a port, or the code page; failures are `302` to `<failure>?error=<reason>` |
| `POST /auth/oidc/exchange` | OIDC on | `{"code"}` → `200 {"user_id","token"}`, `401 invalid or expired code`, `no-store` |
| `POST /auth/oidc/device/exchange` | `cli_audience` set | `{"access_token"}` → `200 {"user_id","token"}`, `400` on an empty body, `401 invalid access token`, `no-store` |
| `POST /auth/sync-profile` | OIDC on, behind `require_auth` | `200 {"synced"}`; `401` when UserInfo answers for another subject |
| `POST /auth/backchannel-logout` | OIDC on | form `logout_token` → `200 {"logged_out":true}`, `400 missing logout_token`, `401` for any token it refuses, `no-store` |

## `jwt` (`oidc`)

```rust
pub const DEFAULT_CACHE_TTL: Duration;  // 1 hour
pub const LEEWAY: Duration;             // 30 s
pub struct Config { issuer, audience, extra_audiences: Vec<String>, cache_ttl: Duration, http: HttpClient, now: Option<Clock> }
pub struct Verifier;
impl Verifier { pub async fn new(cfg: Config) -> Result<Verifier, JwtError>; pub async fn verify(&self, raw: &str) -> Result<Claims, JwtError>; pub fn config(&self) -> &Config }
pub struct Claims { subject, email, name, roles: Option<Vec<String>>, scopes, actor, audience, client_id, id, expires_at, profile: Profile }
pub struct Profile { email_verified: Option<bool>, preferred_username, picture, locale }
pub enum JwtError { Malformed, Algorithm(String), UnknownKey(String), Signature, Issuer(String), Audience,
    Expired, NotYetValid, IssuedInFuture, Fetch(String), Config(String) }
impl JwtError { pub fn is_invalid(&self) -> bool }
```

## `http_client` (`oidc` or `directory`)

```rust
pub type HttpRequest = http::Request<Vec<u8>>; pub type HttpResponse = http::Response<Vec<u8>>;
pub struct TransportError(pub String);
#[async_trait] pub trait Transport { async fn send(&self, HttpRequest) -> Result<HttpResponse, TransportError> }
pub struct HttpClient;  // Clone; reqwest + rustls, no redirects, 10 s timeout
impl HttpClient { new(), from_transport(Arc<dyn Transport>), send(req), get(url) }
impl openidconnect::AsyncHttpClient for HttpClient;
```

## `directory` (`directory`)

```rust
pub const ROLE_MEMBER, ROLE_ADMIN, ROLE_OWNER: &str;
pub const MAX_SNAPSHOT_BYTES: usize = 8 << 20;
pub const SYNC_PATH: &str = "/api/registre/sync";
pub const DELETIONS_PATH: &str = "/api/registre/deletions";
pub const DEFAULT_INTERVAL: Duration;    // 5 minutes
pub const DELETION_RETENTION: Duration;  // 60 days
pub const USER_DELETED_EVENT: &str = "https://schemas.facile.studio/event/user-deleted";
pub enum DirectoryError { Unavailable(String), TooLarge, Failed(String) }

pub struct Client { pub issuer, pub client_id, pub client_secret, pub http: HttpClient }
impl Client { pub async fn snapshot(&self) -> Result<Snapshot, DirectoryError>;
    pub async fn deletions(&self, since: OffsetDateTime) -> Result<Vec<Deleted>, DirectoryError> }
pub struct Snapshot { version: i64, entitlements_revision: i64, spaces: Vec<Space>, people: Vec<Person> }
pub struct Space { id, name, members: Vec<Member>, entitlements: HashMap<String, Value> }
pub struct Member { subject /* "sub" */, email, name, picture, role }
pub struct Person { subject /* "sub" */, entitlements: HashMap<String, Value> }
pub struct Deleted { subject, deleted_at: OffsetDateTime }

#[async_trait] pub trait Apply { async fn apply(&self, &Snapshot) -> Result<(), DirectoryError> }
pub struct Syncer;  // Clone
impl Syncer { pub fn new(client, apply: Arc<dyn Apply>, interval) -> Syncer;
    pub fn nudge_route<S>(&self) -> MethodRouter<S>; pub fn nudge(&self);
    pub async fn sync(&self) -> Result<(), DirectoryError>; pub async fn run(&self, shutdown: CancellationToken) }

#[async_trait] pub trait PersonDeleted { async fn on_person_deleted(&self, provider, subject) -> Result<(), DirectoryError> }
#[async_trait] pub trait IdentityEraser { async fn erase_identity(&self, provider, subject) -> Result<(), DirectoryError> }  // pg::Store
#[async_trait] pub trait StateStore { async fn load(&self) -> Result<Vec<u8>, _>; async fn save(&self, &[u8]) -> Result<(), _> }
pub struct Deletions;  // Clone
impl Deletions { pub fn new(client, on_deleted, eraser: Option<_>, store: Option<_>, interval) -> Deletions;
    pub async fn poll(&self) -> Result<(), DirectoryError>; pub async fn run(&self, shutdown: CancellationToken);
    pub fn route<S>(&self) -> MethodRouter<S> }
```

| Route | Answer |
|---|---|
| `POST /api/registre/sync` (`Syncer::nudge_route`) | `202`, wakes the loop; other methods `405` |
| `POST /api/registre/deletions` (`Deletions::route`) | `202` once erased; `400` for any notice it refuses; `503` when the keys cannot be fetched or an unknown `kid` arrives inside the one-minute refetch gap; `500` when an erase fails; other methods `405` with `Allow: POST` |

## `spaces` (`spaces`)

```rust
pub struct Role(pub String);  // Role::owner(), Role::admin(), Role::member(), as_str(), From<&str>
pub struct Membership { space_id, user_id, role: Role }
pub struct Scope { pub user_id, pub space_id, pub role, /* resolved: private */ }
impl Scope { resolved(), personal() }
pub enum SpaceError { NotMember, Forbidden, SoleOwner, UnknownRole, Store(String) }
pub struct Ladder;  // Default: member < admin < owner
impl Ladder { new(&[Role]), valid, at_least(have, min), top, roles }
#[async_trait] pub trait Store { membership(space, user), memberships(user), count_role(space, &Role) }
#[async_trait] pub trait Seeder: Store { seed(&Membership) }
pub struct Memory;  // Store + Seeder
pub struct Guard;   // Clone
impl Guard { new(Arc<dyn Store>), with_ladder(Ladder), resolve(user, space), require(user, space, &min),
    can_leave(user, space), spaces(user), assignable_by(&Scope, &Role), assignable_over(&Scope, &current, &target),
    ladder(), store() }
pub mod conformance { pub async fn run(new_store) -> Result<(), Vec<String>>; pub async fn run_with_ladder(new_store, Ladder);
    SPACE_A, SPACE_B, USER_OWNER, USER_ADMIN, USER_MEMBER, USER_CO_OWNER, USER_OUTSIDER }
```

## `mcpauth` (`mcp`)

```rust
pub struct Config { issuer, resource, scope_prefix, audience, identities: Arc<dyn IdentityStore>,
    provision: bool, accounts: Option<oidc::Kit>, http: HttpClient }
pub enum VerifyError { InvalidToken, Unavailable }
pub struct Verifier;
impl Verifier { pub async fn new(cfg: Config) -> Result<Verifier, ConfigError>;
    pub async fn verify(&self, raw: &str) -> Result<TokenInfo, VerifyError> }
pub struct TokenInfo { user_id: String, scopes, expiration: OffsetDateTime, client_id, actor, subject }  // extractor
pub const BULLE_CLIENT_ID: &str = "bulle";
pub fn third_party(info: Option<&TokenInfo>) -> bool;   // false only for act + client_id "bulle"
pub fn identity(info: Option<&TokenInfo>) -> Option<Identity>;
pub struct Scopes { read, write }  impl Scopes { list() }
pub fn scopes_for(prefix: &str) -> Scopes; pub fn has_scope(info: Option<&TokenInfo>, scope: &str) -> bool;
pub struct RequireOptions { resource_metadata_url, scopes: Vec<String>, allow_missing_expiration, clock_skew }
pub struct RequireLayer;  impl RequireLayer { pub fn new(Arc<Verifier>, RequireOptions) -> Self }  // tower::Layer
pub struct ProtectedResourceMetadata { resource, authorization_servers, scopes_supported,
    bearer_methods_supported, resource_signing_alg_values_supported }
pub fn protected_resource_metadata(resource, issuer, scopes) -> ProtectedResourceMetadata;
pub fn metadata_url(resource: &str) -> Result<String, ConfigError>;
pub fn metadata_route<S>(ProtectedResourceMetadata) -> MethodRouter<S>;
```

| Refusal by `RequireLayer` | Status | Body | `WWW-Authenticate` |
|---|---|---|---|
| no `Bearer` header | 401 | `no bearer token` | `Bearer resource_metadata="…", scope="…"` |
| any token refusal | 401 | `invalid token` | `Bearer error="invalid_token", resource_metadata="…", scope="…"` |
| a required scope missing | 403 | `insufficient scope` | `Bearer error="insufficient_scope", resource_metadata="…", scope="…"` |
| JWKS or store unreachable | 500 | `token verification is unavailable` | none |

`write` implies `read` in `TokenInfo::scopes`. The bodies are `text/plain`, as the Go SDK
writes them, not the suite envelope.
