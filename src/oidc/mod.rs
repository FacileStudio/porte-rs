//! The engine: discovery, the authorization code flow with PKCE and nonce, the CLI codes, the
//! device exchange, back-channel logout, profile sync, roles and bearer JWTs.
//!
//! [`Kit::new`] runs discovery against `OIDC_ISSUER` and fails at boot on any
//! misconfiguration. A disabled config is not an error: the kit then serves `GET /auth/config`
//! and nothing else.

mod attach;
mod backchannel;
mod bearer;
mod boot;
mod callback;
mod claims;
mod device;
mod erased;
mod exchange;
mod failure;
mod flow;
mod form;
mod handoff;
mod id_token;
mod key_set;
mod login;
mod provision;
mod routes;
mod sync;
mod tokens;

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

pub use bearer::resolve_bearer;
pub use flow::pkce_challenge;
pub use provision::ProvisionError;

use crate::http_client::HttpClient;
use crate::session::Manager;
use crate::{Clock, Config, ConfigError, ErasedSubjects, IdentityStore, LoginCodeStore, UserStore};

/// Extra keys for `GET /auth/config`. `sso_only` and `oidc_enabled` are written over them.
pub type ConfigExtra = Arc<dyn Fn() -> serde_json::Map<String, serde_json::Value> + Send + Sync>;

/// What a [`Kit`] needs.
pub struct Deps {
    /// The app's user write.
    pub users: Arc<dyn UserStore>,
    /// The identity rows.
    pub identities: Arc<dyn IdentityStore>,
    /// The CLI login codes.
    pub codes: Arc<dyn LoginCodeStore>,
    /// The one session manager, built from the same [`Config`].
    pub sessions: Manager,
    /// Extra keys for `GET /auth/config`.
    pub config_extra: Option<ConfigExtra>,
    /// The outbound HTTP. `None` means [`HttpClient::new`].
    pub http: Option<HttpClient>,
    /// The clock. `None` means the wall clock.
    pub now: Option<Clock>,
}

/// The OIDC engine. Clone it freely.
#[derive(Clone)]
pub struct Kit {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: Config,
    users: Arc<dyn UserStore>,
    identities: Arc<dyn IdentityStore>,
    codes: Arc<dyn LoginCodeStore>,
    sessions: Manager,
    config_extra: Option<ConfigExtra>,
    http: HttpClient,
    now: Clock,
    provider: Option<boot::Provider>,
    cli_tokens: Option<Arc<bearer::BearerVerifier>>,
    erased: RwLock<Option<Arc<dyn ErasedSubjects>>>,
    provisioning: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Kit {
    /// Validates the config, checks it agrees with the session manager's, runs discovery and
    /// arms the bearer verifiers. Fails on a half-filled environment, an unreachable issuer, a
    /// roles scope the provider does not offer, or a manager built from another config.
    pub async fn new(cfg: &Config, deps: Deps) -> Result<Kit, ConfigError> {
        cfg.validate()?;
        boot::agrees_with(cfg, deps.sessions.config())?;
        let http = deps.http.unwrap_or_default();
        let now = deps.now.unwrap_or_else(crate::system_clock);
        let (provider, cli_tokens) = match cfg.enabled() {
            true => boot::arm(cfg, &http, &deps.identities, &deps.sessions, &now).await?,
            false => (None, None),
        };
        let kit = Kit {
            inner: Arc::new(Inner {
                cfg: cfg.resolved(),
                users: deps.users,
                identities: deps.identities,
                codes: deps.codes,
                sessions: deps.sessions,
                config_extra: deps.config_extra,
                http,
                now,
                provider,
                cli_tokens,
                erased: RwLock::new(None),
                provisioning: tokio::sync::Mutex::new(HashMap::new()),
            }),
        };
        if kit.inner.provider.is_some() && cfg.claims_enabled() {
            kit.inner.sessions.with_claims(Arc::new(kit.clone()));
        }
        Ok(kit)
    }

    /// Refuses an identity the app already erased before the user write runs, on the login
    /// callback, [`Kit::provision_bearer`] and the profile sync: Go `oidc.Deps.Erased`. Pass the
    /// app's `directory::Deletions`. The refusal is a 403 `permission_denied` whose cause is
    /// [`crate::SubjectErased`]; a ledger that cannot be read fails the request as internal and
    /// creates nothing. Without it nothing is checked. Every clone shares the setting.
    pub fn with_erased(self, erased: Arc<dyn ErasedSubjects>) -> Kit {
        *self.inner.erased.write().unwrap_or_else(PoisonError::into_inner) = Some(erased);
        self
    }

    /// The resolved configuration.
    pub fn config(&self) -> &Config {
        &self.inner.cfg
    }

    /// Whether the OIDC routes are live.
    pub fn enabled(&self) -> bool {
        self.inner.provider.is_some()
    }

    /// The session manager this kit issues through.
    pub fn sessions(&self) -> &Manager {
        &self.inner.sessions
    }

    fn now(&self) -> time::OffsetDateTime {
        (self.inner.now)()
    }

    fn provider(&self) -> Option<&boot::Provider> {
        self.inner.provider.as_ref()
    }
}
