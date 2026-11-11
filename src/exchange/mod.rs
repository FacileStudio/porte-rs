//! Per-user RFC 8693 token exchange, a port of Go `porte/exchange`.
//!
//! It turns the Registre refresh token porte stored at sign-in into an access token for another
//! suite app (an audience) with the scopes the app asks for.
//!
//! One [`Exchanger`] must serve every audience of a process. Registre rotates the refresh token
//! on every refresh, so two refreshes of one grant in parallel leave one of them holding a dead
//! token and the user signed out with `invalid_grant`. The exchanger serializes them per user,
//! across audiences, and persists each rotation through the [`IdentityStore`] before anyone else
//! refreshes. A refresh runs on its own task, so a caller that goes away mid-refresh never loses
//! the rotated token.
//!
//! Exchanged tokens are cached in memory until their expiry minus a margin. A downstream 401
//! forgets the token and retries once ([`Exchanger::call`]). A refresh token Registre no longer
//! accepts is [`ExchangeError::Reconnect`]: the user signs in again.

mod call;
mod config;
mod errors;
mod mint;
mod registre;
mod reply;
mod subject;
mod user;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use call::Source;
pub use config::{Config, Target};
pub use errors::ExchangeError;

use crate::ConfigError;

/// How long before its expiry a token stops being reused.
pub const DEFAULT_MARGIN: Duration = Duration::from_secs(30);

/// Mints and caches exchanged tokens per user. Cloning shares the cache: build one per process.
#[derive(Clone)]
pub struct Exchanger {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: Config,
    margin: time::Duration,
    endpoint: tokio::sync::OnceCell<String>,
    users: Mutex<HashMap<i64, Arc<user::User>>>,
}

impl Exchanger {
    /// Checks `config` and builds an exchanger. It makes no network call: Registre's discovery
    /// document is read on the first exchange.
    pub fn new(config: Config) -> Result<Self, ConfigError> {
        if config.issuer.is_empty() || config.client_id.is_empty() || config.client_secret.is_empty() {
            return Err(ConfigError::new("exchange: issuer, client_id and client_secret are required"));
        }
        let margin = if config.margin.is_zero() { DEFAULT_MARGIN } else { config.margin };
        let margin = time::Duration::try_from(margin).unwrap_or(time::Duration::seconds(30));
        let inner = Inner { cfg: config, margin, endpoint: tokio::sync::OnceCell::new(), users: Mutex::default() };
        Ok(Exchanger { inner: Arc::new(inner) })
    }

    /// An access token for `target` acting for `user_id`, from the cache while it has more than
    /// the margin left, else minted through Registre.
    ///
    /// It fails with [`ExchangeError::Reconnect`] when the user holds no usable Registre grant,
    /// with [`ExchangeError::Refused`] when Registre refuses the exchange itself (a scope the app
    /// is not granted, for one), and with [`ExchangeError::Unavailable`] when Registre cannot be
    /// reached.
    pub async fn token(&self, user_id: i64, target: &Target) -> Result<String, ExchangeError> {
        let user = self.inner.user(user_id);
        let key = target.key();
        if let Some(value) = self.inner.cached(&user, &key) {
            return Ok(value);
        }
        let guard = user.lock.clone().lock_owned().await;
        if let Some(value) = self.inner.cached(&user, &key) {
            return Ok(value);
        }
        self.inner.clone().mint(user, guard, user_id, target).await
    }

    /// Drops the cached token for one target, so the next call mints a new one. Call it when the
    /// downstream app answered 401 to the cached token.
    pub fn forget(&self, user_id: i64, target: &Target) {
        let users = self.inner.users.lock().unwrap_or_else(|poison| poison.into_inner());
        if let Some(user) = users.get(&user_id) {
            user.forget(&target.key());
        }
    }

    /// Drops everything held in memory for a user: every exchanged token and the Registre access
    /// token. Call it on sign-out and on erasure.
    pub fn forget_user(&self, user_id: i64) {
        self.inner.users.lock().unwrap_or_else(|poison| poison.into_inner()).remove(&user_id);
    }

    /// The exchanger bound to `target`.
    pub fn source(&self, target: Target) -> Source {
        Source::new(self.clone(), target)
    }
}
