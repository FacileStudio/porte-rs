//! The credential: issuance, the cookie, the middleware and `POST /auth/logout`.
//!
//! Build exactly one [`Manager`] and pass it to every kit.

mod authenticate;
mod cookie;
mod cookie_parse;
mod extract;
mod issue;
mod layer;
mod logout;
mod origin;
mod request;
mod revoke;
mod rules;
mod sources;

use std::sync::{Arc, RwLock};

pub use authenticate::Authentication;
pub use cookie::append_cookies;
pub use layer::{Auth, AuthLayer};
pub use request::{RequestView, View};
pub use sources::{ClaimsSource, JwtVerifier};

use crate::{Clock, Config, SessionStore, system_clock};

/// What a [`Manager`] needs. Only `sessions` is required.
pub struct Deps {
    /// The session rows.
    pub sessions: Arc<dyn SessionStore>,
    /// The clock. `None` means the wall clock.
    pub now: Option<Clock>,
}

/// Issues sessions, writes the cookie and authenticates requests.
#[derive(Clone)]
pub struct Manager {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: Config,
    store: Arc<dyn SessionStore>,
    claims: RwLock<Option<Arc<dyn ClaimsSource>>>,
    jwt: RwLock<Option<Arc<dyn JwtVerifier>>>,
    now: Clock,
}

impl Manager {
    /// Builds the manager from the resolved configuration.
    pub fn new(cfg: &Config, deps: Deps) -> Self {
        Manager {
            inner: Arc::new(Inner {
                cfg: cfg.resolved(),
                store: deps.sessions,
                claims: RwLock::new(None),
                jwt: RwLock::new(None),
                now: deps.now.unwrap_or_else(system_clock),
            }),
        }
    }

    /// Attaches the claims source after construction. The OIDC kit calls it.
    pub fn with_claims(&self, claims: Arc<dyn ClaimsSource>) {
        *self.inner.claims.write().unwrap_or_else(|poison| poison.into_inner()) = Some(claims);
    }

    /// Attaches the bearer-JWT verifier after construction. The OIDC kit calls it.
    pub fn with_jwt(&self, verifier: Arc<dyn JwtVerifier>) {
        *self.inner.jwt.write().unwrap_or_else(|poison| poison.into_inner()) = Some(verifier);
    }

    /// The resolved configuration.
    pub fn config(&self) -> &Config {
        &self.inner.cfg
    }

    /// The session store.
    pub fn store(&self) -> &Arc<dyn SessionStore> {
        &self.inner.store
    }

    fn now(&self) -> time::OffsetDateTime {
        (self.inner.now)()
    }

    fn claims(&self) -> Option<Arc<dyn ClaimsSource>> {
        self.inner.claims.read().unwrap_or_else(|poison| poison.into_inner()).clone()
    }

    fn jwt(&self) -> Option<Arc<dyn JwtVerifier>> {
        self.inner.jwt.read().unwrap_or_else(|poison| poison.into_inner()).clone()
    }
}
