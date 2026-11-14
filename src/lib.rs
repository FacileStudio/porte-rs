//! `porte`, the auth kit for Facile Suite Rust apps: a port of Go `porte` v0.20.1.
//!
//! It makes a Rust app a Registre client with the routes, cookie, tokens, tables and space
//! model of a Go app. Each part sits behind a feature: `pg`, `oidc`, `directory`, `spaces`,
//! `mcp`, `exchange`, `forfait`. The root, [`token`], [`store`] and [`session`] are always on.

#![deny(unused, dead_code)]
#![warn(missing_docs)]

mod config;
mod config_checks;
mod erased;
mod identity;
mod query;
pub mod session;
mod session_revocation;
mod session_store;
pub mod store;
mod store_traits;
pub mod token;
pub mod wire;

#[cfg(feature = "directory")]
pub mod directory;
#[cfg(feature = "exchange")]
pub mod exchange;
#[cfg(feature = "forfait")]
pub mod forfait;
#[cfg(feature = "net")]
pub mod http_client;
#[cfg(any(feature = "oidc", feature = "directory"))]
mod jose;
#[cfg(feature = "oidc")]
pub mod jwt;
#[cfg(feature = "oidc")]
mod jwt_error;
#[cfg(feature = "mcp")]
pub mod mcpauth;
#[cfg(feature = "oidc")]
pub mod oidc;
#[cfg(feature = "pg")]
pub mod pg;
#[cfg(any(feature = "oidc", feature = "directory"))]
mod rs256;
#[cfg(feature = "spaces")]
pub mod spaces;

use std::time::Duration;

pub use config::Config;
pub use erased::{ErasedSubjects, SubjectErased};
pub use identity::{Claims, Identity, StoredIdentity, TokenSet, normalize_locale};
pub use session_revocation::SessionRevocation;
pub use session_store::SessionStore;
pub use store::{IdentityStore, LoginCode, LoginCodeStore, Session, StoreError, UserStore};
pub use token::{BROWSER_TOKEN_PREFIX, hash_token, new_browser_token, new_token, secure_compare};

/// The browser session cookie. Over https it is written and read as `__Host-session`.
pub const SESSION_COOKIE_NAME: &str = "session";
/// The header a cookie-authenticated mutating request must carry, any non-empty value.
pub const CSRF_HEADER_NAME: &str = "X-Facile-CSRF";
/// Thirty days, what every suite app hardcodes.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// Sixty seconds for a CLI to redeem its code.
pub const DEFAULT_LOGIN_CODE_TTL: Duration = Duration::from_secs(60);
/// Five minutes of trust in a cached roles claim.
pub const DEFAULT_CLAIMS_TTL: Duration = Duration::from_secs(5 * 60);
/// Five minutes between two profile syncs of one user.
pub const DEFAULT_PROFILE_SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// A browser session unused for a week stops authenticating.
pub const DEFAULT_SESSION_IDLE_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
/// What porte's own pages say when no app name can be derived.
pub const DEFAULT_APP_NAME: &str = "Sign-in";
/// The locale a user gets when the provider names none porte knows.
pub const DEFAULT_LOCALE: &str = "en";

/// The routes porte mounts, relative to the app's `/api` router.
pub mod routes {
    /// `GET`, always mounted.
    pub const CONFIG: &str = "/auth/config";
    /// `GET`, starts a browser or CLI login.
    pub const LOGIN: &str = "/auth/oidc";
    /// `GET`, the provider's redirect target.
    pub const CALLBACK: &str = "/auth/oidc/callback";
    /// `POST`, a CLI trades its one-time code for a session token.
    pub const EXCHANGE: &str = "/auth/oidc/exchange";
    /// `POST`, a CLI trades a device-grant access token for a session token.
    pub const DEVICE_EXCHANGE: &str = "/auth/oidc/device/exchange";
    /// `POST`, mounted by the session manager.
    pub const LOGOUT: &str = "/auth/logout";
    /// `POST`, refreshes the profile from UserInfo.
    pub const SYNC_PROFILE: &str = "/auth/sync-profile";
    /// `POST`, OpenID Connect back-channel logout.
    pub const BACKCHANNEL_LOGOUT: &str = "/auth/backchannel-logout";
}

/// A configuration porte refuses at boot.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("porte: {0}")]
pub struct ConfigError(pub String);

impl ConfigError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        ConfigError(message.into())
    }
}

/// A clock, injectable so a test can age a session without sleeping.
pub type Clock = std::sync::Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>;

/// The wall clock.
pub fn system_clock() -> Clock {
    std::sync::Arc::new(time::OffsetDateTime::now_utc)
}
