//! The JSON bodies of porte's routes.

use serde::{Deserialize, Serialize};

/// The body of `GET /auth/config`, field order as Go writes it.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct ConfigResponse {
    /// True whenever OIDC is enabled or `SSO_ONLY` is set.
    pub sso_only: bool,
    /// Whether the OIDC routes are live.
    pub oidc_enabled: bool,
}

/// The body of `POST /auth/oidc/exchange`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExchangeRequest {
    /// The one-time login code.
    pub code: String,
    /// The PKCE verifier of the mobile flow. porte-rs has no mobile flow, so any value fails.
    pub verifier: String,
}

/// The body of `POST /auth/oidc/device/exchange`. The token is a live credential: never log it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceExchangeRequest {
    /// The access token from the provider's device grant.
    pub access_token: String,
}

/// The body of both exchanges. `user_id` is a string on the wire, as in Go.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExchangeResponse {
    /// The account id, as a decimal string.
    pub user_id: String,
    /// The new session token.
    pub token: String,
}

/// The body of `POST /auth/logout` and of the back-channel logout.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct LogoutResponse {
    /// Always true.
    pub logged_out: bool,
}

/// The body of `POST /auth/sync-profile`. False when the rate limit had not elapsed.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct SyncProfileResponse {
    /// Whether the profile was refreshed.
    pub synced: bool,
}
