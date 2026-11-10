use std::collections::BTreeMap;
use std::time::Duration;

use time::OffsetDateTime;

/// What an authenticated request carries, field for field Go `porte.Identity`.
///
/// It is an axum extractor: present after [`crate::session::Manager::require_auth`], and
/// `Option<Identity>` after [`crate::session::Manager::optional`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// Matches `porte_users.id`.
    pub user_id: i64,
    /// The issuer's subject, set on the bearer-JWT path.
    pub subject: String,
    /// The address, set on the bearer-JWT path.
    pub email: String,
    /// Whether the provider verified the address.
    pub email_verified: bool,
    /// The display name, set on the bearer-JWT path.
    pub name: String,
    /// What the provider says this user is, for this app, as of the last refresh.
    pub roles: Vec<String>,
    /// The scopes a bearer JWT carried. Empty for a cookie or opaque session.
    pub scopes: Vec<String>,
    /// The `act.sub` of a delegated token: the service acting for the user. Empty otherwise.
    pub actor: String,
    /// The session row this request authenticated against. Zero on the bearer-JWT path.
    pub session_id: i64,
    /// When `roles` were last refreshed.
    pub roles_synced_at: Option<OffsetDateTime>,
}

impl Identity {
    /// Exact role match. The claim is already scoped per application.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|granted| granted == role)
    }

    /// Whether any of `roles` is held.
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|role| self.has_role(role))
    }
}

/// What the provider asserted during a callback, normalised. `(provider, subject)` is the
/// account matching key, never the email.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Claims {
    /// The issuer URL.
    pub provider: String,
    /// The provider's subject.
    pub subject: String,
    /// Lowercased, trimmed address.
    pub email: String,
    /// True only when the provider said so, or the config trusts silence.
    pub email_verified: bool,
    /// `name`.
    pub name: String,
    /// `preferred_username`.
    pub preferred_username: String,
    /// `given_name`.
    pub given_name: String,
    /// `family_name`.
    pub family_name: String,
    /// `picture`.
    pub picture: String,
    /// One of `fr`, `en`, `es`, `de`, or empty when the provider sent none.
    pub locale: String,
    /// Always empty: porte-rs stores no avatars.
    pub avatar_url: String,
    /// The roles claim, when a claims scope is configured.
    pub roles: Option<Vec<String>>,
    /// The configured extra claims, raw.
    pub extra: BTreeMap<String, serde_json::Value>,
    /// The provider's tokens.
    pub tokens: TokenSet,
}

impl Claims {
    /// `name`, then `preferred_username`, then given and family names joined.
    pub fn display_name(&self) -> String {
        if !self.name.is_empty() {
            return self.name.clone();
        }
        if !self.preferred_username.is_empty() {
            return self.preferred_username.clone();
        }
        format!("{} {}", self.given_name, self.family_name).trim().to_owned()
    }
}

/// The provider's tokens, as plain values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenSet {
    /// The access token.
    pub access_token: String,
    /// The refresh token.
    pub refresh_token: String,
    /// When the access token expires.
    pub expiry: Option<OffsetDateTime>,
}

/// One row of `porte_identities`: one way one human authenticates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredIdentity {
    /// The account.
    pub user_id: i64,
    /// The issuer.
    pub provider: String,
    /// The provider's subject.
    pub subject: String,
    /// Empty on a federated row.
    pub password_hash: String,
    /// The provider's tokens.
    pub tokens: TokenSet,
    /// The cached roles claim.
    pub roles: Option<Vec<String>>,
    /// When the roles were last refreshed.
    pub roles_synced_at: Option<OffsetDateTime>,
    /// When the profile was last synced.
    pub synced_at: Option<OffsetDateTime>,
}

impl StoredIdentity {
    /// Whether the cached roles should be refreshed. A claim never synced is stale.
    pub fn roles_stale(&self, now: OffsetDateTime, ttl: Duration) -> bool {
        self.roles_synced_at.is_none_or(|at| now - at >= ttl)
    }
}

/// Maps a language tag to one of `fr`, `en`, `es`, `de`, defaulting to `en`.
pub fn normalize_locale(tag: &str) -> String {
    let lower = tag.trim().to_ascii_lowercase();
    let primary = lower.split(['-', '_']).next().unwrap_or_default();
    match primary {
        "fr" | "en" | "es" | "de" => primary.to_owned(),
        _ => crate::DEFAULT_LOCALE.to_owned(),
    }
}
