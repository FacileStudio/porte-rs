//! The store contract: the rows porte reads and writes, and the traits an app implements.

use time::OffsetDateTime;

/// What a store returns. Stores are implemented by apps, so the contract carries its own
/// sentinels rather than a driver's error type.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// No row matched.
    #[error("porte: not found")]
    NotFound,
    /// A login code was already exchanged: a replay, not a typo.
    #[error("porte: login code already consumed")]
    CodeConsumed,
    /// The store refuses with a message meant for the user, carried as a tronc error.
    #[error("{0}")]
    Refused(tronc::Error),
    /// Anything else: the database is down, a row is unreadable.
    #[error("{0}")]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl StoreError {
    /// Wraps any error as [`StoreError::Other`].
    pub fn other(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        StoreError::Other(error.into())
    }
}

/// One session row: a browser login, a CLI token or a named API token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    /// The row id.
    pub id: i64,
    /// SHA-256 hex of the token. The plaintext is never stored.
    pub token_hash: String,
    /// The account.
    pub user_id: i64,
    /// A non-empty label makes the row a named API token.
    pub label: String,
    /// When the row was created.
    pub created_at: Option<OffsetDateTime>,
    /// When the row last authenticated, coalesced to one write a minute.
    pub last_used_at: Option<OffsetDateTime>,
    /// `None` never expires.
    pub expires_at: Option<OffsetDateTime>,
    /// With `subject`, binds the issue to an identity row that must still exist. Not stored.
    pub provider: String,
    /// See `provider`.
    pub subject: String,
    /// Binds the issue to a session row that must still exist. Not stored.
    pub issued_by: i64,
}

impl Session {
    /// Whether the absolute lifetime has passed.
    pub fn expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_some_and(|at| now > at)
    }

    /// Whether the row is a named API token.
    pub fn is_api_token(&self) -> bool {
        !self.label.is_empty()
    }
}

/// A one-time CLI login code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginCode {
    /// SHA-256 hex of the code.
    pub code_hash: String,
    /// The account.
    pub user_id: i64,
    /// When the code stops redeeming.
    pub expires_at: OffsetDateTime,
    /// The identity the code was minted for.
    pub provider: String,
    /// See `provider`.
    pub subject: String,
}

impl LoginCode {
    /// Whether the code has expired.
    pub fn expired(&self, now: OffsetDateTime) -> bool {
        now > self.expires_at
    }
}

pub use crate::store_traits::{IdentityStore, LoginCodeStore, UserStore};
