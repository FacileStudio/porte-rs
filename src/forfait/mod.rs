//! Plan enforcement, a port of Go `porte/forfait`.
//!
//! Ardoise computes every entitlement and pushes it to Registre, which serves it inside the
//! directory snapshot an app already syncs. An app never recomputes a plan: it declares the
//! features it enforces, feeds every snapshot to [`Store::apply`], and asks [`Store::enabled`],
//! [`Store::limit`] or [`Store::check`] before creating something new. Reading, downloading and
//! deleting are never gated, so a downgrade never locks anyone out of their own data.
//!
//! A [`Store`] fails open only until its first authoritative snapshot (one with a non-zero
//! `entitlements_revision`) arrives: every declared feature is enabled and unlimited meanwhile,
//! and a warning is logged once. After it, an outage changes nothing: the store keeps the last
//! snapshot it applied, and [`Store::export`] and [`Store::import`] carry it across restarts.

mod decode;
mod persist;
mod query;
mod store;

pub use persist::ImportError;
pub use store::Store;

/// The shape of a feature's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// On or off, such as `glouton.access`.
    Bool,
    /// An integer ceiling, such as `nuage.storage_gb`, where -1 means unlimited.
    Limit,
}

/// One entitlement an app enforces. `key` is the suite-wide name Ardoise uses, such as
/// `courrier.mailboxes`. `default` is the JSON value that applies when a scope carries no value
/// for the key, which is the free plan. A missing or malformed default denies: false for a
/// [`Kind::Bool`], 0 for a [`Kind::Limit`]. A key that does not match
/// `^[a-z0-9_]+\.[a-z0-9_]+$` is never declared.
#[derive(Debug, Clone, PartialEq)]
pub struct Feature {
    /// The suite-wide key.
    pub key: String,
    /// The value's shape.
    pub kind: Kind,
    /// The free plan's value, raw.
    pub default: serde_json::Value,
}

impl Feature {
    /// A [`Kind::Bool`] feature whose free plan is `default`.
    pub fn bool(key: impl Into<String>, default: bool) -> Self {
        Feature { key: key.into(), kind: Kind::Bool, default: default.into() }
    }

    /// A [`Kind::Limit`] feature whose free plan is `default`, -1 meaning unlimited.
    pub fn limit(key: impl Into<String>, default: i64) -> Self {
        Feature { key: key.into(), kind: Kind::Limit, default: default.into() }
    }
}

/// What an entitlement is read for. `space_id` is the Registre space id a resource belongs to.
/// An empty `space_id` is the personal scope of `subject`, the Registre `sub` of the person who
/// holds the resource outside any space.
///
/// Both fields come from the app's own server-side state, never from a value the client sent: a
/// client that could choose the space could pick the most generous plan it can name. An app
/// refuses, rather than falling back to the personal scope, a resource in one of its own spaces
/// that is not linked to Registre yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    /// The Registre space id, empty for the personal scope.
    pub space_id: String,
    /// The person's Registre subject, read when `space_id` is empty.
    pub subject: String,
}

impl Scope {
    /// The scope of a Registre space.
    pub fn space(space_id: impl Into<String>) -> Self {
        Scope { space_id: space_id.into(), subject: String::new() }
    }

    /// The personal scope of a Registre subject.
    pub fn person(subject: impl Into<String>) -> Self {
        Scope { space_id: String::new(), subject: subject.into() }
    }
}

/// Why [`Store::check`] refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckError {
    /// The plan limit is reached. Apps answer HTTP 402 with the upgrade URL, which the
    /// conversion to [`tronc::Error`] does.
    #[error("forfait: plan limit reached: {key} allows {limit}")]
    Limit {
        /// The feature.
        key: String,
        /// The ceiling the scope's plan allows.
        limit: i64,
        /// Where an owner changes the plan, empty when the store has no issuer.
        upgrade_url: String,
    },
    /// A negative used or adding count: a caller bug, not a plan refusal.
    #[error("forfait: negative usage count")]
    InvalidUsage,
}

impl From<CheckError> for tronc::Error {
    fn from(error: CheckError) -> Self {
        match &error {
            CheckError::Limit { upgrade_url, .. } => {
                let url = upgrade_url.clone();
                tronc::Error::payment_required(error.to_string()).with_upgrade_url(url)
            }
            CheckError::InvalidUsage => tronc::Error::internal("internal error", error),
        }
    }
}

/// The Registre page where an owner changes a space's plan: `<issuer>/spaces/<space_id>`, or
/// `<issuer>/spaces` for the personal scope (an empty `space_id`).
pub fn upgrade_url(issuer: &str, space_id: &str) -> String {
    let base = format!("{}/spaces", issuer.strip_suffix('/').unwrap_or(issuer));
    match space_id {
        "" => base,
        id => format!("{base}/{}", percent_encoding::utf8_percent_encode(id, PATH_SEGMENT)),
    }
}

const PATH_SEGMENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b':')
    .remove(b'=')
    .remove(b'@');
