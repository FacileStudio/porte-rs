use std::sync::atomic::Ordering;

use super::decode::Value;
use super::{CheckError, Kind, Scope, Store, upgrade_url};

impl Store {
    /// Whether a [`Kind::Bool`] feature is on for the scope. True before the first snapshot. An
    /// undeclared key, or one declared as a limit, answers false.
    pub fn enabled(&self, scope: &Scope, key: &str) -> bool {
        self.resolve(scope, key, Kind::Bool).enabled
    }

    /// A [`Kind::Limit`] feature's ceiling for the scope, -1 meaning unlimited. -1 before the
    /// first snapshot. An undeclared key, or one declared as a bool, answers 0.
    pub fn limit(&self, scope: &Scope, key: &str) -> i64 {
        self.resolve(scope, key, Kind::Limit).limit
    }

    /// Whether the scope may go from `used` to `used + adding` of a limit feature. It passes at
    /// or under the ceiling, when the ceiling is unlimited, and when `adding` is 0, so an
    /// over-limit scope can always read and delete. A negative count is
    /// [`CheckError::InvalidUsage`]. The comparison cannot overflow. An undeclared key has a
    /// ceiling of 0 and refuses any addition.
    ///
    /// Round coarse units up: a 1 KiB upload against a limit in GB adds 1, not 0. The check and
    /// the creation it guards are not atomic; an app that needs strictness checks again inside
    /// the transaction that creates the resource.
    pub fn check(&self, scope: &Scope, key: &str, used: i64, adding: i64) -> Result<(), CheckError> {
        if used < 0 || adding < 0 {
            return Err(CheckError::InvalidUsage);
        }
        let limit = self.limit(scope, key);
        if adding == 0 || limit == -1 || used <= limit - adding {
            return Ok(());
        }
        let upgrade = match self.issuer.is_empty() {
            true => String::new(),
            false => upgrade_url(&self.issuer, &scope.space_id),
        };
        Err(CheckError::Limit { key: key.to_owned(), limit, upgrade_url: upgrade })
    }

    pub(super) fn resolve(&self, scope: &Scope, key: &str, kind: Kind) -> Value {
        if self.features.get(key).is_none_or(|feature| feature.kind != kind) {
            return Value::default();
        }
        let applied = self.read();
        if applied.revision == 0 {
            if !self.warned.swap(true, Ordering::SeqCst) {
                tracing::warn!("forfait: no entitlements snapshot applied yet, allowing every feature");
            }
            return Value { enabled: true, limit: -1 };
        }
        let values = match scope.space_id.is_empty() {
            true => applied.people.get(&scope.subject),
            false => applied.spaces.get(&scope.space_id),
        };
        values.and_then(|values| values.get(key)).or_else(|| self.defaults.get(key)).copied().unwrap_or_default()
    }
}
