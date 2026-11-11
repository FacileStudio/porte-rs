use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::Feature;
use super::decode::{Value, decode, index, valid_key};
use crate::directory::Snapshot;

#[derive(Default)]
pub(super) struct Applied {
    pub(super) version: i64,
    pub(super) revision: i64,
    pub(super) spaces: HashMap<String, HashMap<String, Value>>,
    pub(super) people: HashMap<String, HashMap<String, Value>>,
}

impl Applied {
    fn accepts(&self, version: i64, revision: i64) -> bool {
        match revision {
            r if r <= 0 || r < self.revision => false,
            r if r > self.revision => true,
            _ => version == 0 || version >= self.version,
        }
    }
}

/// The entitlements of every scope from the last authoritative snapshot, one whose
/// `entitlements_revision` is above 0. It is safe for concurrent use.
///
/// Until the first authoritative snapshot, the store fails open: every declared feature is
/// enabled and unlimited, and one warning is logged. After it the store keeps the last snapshot
/// it applied while Registre is unreachable. The store lives in memory: so that a restart never
/// fails open again, save [`Store::export`] after every apply and hand it to [`Store::import`]
/// at boot, before the first pull.
pub struct Store {
    pub(super) issuer: String,
    pub(super) features: HashMap<String, Feature>,
    pub(super) defaults: HashMap<String, Value>,
    pub(super) warned: AtomicBool,
    applied: RwLock<Applied>,
}

impl Store {
    /// Declares the features an app enforces. A malformed key is skipped and reads as
    /// undeclared, the first of two declarations of one key wins, and a missing or malformed
    /// default denies. Each of those is a programmer error and is logged.
    pub fn new(features: impl IntoIterator<Item = Feature>) -> Self {
        let mut declared = HashMap::new();
        let mut defaults = HashMap::new();
        for feature in features {
            if declared.contains_key(&feature.key) || !valid_key(&feature.key) {
                tracing::warn!(key = %feature.key, "forfait: feature skipped: malformed or duplicate key");
                continue;
            }
            let fallback = decode(feature.kind, &feature.default).unwrap_or_else(|| {
                tracing::warn!(key = %feature.key, "forfait: feature has a missing or malformed default, it denies");
                Value::default()
            });
            defaults.insert(feature.key.clone(), fallback);
            declared.insert(feature.key.clone(), feature);
        }
        Store {
            issuer: String::new(),
            features: declared,
            defaults,
            warned: AtomicBool::new(false),
            applied: RwLock::default(),
        }
    }

    /// Sets the app's OIDC issuer, so every [`CheckError::Limit`] carries
    /// [`upgrade_url`]`(issuer, scope.space_id)`.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    pub(super) fn read(&self) -> RwLockReadGuard<'_, Applied> {
        self.applied.read().unwrap_or_else(|poison| poison.into_inner())
    }

    pub(super) fn write(&self) -> RwLockWriteGuard<'_, Applied> {
        self.applied.write().unwrap_or_else(|poison| poison.into_inner())
    }

    /// Replaces every scope's entitlements with the snapshot's. Call it from the app's
    /// [`crate::directory::Apply`].
    ///
    /// A snapshot whose revision is 0 comes from a Registre that never received a push and is
    /// ignored. From the first revision on, every accepted snapshot is the whole truth and a
    /// scope it carries no value for reads the feature defaults. A snapshot older than the state
    /// held (a lower revision, or at the same revision a lower non-zero version) is refused and
    /// logged; after a Registre restore lowered the revision, call [`Store::reset`]. Malformed
    /// values, undeclared keys and scopes with more than 200 keys read as defaults.
    pub fn apply(&self, snapshot: &Snapshot) {
        let spaces = snapshot
            .spaces
            .iter()
            .filter(|space| !space.id.is_empty())
            .map(|space| (space.id.clone(), index(&self.features, &space.entitlements)))
            .collect();
        let people = snapshot
            .people
            .iter()
            .filter(|person| !person.subject.is_empty())
            .map(|person| (person.subject.clone(), index(&self.features, &person.entitlements)))
            .collect();
        let mut applied = self.write();
        let held = (applied.version, applied.revision);
        if applied.accepts(snapshot.version, snapshot.entitlements_revision) {
            *applied = Applied { version: snapshot.version, revision: snapshot.entitlements_revision, spaces, people };
            return;
        }
        drop(applied);
        if snapshot.entitlements_revision > 0 {
            tracing::warn!(
                version = snapshot.version,
                revision = snapshot.entitlements_revision,
                held_version = held.0,
                held_revision = held.1,
                "forfait: snapshot refused as older than the state held; after a Registre restore, call reset"
            );
        }
    }

    /// Forgets every applied value and its versions, so the store fails open again until the
    /// next authoritative snapshot, which it then accepts whatever its versions. It is the
    /// recovery step after Registre's database is restored from a backup: call it and delete the
    /// state saved from [`Store::export`].
    pub fn reset(&self) {
        *self.write() = Applied::default();
        self.warned.store(false, Ordering::SeqCst);
    }
}
