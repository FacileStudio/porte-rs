use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use super::Store;
use super::decode::{Value, encode, index};
use super::store::Applied;
use crate::directory::MAX_SNAPSHOT_BYTES;

const EXPORT_VERSION: i64 = 1;
const MAX_EXPORT: usize = 4 * MAX_SNAPSHOT_BYTES;

type Scopes = BTreeMap<String, BTreeMap<String, Json>>;

/// Why [`Store::import`] restored nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    /// This store already applied a snapshot: the state in memory is newer than anything saved
    /// before it, so the store keeps it.
    #[error("forfait: import after a snapshot was applied")]
    AlreadyApplied,
    /// The document is not one [`Store::export`] produced.
    #[error("forfait: {0}")]
    Invalid(String),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exported {
    version: i64,
    snapshot_version: i64,
    entitlements_revision: i64,
    spaces: Option<Scopes>,
    people: Option<Scopes>,
}

impl Store {
    /// The applied state as a versioned JSON document, the same shape Go `forfait` exports. Save
    /// it after every apply and hand it to [`Store::import`] at boot. A store still failing open
    /// exports revision 0 and imports as failing open.
    pub fn export(&self) -> Vec<u8> {
        let applied = self.read();
        let live = applied.revision > 0;
        let document = Exported {
            version: EXPORT_VERSION,
            snapshot_version: applied.version,
            entitlements_revision: applied.revision,
            spaces: live.then(|| self.encode_scopes(&applied.spaces)),
            people: live.then(|| self.encode_scopes(&applied.people)),
        };
        drop(applied);
        let mut out = serde_json::to_vec(&document).unwrap_or_default();
        out.push(b'\n');
        out
    }

    /// Restores a document [`Store::export`] produced. Empty input (nothing saved yet) is a
    /// no-op. It reads at most four [`MAX_SNAPSHOT_BYTES`], rejects unknown fields, trailing
    /// data, negative versions and any document version but the current one, and filters every
    /// value through the same rules as [`Store::apply`]. On any error the store is unchanged.
    pub fn import(&self, document: &[u8]) -> Result<(), ImportError> {
        if document.trim_ascii().is_empty() {
            return Ok(());
        }
        let document = decode_export(document)?;
        let spaces = self.index_scopes(document.spaces.unwrap_or_default());
        let people = self.index_scopes(document.people.unwrap_or_default());
        let mut applied = self.write();
        if applied.revision > 0 {
            return Err(ImportError::AlreadyApplied);
        }
        if document.entitlements_revision == 0 {
            return Ok(());
        }
        *applied =
            Applied { version: document.snapshot_version, revision: document.entitlements_revision, spaces, people };
        Ok(())
    }

    fn index_scopes(&self, scopes: Scopes) -> HashMap<String, HashMap<String, Value>> {
        scopes
            .into_iter()
            .map(|(id, entitlements)| (id, index(&self.features, &entitlements.into_iter().collect())))
            .collect()
    }

    fn encode_scopes(&self, scopes: &HashMap<String, HashMap<String, Value>>) -> Scopes {
        let encoded = |values: &HashMap<String, Value>| {
            values
                .iter()
                .filter_map(|(key, value)| Some((key.clone(), encode(self.features.get(key)?.kind, *value))))
                .collect()
        };
        scopes.iter().map(|(id, values)| (id.clone(), encoded(values))).collect()
    }
}

fn decode_export(document: &[u8]) -> Result<Exported, ImportError> {
    let invalid = |reason: String| ImportError::Invalid(reason);
    if document.len() > MAX_EXPORT {
        return Err(invalid(format!("import of {} bytes exceeds {MAX_EXPORT}", document.len())));
    }
    let document: Exported =
        serde_json::from_slice(document).map_err(|error| invalid(format!("decode the import: {error}")))?;
    if document.version != EXPORT_VERSION {
        return Err(invalid(format!("import version {} is not {EXPORT_VERSION}", document.version)));
    }
    if document.snapshot_version < 0 || document.entitlements_revision < 0 {
        return Err(invalid("import carries a negative version".into()));
    }
    Ok(document)
}
