use std::collections::HashMap;

use serde::{Deserialize, Deserializer};
use serde_json::Value;
use time::OffsetDateTime;

/// The directory as Registre sees it now. Every field may be missing; names match
/// case-insensitively, as Go `encoding/json` does, and unknown fields are ignored.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    /// Bumped on every change. Zero means unversioned.
    #[serde(deserialize_with = "nullable")]
    pub version: i64,
    /// Bumped when any entitlement changes.
    #[serde(deserialize_with = "nullable")]
    pub entitlements_revision: i64,
    /// Every space of this app's audience.
    #[serde(deserialize_with = "nullable")]
    pub spaces: Vec<Space>,
    /// Per-person entitlements.
    #[serde(deserialize_with = "nullable")]
    pub people: Vec<Person>,
}

/// One space and its members.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Space {
    /// Registre's id.
    #[serde(deserialize_with = "nullable")]
    pub id: String,
    /// The display name.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// The members.
    #[serde(deserialize_with = "nullable")]
    pub members: Vec<Member>,
    /// Entitlements, raw.
    #[serde(deserialize_with = "nullable")]
    pub entitlements: HashMap<String, Value>,
}

/// One member of a space.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(default)]
pub struct Member {
    /// The issuer's subject.
    #[serde(rename = "sub", deserialize_with = "nullable")]
    pub subject: String,
    /// The address.
    #[serde(deserialize_with = "nullable")]
    pub email: String,
    /// The display name.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// The avatar URL.
    #[serde(deserialize_with = "nullable")]
    pub picture: String,
    /// `member`, `admin` or `owner`.
    #[serde(deserialize_with = "nullable")]
    pub role: String,
}

/// Per-person entitlements.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Person {
    /// The issuer's subject.
    #[serde(rename = "sub", deserialize_with = "nullable")]
    pub subject: String,
    /// Entitlements, raw.
    #[serde(deserialize_with = "nullable")]
    pub entitlements: HashMap<String, Value>,
}

/// One erased person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deleted {
    /// The issuer's subject.
    pub subject: String,
    /// When Registre erased them.
    pub deleted_at: OffsetDateTime,
}

fn nullable<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<T>::deserialize(deserializer).map(Option::unwrap_or_default)
}

pub(crate) fn decode(body: &[u8]) -> Result<Snapshot, super::DirectoryError> {
    let unavailable = |reason: &str| super::DirectoryError::Unavailable(format!("decode the snapshot: {reason}"));
    if body.len() > super::MAX_SNAPSHOT_BYTES {
        return Err(super::DirectoryError::TooLarge);
    }
    let value: Value = serde_json::from_slice(body).map_err(|error| unavailable(&error.to_string()))?;
    if !(value.is_object() || value.is_null()) {
        return Err(unavailable("not an object"));
    }
    tronc::json::decode(body, super::MAX_SNAPSHOT_BYTES).map_err(|error| unavailable(&error.message))
}
