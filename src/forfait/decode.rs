use std::collections::HashMap;

use serde_json::Value as Json;

use super::{Feature, Kind};

pub(super) const MAX_KEYS: usize = 200;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Value {
    pub(super) enabled: bool,
    pub(super) limit: i64,
}

pub(super) fn valid_key(key: &str) -> bool {
    let part = |part: &str| !part.is_empty() && part.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'));
    key.split_once('.').is_some_and(|(app, name)| part(app) && part(name))
}

pub(super) fn decode(kind: Kind, raw: &Json) -> Option<Value> {
    match (kind, raw) {
        (Kind::Bool, Json::Bool(enabled)) => Some(Value { enabled: *enabled, limit: 0 }),
        (Kind::Limit, Json::Number(number)) => {
            number.as_i64().filter(|limit| *limit >= -1).map(|limit| Value { enabled: false, limit })
        }
        _ => None,
    }
}

pub(super) fn index(
    features: &HashMap<String, Feature>,
    entitlements: &HashMap<String, Json>,
) -> HashMap<String, Value> {
    if entitlements.len() > MAX_KEYS {
        return HashMap::new();
    }
    entitlements
        .iter()
        .filter_map(|(key, raw)| {
            let feature = features.get(key)?;
            decode(feature.kind, raw).map(|value| (key.clone(), value))
        })
        .collect()
}

pub(super) fn encode(kind: Kind, value: Value) -> Json {
    match kind {
        Kind::Bool => Json::Bool(value.enabled),
        Kind::Limit => Json::from(value.limit),
    }
}
