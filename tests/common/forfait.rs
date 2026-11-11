use std::collections::HashMap;

use porte::directory::{Person, Snapshot, Space};
use porte::forfait::{Feature, Store};
use serde_json::{Value, json};

pub const MAILBOXES: &str = "courrier.mailboxes";
pub const RECORDING: &str = "echo.recording";

pub fn store() -> Store {
    Store::new([Feature::limit(MAILBOXES, 1), Feature::bool(RECORDING, false)]).with_issuer("https://sso.test/")
}

pub fn values(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs.iter().map(|(key, value)| ((*key).to_owned(), value.clone())).collect()
}

pub fn snapshot(version: i64, revision: i64, mailboxes: Value) -> Snapshot {
    Snapshot {
        version,
        entitlements_revision: revision,
        spaces: vec![Space {
            id: "sp-1".into(),
            entitlements: values(&[(MAILBOXES, mailboxes), (RECORDING, json!(true))]),
            ..Space::default()
        }],
        people: vec![Person { subject: "sub-1".into(), entitlements: values(&[(MAILBOXES, json!(-1))]) }],
    }
}
