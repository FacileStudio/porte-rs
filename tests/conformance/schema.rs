use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::common::vectors::{cases, load};

#[test]
fn schema_vector() {
    let vector = load("schema");
    let pinned = &cases(&vector)[0]["want"];
    assert_eq!(porte_schema(), pinned["sql"].as_str().unwrap());
    assert_eq!(sha(porte_schema()), pinned["sha256"]);
    let short = &cases(&vector)[1];
    let tampered = short["input"]["sql"].as_str().unwrap();
    assert_eq!(sha(tampered), short["want"]["sha256"]);
    assert_ne!(sha(tampered), pinned["sha256"]);
}

#[cfg(feature = "pg")]
fn porte_schema() -> &'static str {
    porte::pg::SCHEMA
}

#[cfg(not(feature = "pg"))]
fn porte_schema() -> &'static str {
    include_str!("../../src/pg/schema.sql")
}

fn sha(text: &str) -> Value {
    Value::from(porte_hex(&Sha256::digest(text.as_bytes())))
}

fn porte_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
