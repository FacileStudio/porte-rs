use porte::pg::TokenSealer;
use serde_json::{Value, json};

use crate::common::vectors::{cases, load};

#[test]
fn sealer_vector() {
    for case in cases(&load("sealer")) {
        let input = &case["input"];
        let spec = input["spec"].as_str().unwrap();
        let got = match input["kind"].as_str().unwrap() {
            "parse" => parse(spec),
            "seal" => seal(spec, input["plain"].as_str().unwrap()),
            _ => open(spec, input["stored"].as_str().unwrap()),
        };
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}

fn parse(spec: &str) -> Value {
    match TokenSealer::parse(spec) {
        Ok(sealer) => json!({ "ok": true, "sealing": sealer.is_some() }),
        Err(_) => json!({ "ok": false, "sealing": false }),
    }
}

fn seal(spec: &str, plain: &str) -> Value {
    let sealed = TokenSealer::parse(spec).unwrap().unwrap().seal(plain).unwrap();
    let prefix = if sealed.starts_with("pv1:") { "pv1:" } else { "" };
    assert_eq!(TokenSealer::parse(spec).unwrap().unwrap().open(&sealed).unwrap(), plain);
    json!({ "length": sealed.len(), "prefix": prefix })
}

fn open(spec: &str, stored: &str) -> Value {
    let opened = match TokenSealer::parse(spec).unwrap() {
        Some(sealer) => sealer.open(stored),
        None if stored.starts_with("pv1:") => Err(porte::pg::TokenUnreadable),
        None => Ok(stored.to_owned()),
    };
    match opened {
        Ok(plain) => json!({ "error": null, "plain": plain }),
        Err(_) => json!({ "error": "unreadable", "plain": "" }),
    }
}
