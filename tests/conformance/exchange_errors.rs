use porte::exchange::ExchangeError;
use serde_json::{Value, json};

use crate::common::exchange::{bulle, setup};
use crate::common::vectors::{cases, load};

#[tokio::test]
async fn exchange_errors_vector() {
    let vector = load("exchange_errors");
    let reconnect = tronc::Error::from(ExchangeError::Reconnect);
    let fixture = json!({ "code": reconnect.code.as_str(), "status": reconnect.code.status().as_u16() });
    assert_eq!(fixture, vector["fixtures"]["reconnect"]);
    for case in cases(&vector) {
        let input = &case["input"];
        let f = setup();
        let answer = (input["status"].as_u64().unwrap() as u16, input["body"].as_str().unwrap().to_owned());
        *f.registre.exchange_answer.lock().unwrap() = Some(answer);
        assert_eq!(outcome(f.ex.token(7, &bulle()).await), case["want"], "{}", case["name"]);
    }
}

fn outcome(result: Result<String, ExchangeError>) -> Value {
    match result {
        Ok(token) => json!({ "outcome": "token", "token": token }),
        Err(ExchangeError::Reconnect) => json!({ "outcome": "reconnect" }),
        Err(ExchangeError::Refused { status, code }) => json!({ "outcome": "refused", "status": status, "code": code }),
        Err(ExchangeError::Unavailable(_)) => json!({ "outcome": "unavailable" }),
        Err(other) => json!({ "outcome": format!("unexpected: {other}") }),
    }
}
