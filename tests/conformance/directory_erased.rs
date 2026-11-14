use std::time::Duration;

use porte::directory::Deletions;
use serde_json::{Value, json};

use crate::common::erasure::{Setup, notice, push};
use crate::common::registre::{ISSUER, client};
use crate::common::vectors::{cases, load};

#[tokio::test]
async fn directory_erased_vector() {
    for case in cases(&load("directory_erased")) {
        let input = &case["input"];
        let setup = Setup::new();
        let got = match input["holds"].as_str() {
            Some(holds) => redelivered(&setup, holds).await,
            None => erased(&setup, input).await,
        };
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}

async fn erased(setup: &Setup, input: &Value) -> Value {
    let receiver = match input["no_state"].as_bool().unwrap_or(false) {
        true => Deletions::new(client(&setup.registre), setup.erasures.clone(), None, None, Duration::ZERO),
        false => setup.plain(),
    };
    push(&receiver, &notice("alice")).await;
    let provider = input["provider"].as_str().unwrap().replace("<issuer>", ISSUER);
    json!({ "erased": receiver.erased(&provider, input["subject"].as_str().unwrap()).await.unwrap() })
}

async fn redelivered(setup: &Setup, holds: &str) -> Value {
    let deletions = setup.holding();
    let token = notice("alice");
    push(&deletions, &token).await;
    match holds {
        "fails" => *setup.accounts.fail.lock().unwrap() = true,
        "yes" => setup.accounts.set("alice", true),
        _ => {}
    }
    let status = push(&deletions, &token).await;
    json!({ "callbacks": setup.calls("app", "alice"), "porte_erasures": setup.calls("porte", "alice"), "status": status })
}
