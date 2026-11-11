#![cfg(feature = "oidc")]

mod common;

use std::time::Duration;

use common::keys::{ROTATED, fetches, logout, rotate, signed, signed_in};
use common::sign::{KEY_ID, now};
use serde_json::json;

#[tokio::test]
async fn cached_keys_outlive_the_hour_and_a_dead_jwks() {
    let flow = signed_in().await;
    flow.provider.state.lock().unwrap().keys_down = true;
    flow.advance(Duration::from_secs(2 * 3600));
    let token = signed(&flow, "idp_key.pem", Some(KEY_ID), json!({ "exp": now() + 3 * 3600 }));
    let answer = logout(&flow, &token).await;
    assert_eq!((answer.status, flow.sessions.count(7), fetches(&flow)), (200, 0, 1));
}

#[tokio::test]
async fn a_rotated_key_is_fetched_on_its_new_kid() {
    let flow = signed_in().await;
    rotate(&flow);
    let answer = logout(&flow, &signed(&flow, "rogue_key.pem", Some(ROTATED), json!({}))).await;
    assert_eq!((answer.status, flow.sessions.count(7), fetches(&flow)), (200, 0, 2));
    let retired = logout(&flow, &signed(&flow, "idp_key.pem", Some(KEY_ID), json!({}))).await;
    assert_eq!(retired.status, 401, "a key dropped from the JWKS still verified");
}

#[tokio::test]
async fn a_token_without_a_kid_tries_every_cached_key_then_refetches() {
    let flow = signed_in().await;
    let cached = logout(&flow, &signed(&flow, "idp_key.pem", None, json!({}))).await;
    assert_eq!((cached.status, fetches(&flow)), (200, 1));
    rotate(&flow);
    let rotated = logout(&flow, &signed(&flow, "rogue_key.pem", None, json!({}))).await;
    assert_eq!((rotated.status, fetches(&flow)), (200, 2));
}

#[tokio::test]
async fn an_unknown_kid_refetches_at_most_every_30_seconds() {
    let flow = signed_in().await;
    let forged = || signed(&flow, "rogue_key.pem", Some("forged"), json!({}));
    assert_eq!((logout(&flow, &forged()).await.status, fetches(&flow)), (401, 2));
    assert_eq!((logout(&flow, &forged()).await.status, fetches(&flow)), (401, 2));
    flow.advance(Duration::from_secs(31));
    assert_eq!((logout(&flow, &forged()).await.status, fetches(&flow)), (401, 3));
    assert_eq!(flow.sessions.count(7), 1);
}

#[tokio::test]
async fn a_dead_jwks_makes_an_unknown_key_a_retryable_503_not_a_refusal() {
    let flow = signed_in().await;
    flow.provider.state.lock().unwrap().keys_down = true;
    let rotated = || signed(&flow, "rogue_key.pem", Some(ROTATED), json!({}));
    let first = logout(&flow, &rotated()).await;
    assert_eq!((first.status, fetches(&flow)), (503, 2));
    assert!(first.body.contains("could not fetch the provider keys"), "{}", first.body);
    assert_eq!((logout(&flow, &rotated()).await.status, fetches(&flow)), (503, 2));
    let unkeyed = logout(&flow, &signed(&flow, "rogue_key.pem", None, json!({}))).await;
    assert_eq!(unkeyed.status, 503);
    assert_eq!(flow.sessions.count(7), 1);
    let cached = logout(&flow, &signed(&flow, "idp_key.pem", Some(KEY_ID), json!({}))).await;
    assert_eq!((cached.status, flow.sessions.count(7)), (200, 0));
    flow.provider.state.lock().unwrap().keys_down = false;
    rotate(&flow);
    flow.advance(Duration::from_secs(31));
    assert_eq!(logout(&flow, &rotated()).await.status, 200);
}
