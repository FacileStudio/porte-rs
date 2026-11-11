use axum::body::Body;
use http::Request;
use serde_json::{Value, json};

use super::flow::{Browser, Flow, harness};
use super::http::Answer;
use super::sign::{jwk, key, sign_with};

pub const ROTATED: &str = "rotated-key";

pub async fn logout(flow: &Flow, token: &str) -> Answer {
    let request = Request::post("/auth/backchannel-logout")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!("logout_token={token}")));
    Browser::default().send(flow, request.unwrap()).await
}

pub fn signed(flow: &Flow, key_name: &str, kid: Option<&str>, extra: Value) -> String {
    let header = match kid {
        Some(kid) => json!({ "alg": "RS256", "kid": kid, "typ": "JWT" }),
        None => json!({ "alg": "RS256", "typ": "JWT" }),
    };
    sign_with(&key(key_name), &header, &flow.provider.logout_claims(extra))
}

pub fn rotate(flow: &Flow) {
    flow.provider.state.lock().unwrap().jwks = json!({ "keys": [jwk(&key("rogue_key.pem"), ROTATED)] });
}

pub fn fetches(flow: &Flow) -> usize {
    flow.provider.state.lock().unwrap().key_fetches
}

pub async fn signed_in() -> Flow {
    let flow = harness(|_, _| {}).await.unwrap();
    flow.login(&mut Browser::default(), "").await;
    assert_eq!((flow.sessions.count(7), fetches(&flow)), (1, 1));
    flow
}
