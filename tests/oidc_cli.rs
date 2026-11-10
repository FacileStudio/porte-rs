#![cfg(feature = "oidc")]

mod common;

use axum::body::Body;
use common::flow::{Browser, Flow, harness};
use common::http::Answer;
use http::Request;
use serde_json::{Value, json};

async fn exchange(flow: &Flow, body: &str, path: &str) -> Answer {
    let request = Request::post(path).header("content-type", "application/json").body(Body::from(body.to_owned()));
    Browser::default().send(flow, request.unwrap()).await
}

fn bearer(path: &str, token: &str) -> Request<Body> {
    Request::get(path).header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn a_cli_login_redirects_to_the_loopback_with_its_nonce_and_the_code_redeems_once() {
    let flow = harness(|_, _| {}).await.unwrap();
    let callback = flow.login(&mut Browser::default(), "?flow=cli&port=8765&cli_state=nonce-1").await;
    let location = url::Url::parse(&callback.header("location").unwrap()).unwrap();
    assert_eq!((location.host_str(), location.port()), (Some("127.0.0.1"), Some(8765)));
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert_eq!(query["state"], "nonce-1");
    let first = exchange(&flow, &json!({ "code": query["code"] }).to_string(), "/auth/oidc/exchange").await;
    assert_eq!((first.status, first.header("cache-control").as_deref()), (200, Some("no-store")));
    let token: Value = serde_json::from_str(&first.body).unwrap();
    assert_eq!(token["user_id"], "7");
    let me = Browser::default().send(&flow, bearer("/whoami", token["token"].as_str().unwrap())).await;
    assert_eq!(me.status, 200);
    let replay = exchange(&flow, &json!({ "code": query["code"] }).to_string(), "/auth/oidc/exchange").await;
    assert_eq!(
        (replay.status, replay.body.as_str()),
        (401, "{\"error\":{\"code\":\"unauthenticated\",\"message\":\"invalid or expired code\"}}\n")
    );
}

#[tokio::test]
async fn without_a_port_the_cli_gets_a_page_that_names_the_app_and_is_never_cached() {
    let flow = harness(|_, _| {}).await.unwrap();
    let page = flow.login(&mut Browser::default(), "?flow=cli&port=80").await;
    assert_eq!(page.status, 200);
    assert_eq!(page.header("content-type").as_deref(), Some("text/html; charset=utf-8"));
    assert_eq!(page.header("cache-control").as_deref(), Some("no-store"));
    assert!(page.body.contains("<span>App</span>") && page.body.contains("https://app.test/logo.svg"));
    assert!(page.body.contains("valid for 60 seconds") && !page.body.contains("border:1px"));
    let code = page.body.split("<output id=\"c\">").nth(1).unwrap().split("</output>").next().unwrap();
    let redeemed = exchange(&flow, &json!({ "code": code }).to_string(), "/auth/oidc/exchange").await;
    assert_eq!(redeemed.status, 200);
}

#[tokio::test]
async fn a_cli_state_that_is_not_a_nonce_is_dropped() {
    let flow = harness(|_, _| {}).await.unwrap();
    let callback = flow.login(&mut Browser::default(), "?flow=cli&port=8765&cli_state=a%20b").await;
    assert!(!callback.header("location").unwrap().contains("state="));
}

#[tokio::test]
async fn the_device_exchange_mints_this_apps_own_session() {
    let flow = harness(|cfg, _| cfg.cli_audience = "facile-cli".into()).await.unwrap();
    use porte::IdentityStore;
    let row = porte::StoredIdentity {
        user_id: 7,
        provider: common::provider::ISSUER.into(),
        subject: "subject-1".into(),
        ..Default::default()
    };
    flow.identities.save(&row).await.unwrap();
    let token = flow.provider.access_token("facile-cli", json!({}));
    let answer = exchange(&flow, &json!({ "access_token": token }).to_string(), "/auth/oidc/device/exchange").await;
    assert_eq!((answer.status, answer.header("cache-control").as_deref()), (200, Some("no-store")));
    let minted: Value = serde_json::from_str(&answer.body).unwrap();
    assert_eq!(minted["user_id"], "7");
    let direct = Browser::default().send(&flow, bearer("/whoami", &token)).await;
    assert_eq!(direct.status, 401, "a facile-cli token opened a RequireAuth route directly");
}

#[tokio::test]
async fn every_device_refusal_is_the_same_401_and_a_bad_body_is_a_400() {
    let flow = harness(|cfg, _| cfg.cli_audience = "facile-cli".into()).await.unwrap();
    let path = "/auth/oidc/device/exchange";
    assert_eq!(exchange(&flow, "", path).await.status, 400, "the CLI probe must not see a 404");
    assert_eq!(exchange(&flow, "{}", path).await.status, 400);
    let wrong_audience = flow.provider.access_token("app-client", json!({}));
    let unknown = flow.provider.access_token("facile-cli", json!({}));
    for token in [wrong_audience, unknown, "garbage".to_owned()] {
        let answer = exchange(&flow, &json!({ "access_token": token }).to_string(), path).await;
        assert_eq!(answer.body, "{\"error\":{\"code\":\"unauthenticated\",\"message\":\"invalid access token\"}}\n");
    }
}

#[tokio::test]
async fn the_device_route_is_absent_without_a_cli_audience() {
    let flow = harness(|_, _| {}).await.unwrap();
    assert_eq!(exchange(&flow, "", "/auth/oidc/device/exchange").await.status, 404);
}
