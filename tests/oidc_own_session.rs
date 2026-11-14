#![cfg(feature = "mcp")]

mod common;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::response::IntoResponse;
use axum::routing::post;
use common::flow::{Browser, Flow, harness};
use common::http::send;
use porte::mcpauth::require_own_session;
use porte::{CSRF_HEADER_NAME, IdentityStore, StoredIdentity};
use serde_json::{Value, json};

fn confirm_page(flow: &Flow) -> Router {
    let confirm = post(|request: Request| async move {
        match require_own_session(&request) {
            Ok(identity) => identity.user_id.to_string().into_response(),
            Err(error) => error.into_response(),
        }
    });
    Router::new().route("/confirm", confirm).route_layer(flow.manager.require_auth())
}

async fn confirm_with_cookie(flow: &Flow, token: &str) -> u16 {
    let request = Request::post("/confirm")
        .header("cookie", format!("__Host-session={token}"))
        .header(CSRF_HEADER_NAME, "1")
        .header("x-forwarded-proto", "https");
    send(confirm_page(flow), request.body(Body::empty()).unwrap()).await.status
}

async fn minted(flow: &Flow, path: &str, body: Value) -> String {
    let request = Request::post(path).header("content-type", "application/json").body(Body::from(body.to_string()));
    let answer = Browser::default().send(flow, request.unwrap()).await;
    assert_eq!(answer.status, 200, "{path}: {}", answer.body);
    serde_json::from_str::<Value>(&answer.body).unwrap()["token"].as_str().unwrap().to_owned()
}

async fn cli_exchange_token(flow: &Flow) -> String {
    let callback = flow.login(&mut Browser::default(), "?flow=cli&port=8765&cli_state=nonce-1").await;
    let location = url::Url::parse(&callback.header("location").unwrap()).unwrap();
    let code = location.query_pairs().find(|(key, _)| key == "code").unwrap().1.into_owned();
    minted(flow, "/auth/oidc/exchange", json!({ "code": code })).await
}

async fn device_token(flow: &Flow) -> String {
    let row = StoredIdentity {
        user_id: 7,
        provider: common::provider::ISSUER.into(),
        subject: "subject-1".into(),
        ..StoredIdentity::default()
    };
    flow.identities.save(&row).await.unwrap();
    let access = flow.provider.access_token("facile-cli", json!({}));
    minted(flow, "/auth/oidc/device/exchange", json!({ "access_token": access })).await
}

#[tokio::test]
async fn only_a_fresh_browser_login_confirms_through_the_real_flows() {
    let flow = harness(|cfg, _| cfg.cli_audience = "facile-cli".into()).await.unwrap();
    let mut browser = Browser::default();
    flow.login(&mut browser, "").await;
    let login = browser.cookies["__Host-session"].clone();
    assert!(login.starts_with(porte::BROWSER_TOKEN_PREFIX), "{login}");
    assert_eq!(confirm_with_cookie(&flow, &login).await, 200);
    let (named, _) = flow.manager.issue(7, "agent").await.unwrap();
    let refused = [
        ("a CLI code-exchange token", cli_exchange_token(&flow).await),
        ("a device token", device_token(&flow).await),
        ("a labelled API token", named),
    ];
    for (name, token) in refused {
        assert_eq!(confirm_with_cookie(&flow, &token).await, 403, "{name} sent as a cookie confirmed");
    }
}

#[tokio::test]
async fn a_browser_cookie_from_before_the_mark_signs_in_but_cannot_confirm() {
    let flow = harness(|_, _| {}).await.unwrap();
    let (old, _) = flow.manager.issue(7, "").await.unwrap();
    let whoami =
        Request::get("/whoami").header("cookie", format!("__Host-session={old}")).header("x-forwarded-proto", "https");
    let me = send(flow.router(), whoami.body(Body::empty()).unwrap()).await;
    assert_eq!((me.status, me.body.as_str()), (200, "7 "));
    assert_eq!(confirm_with_cookie(&flow, &old).await, 403);
}
