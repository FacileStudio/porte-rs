#![cfg(feature = "oidc")]

mod common;

use axum::body::Body;
use common::flow::{Browser, Flow, harness};
use common::http::Answer;
use common::provider::ISSUER;
use http::Request;
use porte::IdentityStore;
use serde_json::json;

async fn sync(flow: &Flow, browser: &mut Browser) -> Answer {
    let request = Request::post("/auth/sync-profile").header(porte::CSRF_HEADER_NAME, "1").body(Body::empty());
    browser.send(flow, request.unwrap()).await
}

async fn age_the_last_sync(flow: &Flow) {
    let mut row = flow.identities.find(ISSUER, "subject-1").await.unwrap();
    row.synced_at = Some(time::OffsetDateTime::now_utc() - std::time::Duration::from_secs(600));
    flow.identities.save(&row).await.unwrap();
}

#[tokio::test]
async fn sync_profile_refreshes_the_name_and_honours_its_rate_limit() {
    let flow = harness(|_, _| {}).await.unwrap();
    let mut browser = Browser::default();
    flow.login(&mut browser, "").await;
    assert_eq!(sync(&flow, &mut browser).await.body, "{\"synced\":false}\n", "a sync inside the interval ran");
    age_the_last_sync(&flow).await;
    assert_eq!(sync(&flow, &mut browser).await.body, "{\"synced\":true}\n");
    assert_eq!(flow.users.claims.lock().unwrap().last().unwrap().name, "Renamed User");
}

#[tokio::test]
async fn sync_profile_refuses_a_userinfo_answer_for_another_subject() {
    let flow =
        harness(|_, idp| idp.state.lock().unwrap().userinfo_subject = Some("someone-else".into())).await.unwrap();
    let mut browser = Browser::default();
    flow.login(&mut browser, "").await;
    age_the_last_sync(&flow).await;
    let written = flow.users.claims.lock().unwrap().len();
    let answer = sync(&flow, &mut browser).await;
    assert_eq!(answer.status, 401);
    assert!(answer.body.contains("the userinfo response is for a different subject"));
    assert_eq!(flow.users.claims.lock().unwrap().len(), written, "a foreign profile was written");
}

async fn logout(flow: &Flow, token: &str) -> Answer {
    let body = format!("logout_token={token}");
    let request = Request::post("/auth/backchannel-logout")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body));
    Browser::default().send(flow, request.unwrap()).await
}

#[tokio::test]
async fn back_channel_logout_revokes_every_session_of_the_subject() {
    let flow = harness(|_, _| {}).await.unwrap();
    flow.login(&mut Browser::default(), "").await;
    flow.login(&mut Browser::default(), "").await;
    assert_eq!(flow.sessions.count(7), 2);
    let answer = logout(&flow, &flow.provider.logout_token(json!({}))).await;
    assert_eq!((answer.status, answer.body.as_str()), (200, "{\"logged_out\":true}\n"));
    assert_eq!(flow.sessions.count(7), 0);
}

#[tokio::test]
async fn back_channel_logout_refuses_an_id_token_and_reveals_nothing_for_a_stranger() {
    let flow = harness(|_, _| {}).await.unwrap();
    flow.login(&mut Browser::default(), "").await;
    let id_token = flow.provider.logout_token(json!({ "nonce": "n", "events": null }));
    assert_eq!(logout(&flow, &id_token).await.status, 401);
    let stranger = flow.provider.logout_token(json!({ "sub": "nobody" }));
    assert_eq!(logout(&flow, &stranger).await.status, 200);
    assert_eq!(flow.sessions.count(7), 1);
}

#[tokio::test]
async fn a_machine_token_authenticates_through_the_kit_and_meets_the_scope_gate() {
    let flow = harness(|cfg, _| {
        cfg.machine_audience = "app-client".into();
        cfg.scope_prefix = "app".into();
    })
    .await
    .unwrap();
    flow.login(&mut Browser::default(), "").await;
    let read = flow.provider.access_token("app-client", json!({ "scope": "app.read" }));
    let get = Request::get("/whoami").header("authorization", format!("Bearer {read}")).body(Body::empty()).unwrap();
    assert_eq!(Browser::default().send(&flow, get).await.status, 200);
    let post =
        Request::post("/auth/sync-profile").header("authorization", format!("Bearer {read}")).body(Body::empty());
    assert_eq!(Browser::default().send(&flow, post.unwrap()).await.status, 403);
}
