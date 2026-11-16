use std::time::Duration;

use axum::body::Body;
use http::Request;
use porte::{IdentityStore, StoredIdentity};
use time::OffsetDateTime;

use super::flow::{Browser, Flow, harness};
use super::provider::ISSUER;

pub async fn admin(browser: &mut Browser) -> Flow {
    let flow = harness(|cfg, idp| {
        cfg.claims_scope = "facile".into();
        idp.state.lock().unwrap().roles = Some(vec!["admin".into()]);
    })
    .await
    .unwrap();
    flow.login(browser, "").await;
    flow
}

pub async fn age(flow: &Flow, by: Duration, change: impl FnOnce(&mut StoredIdentity)) -> OffsetDateTime {
    let mut row = row(flow).await;
    let synced = OffsetDateTime::now_utc() - by;
    row.roles_synced_at = Some(synced);
    change(&mut row);
    flow.identities.save(&row).await.unwrap();
    synced
}

pub async fn row(flow: &Flow) -> StoredIdentity {
    flow.identities.find(ISSUER, "subject-1").await.unwrap()
}

pub async fn whoami(flow: &Flow, browser: &mut Browser) -> (u16, String) {
    let answer = browser.send(flow, Request::get("/whoami").body(Body::empty()).unwrap()).await;
    (answer.status, answer.body)
}

pub fn token_requests(flow: &Flow) -> usize {
    flow.provider.state.lock().unwrap().token_requests
}

pub fn recover(flow: &Flow, roles: &[&str]) {
    let mut state = flow.provider.state.lock().unwrap();
    (state.token_fault, state.roles) = (None, Some(roles.iter().map(|role| role.to_string()).collect()));
}
