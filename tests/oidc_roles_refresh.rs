#![cfg(feature = "oidc")]

mod common;

use std::time::Duration;

use axum::body::Body;
use common::flow::Browser;
use common::roles::{admin, age, recover, row, token_requests, whoami};
use http::Request;

#[tokio::test]
async fn a_revoked_grant_ends_the_session_and_clears_the_roles() {
    let mut browser = Browser::default();
    let flow = admin(&mut browser).await;
    let (api_token, _) = flow.manager.issue(7, "ci").await.unwrap();
    age(&flow, Duration::from_secs(600), |row| row.tokens.refresh_token = "revoked".into()).await;

    let refused = whoami(&flow, &mut browser).await;
    assert_eq!(refused.0, 401, "{}", refused.1);
    assert!(browser.cookies.is_empty(), "the dead cookie was kept");
    assert_eq!(flow.sessions.count(7), 1, "only the named token survives");
    let stored = row(&flow).await;
    assert_eq!((stored.roles, stored.roles_synced_at), (None, None));
    assert!(stored.tokens.refresh_token.is_empty());

    let bearer = Request::get("/whoami").header("authorization", format!("Bearer {api_token}"));
    let named = Browser::default().send(&flow, bearer.body(Body::empty()).unwrap()).await;
    assert_eq!((named.status, named.body.as_str()), (200, "7 "));
}

#[tokio::test]
async fn a_transient_failure_keeps_the_roles_unstamped_and_retries() {
    for fault in [0, 503, 401] {
        let mut browser = Browser::default();
        let flow = admin(&mut browser).await;
        let synced = age(&flow, Duration::from_secs(600), |_| {}).await;
        let before = token_requests(&flow);
        flow.provider.state.lock().unwrap().token_fault = Some(fault);

        assert_eq!(whoami(&flow, &mut browser).await, (200, "7 admin".into()), "fault {fault}");
        assert_eq!(whoami(&flow, &mut browser).await, (200, "7 admin".into()), "fault {fault}");
        assert_eq!(token_requests(&flow), before + 1, "a failed refresh was retried within 30 s");
        assert_eq!(row(&flow).await.roles_synced_at, Some(synced), "a failed refresh stamped the roles");

        flow.advance(Duration::from_secs(31));
        recover(&flow, &["staff"]);
        assert_eq!(whoami(&flow, &mut browser).await, (200, "7 staff".into()), "fault {fault}");
        assert!(row(&flow).await.roles_synced_at.unwrap() > synced);
    }
}

#[tokio::test]
async fn unverified_roles_lapse_an_hour_past_the_claims_ttl() {
    let mut browser = Browser::default();
    let flow = admin(&mut browser).await;
    age(&flow, Duration::from_secs(3600 + 301), |_| {}).await;
    flow.provider.state.lock().unwrap().token_fault = Some(0);

    assert_eq!(whoami(&flow, &mut browser).await, (200, "7 ".into()));
    assert_eq!(row(&flow).await.roles, Some(vec!["admin".into()]), "an outage erased the stored roles");

    flow.advance(Duration::from_secs(31));
    recover(&flow, &["admin"]);
    assert_eq!(whoami(&flow, &mut browser).await, (200, "7 admin".into()));
}
