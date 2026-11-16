#![cfg(feature = "oidc")]

mod common;

use std::time::Duration;

use common::flow::Browser;
use common::roles::{admin, age, row, token_requests, whoami};
use time::OffsetDateTime;

#[tokio::test]
async fn stale_roles_are_refreshed_while_the_access_token_is_still_valid() {
    let mut browser = Browser::default();
    let flow = admin(&mut browser).await;
    age(&flow, Duration::from_secs(600), |row| {
        row.tokens.expiry = Some(OffsetDateTime::now_utc() + Duration::from_secs(3600));
    })
    .await;
    flow.provider.state.lock().unwrap().roles = Some(vec![]);

    assert_eq!(whoami(&flow, &mut browser).await, (200, "7 ".into()));
    assert_eq!(row(&flow).await.roles, Some(vec![]));
}

#[tokio::test]
async fn a_refresh_without_an_id_token_keeps_the_roles_and_the_session() {
    let mut browser = Browser::default();
    let flow = admin(&mut browser).await;
    let synced = age(&flow, Duration::from_secs(600), |row| row.tokens.access_token = "spent".into()).await;
    flow.provider.state.lock().unwrap().omit_id_token = true;

    assert_eq!(whoami(&flow, &mut browser).await, (200, "7 admin".into()));
    let stored = row(&flow).await;
    assert!(stored.roles_synced_at.unwrap() > synced, "a live grant was not recorded");
    assert_ne!(stored.tokens.access_token, "spent", "the new tokens were dropped");
    assert_eq!(flow.sessions.count(7), 1);
}

#[tokio::test]
async fn a_refresh_token_rotated_elsewhere_is_retried_not_refused() {
    let mut browser = Browser::default();
    let flow = admin(&mut browser).await;
    age(&flow, Duration::from_secs(600), |row| row.tokens.refresh_token = "spent".into()).await;
    let identities = flow.identities.clone();
    flow.provider.state.lock().unwrap().on_refresh = Some(std::sync::Arc::new(move || {
        let mut rows = identities.rows.lock().unwrap();
        rows.values_mut().for_each(|row| row.tokens.refresh_token = "refresh-token".into());
    }));

    assert_eq!(whoami(&flow, &mut browser).await, (200, "7 admin".into()));
    assert_eq!(flow.sessions.count(7), 1);
}

#[tokio::test]
async fn concurrent_requests_refresh_stale_roles_once() {
    let mut browser = Browser::default();
    let flow = admin(&mut browser).await;
    age(&flow, Duration::from_secs(600), |_| {}).await;
    let before = token_requests(&flow);
    let (mut first, mut second) =
        (Browser { cookies: browser.cookies.clone() }, Browser { cookies: browser.cookies.clone() });

    let (one, two) = tokio::join!(whoami(&flow, &mut first), whoami(&flow, &mut second));
    assert_eq!((one.0, two.0), (200, 200));
    assert_eq!(token_requests(&flow), before + 1);
}
