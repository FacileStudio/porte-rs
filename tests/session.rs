mod common;

use std::time::Duration;

use common::harness::{harness, with_bearer, with_cookie};
use common::http::send;
use porte::Config;

#[tokio::test]
async fn an_issued_session_authenticates_through_both_transports() {
    let h = harness(Config::default());
    let (token, session) = h.manager.issue(7, "").await.unwrap();
    assert_eq!(session.expires_at, Some(*h.clock.lock().unwrap() + porte::DEFAULT_SESSION_TTL));
    assert_eq!(send(h.app(), with_cookie("/whoami", &token)).await.body, "7");
    assert_eq!(send(h.app(), with_bearer("/whoami", &token)).await.body, "7");
    assert!(!h.store.by_hash().contains_key(&token), "the plaintext token reached the store");
}

#[tokio::test]
async fn an_expired_session_is_deleted_and_its_cookie_cleared() {
    let h = harness(Config::default());
    let (token, _) = h.manager.issue(7, "").await.unwrap();
    h.advance(porte::DEFAULT_SESSION_TTL + Duration::from_secs(1));
    let answer = send(h.app(), with_cookie("/whoami", &token)).await;
    assert_eq!(answer.status, 401);
    assert!(answer.body.contains("session expired"));
    assert_eq!(answer.set_cookies().unwrap(), vec!["session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"]);
    assert_eq!(h.store.count(7), 0);
}

#[tokio::test]
async fn the_idle_window_retires_cookies_only() {
    let h = harness(Config { session_idle_ttl: Some(Duration::from_secs(3600)), ..Config::default() });
    let (cookie, _) = h.manager.issue(7, "").await.unwrap();
    let (bearer, _) = h.manager.issue(7, "").await.unwrap();
    h.advance(Duration::from_secs(3601));
    assert_eq!(send(h.app(), with_bearer("/whoami", &bearer)).await.status, 200);
    assert_eq!(send(h.app(), with_cookie("/whoami", &cookie)).await.status, 401);
    let disabled = harness(Config { session_idle_ttl: Some(Duration::ZERO), ..Config::default() });
    let (token, _) = disabled.manager.issue(7, "").await.unwrap();
    disabled.advance(Duration::from_secs(30 * 24 * 3600 - 10));
    assert_eq!(send(disabled.app(), with_cookie("/whoami", &token)).await.status, 200);
}

#[tokio::test]
async fn last_used_is_written_at_most_once_a_minute() {
    let h = harness(Config::default());
    let (token, session) = h.manager.issue(7, "").await.unwrap();
    h.advance(Duration::from_secs(30));
    send(h.app(), with_bearer("/whoami", &token)).await;
    assert_eq!(h.store.by_hash()[&session.token_hash].last_used_at, session.last_used_at);
    h.advance(Duration::from_secs(31));
    send(h.app(), with_bearer("/whoami", &token)).await;
    assert_eq!(h.store.by_hash()[&session.token_hash].last_used_at, Some(*h.clock.lock().unwrap()));
}
