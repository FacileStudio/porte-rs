#![cfg(feature = "exchange")]

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use common::exchange::{CLIENT_ID, Identities, SECRET, bulle, setup};
use porte::Identity;
use porte::exchange::{Config, ExchangeError, Exchanger, Target};
use tronc::bulle::TokenSource;

#[tokio::test]
async fn a_dead_refresh_token_is_reconnect() {
    let f = setup();
    f.ids.set_refresh_token(7, "rt-revoked".into());
    assert_eq!(f.ex.token(7, &bulle()).await, Err(ExchangeError::Reconnect));
    assert_eq!(f.ex.token(99, &bulle()).await, Err(ExchangeError::Reconnect));
    let envelope = tronc::Error::from(ExchangeError::Reconnect);
    assert_eq!(envelope.code.status(), 412);
}

#[tokio::test]
async fn a_refused_scope_is_not_reconnect() {
    let f = setup();
    let refused = f.ex.token(7, &Target::new("courrier", ["courrier.write"])).await;
    assert_eq!(refused, Err(ExchangeError::Refused { status: 400, code: "invalid_scope".into() }));
    f.registre.down.store(true, Ordering::SeqCst);
    f.ex.forget_user(7);
    assert!(matches!(f.ex.token(7, &bulle()).await, Err(ExchangeError::Unavailable(_))));
}

#[tokio::test]
async fn call_retries_once_on_401() {
    let f = setup();
    let seen = Mutex::new(Vec::new());
    let request = |token: String| {
        let mut seen = seen.lock().unwrap();
        seen.push(token);
        let status = if seen.len() > 1 { 200 } else { 401 };
        async move { Ok::<_, ExchangeError>(http::Response::builder().status(status).body(()).unwrap()) }
    };
    let identity = Identity { user_id: 7, ..Identity::default() };
    let response = f.ex.source(bulle()).call(&identity, request).await.unwrap();
    assert_eq!(response.status(), 200);
    let seen = seen.into_inner().unwrap();
    assert!(seen.len() == 2 && seen[0] != seen[1], "{seen:?}");
    let always = |_: String| async { Ok::<_, ExchangeError>(http::Response::builder().status(401).body(()).unwrap()) };
    assert_eq!(f.ex.call(7, &bulle(), always).await.unwrap().status(), 401);
    assert_eq!(f.ex.source(bulle()).token(&Identity::default()).await, Err(ExchangeError::NoUser));
}

#[tokio::test]
async fn a_bound_source_is_the_bulle_token_source() {
    let f = setup();
    let source = f.ex.bound(7, bulle());
    let first = TokenSource::token(&source).await.unwrap();
    assert_eq!(TokenSource::token(&source).await.unwrap(), first, "the bound source did not reuse the cached token");
    assert!(TokenSource::forget(&source).is_some(), "a bound source never asks the client to retry a 401");
    assert_ne!(TokenSource::token(&source).await.unwrap(), first, "forget kept the token Bulle refused");
    let nobody = TokenSource::token(&f.ex.bound(0, bulle())).await.unwrap_err();
    assert_eq!(nobody.code.status().as_u16(), 401);
    let no_grant = TokenSource::token(&f.ex.bound(99, bulle())).await.unwrap_err();
    assert_eq!(no_grant.code.status().as_u16(), 412);
}

#[test]
fn the_config_is_checked() {
    let config = Config::new("", CLIENT_ID, SECRET, Arc::new(Identities::default()));
    assert!(Exchanger::new(config).is_err());
}
