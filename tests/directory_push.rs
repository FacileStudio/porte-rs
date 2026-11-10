#![cfg(feature = "directory")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use common::registre::{Blob, Erasures, ISSUER, Registre, client};
use common::sign::{KEY_ID, key, now, sign_with};
use http::Request;
use porte::directory::{DELETIONS_PATH, Deletions, USER_DELETED_EVENT};
use serde_json::{Value, json};
use tower::ServiceExt;

fn deletions(registre: &Arc<Registre>, erasures: &Arc<Erasures>, blob: &Arc<Blob>) -> Deletions {
    Deletions::new(client(registre), erasures.clone(), Some(erasures.clone()), Some(blob.clone()), Duration::ZERO)
}

fn setup() -> (Arc<Registre>, Arc<Erasures>, Arc<Blob>) {
    (Arc::new(Registre::default()), Arc::new(Erasures::default()), Arc::new(Blob::default()))
}

fn notice(header: Value, claims: Value) -> String {
    sign_with(&key("idp_key.pem"), &header, &claims)
}

fn good_claims() -> Value {
    json!({ "iss": ISSUER, "aud": "app-client", "sub": "u9", "iat": now(), "exp": now() + 300,
            "events": { USER_DELETED_EVENT: {} } })
}

async fn push(deletions: &Deletions, method: &str, body: String) -> (u16, Option<String>) {
    let app: Router = Router::new().route(DELETIONS_PATH, deletions.route());
    let request = Request::builder().method(method).uri(DELETIONS_PATH).body(Body::from(body)).unwrap();
    let response = app.oneshot(request).await.unwrap();
    (response.status().as_u16(), response.headers().get("allow").map(|v| v.to_str().unwrap().to_owned()))
}

#[tokio::test]
async fn a_signed_notice_erases_at_once() {
    let (registre, erasures, blob) = setup();
    let deletions = deletions(&registre, &erasures, &blob);
    let header = json!({ "alg": "RS256", "typ": "secevent+jwt", "kid": KEY_ID });
    assert_eq!(push(&deletions, "POST", notice(header, good_claims())).await.0, 202);
    assert_eq!(erasures.calls.lock().unwrap().len(), 2);
    assert_eq!(push(&deletions, "GET", String::new()).await, (405, Some("POST".into())));
}

#[tokio::test]
async fn every_bad_notice_is_a_400() {
    let (registre, erasures, blob) = setup();
    let deletions = deletions(&registre, &erasures, &blob);
    let header = json!({ "alg": "RS256", "typ": "secevent+jwt", "kid": KEY_ID });
    let with = |change: Value| {
        let mut claims = good_claims();
        common::sign::merge(&mut claims, change);
        claims
    };
    let bad = [
        notice(json!({ "alg": "RS256", "typ": "JWT", "kid": KEY_ID }), good_claims()),
        notice(header.clone(), with(json!({ "aud": "other-app" }))),
        notice(header.clone(), with(json!({ "iss": "https://evil.test" }))),
        notice(header.clone(), with(json!({ "events": { "x": {} } }))),
        notice(header.clone(), with(json!({ "exp": now() + 7200 }))),
        notice(header.clone(), with(json!({ "exp": now() - 120, "iat": now() - 180 }))),
        sign_with(&key("rogue_key.pem"), &header, &good_claims()),
        "not.a.notice".to_owned(),
    ];
    for token in bad {
        assert_eq!(push(&deletions, "POST", token).await.0, 400);
    }
    assert!(erasures.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_unknown_kid_inside_the_refetch_gap_is_a_503() {
    let (registre, erasures, blob) = setup();
    let deletions = deletions(&registre, &erasures, &blob);
    let stranger = notice(json!({ "alg": "RS256", "typ": "secevent+jwt", "kid": "other" }), good_claims());
    assert_eq!(push(&deletions, "POST", stranger.clone()).await.0, 400);
    assert_eq!(push(&deletions, "POST", stranger).await.0, 503);
    assert_eq!(*registre.key_fetches.lock().unwrap(), 1);
}
