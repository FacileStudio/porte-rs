#![cfg(feature = "oidc")]

mod common;

use axum::body::Body;
use common::flow::{Browser, harness};
use common::provider::ISSUER;
use http::Request;
use porte::IdentityStore;
use serde_json::Value;

#[tokio::test]
async fn a_browser_login_ends_in_a_session_the_middleware_accepts() {
    let flow = harness(|_, _| {}).await.unwrap();
    let mut browser = Browser::default();
    let callback = flow.login(&mut browser, "").await;
    assert_eq!((callback.status, callback.header("location").as_deref()), (302, Some("https://app.test/")));
    let cookies = callback.set_cookies().unwrap();
    assert!(cookies.iter().any(|c| c.starts_with("__Host-session=b-")
        && c.ends_with("; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax")));
    assert!(cookies.iter().any(|c| c.starts_with("__Host-oidc_state=; Path=/; Max-Age=0")));
    assert_eq!(flow.sessions.count(7), 1);
    let me = browser.send(&flow, Request::get("/whoami").body(Body::empty()).unwrap()).await;
    assert_eq!((me.status, me.body.as_str()), (200, "7 "));
    let stored = flow.identities.find(ISSUER, "subject-1").await.unwrap();
    assert_eq!(stored.tokens.refresh_token, "refresh-token");
    let claims = flow.users.claims.lock().unwrap()[0].clone();
    assert_eq!(
        (claims.email.as_str(), claims.email_verified, claims.name.as_str()),
        ("user@example.test", true, "Test User")
    );
}

#[tokio::test]
async fn an_omitted_email_verified_vouches_for_nothing_unless_trusted() {
    let silent = harness(|_, idp| idp.state.lock().unwrap().email_verified = None).await.unwrap();
    silent.login(&mut Browser::default(), "").await;
    assert!(!silent.users.claims.lock().unwrap()[0].email_verified);
    let trusted = harness(|cfg, idp| {
        cfg.trust_email_without_verified_claim = true;
        idp.state.lock().unwrap().email_verified = None;
    })
    .await
    .unwrap();
    trusted.login(&mut Browser::default(), "").await;
    assert!(trusted.users.claims.lock().unwrap()[0].email_verified);
    let refused = harness(|cfg, idp| {
        cfg.trust_email_without_verified_claim = true;
        idp.state.lock().unwrap().email_verified = Some(Value::Bool(false));
    })
    .await
    .unwrap();
    refused.login(&mut Browser::default(), "").await;
    assert!(!refused.users.claims.lock().unwrap()[0].email_verified, "trusting silence overruled a refusal");
}

#[tokio::test]
async fn a_wrong_nonce_is_refused() {
    let flow = harness(|_, idp| idp.state.lock().unwrap().nonce_override = Some("replayed".into())).await.unwrap();
    let callback = flow.login(&mut Browser::default(), "").await;
    assert_eq!(callback.header("location").unwrap(), "https://app.test/login?error=id_token+nonce+mismatch");
    assert_eq!(flow.sessions.count(7), 0);
}

#[tokio::test]
async fn a_tampered_state_or_a_missing_flow_cookie_is_refused() {
    let flow = harness(|_, _| {}).await.unwrap();
    let mut browser = Browser::default();
    let start = browser.send(&flow, Request::get("/auth/oidc").body(Body::empty()).unwrap()).await;
    let callback = flow.provider.authorize(&start.header("location").unwrap());
    let tampered = callback.replace("&state=", "&state=x");
    let answer = browser.send(&flow, Request::get(tampered).body(Body::empty()).unwrap()).await;
    assert_eq!(
        answer.header("location").unwrap(),
        "https://app.test/login?error=the+login+could+not+be+verified%2C+start+again"
    );
    let replay = browser.send(&flow, Request::get(callback).body(Body::empty()).unwrap()).await;
    assert_eq!(replay.header("location").unwrap(), "https://app.test/login?error=the+login+has+expired%2C+start+again");
    assert_eq!(flow.sessions.count(7), 0);
}

#[tokio::test]
async fn logout_revokes_the_session_and_clears_both_cookie_spellings() {
    let flow = harness(|_, _| {}).await.unwrap();
    let mut browser = Browser::default();
    flow.login(&mut browser, "").await;
    let logout = Request::post("/auth/logout").header(porte::CSRF_HEADER_NAME, "1").body(Body::empty()).unwrap();
    let answer = browser.send(&flow, logout).await;
    assert_eq!(answer.status, 200);
    let cookies = answer.set_cookies().unwrap();
    assert!(cookies.contains(&"__Host-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax".to_owned()));
    assert!(cookies.contains(&"session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax".to_owned()));
    assert_eq!(flow.sessions.count(7), 0);
}

#[tokio::test]
async fn the_kit_refuses_a_manager_built_from_another_config() {
    let flow = harness(|_, _| {}).await.unwrap();
    let other = porte::session::Manager::new(
        &porte::Config::default(),
        porte::session::Deps { sessions: flow.sessions.clone(), now: None },
    );
    let deps = porte::oidc::Deps {
        users: flow.users.clone(),
        identities: flow.identities.clone(),
        codes: std::sync::Arc::new(common::stores::Codes::default()),
        sessions: other,
        config_extra: None,
        http: Some(flow.provider.client()),
        now: None,
    };
    let refused = porte::oidc::Kit::new(&common::flow::base_config(), deps).await.err().unwrap();
    assert!(refused.0.contains("OIDC_REDIRECT_URL"), "{refused}");
}

#[tokio::test]
async fn boot_refuses_a_discovery_document_that_names_another_issuer() {
    let published = format!("{ISSUER}/");
    let refused = harness(|_, idp| idp.state.lock().unwrap().published_issuer = published).await.err().unwrap();
    assert!(refused.0.contains("the provider publishes issuer \"https://idp.test/\""), "{refused}");
}
