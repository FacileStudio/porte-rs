mod common;

use axum::body::Body;
use common::harness::harness;
use common::http::send;
use http::Request;
use porte::{Config, Identity, SESSION_COOKIE_NAME, SessionStore};

#[tokio::test]
async fn a_named_token_never_expires_and_binds_to_its_minter() {
    let h = harness(Config::default());
    let caller = Identity { user_id: 7, session_id: 3, ..Identity::default() };
    let template = porte::Session { user_id: 7, label: "ci".into(), ..porte::Session::default() };
    let (_, token) = h.manager.issue_for(Some(&caller), template.clone()).await.unwrap();
    assert_eq!((token.expires_at, token.issued_by), (None, 3));
    let stranger = Identity { user_id: 8, session_id: 4, ..Identity::default() };
    let (_, unbound) = h.manager.issue_for(Some(&stranger), template).await.unwrap();
    assert_eq!(unbound.issued_by, 0);
}

#[tokio::test]
async fn logout_ends_the_session_and_needs_the_csrf_header_with_a_cookie() {
    let h = harness(Config { success_url: "https://app.test/".into(), ..Config::default() });
    let (token, _) = h.manager.issue(7, "").await.unwrap();
    let cookie = format!("__Host-{SESSION_COOKIE_NAME}={token}");
    let bare = Request::post("/auth/logout").header("cookie", &cookie).body(Body::empty()).unwrap();
    assert_eq!(send(h.app(), bare).await.status, 403);
    let request = Request::post("/auth/logout")
        .header("cookie", &cookie)
        .header(porte::CSRF_HEADER_NAME, "1")
        .body(Body::empty());
    let answer = send(h.app(), request.unwrap()).await;
    assert_eq!((answer.status, answer.body.as_str()), (200, "{\"logged_out\":true}\n"));
    assert_eq!(answer.set_cookies().unwrap().len(), 2);
    assert_eq!(h.store.list_by_user(7).await.unwrap().len(), 0);
}
