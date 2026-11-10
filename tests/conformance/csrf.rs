use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use http::Request;
use porte::session::{Deps, Manager};
use porte::{Config, SESSION_COOKIE_NAME, Session, SessionStore, hash_token, new_token};
use serde_json::{Value, json};
use tower::service_fn;

use crate::common::http::send;
use crate::common::memory::Sessions;
use crate::common::vectors::{cases, load};

#[tokio::test]
async fn csrf_vector() {
    for case in cases(&load("csrf")) {
        let store = Arc::new(Sessions::default());
        let manager = Manager::new(&Config::default(), Deps { sessions: store.clone(), now: None });
        let valid = issue(&*store, 7).await;
        let request = csrf_request(&case["input"], &valid);
        let probe = tower::Layer::layer(&manager.require_auth(), service_fn(ok));
        let answer = send(probe, request).await;
        let got = json!({ "body": answer.body, "set_cookie": answer.set_cookies(), "status": answer.status });
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}

async fn ok(_: Request<Body>) -> Result<axum::response::Response, std::convert::Infallible> {
    Ok(axum::response::Response::new(Body::empty()))
}

pub async fn issue(store: &dyn SessionStore, user_id: i64) -> String {
    let token = new_token().unwrap();
    let now = time::OffsetDateTime::now_utc();
    let session = Session {
        token_hash: hash_token(&token),
        user_id,
        last_used_at: Some(now),
        expires_at: Some(now + Duration::from_secs(3600)),
        ..Session::default()
    };
    store.create(session).await.unwrap();
    token
}

fn csrf_request(input: &Value, valid: &str) -> Request<Body> {
    let method = input["method"].as_str().unwrap();
    let mut builder = Request::builder().method(method).uri("http://app.test/probe");
    let cookie = |value: &str| format!("{SESSION_COOKIE_NAME}={value}");
    builder = match input["transport"].as_str().unwrap() {
        "cookie" => builder.header("cookie", cookie(valid)),
        "bearer" => builder.header("authorization", format!("Bearer {valid}")),
        "unknown_cookie" => builder.header("cookie", cookie("not-a-session")),
        "unknown_bearer" => builder.header("authorization", "Bearer not-a-session"),
        "cookie_and_unknown_bearer" => {
            builder.header("cookie", cookie(valid)).header("authorization", "Bearer not-a-session")
        }
        _ => builder,
    };
    if input["header_present"].as_bool().unwrap() {
        builder = builder.header(porte::CSRF_HEADER_NAME, input["header_value"].as_str().unwrap_or_default());
    }
    builder.body(Body::empty()).unwrap()
}
