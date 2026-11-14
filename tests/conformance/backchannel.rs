use axum::body::Body;
use http::Request;
use serde_json::json;

use crate::common::http::send;
use crate::common::idp::fixture_client_with_keys;
use crate::common::kit::{app_over, oidc_env};
use crate::common::vectors::{cases, load};

use super::csrf::issue;

#[tokio::test]
async fn backchannel_logout_vector() {
    for case in cases(&load("backchannel_logout")) {
        let input = &case["input"];
        let keys = input["keys"].as_str().unwrap_or_default();
        let app = app_over(&oidc_env(&[]), None, fixture_client_with_keys(keys)).await;
        for user in [7, 7, 8] {
            issue(&*app.sessions, user).await;
        }
        let request = Request::post("/auth/backchannel-logout")
            .header("content-type", input["content_type"].as_str().unwrap())
            .body(Body::from(input["body"].as_str().unwrap().to_owned()))
            .unwrap();
        let answer = send(app.router, request).await;
        let got = json!({
            "body": answer.body, "cache_control": answer.header("cache-control"),
            "other_user_sessions_left": app.sessions.count(8), "sessions_deleted": 2 - app.sessions.count(7),
            "status": answer.status,
        });
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}
