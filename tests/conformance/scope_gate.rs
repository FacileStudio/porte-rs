use axum::body::Body;
use http::Request;
use serde_json::json;
use tower::{Layer, service_fn};

use crate::common::http::send;
use crate::common::kit::{app, oidc_env};
use crate::common::vectors::{cases, load};

use super::csrf::ok;

#[tokio::test]
async fn scope_gate_vector() {
    for case in cases(&load("scope_gate")) {
        let input = &case["input"];
        let prefix = input["prefix"].as_str().unwrap();
        let app = app(&oidc_env(&[("OIDC_MACHINE_AUDIENCE", "app-client"), ("OIDC_SCOPE_PREFIX", prefix)]), None).await;
        let request = Request::builder()
            .method(input["method"].as_str().unwrap())
            .uri("http://app.test/probe")
            .header("authorization", format!("Bearer {}", input["token"].as_str().unwrap()))
            .body(Body::empty())
            .unwrap();
        let answer = send(app.manager.require_auth().layer(service_fn(ok)), request).await;
        assert_eq!(json!({ "body": answer.body, "status": answer.status }), case["want"], "{}", case["name"]);
    }
}
