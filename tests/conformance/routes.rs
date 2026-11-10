use std::sync::Arc;

use axum::body::Body;
use http::Request;
use serde_json::{Map, Value, json};
use url::Url;

use crate::common::http::send;
use crate::common::kit::app;
use crate::common::vectors::{cases, load};

#[tokio::test]
async fn routes_vector() {
    for case in cases(&load("routes")) {
        let input = &case["input"];
        let app = app(&input["config"], None).await;
        let request = Request::builder()
            .method(input["method"].as_str().unwrap())
            .uri(input["path"].as_str().unwrap())
            .body(Body::empty())
            .unwrap();
        let answer = send(app.router, request).await;
        let mut got = json!({ "status": answer.status, "location": location(answer.header("location")) });
        if ![302, 404, 405].contains(&answer.status) {
            got["body"] = Value::from(answer.body.clone());
        }
        let redacted = answer.set_cookies().map(|values| values.iter().map(|v| redact(v)).collect::<Vec<_>>());
        got["set_cookie"] = json!(redacted);
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}

fn location(header: Option<String>) -> Value {
    let Some(header) = header else { return Value::Null };
    match Url::parse(&header) {
        Ok(mut url) if url.query_pairs().any(|(key, _)| key == "state") => {
            let mut keys: Vec<String> = url.query_pairs().map(|(key, _)| key.into_owned()).collect();
            keys.sort();
            keys.dedup();
            url.set_query(None);
            json!({ "url": url.to_string(), "query_keys": keys })
        }
        _ => json!({ "url": header }),
    }
}

fn redact(header: &str) -> String {
    let (name, rest) = header.split_once('=').unwrap();
    let attributes = rest.split_once(';').map(|(_, attributes)| attributes).unwrap_or_default();
    format!("{name}=<value>;{attributes}")
}

#[tokio::test]
async fn config_answer_vector() {
    for case in cases(&load("config_answer")) {
        let input = &case["input"];
        let extra = input.get("config_extra").and_then(Value::as_object).cloned().map(|map: Map<String, Value>| {
            let extra: porte::oidc::ConfigExtra = Arc::new(move || map.clone());
            extra
        });
        let app = app(&input["config"], extra).await;
        let answer = send(app.router, Request::get("/auth/config").body(Body::empty()).unwrap()).await;
        let got =
            json!({ "body": answer.body, "content_type": answer.header("content-type"), "status": answer.status });
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}
