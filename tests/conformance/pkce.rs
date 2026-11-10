use axum::body::Body;
use http::Request;
use porte::oidc::pkce_challenge;
use serde_json::{Map, Value, json};
use url::Url;

use crate::common::http::send;
use crate::common::kit::app;
use crate::common::vectors::{cases, load};

#[tokio::test]
async fn pkce_vector() {
    let vector = load("pkce");
    assert_eq!(vector["fixtures"], json!({ "method": "S256", "verifier_length": 43 }));
    for case in cases(&vector) {
        let input = &case["input"];
        let got = match input["kind"].as_str().unwrap() {
            "challenge" => challenge(input),
            _ => authorize(input).await,
        };
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}

fn challenge(input: &Value) -> Value {
    let challenge = pkce_challenge(input["verifier"].as_str().unwrap());
    match input["offered_challenge"].as_str() {
        Some(offered) => json!({ "challenge": challenge, "matches": offered == challenge }),
        None => json!({ "challenge": challenge }),
    }
}

async fn authorize(input: &Value) -> Value {
    let app = app(&input["config"], None).await;
    let answer = send(app.router, Request::get(input["path"].as_str().unwrap()).body(Body::empty()).unwrap()).await;
    let mut url = Url::parse(&answer.header("location").unwrap()).unwrap();
    let mut query = Map::new();
    for (key, value) in url.query_pairs() {
        let value = match key.as_ref() {
            "state" | "nonce" | "code_challenge" => {
                assert_eq!(value.len(), 43, "{key} is not 43 base64url characters");
                "<43 random base64url characters>".to_owned()
            }
            _ => value.into_owned(),
        };
        query.insert(key.into_owned(), Value::from(value));
    }
    url.set_query(None);
    json!({ "query": query, "status": answer.status, "url": url.to_string() })
}
