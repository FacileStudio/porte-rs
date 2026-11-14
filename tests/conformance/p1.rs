use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Request;
use porte::session::{Deps, Manager};
use porte::{
    BROWSER_TOKEN_PREFIX, Config, SESSION_COOKIE_NAME, hash_token, new_browser_token, new_token, secure_compare,
};
use serde_json::{Value, json};

use crate::common::memory::Sessions;
use crate::common::vectors::{cases, load, source_file};

#[test]
fn vectors_source_is_pinned() {
    assert_eq!(source_file(), "v0.20.0\n");
}

#[test]
fn token_vector() {
    for case in cases(&load("token")) {
        let (input, want) = (&case["input"], &case["want"]);
        let text = |key: &str| input[key].as_str().unwrap_or_default().to_owned();
        let got = match input["kind"].as_str().unwrap() {
            "hash" => json!({ "hash": hash_token(&text("token")) }),
            "compare" => json!({ "equal": secure_compare(&text("a"), &text("b")) }),
            "new_token" => token_shape(),
            "new_browser_token" => browser_token_shape(),
            kind => panic!("{}: no runner for token kind {kind:?}", case["name"]),
        };
        assert_eq!(&got, want, "{}", case["name"]);
    }
}

fn token_shape() -> Value {
    let token = new_token().unwrap();
    assert!(token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    json!({ "alphabet": "^[A-Za-z0-9_-]+$", "decoded_bytes": 32, "padding": token.contains('='), "token_length": token.len() })
}

fn browser_token_shape() -> Value {
    let token = new_browser_token().unwrap();
    let rest = token.strip_prefix(BROWSER_TOKEN_PREFIX).expect("a browser token starts with the prefix");
    assert!(token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    json!({
        "alphabet": "^[A-Za-z0-9_-]+$", "decoded_bytes_after_prefix": URL_SAFE_NO_PAD.decode(rest).unwrap().len(),
        "padding": token.contains('='), "prefix": BROWSER_TOKEN_PREFIX, "token_length": token.len(),
    })
}

#[tokio::test]
async fn cookie_vector() {
    for case in cases(&load("cookie")) {
        let input = &case["input"];
        let config = Config {
            redirect_url: input["redirect_url"].as_str().unwrap().to_owned(),
            session_ttl: Duration::from_secs(input["ttl_seconds"].as_u64().unwrap()),
            accept_legacy_cookie: input["accept_legacy_cookie"].as_bool().unwrap(),
            ..Config::default()
        };
        let manager = Manager::new(&config, Deps { sessions: Arc::new(Sessions::default()), now: None });
        let request = cookie_request(input);
        let got = match input["action"].as_str().unwrap() {
            "set" => json!({ "set_cookie": [manager.session_cookie(&request, "TOKEN").to_str().unwrap()] }),
            "clear" => {
                let values = manager.clear_cookie(&request, SESSION_COOKIE_NAME);
                json!({ "set_cookie": values.iter().map(|v| v.to_str().unwrap()).collect::<Vec<_>>() })
            }
            _ => {
                let value = manager.read_cookie(&request, SESSION_COOKIE_NAME);
                json!({ "found": value.is_some(), "value": value.unwrap_or_default() })
            }
        };
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}

fn cookie_request(input: &Value) -> Request<Body> {
    let mut request = Request::get("http://app.test/").body(Body::empty()).unwrap();
    if input["tls"].as_bool().unwrap() {
        request.extensions_mut().insert(tronc::http::Tls);
    }
    if let Some(proto) = input["forwarded_proto"].as_str().filter(|proto| !proto.is_empty()) {
        request.headers_mut().insert("x-forwarded-proto", proto.parse().unwrap());
    }
    if let Some(cookie) = input["cookie_header"].as_str() {
        request.headers_mut().insert("cookie", cookie.parse().unwrap());
    }
    request
}
