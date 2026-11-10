#![cfg(feature = "mcp")]

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::response::Response;
use common::http::{Answer, send};
use common::mcp::{RESOURCE, known, mint, verifier};
use http::Request;
use porte::mcpauth::{
    RequireLayer, RequireOptions, metadata_route, metadata_url, protected_resource_metadata, scopes_for,
};
use serde_json::{Value, json};
use tower::{Layer, service_fn};

const METADATA: &str = "https://courrier.example/.well-known/oauth-protected-resource/mcp";

async fn call(scopes: &[&str], token: Option<String>) -> Answer {
    let options = RequireOptions {
        resource_metadata_url: METADATA.into(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        ..RequireOptions::default()
    };
    let layer = RequireLayer::new(Arc::new(verifier(known()).await), options);
    let handler = service_fn(|_: Request<Body>| async {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = http::StatusCode::FORBIDDEN;
        Ok::<_, std::convert::Infallible>(response)
    });
    let mut request = Request::post("/mcp");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    send(layer.layer(handler), request.body(Body::empty()).unwrap()).await
}

#[tokio::test]
async fn a_missing_scope_is_an_insufficient_scope_challenge() {
    let answer = call(&["courrier.write"], Some(mint(json!({})))).await;
    assert_eq!((answer.status, answer.body.as_str()), (403, "insufficient scope\n"));
    let expected =
        format!("Bearer error=\"insufficient_scope\", resource_metadata=\"{METADATA}\", scope=\"courrier.write\"");
    assert_eq!(answer.header("www-authenticate").unwrap(), expected);
}

#[tokio::test]
async fn an_invalid_token_is_an_invalid_token_challenge() {
    let answer = call(&["courrier.read"], Some(mint(json!({ "aud": "https://other.example/mcp" })))).await;
    assert_eq!((answer.status, answer.body.as_str()), (401, "invalid token\n"));
    assert!(
        answer.header("www-authenticate").unwrap().starts_with("Bearer error=\"invalid_token\", resource_metadata=")
    );
}

#[tokio::test]
async fn no_token_is_a_challenge_without_an_error_code() {
    let answer = call(&["courrier.read"], None).await;
    assert_eq!((answer.status, answer.body.as_str()), (401, "no bearer token\n"));
    assert_eq!(
        answer.header("www-authenticate").unwrap(),
        format!("Bearer resource_metadata=\"{METADATA}\", scope=\"courrier.read\"")
    );
}

#[tokio::test]
async fn the_protected_handler_keeps_its_own_response() {
    let answer = call(&["courrier.read"], Some(mint(json!({})))).await;
    assert_eq!((answer.status, answer.header("www-authenticate")), (403, None));
}

#[test]
fn the_metadata_url_inserts_the_well_known_suffix() {
    let cases = [
        (RESOURCE, METADATA),
        ("https://app.example/", "https://app.example/.well-known/oauth-protected-resource"),
        ("https://app.example", "https://app.example/.well-known/oauth-protected-resource"),
        ("http://127.0.0.1:8080/api/mcp", "http://127.0.0.1:8080/.well-known/oauth-protected-resource/api/mcp"),
    ];
    for (resource, want) in cases {
        assert_eq!(metadata_url(resource).unwrap(), want);
    }
    assert!(metadata_url("/mcp").is_err());
}

#[tokio::test]
async fn the_metadata_document_is_served_with_open_cors() {
    let metadata = protected_resource_metadata(RESOURCE, "https://registre.example", scopes_for("courrier").list());
    let app: axum::Router =
        axum::Router::new().route("/.well-known/oauth-protected-resource/mcp", metadata_route(metadata));
    let answer =
        send(app.clone(), Request::get("/.well-known/oauth-protected-resource/mcp").body(Body::empty()).unwrap()).await;
    let body: Value = serde_json::from_str(&answer.body).unwrap();
    assert_eq!(body["authorization_servers"], json!(["https://registre.example"]));
    assert_eq!(body["scopes_supported"], json!(["courrier.read", "courrier.write"]));
    assert_eq!(answer.header("access-control-allow-origin").as_deref(), Some("*"));
    let options = Request::options("/.well-known/oauth-protected-resource/mcp").body(Body::empty()).unwrap();
    assert_eq!(send(app, options).await.status, 204);
}
