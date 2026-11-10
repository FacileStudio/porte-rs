use std::sync::Arc;

use porte::http_client::{HttpClient, HttpRequest, HttpResponse, Transport, TransportError};
use serde_json::Value;

use super::vectors::load;

pub const ISSUER: &str = "https://sso.test";

pub struct Fixture {
    discovery: Value,
    jwks: Value,
}

#[async_trait::async_trait]
impl Transport for Fixture {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let url = request.uri().to_string();
        let body = match url.strip_prefix(ISSUER) {
            Some("/.well-known/openid-configuration") => &self.discovery,
            Some("/keys") => &self.jwks,
            _ => return Err(TransportError(format!("conformance: no network outside the fake issuer: {url}"))),
        };
        let response = http::Response::builder().status(200).header("content-type", "application/json");
        Ok(response.body(serde_json::to_vec(body).unwrap()).unwrap())
    }
}

pub fn fixture_client() -> HttpClient {
    let jwt = load("jwt");
    let fixture = Fixture { discovery: jwt["fixtures"]["discovery"].clone(), jwks: jwt["fixtures"]["jwks"].clone() };
    HttpClient::from_transport(Arc::new(fixture))
}
