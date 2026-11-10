use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, any};
use http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE,
};
use http::{Method, StatusCode};
use serde::Serialize;
use url::Url;

use crate::ConfigError;

const WELL_KNOWN_PATH: &str = "/.well-known/oauth-protected-resource";

/// The RFC 9728 protected resource metadata document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectedResourceMetadata {
    /// The resource, `https://<app>.facile.studio/mcp`.
    pub resource: String,
    /// The issuer.
    pub authorization_servers: Vec<String>,
    /// `<prefix>.read` and `<prefix>.write`.
    pub scopes_supported: Vec<String>,
    /// Always `["header"]`.
    pub bearer_methods_supported: Vec<String>,
    /// Always `["RS256"]`.
    pub resource_signing_alg_values_supported: Vec<String>,
}

/// The metadata for `resource`, served by its issuer and granting `scopes`.
pub fn protected_resource_metadata(resource: &str, issuer: &str, scopes: Vec<String>) -> ProtectedResourceMetadata {
    ProtectedResourceMetadata {
        resource: resource.into(),
        authorization_servers: vec![issuer.into()],
        scopes_supported: scopes,
        bearer_methods_supported: vec!["header".into()],
        resource_signing_alg_values_supported: vec!["RS256".into()],
    }
}

/// Where the metadata lives: the resource's origin, the well-known path, then the resource's
/// path without its trailing slash.
pub fn metadata_url(resource: &str) -> Result<String, ConfigError> {
    let refused = || ConfigError::new(format!("mcpauth: resource {resource:?} is not an absolute URI"));
    let parsed = Url::parse(resource).map_err(|_| refused())?;
    if !parsed.has_host() {
        return Err(refused());
    }
    let suffix = parsed.path().trim_end_matches('/');
    Ok(format!("{}{WELL_KNOWN_PATH}{suffix}", parsed.origin().ascii_serialization()))
}

/// The metadata endpoint as the MCP Go SDK serves it: open CORS, `OPTIONS` 204, `GET` JSON,
/// anything else 405.
pub fn metadata_route<S: Clone + Send + Sync + 'static>(metadata: ProtectedResourceMetadata) -> MethodRouter<S> {
    any(move |method: Method| async move { answer(&method, &metadata) })
}

fn answer(method: &Method, metadata: &ProtectedResourceMetadata) -> Response {
    let cors = [
        (ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        (ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS"),
        (ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type"),
    ];
    match *method {
        Method::OPTIONS => (StatusCode::NO_CONTENT, cors).into_response(),
        Method::GET => {
            let mut body = serde_json::to_vec(metadata).unwrap_or_default();
            body.push(b'\n');
            (cors, [(CONTENT_TYPE, "application/json")], body).into_response()
        }
        _ => (
            StatusCode::METHOD_NOT_ALLOWED,
            cors,
            [(CONTENT_TYPE, "text/plain; charset=utf-8")],
            "Method not allowed\n",
        )
            .into_response(),
    }
}
