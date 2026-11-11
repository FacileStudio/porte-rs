use serde::Deserialize;

use super::JwtError;
use crate::http_client::HttpClient;

const MAX_DOCUMENT: usize = 1 << 20;

/// The fields of `/.well-known/openid-configuration` porte reads.
#[derive(Default, Deserialize)]
#[serde(default)]
pub(crate) struct Discovery {
    pub(crate) issuer: String,
    pub(crate) jwks_uri: String,
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) userinfo_endpoint: String,
    pub(crate) scopes_supported: Option<Vec<String>>,
}

/// Fetches the issuer's discovery document.
pub(crate) async fn document(http: &HttpClient, issuer: &str) -> Result<Discovery, String> {
    get_json(http, &document_url(issuer)).await
}

fn document_url(issuer: &str) -> String {
    format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'))
}

pub(crate) async fn jwks_uri(http: &HttpClient, issuer: &str) -> Result<String, JwtError> {
    let document = document(http, issuer)
        .await
        .map_err(|error| JwtError::Fetch(format!("discovery failed for {issuer}: {error}")))?;
    if !document.issuer.is_empty() && document.issuer != issuer {
        let url = document_url(issuer);
        return Err(JwtError::Fetch(format!("{url} publishes issuer {:?}, not {issuer:?}", document.issuer)));
    }
    if document.jwks_uri.is_empty() {
        return Err(JwtError::Fetch(format!("{issuer} advertises no jwks_uri")));
    }
    Ok(document.jwks_uri)
}

pub(crate) async fn get_json<T: serde::de::DeserializeOwned>(http: &HttpClient, url: &str) -> Result<T, String> {
    let response = http.get(url).await.map_err(|error| error.to_string())?;
    if response.status() != http::StatusCode::OK {
        return Err(format!("status {}", response.status().as_u16()));
    }
    let body = response.body();
    let body = &body[..body.len().min(MAX_DOCUMENT)];
    tronc::json::decode(body, usize::MAX).map_err(|error| error.message)
}
