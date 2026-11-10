//! The outbound HTTP porte uses for discovery, keys, the token endpoint and the directory.
//!
//! [`HttpClient::new`] is `reqwest` with redirects off and a 10 s timeout. A test hands in its
//! own [`Transport`] to answer for a fake issuer such as `https://sso.test`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// An outbound request: method, URL, headers and a byte body.
pub type HttpRequest = http::Request<Vec<u8>>;
/// An inbound response.
pub type HttpResponse = http::Response<Vec<u8>>;

/// A network failure: nothing answered, or the answer could not be read.
#[derive(Debug, thiserror::Error)]
#[error("porte/http: {0}")]
pub struct TransportError(pub String);

/// Sends one request. Never follows redirects.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// The response, whatever its status.
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError>;
}

/// A cloneable handle on a [`Transport`].
#[derive(Clone)]
pub struct HttpClient {
    transport: Arc<dyn Transport>,
}

impl HttpClient {
    /// `reqwest` with rustls, no redirects and a 10 s timeout.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        HttpClient { transport: Arc::new(Reqwest(client)) }
    }

    /// A client over any transport.
    pub fn from_transport(transport: Arc<dyn Transport>) -> Self {
        HttpClient { transport }
    }

    /// Sends one request.
    pub async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.transport.send(request).await
    }

    /// `GET url` with `Accept: application/json`.
    pub async fn get(&self, url: &str) -> Result<HttpResponse, TransportError> {
        let request = http::Request::get(url).header(http::header::ACCEPT, "application/json").body(Vec::new());
        self.send(request.map_err(|error| TransportError(error.to_string()))?).await
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        HttpClient::new()
    }
}

impl<'c> openidconnect::AsyncHttpClient<'c> for HttpClient {
    type Error = TransportError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(self.send(request))
    }
}

struct Reqwest(reqwest::Client);

#[async_trait::async_trait]
impl Transport for Reqwest {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let fail = |error: reqwest::Error| TransportError(error.to_string());
        let request = reqwest::Request::try_from(request).map_err(fail)?;
        let response = self.0.execute(request).await.map_err(fail)?;
        let mut builder = http::Response::builder().status(response.status());
        if let Some(headers) = builder.headers_mut() {
            headers.extend(response.headers().clone());
        }
        let body = response.bytes().await.map_err(fail)?.to_vec();
        builder.body(body).map_err(|error| TransportError(error.to_string()))
    }
}
