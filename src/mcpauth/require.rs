use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS};
use http::{HeaderValue, StatusCode};
use time::OffsetDateTime;
use tower::{Layer, Service};

use super::{TokenInfo, Verifier, VerifyError};

const CLOCK_SKEW: Duration = Duration::from_secs(30);

/// What [`RequireLayer`] demands beyond a valid token.
#[derive(Debug, Clone, Default)]
pub struct RequireOptions {
    /// Named in every challenge as `resource_metadata`.
    pub resource_metadata_url: String,
    /// Scopes the token must all hold, named in challenges as `scope`.
    pub scopes: Vec<String>,
    /// Accept a token without `exp`.
    pub allow_missing_expiration: bool,
    /// Forgiven on `exp`. Zero means 30 s.
    pub clock_skew: Duration,
}

/// Guards `/mcp` as the MCP Go SDK's `RequireBearerToken` does, with `error="invalid_token"`
/// on a 401 that carried a token and `error="insufficient_scope"` on a 403.
#[derive(Clone)]
pub struct RequireLayer {
    verifier: Arc<Verifier>,
    options: Arc<RequireOptions>,
}

impl RequireLayer {
    /// The layer over `verifier`.
    pub fn new(verifier: Arc<Verifier>, mut options: RequireOptions) -> RequireLayer {
        if options.clock_skew.is_zero() {
            options.clock_skew = CLOCK_SKEW;
        }
        RequireLayer { verifier, options: Arc::new(options) }
    }
}

/// The service a [`RequireLayer`] wraps.
#[derive(Clone)]
pub struct Require<S> {
    inner: S,
    layer: RequireLayer,
}

impl<S> Layer<S> for RequireLayer {
    type Service = Require<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Require { inner, layer: self.clone() }
    }
}

impl<S> Service<Request> for Require<S>
where
    S: Service<Request, Error = Infallible> + Clone + Send + 'static,
    S::Response: IntoResponse,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let layer = self.layer.clone();
        Box::pin(async move {
            let header =
                request.headers().get(AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
            match layer.check(&header).await {
                Ok(info) => {
                    request.extensions_mut().insert(info);
                    Ok(inner.call(request).await?.into_response())
                }
                Err((status, message)) => Ok(layer.refuse(status, message, !header.is_empty())),
            }
        })
    }
}

impl RequireLayer {
    async fn check(&self, header: &str) -> Result<TokenInfo, (StatusCode, &'static str)> {
        let fields: Vec<&str> = header.split_whitespace().collect();
        let [scheme, token] = fields.as_slice() else { return Err((StatusCode::UNAUTHORIZED, "no bearer token")) };
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err((StatusCode::UNAUTHORIZED, "no bearer token"));
        }
        let info = self.verifier.verify(token).await.map_err(|error| match error {
            VerifyError::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid token"),
            VerifyError::Unavailable => (StatusCode::INTERNAL_SERVER_ERROR, "token verification is unavailable"),
        })?;
        if self.options.scopes.iter().any(|scope| !info.scopes.contains(scope)) {
            return Err((StatusCode::FORBIDDEN, "insufficient scope"));
        }
        if info.expiration == OffsetDateTime::UNIX_EPOCH && !self.options.allow_missing_expiration {
            return Err((StatusCode::UNAUTHORIZED, "token missing expiration"));
        }
        if info.expiration + self.options.clock_skew < OffsetDateTime::now_utc() {
            return Err((StatusCode::UNAUTHORIZED, "token expired"));
        }
        Ok(info)
    }

    fn refuse(&self, status: StatusCode, message: &str, with_token: bool) -> Response {
        let mut response = (
            status,
            [(CONTENT_TYPE, "text/plain; charset=utf-8"), (X_CONTENT_TYPE_OPTIONS, "nosniff")],
            format!("{message}\n"),
        )
            .into_response();
        let mut params = Vec::new();
        match status {
            StatusCode::FORBIDDEN => params.push("error=\"insufficient_scope\"".to_owned()),
            StatusCode::UNAUTHORIZED if with_token => params.push("error=\"invalid_token\"".to_owned()),
            _ => {}
        }
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            if !self.options.resource_metadata_url.is_empty() {
                params.push(format!("resource_metadata={:?}", self.options.resource_metadata_url));
            }
            if !self.options.scopes.is_empty() {
                params.push(format!("scope={:?}", self.options.scopes.join(" ")));
            }
        }
        if !params.is_empty()
            && let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", params.join(", ")))
        {
            response.headers_mut().insert(WWW_AUTHENTICATE, value);
        }
        response
    }
}
