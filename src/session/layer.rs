use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use tower::{Layer, Service};

use super::Manager;
use super::cookie::append_cookies;

/// The middleware layer [`Manager::require_auth`] and [`Manager::optional`] return.
#[derive(Clone)]
pub struct AuthLayer {
    manager: Manager,
    required: bool,
}

/// The service an [`AuthLayer`] wraps around a route.
#[derive(Clone)]
pub struct Auth<S> {
    inner: S,
    manager: Manager,
    required: bool,
}

impl Manager {
    /// Rejects an unauthenticated request with the suite envelope; inserts the [`crate::Identity`]
    /// into the request extensions otherwise.
    pub fn require_auth(&self) -> AuthLayer {
        AuthLayer { manager: self.clone(), required: true }
    }

    /// Attaches an identity when there is one and lets the request through either way.
    pub fn optional(&self) -> AuthLayer {
        AuthLayer { manager: self.clone(), required: false }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = Auth<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Auth { inner, manager: self.manager.clone(), required: self.required }
    }
}

impl<S> Service<Request> for Auth<S>
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

    fn call(&mut self, request: Request) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let manager = self.manager.clone();
        let required = self.required;
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let auth = manager.authenticate(&parts).await;
            let mut request = Request::from_parts(parts, body);
            let mut response = match auth.result {
                Ok(identity) => {
                    request.extensions_mut().insert(identity);
                    inner.call(request).await?.into_response()
                }
                Err(error) if required => error.into_response(),
                Err(_) => inner.call(request).await?.into_response(),
            };
            append_cookies(response.headers_mut(), auth.set_cookies);
            Ok(response)
        })
    }
}
