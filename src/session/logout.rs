use axum::Router;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use tronc::Error;

use super::Manager;
use super::cookie::append_cookies;
use crate::wire::LogoutResponse;
use crate::{CSRF_HEADER_NAME, Identity, SESSION_COOKIE_NAME, routes};

impl Manager {
    /// `POST /auth/logout`, behind [`Manager::optional`]. It ends the session the request
    /// authenticated with and expires both cookie spellings; without a session it only clears
    /// the cookie. A cookie without the CSRF header is refused.
    pub fn routes<S: Clone + Send + Sync + 'static>(&self) -> Router<S> {
        let manager = self.clone();
        Router::new()
            .route(routes::LOGOUT, post(move |request: Request| async move { manager.logout(request).await }))
            .route_layer(self.optional())
    }

    async fn logout(&self, request: Request) -> Response {
        let (parts, _) = request.into_parts();
        let has_csrf = parts.headers.get(CSRF_HEADER_NAME).is_some_and(|value| !value.is_empty());
        if self.read_cookie(&parts, SESSION_COOKIE_NAME).is_some() && !has_csrf {
            return Error::forbidden(format!("missing {CSRF_HEADER_NAME} header")).into_response();
        }
        if let Some(identity) = parts.extensions.get::<Identity>()
            && let Err(error) = self.end(identity).await
        {
            return error.into_response();
        }
        let mut response = tronc::json::write(http::StatusCode::OK, &LogoutResponse { logged_out: true });
        append_cookies(response.headers_mut(), self.clear_cookie(&parts, SESSION_COOKIE_NAME));
        response
    }
}
