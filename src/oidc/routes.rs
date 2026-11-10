use axum::Router;
use axum::extract::Request;
use axum::response::Response;
use axum::routing::{get, post};
use http::StatusCode;
use serde_json::{Map, Value};

use super::Kit;
use crate::routes;
use crate::wire::ConfigResponse;

impl Kit {
    /// The routes at Go's paths, relative to the app's `/api` router. `GET /auth/config` is
    /// always there; the OIDC routes only when a provider is configured, and the device
    /// exchange only when `OIDC_CLI_AUDIENCE` is set. `POST /auth/logout` is the session
    /// manager's: merge `sessions.routes()` too.
    pub fn routes<S: Clone + Send + Sync + 'static>(&self) -> Router<S> {
        let kit = self.clone();
        let router = Router::new().route(routes::CONFIG, get(move || async move { kit.config_answer() }));
        if !self.enabled() {
            return router;
        }
        let (a, b, c, d, e) = (self.clone(), self.clone(), self.clone(), self.clone(), self.clone());
        let sync = Router::new()
            .route(routes::SYNC_PROFILE, post(move |request: Request| async move { a.sync_profile(request).await }))
            .route_layer(self.sessions().require_auth());
        let router = router
            .merge(sync)
            .route(routes::LOGIN, get(move |request: Request| async move { b.login(request) }))
            .route(routes::CALLBACK, get(move |request: Request| async move { c.callback(request).await }))
            .route(routes::EXCHANGE, post(move |request: Request| async move { d.exchange(request).await }))
            .route(
                routes::BACKCHANNEL_LOGOUT,
                post(move |request: Request| async move { e.backchannel(request).await }),
            );
        match self.inner.cli_tokens.is_some() {
            true => {
                let f = self.clone();
                router.route(
                    routes::DEVICE_EXCHANGE,
                    post(move |request: Request| async move { f.device(request).await }),
                )
            }
            false => router,
        }
    }

    fn config_answer(&self) -> Response {
        let sso_only = self.config().sso_only || self.enabled();
        let Some(extra) = &self.inner.config_extra else {
            return tronc::json::write(StatusCode::OK, &ConfigResponse { sso_only, oidc_enabled: self.enabled() });
        };
        let mut body: Map<String, Value> = extra();
        body.insert("sso_only".into(), Value::Bool(sso_only));
        body.insert("oidc_enabled".into(), Value::Bool(self.enabled()));
        tronc::json::write(StatusCode::OK, &body)
    }
}
