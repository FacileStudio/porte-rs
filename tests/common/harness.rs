use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use http::Request;
use porte::session::{Deps, Manager};
use porte::{Config, Identity, SESSION_COOKIE_NAME};
use time::OffsetDateTime;

use super::memory::Sessions;

pub struct Harness {
    pub manager: Manager,
    pub store: Arc<Sessions>,
    pub clock: Arc<Mutex<OffsetDateTime>>,
}

pub fn harness(config: Config) -> Harness {
    let store = Arc::new(Sessions::default());
    let clock = Arc::new(Mutex::new(OffsetDateTime::now_utc()));
    let now = clock.clone();
    let deps = Deps { sessions: store.clone(), now: Some(Arc::new(move || *now.lock().unwrap())) };
    Harness { manager: Manager::new(&config, deps), store, clock }
}

impl Harness {
    pub fn advance(&self, by: Duration) {
        *self.clock.lock().unwrap() += by;
    }

    pub fn app(&self) -> Router {
        let whoami = get(|identity: Identity| async move { identity.user_id.to_string() });
        Router::new().route("/whoami", whoami).route_layer(self.manager.require_auth()).merge(self.manager.routes())
    }
}

pub fn with_cookie(path: &str, token: &str) -> Request<Body> {
    Request::get(path).header("cookie", format!("{SESSION_COOKIE_NAME}={token}")).body(Body::empty()).unwrap()
}

pub fn with_bearer(path: &str, token: &str) -> Request<Body> {
    Request::get(path).header("authorization", format!("bearer {token}")).body(Body::empty()).unwrap()
}
