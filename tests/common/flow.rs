use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use http::Request;
use porte::oidc::{Deps, Kit};
use porte::session::{self, Manager};
use porte::{Config, ConfigError, Identity};
use time::OffsetDateTime;

use super::http::{Answer, send};
use super::memory::Sessions;
use super::provider::{CLIENT_ID, ISSUER, Provider, REDIRECT, SECRET};
use super::stores::{Codes, Identities, Users};

pub struct Flow {
    pub provider: Provider,
    pub kit: Kit,
    pub manager: Manager,
    pub sessions: Arc<Sessions>,
    pub identities: Arc<Identities>,
    pub users: Arc<Users>,
    pub clock: Arc<Mutex<Option<OffsetDateTime>>>,
}

pub fn base_config() -> Config {
    Config {
        issuer: ISSUER.into(),
        client_id: CLIENT_ID.into(),
        client_secret: SECRET.into(),
        redirect_url: REDIRECT.into(),
        success_url: "https://app.test/".into(),
        ..Config::default()
    }
}

pub async fn harness(configure: impl FnOnce(&mut Config, &Provider)) -> Result<Flow, ConfigError> {
    let provider = Provider::new();
    let mut cfg = base_config();
    configure(&mut cfg, &provider);
    let sessions = Arc::new(Sessions::default());
    let manager = Manager::new(&cfg, session::Deps { sessions: sessions.clone(), now: None });
    let (identities, users) = (Arc::new(Identities::default()), Arc::new(Users::default()));
    let clock: Arc<Mutex<Option<OffsetDateTime>>> = Arc::default();
    let frozen = clock.clone();
    let deps = Deps {
        users: users.clone(),
        identities: identities.clone(),
        codes: Arc::new(Codes::default()),
        sessions: manager.clone(),
        config_extra: None,
        http: Some(provider.client()),
        now: Some(Arc::new(move || frozen.lock().unwrap().unwrap_or_else(OffsetDateTime::now_utc))),
    };
    let kit = Kit::new(&cfg, deps).await?;
    Ok(Flow { provider, kit, manager, sessions, identities, users, clock })
}

impl Flow {
    pub fn advance(&self, by: std::time::Duration) {
        let mut clock = self.clock.lock().unwrap();
        *clock = Some(clock.unwrap_or_else(OffsetDateTime::now_utc) + by);
    }

    pub fn router(&self) -> Router {
        let whoami = get(|me: Identity| async move { format!("{} {}", me.user_id, me.roles.join(",")) });
        let protected = Router::new().route("/whoami", whoami).route_layer(self.manager.require_auth());
        self.manager.routes().merge(self.kit.routes()).merge(protected)
    }

    pub async fn login(&self, browser: &mut Browser, query: &str) -> Answer {
        let start = browser.send(self, Request::get(format!("/auth/oidc{query}")).body(Body::empty()).unwrap()).await;
        assert_eq!(start.status, 302, "the login did not redirect: {}", start.body);
        let callback = self.provider.authorize(&start.header("location").unwrap());
        browser.send(self, Request::get(callback).body(Body::empty()).unwrap()).await
    }
}

#[derive(Default)]
pub struct Browser {
    pub cookies: BTreeMap<String, String>,
}

impl Browser {
    pub async fn send(&mut self, flow: &Flow, mut request: Request<Body>) -> Answer {
        if !self.cookies.is_empty() {
            let header = self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
            request.headers_mut().insert("cookie", header.parse().unwrap());
        }
        let answer = send(flow.router(), request).await;
        for cookie in answer.set_cookies().unwrap_or_default() {
            let (pair, attributes) = cookie.split_once(';').unwrap_or((&cookie, ""));
            let (name, value) = pair.split_once('=').unwrap();
            match attributes.contains("Max-Age=0") {
                true => self.cookies.remove(name),
                false => self.cookies.insert(name.to_owned(), value.to_owned()),
            };
        }
        answer
    }
}
