use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use porte::Config;
use porte::oidc::{ConfigExtra, Deps, Kit};
use porte::session::{self, Manager};
use serde_json::Value;

use super::idp::{ISSUER, fixture_client};
use super::memory::Sessions;
use super::stores::{Codes, Identities, Users};

pub struct App {
    pub router: Router,
    pub manager: Manager,
    pub sessions: Arc<Sessions>,
}

pub fn config_from(env: &Value) -> Config {
    let text = |key: &str| env[key].as_str().unwrap_or_default().to_owned();
    Config {
        issuer: text("OIDC_ISSUER"),
        client_id: text("OIDC_CLIENT_ID"),
        client_secret: text("OIDC_CLIENT_SECRET"),
        redirect_url: text("OIDC_REDIRECT_URL"),
        success_url: text("OIDC_SUCCESS_URL"),
        sso_only: text("SSO_ONLY") == "true",
        machine_audience: text("OIDC_MACHINE_AUDIENCE"),
        scope_prefix: text("OIDC_SCOPE_PREFIX"),
        cli_audience: text("OIDC_CLI_AUDIENCE"),
        ..Config::default()
    }
}

pub fn oidc_env(extra: &[(&str, &str)]) -> Value {
    let mut env: HashMap<&str, &str> = HashMap::from([
        ("OIDC_ISSUER", ISSUER),
        ("OIDC_CLIENT_ID", "app-client"),
        ("OIDC_CLIENT_SECRET", "conformance-secret"),
        ("OIDC_REDIRECT_URL", "https://app.test/api/auth/oidc/callback"),
        ("OIDC_SUCCESS_URL", "https://app.test/"),
    ]);
    env.extend(extra.iter().copied());
    serde_json::to_value(env).unwrap()
}

pub async fn app(env: &Value, extra: Option<ConfigExtra>) -> App {
    let cfg = config_from(env);
    let sessions = Arc::new(Sessions::default());
    let manager = Manager::new(&cfg, session::Deps { sessions: sessions.clone(), now: None });
    let deps = Deps {
        users: Arc::new(Users::default()),
        identities: Arc::new(Identities::with(ISSUER, "subject-1", 7)),
        codes: Arc::new(Codes::default()),
        sessions: manager.clone(),
        config_extra: extra,
        http: Some(fixture_client()),
        now: None,
    };
    let kit = Kit::new(&cfg, deps).await.unwrap();
    App { router: manager.routes().merge(kit.routes()), manager, sessions }
}
