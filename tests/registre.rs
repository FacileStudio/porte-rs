#![cfg(feature = "oidc")]

mod common;

use std::sync::Arc;

use common::memory::Sessions;
use common::stores::{Codes, Identities, Users};
use porte::oidc::{Deps, Kit};
use porte::session::{self, Manager};
use porte::{Config, routes};

#[tokio::test]
async fn the_kit_boots_against_a_live_registre() {
    let Ok(issuer) = std::env::var("REGISTRE_ISSUER_URL") else {
        eprintln!("REGISTRE_ISSUER_URL unset; point it at a running Registre, e.g. https://sso.facile.studio");
        return;
    };
    let cfg = Config {
        issuer,
        client_id: "discovery-probe".into(),
        client_secret: "unused-discovery-does-not-authenticate".into(),
        redirect_url: "https://app.test/api/auth/oidc/callback".into(),
        success_url: "https://app.test/".into(),
        claims_scope: "roles".into(),
        ..Config::default()
    };
    let manager = Manager::new(&cfg, session::Deps { sessions: Arc::new(Sessions::default()), now: None });
    let deps = Deps {
        users: Arc::new(Users::default()),
        identities: Arc::new(Identities::default()),
        codes: Arc::new(Codes::default()),
        sessions: manager,
        config_extra: None,
        http: None,
        now: None,
    };
    let kit = Kit::new(&cfg, deps).await.unwrap_or_else(|error| panic!("discovery against {}: {error}", cfg.issuer));
    assert!(kit.enabled());
    let router: axum::Router = kit.routes();
    let login = http::Request::get(routes::LOGIN).body(axum::body::Body::empty()).unwrap();
    let answer = common::http::send(router, login).await;
    assert_eq!(answer.status, 302);
    assert!(answer.header("location").unwrap().starts_with(&format!("{}/authorize?", cfg.issuer)));
}
