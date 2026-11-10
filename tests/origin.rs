mod common;

use std::sync::Arc;

use axum::body::Body;
use common::memory::Sessions;
use http::Request;
use porte::Config;
use porte::session::{Deps, Manager};

fn manager(success_url: &str) -> Manager {
    let config = Config { success_url: success_url.into(), ..Config::default() };
    Manager::new(&config, Deps { sessions: Arc::new(Sessions::default()), now: None })
}

fn upgrade(cookie: Option<&str>, host: &str, origin: Option<&str>) -> Request<Body> {
    let mut builder = Request::get("/api/sheets/1/ws").header("host", host);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    builder.header("x-forwarded-proto", "https").body(Body::empty()).unwrap()
}

#[test]
fn a_cookie_upgrade_must_come_from_its_own_origin() {
    let manager = manager("https://feuilles.facile.studio/");
    let cookie = Some("__Host-session=abc");
    let host = "feuilles.facile.studio";
    assert!(manager.check_origin(&upgrade(cookie, host, Some("https://feuilles.facile.studio"))).is_ok());
    assert!(manager.check_origin(&upgrade(cookie, host, Some("https://evil.test"))).is_err());
    assert!(manager.check_origin(&upgrade(cookie, host, Some("http://feuilles.facile.studio"))).is_err());
    assert!(manager.check_origin(&upgrade(cookie, host, Some("https://feuilles.facile.studio.evil.test"))).is_err());
    assert!(manager.check_origin(&upgrade(cookie, host, Some("null"))).is_err());
    let missing = manager.check_origin(&upgrade(cookie, host, None)).unwrap_err();
    assert_eq!((missing.code.as_str(), missing.message.as_str()), ("permission_denied", "missing Origin header"));
}

#[test]
fn the_success_url_origin_is_accepted_behind_a_rewriting_proxy() {
    let manager = manager("https://feuilles.facile.studio/");
    let upgrade = upgrade(Some("__Host-session=abc"), "api:8080", Some("https://feuilles.facile.studio"));
    assert!(manager.check_origin(&upgrade).is_ok());
}

#[test]
fn a_bearer_upgrade_is_exempt_as_it_is_from_the_csrf_header() {
    let manager = manager("https://feuilles.facile.studio/");
    assert!(manager.check_origin(&upgrade(None, "feuilles.facile.studio", Some("https://evil.test"))).is_ok());
    assert!(manager.check_origin(&upgrade(Some("session=abc"), "feuilles.facile.studio", None)).is_ok());
}
