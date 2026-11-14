#![cfg(feature = "mcp")]

mod common;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::response::IntoResponse;
use axum::routing::post;
use common::harness::{Harness, harness, with_cookie};
use common::http::send;
use porte::mcpauth::require_own_session;
use porte::{CSRF_HEADER_NAME, Config, Identity, SESSION_COOKIE_NAME, Session};
use tronc::mcp::DELEGATED;

struct Page {
    harness: Harness,
    login: String,
    cli: String,
    named: String,
}

async fn page() -> Page {
    let harness = harness(Config::default());
    let (request, _) = Request::get("/").body(Body::empty()).unwrap().into_parts();
    let template = Session { user_id: 7, ..Session::default() };
    let (login, _, _) = harness.manager.issue_cookie_for(&request, template).await.unwrap();
    let (cli, _) = harness.manager.issue(7, "").await.unwrap();
    let (named, _) = harness.manager.issue(7, "agent").await.unwrap();
    Page { harness, login, cli, named }
}

impl Page {
    async fn confirm(&self, cookie: &str, authorization: &str) -> (u16, String) {
        let confirm = post(|request: Request| async move {
            match require_own_session(&request) {
                Ok(identity) => identity.user_id.to_string().into_response(),
                Err(error) => error.into_response(),
            }
        });
        let app = Router::new().route("/confirm", confirm).route_layer(self.harness.manager.require_auth());
        let mut request = Request::post("/confirm").header(CSRF_HEADER_NAME, "1");
        if !cookie.is_empty() {
            request = request.header("cookie", format!("{SESSION_COOKIE_NAME}={cookie}"));
        }
        if !authorization.is_empty() {
            request = request.header("authorization", authorization);
        }
        let answer = send(app, request.body(Body::empty()).unwrap()).await;
        (answer.status, answer.body)
    }
}

#[tokio::test]
async fn only_the_persons_browser_session_confirms() {
    let page = page().await;
    assert!(page.login.starts_with(porte::BROWSER_TOKEN_PREFIX), "{}", page.login);
    assert_eq!(page.confirm(&page.login, "").await, (200, "7".to_owned()));
    let refused = [
        ("the login session as a bearer", String::new(), format!("Bearer {}", page.login)),
        ("a named API token as a bearer", String::new(), format!("Bearer {}", page.named)),
        ("a CLI session as a bearer", String::new(), format!("Bearer {}", page.cli)),
        ("a named API token sent as a cookie", page.named.clone(), String::new()),
        ("a CLI exchange token sent as a cookie", page.cli.clone(), String::new()),
        ("a browser session with a bearer attached", page.login.clone(), format!("Bearer {}", page.named)),
    ];
    for (name, cookie, authorization) in refused {
        let (status, body) = page.confirm(&cookie, &authorization).await;
        assert_eq!(status, 403, "{name}: {body}");
        assert!(body.contains("permission_denied") && body.contains(DELEGATED), "{name}: {body}");
    }
}

#[tokio::test]
async fn the_browser_mark_cannot_be_forged_onto_a_cli_token() {
    let page = page().await;
    let forged = format!("{}{}", porte::BROWSER_TOKEN_PREFIX, page.cli);
    assert_eq!(page.confirm(&forged, "").await.0, 401);
}

#[tokio::test]
async fn an_unprefixed_cookie_still_signs_in_but_cannot_confirm() {
    let page = page().await;
    let whoami = send(page.harness.app(), with_cookie("/whoami", &page.cli)).await;
    assert_eq!((whoami.status, whoami.body.as_str()), (200, "7"));
    assert_eq!(page.confirm(&page.cli, "").await.0, 403);
}

fn own_session(identity: Identity) -> Result<Identity, tronc::Error> {
    let mut request = Request::post("/").body(Body::empty()).unwrap();
    request.extensions_mut().insert(identity);
    require_own_session(&request)
}

#[test]
fn every_other_caller_is_the_same_refusal() {
    let browser = Identity { user_id: 7, session_id: 3, browser_session: true, ..Identity::default() };
    assert_eq!(own_session(browser.clone()).unwrap(), browser);
    let cases = [
        (
            "a delegated JWT",
            Identity {
                user_id: 7,
                subject: "s".into(),
                actor: "bulle".into(),
                scopes: vec!["a.write".into()],
                ..Identity::default()
            },
        ),
        (
            "a machine token",
            Identity { subject: "suite-ci".into(), scopes: vec!["a.read".into()], ..Identity::default() },
        ),
        ("an MCP token", Identity { user_id: 7, subject: "s".into(), ..Identity::default() }),
        ("an opaque bearer session", Identity { user_id: 7, session_id: 3, ..Identity::default() }),
        ("an actor on a session", Identity { actor: "agent".into(), ..browser.clone() }),
        ("a subject on a session", Identity { subject: "s".into(), ..browser.clone() }),
        ("scopes on a session", Identity { scopes: vec!["a.write".into()], ..browser.clone() }),
        ("no session row", Identity { session_id: 0, ..browser.clone() }),
        ("no user", Identity { user_id: 0, ..browser.clone() }),
    ];
    for (name, identity) in cases {
        let refused = own_session(identity).unwrap_err();
        assert_eq!((refused.code.status().as_u16(), refused.message.as_str()), (403, DELEGATED), "{name}");
    }
}

#[test]
fn a_request_without_an_identity_is_unauthenticated() {
    let refused = require_own_session(&Request::post("/").body(Body::empty()).unwrap()).unwrap_err();
    assert_eq!((refused.code.status().as_u16(), refused.message.as_str()), (401, "missing auth"));
}
