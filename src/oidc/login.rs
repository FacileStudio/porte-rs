use axum::extract::Request;
use axum::response::Response;

use super::Kit;
use super::failure::{fail, redirect};
use super::flow::{FLOW_COOKIE, FLOW_TTL_SECONDS, Flow, cli_state, loopback_port, pkce_challenge};
use crate::new_token;
use crate::query::encode_sorted;
use crate::session::append_cookies;

const START_FAILED: &str = "could not start the login";

impl Kit {
    pub(crate) fn login(&self, request: Request) -> Response {
        let query = query_pairs(request.uri());
        let param = |key: &str| query.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).unwrap_or_default();
        let (Ok(state), Ok(nonce), Ok(verifier)) = (new_token(), new_token(), new_token()) else {
            return fail(self.config(), START_FAILED);
        };
        let mut flow = Flow { state, nonce, verifier, ..Flow::default() };
        match param("flow").as_str() {
            "cli" => {
                flow.cli = true;
                flow.port = loopback_port(&param("port"));
                flow.cli_state = cli_state(&param("cli_state"));
            }
            "mobile" => return fail(self.config(), START_FAILED),
            _ => {}
        }
        let mut response = redirect(&self.authorize_url(&flow, &param("ui_locales")));
        let cookie = self.sessions().set_cookie(&request, FLOW_COOKIE, &flow.encode(), FLOW_TTL_SECONDS);
        append_cookies(response.headers_mut(), [cookie]);
        response
    }

    fn authorize_url(&self, flow: &Flow, ui_locales: &str) -> String {
        let cfg = self.config();
        let mut params = vec![
            ("response_type".to_owned(), "code".to_owned()),
            ("client_id".to_owned(), cfg.client_id.clone()),
            ("redirect_uri".to_owned(), cfg.redirect_url.clone()),
            ("scope".to_owned(), cfg.scopes().join(" ")),
            ("state".to_owned(), flow.state.clone()),
            ("code_challenge".to_owned(), pkce_challenge(&flow.verifier)),
            ("code_challenge_method".to_owned(), "S256".to_owned()),
            ("nonce".to_owned(), flow.nonce.clone()),
        ];
        let tag = ui_locales.trim().to_ascii_lowercase();
        if !tag.is_empty() && crate::normalize_locale(&tag) == tag {
            params.push(("ui_locales".to_owned(), tag));
        }
        let endpoint = self.provider().map(|p| p.authorization_endpoint.as_str()).unwrap_or_default();
        let separator = if endpoint.contains('?') { '&' } else { '?' };
        format!("{endpoint}{separator}{}", encode_sorted(&params))
    }
}

pub(crate) fn query_pairs(uri: &http::Uri) -> Vec<(String, String)> {
    let query = uri.query().unwrap_or_default();
    url::form_urlencoded::parse(query.as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
}
