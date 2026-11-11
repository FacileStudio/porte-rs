use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use porte::http_client::{HttpRequest, HttpResponse, TransportError};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::provider::{CLIENT_ID, ISSUER, Provider, SECRET};
use super::sign::{now, sign};

impl Provider {
    pub fn token(&self, request: &HttpRequest) -> HttpResponse {
        let basic = request.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default();
        let expected = format!("Basic {}", STANDARD.encode(format!("{CLIENT_ID}:{SECRET}")));
        if basic != expected {
            return answer(401, json!({ "error": "invalid_client" }));
        }
        let form: HashMap<String, String> = url::form_urlencoded::parse(request.body()).into_owned().collect();
        self.state.lock().unwrap().token_requests += 1;
        match form.get("grant_type").map(String::as_str) {
            Some("authorization_code") => self.code_grant(&form),
            Some("refresh_token") if form.get("refresh_token").is_some_and(|t| t == "refresh-token") => {
                answer(200, self.tokens(None))
            }
            _ => answer(400, json!({ "error": "invalid_grant" })),
        }
    }

    fn code_grant(&self, form: &HashMap<String, String>) -> HttpResponse {
        let issued = self.state.lock().unwrap().codes.remove(form.get("code").map(String::as_str).unwrap_or_default());
        let Some(issued) = issued else { return answer(400, json!({ "error": "invalid_grant" })) };
        let verifier = form.get("code_verifier").cloned().unwrap_or_default();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        if challenge != issued.challenge || form.get("redirect_uri") != Some(&issued.redirect_uri) {
            return answer(400, json!({ "error": "invalid_grant", "error_description": "PKCE or redirect mismatch" }));
        }
        answer(200, self.tokens(Some(issued.nonce)))
    }

    fn tokens(&self, nonce: Option<String>) -> Value {
        let state = self.state.lock().unwrap();
        let mut claims = json!({
            "iss": ISSUER, "sub": state.subject, "aud": CLIENT_ID, "exp": now() + 600, "iat": now(),
            "email": state.email, "name": state.name, "email_verified": state.email_verified,
        });
        if let Some(nonce) = state.nonce_override.clone().or(nonce) {
            claims["nonce"] = Value::from(nonce);
        }
        if let Some(roles) = &state.roles {
            claims["roles"] = json!(roles);
        }
        let access = sign(&json!({ "iss": ISSUER, "sub": state.subject, "aud": CLIENT_ID, "exp": now() + 600 }));
        json!({ "access_token": access, "token_type": "Bearer", "refresh_token": "refresh-token",
                "expires_in": 600, "id_token": sign(&claims) })
    }

    pub fn keys(&self) -> Result<HttpResponse, TransportError> {
        let mut state = self.state.lock().unwrap();
        state.key_fetches += 1;
        match state.keys_down {
            true => Err(TransportError("the JWKS endpoint is down".into())),
            false => Ok(answer(200, state.jwks.clone())),
        }
    }

    pub fn userinfo(&self, request: &HttpRequest) -> HttpResponse {
        if !request
            .headers()
            .get("authorization")
            .is_some_and(|v| v.to_str().unwrap_or_default().starts_with("Bearer "))
        {
            return answer(401, json!({ "error": "invalid_token" }));
        }
        let state = self.state.lock().unwrap();
        let subject = state.userinfo_subject.clone().unwrap_or_else(|| state.subject.clone());
        answer(200, json!({ "sub": subject, "email": state.email, "name": "Renamed User", "email_verified": true }))
    }
}

pub fn answer(status: u16, body: Value) -> HttpResponse {
    let response = http::Response::builder().status(status).header("content-type", "application/json");
    response.body(serde_json::to_vec(&body).unwrap()).unwrap()
}
