use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use porte::http_client::{HttpClient, HttpRequest, HttpResponse, Transport, TransportError};
use serde_json::{Value, json};

use super::provider_endpoints::answer;
use super::sign::{jwks, merge, now, sign};

pub const ISSUER: &str = "https://idp.test";
pub const CLIENT_ID: &str = "app-client";
pub const SECRET: &str = "app-secret";
pub const REDIRECT: &str = "https://app.test/api/auth/oidc/callback";

#[derive(Clone)]
pub struct AuthRequest {
    pub nonce: String,
    pub challenge: String,
    pub redirect_uri: String,
}

pub struct State {
    pub codes: HashMap<String, AuthRequest>,
    pub scopes_supported: Vec<String>,
    pub subject: String,
    pub email: String,
    pub name: String,
    pub email_verified: Option<Value>,
    pub roles: Option<Vec<String>>,
    pub userinfo_subject: Option<String>,
    pub nonce_override: Option<String>,
    pub token_requests: usize,
}

#[derive(Clone)]
pub struct Provider {
    pub state: Arc<Mutex<State>>,
}

impl Provider {
    pub fn new() -> Self {
        let scopes = ["openid", "email", "profile", "offline_access", "facile"].map(String::from).to_vec();
        let state = State {
            codes: HashMap::new(),
            scopes_supported: scopes,
            subject: "subject-1".into(),
            email: "user@example.test".into(),
            name: "Test User".into(),
            email_verified: Some(Value::Bool(true)),
            roles: None,
            userinfo_subject: None,
            nonce_override: None,
            token_requests: 0,
        };
        Provider { state: Arc::new(Mutex::new(state)) }
    }

    pub fn client(&self) -> HttpClient {
        HttpClient::from_transport(Arc::new(self.clone()))
    }

    pub fn authorize(&self, location: &str) -> String {
        let url = url::Url::parse(location).unwrap();
        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(query["client_id"], CLIENT_ID);
        assert_eq!(query["code_challenge_method"], "S256");
        let code = porte::new_token().unwrap();
        let request = AuthRequest {
            nonce: query["nonce"].clone(),
            challenge: query["code_challenge"].clone(),
            redirect_uri: query["redirect_uri"].clone(),
        };
        self.state.lock().unwrap().codes.insert(code.clone(), request);
        format!("/auth/oidc/callback?code={code}&state={}", query["state"])
    }

    pub fn access_token(&self, audience: &str, extra: Value) -> String {
        let subject = self.state.lock().unwrap().subject.clone();
        let mut claims = json!({ "iss": ISSUER, "sub": subject, "aud": audience, "exp": now() + 600, "iat": now() });
        merge(&mut claims, extra);
        sign(&claims)
    }

    pub fn logout_token(&self, extra: Value) -> String {
        let subject = self.state.lock().unwrap().subject.clone();
        let mut claims = json!({
            "iss": ISSUER, "sub": subject, "aud": CLIENT_ID, "iat": now(), "exp": now() + 120, "jti": "logout-1",
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        });
        merge(&mut claims, extra);
        sign(&claims)
    }

    fn discovery(&self) -> Value {
        json!({
            "issuer": ISSUER, "authorization_endpoint": format!("{ISSUER}/authorize"),
            "token_endpoint": format!("{ISSUER}/token"), "userinfo_endpoint": format!("{ISSUER}/userinfo"),
            "jwks_uri": format!("{ISSUER}/keys"), "response_types_supported": ["code"],
            "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": self.state.lock().unwrap().scopes_supported,
        })
    }
}

#[async_trait::async_trait]
impl Transport for Provider {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let url = request.uri().to_string();
        match url.strip_prefix(ISSUER) {
            Some("/.well-known/openid-configuration") => Ok(answer(200, self.discovery())),
            Some("/keys") => Ok(answer(200, jwks())),
            Some("/token") => Ok(self.token(&request)),
            Some("/userinfo") => Ok(self.userinfo(&request)),
            _ => Err(TransportError(format!("no route to {url}"))),
        }
    }
}
