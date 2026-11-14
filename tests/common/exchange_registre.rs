use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use porte::http_client::{HttpRequest, HttpResponse, Transport, TransportError};

use super::exchange::{CLIENT_ID, ISSUER, SECRET};

#[derive(Default)]
pub struct Ledger {
    pub refresh: HashSet<String>,
    pub access: HashSet<String>,
    pub serial: u64,
}

impl Ledger {
    pub fn mint(&mut self, prefix: &str, access: bool) -> String {
        self.serial += 1;
        let value = format!("{prefix}-{}", self.serial);
        let set = if access { &mut self.access } else { &mut self.refresh };
        set.insert(value.clone());
        value
    }
}

#[derive(Default)]
pub struct Registre {
    pub ledger: Mutex<Ledger>,
    pub refreshes: AtomicI32,
    pub exchanges: AtomicI32,
    pub in_flight: AtomicI32,
    pub overlapping: AtomicBool,
    pub down: AtomicBool,
    pub exchange_answer: Mutex<Option<(u16, String)>>,
}

pub fn reply(status: u16, body: serde_json::Value) -> HttpResponse {
    http::Response::builder().status(status).body(body.to_string().into_bytes()).unwrap()
}

impl Registre {
    pub fn seed(&self) -> String {
        self.ledger.lock().unwrap().mint("rt", false)
    }

    pub fn revoke_access(&self) {
        self.ledger.lock().unwrap().access.clear();
    }

    pub async fn rotate(&self, used: &str) -> HttpResponse {
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        if self.in_flight.fetch_add(1, Ordering::SeqCst) > 0 {
            self.overlapping.store(true, Ordering::SeqCst);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        let mut ledger = self.ledger.lock().unwrap();
        if !ledger.refresh.remove(used) {
            return reply(400, serde_json::json!({"error": "invalid_grant"}));
        }
        let (access, refresh) = (ledger.mint("at", true), ledger.mint("rt", false));
        reply(200, serde_json::json!({"access_token": access, "refresh_token": refresh, "expires_in": 900}))
    }

    pub fn exchange(&self, form: &HashMap<String, String>) -> HttpResponse {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        if let Some((status, body)) = self.exchange_answer.lock().unwrap().clone() {
            return http::Response::builder().status(status).body(body.into_bytes()).unwrap();
        }
        let mut ledger = self.ledger.lock().unwrap();
        if !ledger.access.contains(&form["subject_token"]) {
            return reply(400, serde_json::json!({"error": "invalid_grant"}));
        }
        assert_eq!(form["subject_token_type"], "urn:ietf:params:oauth:token-type:access_token");
        let granted: &[&str] = match form["audience"].as_str() {
            "bulle" => &["bulle.read", "bulle.write"],
            "courrier" => &["courrier.read"],
            _ => return reply(400, serde_json::json!({"error": "invalid_target"})),
        };
        if form["scope"].split_whitespace().any(|scope| !granted.contains(&scope)) {
            return reply(400, serde_json::json!({"error": "invalid_scope"}));
        }
        ledger.serial += 1;
        let token = format!("x-{}-{}", form["audience"], ledger.serial);
        reply(200, serde_json::json!({"access_token": token, "expires_in": 300}))
    }
}

#[async_trait::async_trait]
impl Transport for Registre {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let uri = request.uri().to_string();
        if uri == format!("{ISSUER}/.well-known/openid-configuration") {
            return Ok(reply(200, serde_json::json!({"token_endpoint": format!("{ISSUER}/oauth/token")})));
        }
        assert_eq!(uri, format!("{ISSUER}/oauth/token"));
        if self.down.load(Ordering::SeqCst) {
            return Ok(reply(502, serde_json::json!({})));
        }
        let basic = format!("Basic {}", STANDARD.encode(format!("{CLIENT_ID}:{SECRET}")));
        if request.headers().get(http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some(&basic) {
            return Ok(reply(401, serde_json::json!({"error": "invalid_client"})));
        }
        let form: HashMap<String, String> = url::form_urlencoded::parse(request.body()).into_owned().collect();
        Ok(match form["grant_type"].as_str() {
            "refresh_token" => self.rotate(&form["refresh_token"]).await,
            "urn:ietf:params:oauth:grant-type:token-exchange" => self.exchange(&form),
            _ => reply(400, serde_json::json!({"error": "unsupported_grant_type"})),
        })
    }
}
