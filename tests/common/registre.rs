use std::sync::{Arc, Mutex};

use porte::directory::{Client, DirectoryError, IdentityEraser, PersonDeleted, StateStore};
use porte::http_client::{HttpClient, HttpRequest, HttpResponse, Transport, TransportError};
use serde_json::{Value, json};

use super::sign::jwks;

pub const ISSUER: &str = "https://sso.test";

#[derive(Default)]
pub struct Registre {
    pub deleted: Mutex<Vec<(String, String)>>,
    pub asked: Mutex<Vec<String>>,
    pub key_fetches: Mutex<usize>,
}

fn json_answer(body: Value) -> HttpResponse {
    http::Response::builder().status(200).body(serde_json::to_vec(&body).unwrap()).unwrap()
}

#[async_trait::async_trait]
impl Transport for Registre {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let url = request.uri().to_string();
        let path = url.strip_prefix(ISSUER).unwrap_or_default();
        if path == "/.well-known/openid-configuration" {
            return Ok(json_answer(json!({ "issuer": ISSUER, "jwks_uri": format!("{ISSUER}/keys") })));
        }
        if path == "/keys" {
            *self.key_fetches.lock().unwrap() += 1;
            return Ok(json_answer(jwks()));
        }
        self.asked.lock().unwrap().push(url.clone());
        let rows: Vec<Value> =
            self.deleted.lock().unwrap().iter().map(|(sub, at)| json!({ "sub": sub, "deleted_at": at })).collect();
        Ok(json_answer(json!({ "deleted": rows })))
    }
}

pub fn client(registre: &Arc<Registre>) -> Client {
    Client {
        issuer: ISSUER.into(),
        client_id: "app-client".into(),
        client_secret: "secret".into(),
        http: HttpClient::from_transport(registre.clone()),
    }
}

#[derive(Default)]
pub struct Erasures {
    pub calls: Mutex<Vec<String>>,
    pub refuse: Mutex<Option<String>>,
}

#[async_trait::async_trait]
impl PersonDeleted for Erasures {
    async fn on_person_deleted(&self, provider: &str, subject: &str) -> Result<(), DirectoryError> {
        if self.refuse.lock().unwrap().as_deref() == Some(subject) {
            return Err(DirectoryError::Failed("the app's store is down".into()));
        }
        self.calls.lock().unwrap().push(format!("app {provider} {subject}"));
        Ok(())
    }
}

#[async_trait::async_trait]
impl IdentityEraser for Erasures {
    async fn erase_identity(&self, provider: &str, subject: &str) -> Result<(), DirectoryError> {
        self.calls.lock().unwrap().push(format!("porte {provider} {subject}"));
        Ok(())
    }
}

#[derive(Default)]
pub struct Blob(pub Mutex<Vec<u8>>);

#[async_trait::async_trait]
impl StateStore for Blob {
    async fn load(&self) -> Result<Vec<u8>, DirectoryError> {
        Ok(self.0.lock().unwrap().clone())
    }

    async fn save(&self, state: &[u8]) -> Result<(), DirectoryError> {
        *self.0.lock().unwrap() = state.to_vec();
        Ok(())
    }
}
