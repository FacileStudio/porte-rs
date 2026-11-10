use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use porte::directory::{Client, DirectoryError, Snapshot};
use porte::http_client::{HttpClient, HttpRequest, HttpResponse, Transport, TransportError};
use serde_json::{Map, Value, json};

use crate::common::vectors::{cases, load};

type Seen = (String, String, Option<String>, Option<String>);

struct Canned {
    status: u16,
    body: String,
    seen: Mutex<Option<Seen>>,
}

#[async_trait::async_trait]
impl Transport for Canned {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let header = |name: &str| request.headers().get(name).map(|v| v.to_str().unwrap().to_owned());
        let seen =
            (request.method().to_string(), request.uri().to_string(), header("authorization"), header("content-type"));
        *self.seen.lock().unwrap() = Some(seen);
        Ok(http::Response::builder().status(self.status).body(self.body.clone().into_bytes()).unwrap())
    }
}

fn view(snapshot: &Snapshot) -> Value {
    let raw = |map: &std::collections::HashMap<String, Value>| -> Map<String, Value> {
        map.iter().map(|(k, v)| (k.clone(), Value::from(v.to_string()))).collect()
    };
    let spaces: Vec<Value> = snapshot
        .spaces
        .iter()
        .map(|s| json!({ "entitlements": raw(&s.entitlements), "id": s.id, "members": s.members, "name": s.name }))
        .collect();
    let people: Vec<Value> =
        snapshot.people.iter().map(|p| json!({ "entitlements": raw(&p.entitlements), "sub": p.subject })).collect();
    json!({ "entitlements_revision": snapshot.entitlements_revision, "people": people, "spaces": spaces, "version": snapshot.version })
}

fn request_view(seen: Seen) -> Value {
    let basic = seen.2.unwrap().strip_prefix("Basic ").map(|b| String::from_utf8(STANDARD.decode(b).unwrap()).unwrap());
    let (user, password) = basic.as_deref().unwrap().split_once(':').unwrap();
    json!({ "basic_password": password, "basic_user": user, "content_type": seen.3, "method": seen.0, "url": seen.1 })
}

#[tokio::test]
async fn directory_snapshot_vector() {
    for case in cases(&load("directory_snapshot")) {
        let input = &case["input"];
        let mut body = input["body"].as_str().unwrap().to_owned();
        let pad = input["pad_to"].as_u64().unwrap_or(0) as usize;
        body.extend(std::iter::repeat_n(' ', pad.saturating_sub(body.len())));
        let canned =
            Arc::new(Canned { status: input["status"].as_u64().unwrap() as u16, body, seen: Mutex::new(None) });
        let client = Client {
            issuer: "https://sso.test/".into(),
            client_id: "app-client".into(),
            client_secret: "app-secret".into(),
            http: HttpClient::from_transport(canned.clone()),
        };
        let (error, snapshot) = match client.snapshot().await {
            Ok(snapshot) => (Value::Null, view(&snapshot)),
            Err(DirectoryError::TooLarge) => (json!("too_large"), Value::Null),
            Err(DirectoryError::Unavailable(_)) => (json!("unavailable"), Value::Null),
            Err(other) => (json!(other.to_string()), Value::Null),
        };
        let seen = canned.seen.lock().unwrap().take().unwrap();
        let got = json!({ "error": error, "request": request_view(seen), "snapshot": snapshot });
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}
