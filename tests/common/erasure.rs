use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use http::Request;
use porte::directory::{DELETIONS_PATH, Deletions, DirectoryError, USER_DELETED_EVENT};
use serde_json::json;
use tower::ServiceExt;

use super::registre::{Blob, Erasures, ISSUER, Registre, client};
use super::sign::{KEY_ID, key, now, sign_with};

#[derive(Default)]
pub struct Accounts {
    pub held: Mutex<std::collections::HashSet<String>>,
    pub fail: Mutex<bool>,
}

impl Accounts {
    pub fn set(&self, subject: &str, held: bool) {
        let mut accounts = self.held.lock().unwrap();
        match held {
            true => accounts.insert(subject.to_owned()),
            false => accounts.remove(subject),
        };
    }
}

#[async_trait::async_trait]
impl porte::directory::IdentityHolder for Accounts {
    async fn holds_identity(&self, _: &str, subject: &str) -> Result<bool, DirectoryError> {
        if *self.fail.lock().unwrap() {
            return Err(DirectoryError::Failed("db is down".into()));
        }
        Ok(self.held.lock().unwrap().contains(subject))
    }
}

pub struct Setup {
    pub registre: Arc<Registre>,
    pub erasures: Arc<Erasures>,
    pub blob: Arc<Blob>,
    pub accounts: Arc<Accounts>,
}

impl Setup {
    pub fn new() -> Setup {
        Setup { registre: Arc::default(), erasures: Arc::default(), blob: Arc::default(), accounts: Arc::default() }
    }

    pub fn plain(&self) -> Deletions {
        let store = Some(self.blob.clone() as Arc<dyn porte::directory::StateStore>);
        Deletions::new(
            client(&self.registre),
            self.erasures.clone(),
            Some(self.erasures.clone()),
            store,
            Duration::ZERO,
        )
    }

    pub fn holding(&self) -> Deletions {
        self.plain().with_holds(self.accounts.clone())
    }

    pub fn calls(&self, prefix: &str, subject: &str) -> usize {
        let wanted = format!("{prefix} {ISSUER} {subject}");
        self.erasures.calls.lock().unwrap().iter().filter(|call| **call == wanted).count()
    }
}

pub fn notice(subject: &str) -> String {
    let header = json!({ "alg": "RS256", "typ": "secevent+jwt", "kid": KEY_ID });
    let claims = json!({ "iss": ISSUER, "aud": "app-client", "sub": subject, "iat": now(), "exp": now() + 300,
                         "events": { USER_DELETED_EVENT: {} } });
    sign_with(&key("idp_key.pem"), &header, &claims)
}

pub async fn push(deletions: &Deletions, token: &str) -> u16 {
    let app: Router = Router::new().route(DELETIONS_PATH, deletions.route());
    let request = Request::post(DELETIONS_PATH).body(Body::from(token.to_owned())).unwrap();
    app.oneshot(request).await.unwrap().status().as_u16()
}
