use std::sync::{Arc, Mutex};

use porte::exchange::{Config, Exchanger, Target};
use porte::http_client::HttpClient;
use porte::{StoredIdentity, TokenSet};
use time::OffsetDateTime;

pub use super::exchange_registre::Registre;
pub use super::exchange_store::Identities;

pub const ISSUER: &str = "https://sso.test";
pub const CLIENT_ID: &str = "nuage-client";
pub const SECRET: &str = "s3cret";

pub fn bulle() -> Target {
    Target::new("bulle", ["bulle.read", "bulle.write"])
}

pub fn courrier() -> Target {
    Target::new("courrier", ["courrier.read"])
}

pub struct Fixture {
    pub registre: Arc<Registre>,
    pub ids: Arc<Identities>,
    pub ex: Exchanger,
    pub now: Arc<Mutex<OffsetDateTime>>,
}

impl Fixture {
    pub fn advance(&self, by: time::Duration) {
        *self.now.lock().unwrap() += by;
    }
}

pub fn setup() -> Fixture {
    let registre = Arc::new(Registre::default());
    let ids = Arc::new(Identities::default());
    let row = StoredIdentity {
        user_id: 7,
        provider: ISSUER.into(),
        subject: "sub-7".into(),
        tokens: TokenSet { refresh_token: registre.seed(), ..TokenSet::default() },
        ..StoredIdentity::default()
    };
    ids.rows.lock().unwrap().insert(7, row);
    let now = Arc::new(Mutex::new(OffsetDateTime::now_utc()));
    let mut config = Config::new(format!("{ISSUER}/"), CLIENT_ID, SECRET, ids.clone());
    config.http = HttpClient::from_transport(registre.clone());
    config.clock = Arc::new({
        let now = now.clone();
        move || *now.lock().unwrap()
    });
    Fixture { registre, ids, ex: Exchanger::new(config).unwrap(), now }
}
