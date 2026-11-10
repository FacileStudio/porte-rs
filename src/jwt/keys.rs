use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use super::JwtError;
use super::discover::get_json;
use crate::Clock;
use crate::http_client::HttpClient;
use crate::rs256::{PublicKey, jwk_key};

const MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct KeySet {
    #[serde(default)]
    keys: Vec<Jwk>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Default)]
struct State {
    keys: Option<HashMap<String, PublicKey>>,
    fetched_at: Option<OffsetDateTime>,
    refetched_at: Option<OffsetDateTime>,
}

pub(crate) struct KeyCache {
    http: HttpClient,
    jwks_uri: String,
    ttl: Duration,
    now: Clock,
    state: Mutex<State>,
}

impl KeyCache {
    pub(crate) fn new(http: HttpClient, jwks_uri: String, ttl: Duration, now: Clock) -> Self {
        KeyCache { http, jwks_uri, ttl, now, state: Mutex::new(State::default()) }
    }

    pub(crate) async fn key(&self, kid: &str) -> Result<PublicKey, JwtError> {
        let mut state = self.state.lock().await;
        let now = (self.now)();
        let stale = state.keys.is_none() || state.fetched_at.is_none_or(|at| now - at >= self.ttl);
        if stale {
            self.fetch(&mut state).await?;
        }
        if let Some(key) = state.keys.as_ref().and_then(|keys| keys.get(kid)) {
            return Ok(key.clone());
        }
        if !stale && take_refetch_slot(&mut state, now) {
            self.fetch(&mut state).await?;
            if let Some(key) = state.keys.as_ref().and_then(|keys| keys.get(kid)) {
                return Ok(key.clone());
            }
        }
        Err(JwtError::UnknownKey(kid.to_owned()))
    }

    pub(crate) async fn candidates(&self, kid: &str) -> Result<Vec<PublicKey>, JwtError> {
        if !kid.is_empty() {
            return self.key(kid).await.map(|key| vec![key]);
        }
        let mut state = self.state.lock().await;
        if state.keys.is_none() {
            self.fetch(&mut state).await?;
        }
        Ok(state.keys.iter().flat_map(|keys| keys.values().cloned()).collect())
    }

    async fn fetch(&self, state: &mut State) -> Result<(), JwtError> {
        let set: KeySet = get_json(&self.http, &self.jwks_uri)
            .await
            .map_err(|error| JwtError::Fetch(format!("JWKS fetch failed: {error}")))?;
        let keys = set
            .keys
            .into_iter()
            .filter(|jwk| !jwk.kid.is_empty())
            .filter_map(|jwk| jwk_key(&jwk.n, &jwk.e).map(|key| (jwk.kid, key)))
            .collect();
        state.keys = Some(keys);
        state.fetched_at = Some((self.now)());
        Ok(())
    }
}

fn take_refetch_slot(state: &mut State, now: OffsetDateTime) -> bool {
    if state.refetched_at.is_some_and(|at| now - at < MIN_REFETCH_INTERVAL) {
        return false;
    }
    state.refetched_at = Some(now);
    true
}
