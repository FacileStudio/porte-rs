use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::Clock;
use crate::http_client::HttpClient;
use crate::jwt::discover::get_json;
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

type Keys = Arc<Vec<(String, PublicKey)>>;

/// Why a signature could not be checked against the provider's keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyError {
    /// No key verifies it, and the provider's current set was checked or recently refetched.
    Unverified,
    /// The provider's keys could not be fetched, so the signature may be valid under a key porte
    /// has not seen. Worth retrying.
    Fetch(String),
}

#[derive(Default)]
struct State {
    keys: Option<Keys>,
    generation: u64,
    refetched_at: Option<OffsetDateTime>,
    last_error: Option<String>,
}

/// The issuer's JWKS with go-oidc's `RemoteKeySet` rules: cached keys never expire, a signature
/// no cached key verifies triggers a refetch (at most every 30 s once a set is held), and a
/// failed refetch keeps the keys already held.
pub(crate) struct RemoteKeySet {
    http: HttpClient,
    jwks_uri: String,
    now: Clock,
    state: Mutex<State>,
}

impl RemoteKeySet {
    pub(crate) fn new(http: HttpClient, jwks_uri: String, now: Clock) -> Self {
        RemoteKeySet { http, jwks_uri, now, state: Mutex::new(State::default()) }
    }

    /// Checks an RS256 signature against the keys matching `kid`, or every key when `kid` is
    /// empty.
    pub(crate) async fn verify(&self, kid: &str, signing_input: &str, signature: &str) -> Result<(), KeyError> {
        let (held, generation) = {
            let state = self.state.lock().await;
            (state.keys.clone(), state.generation)
        };
        if held.as_ref().is_some_and(|keys| verifies(keys, kid, signing_input, signature)) {
            return Ok(());
        }
        let fresh = self.refresh(generation).await?;
        match verifies(&fresh, kid, signing_input, signature) {
            true => Ok(()),
            false => Err(KeyError::Unverified),
        }
    }

    async fn refresh(&self, seen: u64) -> Result<Keys, KeyError> {
        let mut state = self.state.lock().await;
        if let Some(keys) = state.keys.clone() {
            if state.generation != seen {
                return Ok(keys);
            }
            let now = (self.now)();
            if state.refetched_at.is_some_and(|at| now - at < MIN_REFETCH_INTERVAL) {
                return match &state.last_error {
                    Some(error) => Err(KeyError::Fetch(error.clone())),
                    None => Ok(keys),
                };
            }
            state.refetched_at = Some(now);
        }
        match self.fetch().await {
            Ok(keys) => {
                state.keys = Some(keys.clone());
                state.generation += 1;
                state.last_error = None;
                Ok(keys)
            }
            Err(error) => {
                state.last_error = Some(error.clone());
                Err(KeyError::Fetch(error))
            }
        }
    }

    async fn fetch(&self) -> Result<Keys, String> {
        let set: KeySet =
            get_json(&self.http, &self.jwks_uri).await.map_err(|error| format!("JWKS fetch failed: {error}"))?;
        let keys = set.keys.into_iter().filter_map(|jwk| jwk_key(&jwk.n, &jwk.e).map(|key| (jwk.kid, key))).collect();
        Ok(Arc::new(keys))
    }
}

fn verifies(keys: &[(String, PublicKey)], kid: &str, signing_input: &str, signature: &str) -> bool {
    keys.iter()
        .filter(|(key_id, _)| kid.is_empty() || key_id == kid)
        .any(|(_, key)| crate::rs256::verify(key, signing_input, signature))
}
