use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use super::{Client, DirectoryError};
use crate::rs256::{PublicKey, jwk_key};

const REFETCH_GAP: Duration = Duration::from_secs(60);
const MAX_KEY_DOCUMENT: usize = 1 << 20;

#[derive(Default)]
pub(crate) struct KeySet {
    keys: RwLock<(HashMap<String, PublicKey>, Option<Instant>)>,
    fetch: Mutex<()>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Document {
    keys: Vec<Jwk>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Jwk {
    kty: String,
    #[serde(rename = "use")]
    usage: String,
    alg: String,
    kid: String,
    n: String,
    e: String,
}

pub(crate) enum Lookup {
    Found(PublicKey),
    Unknown,
}

impl KeySet {
    pub(crate) async fn lookup(&self, client: &Client, kid: &str) -> Result<Lookup, DirectoryError> {
        if let Some(key) = self.keys.read().await.0.get(kid) {
            return Ok(Lookup::Found(key.clone()));
        }
        let _fetching = self.fetch.lock().await;
        let fetched = {
            let cached = self.keys.read().await;
            if let Some(key) = cached.0.get(kid) {
                return Ok(Lookup::Found(key.clone()));
            }
            cached.1
        };
        if fetched.is_some_and(|at| at.elapsed() < REFETCH_GAP) {
            return Err(DirectoryError::Unavailable("unknown kid, keys fetched less than a minute ago".into()));
        }
        let keys = fetch_keys(client).await;
        let mut cache = self.keys.write().await;
        cache.1 = Some(Instant::now());
        cache.0 = keys?;
        Ok(cache.0.get(kid).cloned().map_or(Lookup::Unknown, Lookup::Found))
    }
}

async fn fetch_keys(client: &Client) -> Result<HashMap<String, PublicKey>, DirectoryError> {
    let issuer = client.issuer.trim_end_matches('/');
    let discovery: Discovery = get_json(client, &format!("{issuer}/.well-known/openid-configuration")).await?;
    if discovery.issuer.trim_end_matches('/') != issuer {
        return Err(DirectoryError::Unavailable(format!("discovery names issuer {:?}", discovery.issuer)));
    }
    if !discovery.jwks_uri.starts_with("https://") && !client.issuer.starts_with("http://") {
        return Err(DirectoryError::Unavailable(format!("jwks_uri {:?} is not https", discovery.jwks_uri)));
    }
    let document: Document = get_json(client, &discovery.jwks_uri).await?;
    let usable = |jwk: &Jwk| {
        jwk.kty == "RSA" && (jwk.usage.is_empty() || jwk.usage == "sig") && (jwk.alg.is_empty() || jwk.alg == "RS256")
    };
    Ok(document
        .keys
        .iter()
        .filter(|jwk| usable(jwk))
        .filter_map(|jwk| Some((jwk.kid.clone(), jwk_key(&jwk.n, &jwk.e)?)))
        .collect())
}

async fn get_json<T: serde::de::DeserializeOwned>(client: &Client, url: &str) -> Result<T, DirectoryError> {
    let unavailable = |reason: String| DirectoryError::Unavailable(format!("{url}: {reason}"));
    let response = client.http.get(url).await.map_err(|error| unavailable(error.to_string()))?;
    if response.status() != http::StatusCode::OK {
        return Err(unavailable(format!("answered {}", response.status().as_u16())));
    }
    if response.body().len() > MAX_KEY_DOCUMENT {
        return Err(unavailable("body too large".into()));
    }
    tronc::json::decode(response.body(), MAX_KEY_DOCUMENT).map_err(|error| unavailable(error.message))
}
