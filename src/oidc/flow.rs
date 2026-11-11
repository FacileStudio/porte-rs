use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const FLOW_COOKIE: &str = "oidc_state";
pub(crate) const FLOW_TTL_SECONDS: i64 = 600;
const MAX_CLI_STATE: usize = 128;

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Flow {
    #[serde(rename = "s")]
    pub(crate) state: String,
    #[serde(rename = "n")]
    pub(crate) nonce: String,
    #[serde(rename = "v")]
    pub(crate) verifier: String,
    #[serde(rename = "c", skip_serializing_if = "std::ops::Not::not")]
    pub(crate) cli: bool,
    #[serde(rename = "p", skip_serializing_if = "String::is_empty")]
    pub(crate) port: String,
    #[serde(rename = "cs", skip_serializing_if = "String::is_empty")]
    pub(crate) cli_state: String,
}

impl Flow {
    pub(crate) fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).unwrap_or_default())
    }

    pub(crate) fn decode(value: &str) -> Option<Flow> {
        let payload = URL_SAFE_NO_PAD.decode(value).ok()?;
        let flow: Flow = tronc::json::decode(&payload, usize::MAX).ok()?;
        (!flow.state.is_empty() && !flow.verifier.is_empty() && !flow.nonce.is_empty()).then_some(flow)
    }
}

/// The S256 PKCE challenge of a verifier: unpadded base64url SHA-256.
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub(crate) fn cli_state(value: &str) -> String {
    let valid = !value.is_empty()
        && value.len() <= MAX_CLI_STATE
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if valid { value.to_owned() } else { String::new() }
}

pub(crate) fn loopback_port(value: &str) -> String {
    match value.parse::<i64>() {
        Ok(port) if (1024..=65535).contains(&port) => value.to_owned(),
        _ => String::new(),
    }
}
