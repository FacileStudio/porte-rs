use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use super::JwtError;

#[derive(Default, Deserialize)]
#[serde(default)]
pub(crate) struct Header {
    pub(crate) alg: String,
    pub(crate) kid: String,
}

pub(crate) struct Token {
    pub(crate) header: Header,
    pub(crate) payload: Vec<u8>,
    pub(crate) signing_input: String,
    pub(crate) signature: String,
}

pub(crate) fn split(raw: &str) -> Result<Token, JwtError> {
    let parts: Vec<&str> = raw.split('.').collect();
    let [header, payload, signature] = parts.as_slice() else { return Err(JwtError::Malformed) };
    let header_bytes = URL_SAFE_NO_PAD.decode(header).map_err(|_| JwtError::Malformed)?;
    let header: Header = decode_object(&header_bytes)?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| JwtError::Malformed)?;
    Ok(Token {
        header,
        payload: payload_bytes,
        signing_input: format!("{}.{}", parts[0], parts[1]),
        signature: (*signature).to_owned(),
    })
}

pub(crate) fn decode_object<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, JwtError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| JwtError::Malformed)?;
    if !(value.is_object() || value.is_null()) {
        return Err(JwtError::Malformed);
    }
    tronc::json::decode(bytes, usize::MAX).map_err(|_| JwtError::Malformed)
}
