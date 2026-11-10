use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

/// A token or a segment that does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

#[derive(Default, Deserialize)]
#[serde(default)]
pub(crate) struct Header {
    pub(crate) alg: String,
    pub(crate) kid: String,
    pub(crate) typ: Option<serde_json::Value>,
}

pub(crate) struct Token {
    pub(crate) header: Header,
    pub(crate) payload: Vec<u8>,
    pub(crate) signing_input: String,
    pub(crate) signature: String,
}

pub(crate) fn split(raw: &str) -> Result<Token, Malformed> {
    let parts: Vec<&str> = raw.split('.').collect();
    let [header, payload, signature] = parts.as_slice() else { return Err(Malformed) };
    let header_bytes = URL_SAFE_NO_PAD.decode(header).map_err(|_| Malformed)?;
    let header: Header = decode_object(&header_bytes)?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| Malformed)?;
    Ok(Token {
        header,
        payload: payload_bytes,
        signing_input: format!("{}.{}", parts[0], parts[1]),
        signature: (*signature).to_owned(),
    })
}

pub(crate) fn decode_object<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Malformed> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Malformed)?;
    if !(value.is_object() || value.is_null()) {
        return Err(Malformed);
    }
    tronc::json::decode(bytes, usize::MAX).map_err(|_| Malformed)
}

pub(crate) fn audience(value: Option<serde_json::Value>) -> Result<Vec<String>, Malformed> {
    match value {
        None => Ok(Vec::new()),
        Some(serde_json::Value::Null) => Ok(vec![String::new()]),
        Some(serde_json::Value::String(one)) => Ok(vec![one]),
        Some(many) => serde_json::from_value(many).map_err(|_| Malformed),
    }
}
