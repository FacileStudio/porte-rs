use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::ConfigError;

pub(crate) const SECRET_SIZE: usize = 32;

pub(crate) fn decode_secret(text: &str) -> Result<[u8; SECRET_SIZE], ConfigError> {
    let refused = || ConfigError::new(format!("a token secret must be {SECRET_SIZE} bytes as hex or base64"));
    if let Some(secret) = decode_hex(text) {
        return Ok(secret);
    }
    STANDARD.decode(text).ok().and_then(|bytes| bytes.try_into().ok()).ok_or_else(refused)
}

fn decode_hex(text: &str) -> Option<[u8; SECRET_SIZE]> {
    if text.len() != SECRET_SIZE * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> =
        (0..SECRET_SIZE).filter_map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()).collect();
    bytes.try_into().ok()
}
