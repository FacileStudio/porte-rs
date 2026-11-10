//! Tokens: minting, hashing and constant-time comparison.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const TOKEN_BYTES: usize = 32;

/// Mints a credential: 32 bytes from the OS random source, base64url without padding (43
/// characters). Every session token, login code and flow secret porte issues comes from here.
pub fn new_token() -> Result<String, getrandom::Error> {
    let mut buffer = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut buffer)?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

/// The stored form of a token: lowercase hex SHA-256, the encoding Go porte and every suite app
/// already use.
pub fn hash_token(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// Constant-time string comparison. Strings of different lengths compare unequal.
pub fn secure_compare(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
