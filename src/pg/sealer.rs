use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use sha2::Sha256;

use super::secret::{SECRET_SIZE, decode_secret};
use crate::ConfigError;

const SEALED_PREFIX: &str = "pv1:";
const SEAL_INFO: &[u8] = b"porte/pg token sealing v1";
const SEAL_AAD: &[u8] = b"porte/pg identity token";
const NONCE_SIZE: usize = 12;

/// A sealed token no key opens: wrong key, tampered, or no sealer configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("porte/pg: sealed token is unreadable")]
pub struct TokenUnreadable;

/// Seals OIDC tokens at rest as Go `pg.TokenSealer` does: AES-256-GCM with a random 12-byte
/// nonce, the key from HKDF-SHA256 over a 32-byte secret, stored as `pv1:` +
/// base64url(nonce || ciphertext || tag). It seals with the first secret and opens with all.
pub struct TokenSealer {
    ciphers: Vec<Aes256Gcm>,
}

impl TokenSealer {
    /// A sealer over raw 32-byte secrets, newest first.
    pub fn new(secrets: &[[u8; SECRET_SIZE]]) -> Result<Self, ConfigError> {
        if secrets.is_empty() {
            return Err(ConfigError::new("a token sealer needs at least one secret"));
        }
        let ciphers = secrets.iter().map(derive).collect::<Result<_, _>>()?;
        Ok(TokenSealer { ciphers })
    }

    /// Parses `PORTE_TOKEN_KEY`: empty is `None` (sealing off), otherwise comma-separated
    /// secrets, newest first, each 32 bytes as hex or standard base64.
    pub fn parse(spec: &str) -> Result<Option<Self>, ConfigError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Ok(None);
        }
        let secrets = spec.split(',').map(|part| decode_secret(part.trim())).collect::<Result<Vec<_>, _>>()?;
        TokenSealer::new(&secrets).map(Some)
    }

    /// Seals a token. An empty token stays empty.
    pub fn seal(&self, plain: &str) -> Result<String, getrandom::Error> {
        if plain.is_empty() {
            return Ok(String::new());
        }
        let mut nonce = [0u8; NONCE_SIZE];
        getrandom::fill(&mut nonce)?;
        let payload = Payload { msg: plain.as_bytes(), aad: SEAL_AAD };
        let sealed = self.ciphers[0].encrypt(&Nonce::from(nonce), payload).unwrap_or_default();
        Ok(format!("{SEALED_PREFIX}{}", URL_SAFE_NO_PAD.encode([nonce.as_slice(), &sealed].concat())))
    }

    /// Opens a stored value. Anything without the `pv1:` prefix is returned as plaintext.
    pub fn open(&self, stored: &str) -> Result<String, TokenUnreadable> {
        open(Some(self), stored).map(|(plain, _)| plain)
    }
}

pub(crate) fn open(sealer: Option<&TokenSealer>, stored: &str) -> Result<(String, bool), TokenUnreadable> {
    let Some(body) = stored.strip_prefix(SEALED_PREFIX) else { return Ok((stored.to_owned(), false)) };
    let sealer = sealer.ok_or(TokenUnreadable)?;
    let raw = URL_SAFE_NO_PAD.decode(body).map_err(|_| TokenUnreadable)?;
    if raw.len() < NONCE_SIZE {
        return Err(TokenUnreadable);
    }
    let (nonce, text) = raw.split_at(NONCE_SIZE);
    let nonce = Nonce::try_from(nonce).map_err(|_| TokenUnreadable)?;
    sealer
        .ciphers
        .iter()
        .enumerate()
        .find_map(|(index, cipher)| {
            let opened = cipher.decrypt(&nonce, Payload { msg: text, aad: SEAL_AAD }).ok()?;
            Some((String::from_utf8_lossy(&opened).into_owned(), index == 0))
        })
        .ok_or(TokenUnreadable)
}

pub(crate) fn open_or_empty(sealer: Option<&TokenSealer>, stored: &str) -> String {
    open(sealer, stored).map(|(plain, _)| plain).unwrap_or_default()
}

pub(crate) fn seal(sealer: Option<&TokenSealer>, plain: &str) -> Result<String, getrandom::Error> {
    match sealer {
        Some(sealer) => sealer.seal(plain),
        None => Ok(plain.to_owned()),
    }
}

fn derive(secret: &[u8; SECRET_SIZE]) -> Result<Aes256Gcm, ConfigError> {
    let mut key = [0u8; SECRET_SIZE];
    Hkdf::<Sha256>::new(None, secret).expand(SEAL_INFO, &mut key).map_err(|_| ConfigError::new("derive token key"))?;
    Aes256Gcm::new_from_slice(&key).map_err(|_| ConfigError::new("token cipher"))
}
