use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::PrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use serde_json::{Value, json};
use sha2::Sha256;

pub const KEY_ID: &str = "conformance-key";

pub fn key(name: &str) -> PrivateKey {
    let path = format!("{}/tests/vectors/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    PrivateKey::from_pkcs8_pem(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub fn sign_with(key: &PrivateKey, header: &Value, claims: &Value) -> String {
    let segment = |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap());
    let input = format!("{}.{}", segment(header), segment(claims));
    let signature = SigningKey::<Sha256>::new(key.clone()).sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

pub fn sign(claims: &Value) -> String {
    sign_with(&key("idp_key.pem"), &json!({ "alg": "RS256", "kid": KEY_ID, "typ": "JWT" }), claims)
}

pub fn jwks() -> Value {
    super::vectors::load("jwt")["fixtures"]["jwks"].clone()
}

pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
