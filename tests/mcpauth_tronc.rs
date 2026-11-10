#![cfg(feature = "mcp")]

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::mcp::{APP_AUDIENCE, Broken, known, mint, verifier};
use serde_json::json;
use tronc::mcp::{EXTRA_ACTOR, EXTRA_CLIENT_ID, TokenInfo, Verifier, VerifyError};

async fn through_tronc(verifier: &dyn Verifier, token: &str) -> Result<TokenInfo, VerifyError> {
    let (parts, ()) = http::Request::new(()).into_parts();
    verifier.verify(token, &parts).await
}

#[tokio::test]
async fn tronc_sees_the_account_scopes_expiry_client_and_actor() {
    let exp = common::sign::now() + 600;
    let token = mint(json!({ "aud": APP_AUDIENCE, "client_id": "bulle", "act": { "sub": "bulle" }, "exp": exp }));
    let info = through_tronc(&verifier(known()).await, &token).await.unwrap();
    assert_eq!(info.user_id, "42");
    assert_eq!(info.scopes, vec!["courrier.read"]);
    assert_eq!(info.expires_at, Some(SystemTime::UNIX_EPOCH + Duration::from_secs(exp.unsigned_abs())));
    assert_eq!(info.extra.get(EXTRA_CLIENT_ID).map(String::as_str), Some("bulle"));
    assert_eq!(info.extra.get(EXTRA_ACTOR).map(String::as_str), Some("bulle"));
    assert_eq!(info.extra.len(), 2);
}

#[tokio::test]
async fn tronc_sees_a_refusal_as_invalid_and_a_store_failure_as_unavailable() {
    let refused = through_tronc(&verifier(known()).await, "garbage").await;
    assert!(matches!(refused, Err(VerifyError::Invalid)));
    let broken = through_tronc(&verifier(Arc::new(Broken)).await, &mint(json!({}))).await;
    assert!(matches!(broken, Err(VerifyError::Unavailable)));
}
