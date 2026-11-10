#![cfg(feature = "mcp")]

mod common;

use std::sync::Arc;

use common::mcp::{APP_AUDIENCE, Broken, RESOURCE, SUBJECT, config, known, mint, verifier};
use porte::mcpauth::{Verifier, VerifyError, identity, scopes_for, third_party};
use serde_json::json;

#[tokio::test]
async fn a_resource_bound_token_yields_the_local_account() {
    let info = verifier(known()).await.verify(&mint(json!({}))).await.unwrap();
    assert_eq!((info.user_id.as_str(), info.client_id.as_str(), info.subject.as_str()), ("42", "claude", SUBJECT));
    assert_eq!(info.scopes, vec!["courrier.read"]);
    assert!(third_party(Some(&info)));
    assert_eq!(identity(Some(&info)).unwrap().user_id, 42);
}

#[tokio::test]
async fn a_bulle_exchanged_token_is_accepted_and_first_party() {
    let token = mint(json!({ "aud": APP_AUDIENCE, "client_id": "bulle", "act": { "sub": "bulle" } }));
    let info = verifier(known()).await.verify(&token).await.unwrap();
    assert_eq!(info.actor, "bulle");
    assert!(!third_party(Some(&info)));
}

#[tokio::test]
async fn every_refused_token_is_the_same_invalid_token() {
    let verifier = verifier(known()).await;
    let refused = [
        mint(json!({ "aud": "https://other.example/mcp" })),
        mint(json!({ "aud": APP_AUDIENCE })),
        mint(json!({ "sub": "stranger" })),
        mint(json!({ "sub": null })),
        mint(json!({ "exp": common::sign::now() - 120 })),
        mint(json!({ "iss": "https://evil.test" })),
        "garbage".to_owned(),
    ];
    for token in refused {
        assert_eq!(verifier.verify(&token).await, Err(VerifyError::InvalidToken));
    }
}

#[tokio::test]
async fn a_store_failure_is_unavailable_not_an_invalid_token() {
    let verifier = verifier(Arc::new(Broken)).await;
    assert_eq!(verifier.verify(&mint(json!({}))).await, Err(VerifyError::Unavailable));
}

#[tokio::test]
async fn write_implies_read() {
    let info = verifier(known()).await.verify(&mint(json!({ "scope": "courrier.write" }))).await.unwrap();
    assert_eq!(info.scopes, vec!["courrier.write", "courrier.read"]);
    assert_eq!(scopes_for("courrier").list(), vec!["courrier.read", "courrier.write"]);
}

#[tokio::test]
async fn the_config_is_validated() {
    let invalid = [
        porte::mcpauth::Config { scope_prefix: "Courrier".into(), ..config(known()) },
        porte::mcpauth::Config { resource: format!("{RESOURCE}?x=1"), ..config(known()) },
        porte::mcpauth::Config { resource: "/mcp".into(), ..config(known()) },
        porte::mcpauth::Config { provision: true, ..config(known()) },
    ];
    for cfg in invalid {
        assert!(Verifier::new(cfg).await.is_err());
    }
}
