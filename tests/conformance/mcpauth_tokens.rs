use std::sync::Arc;

use porte::IdentityStore;
use porte::mcpauth::{Verifier, VerifyError};
use serde_json::{Value, json};

use crate::common::idp::ISSUER;
use crate::common::kit::{accounts, config_from, oidc_env};
use crate::common::mcp::{Broken, config};
use crate::common::scripted::ScriptedUsers;
use crate::common::sign::sign;
use crate::common::stores::Identities;
use crate::common::vectors::{cases, load};

#[tokio::test]
async fn mcpauth_tokens_vector() {
    let vector = load("mcpauth_tokens");
    for case in cases(&vector) {
        let input = &case["input"];
        let (verifier, users) = verifier(&vector["fixtures"], input).await;
        let got = match verifier.verify(&sign(&claims(&input["claims"]))).await {
            Ok(info) => json!({
                "outcome": "account", "user_id": info.user_id, "scopes": info.scopes, "subject": info.subject,
                "actor": info.actor, "provisionings": users.calls(),
            }),
            Err(VerifyError::InvalidToken) => {
                json!({ "outcome": "invalid_token", "message": VerifyError::InvalidToken.to_string(), "provisionings": users.calls() })
            }
            Err(VerifyError::Unavailable) => json!({ "outcome": "unavailable", "provisionings": users.calls() }),
        };
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}

async fn verifier(fixtures: &Value, input: &Value) -> (Verifier, Arc<ScriptedUsers>) {
    let known = fixtures["known_user_id"].as_i64().unwrap();
    let subject = fixtures["known_subject"].as_str().unwrap();
    let identities: Arc<dyn IdentityStore> = match input["store"].as_str() {
        Some("fails") => Arc::new(Broken),
        _ => Arc::new(Identities::with(ISSUER, subject, known)),
    };
    let provision = input["provision"].as_str().unwrap_or_default();
    let users = Arc::new(ScriptedUsers::new(fixtures["provisioned_user_id"].as_i64().unwrap(), provision));
    let mut cfg = config(identities.clone());
    cfg.resource = fixtures["resource"].as_str().unwrap().to_owned();
    cfg.scope_prefix = fixtures["scope_prefix"].as_str().unwrap().to_owned();
    cfg.audience = fixtures["audience"].as_str().unwrap().to_owned();
    if !provision.is_empty() {
        cfg.provision = true;
        cfg.accounts = Some(accounts(&config_from(&oidc_env(&[])), identities, users.clone()).await);
    }
    (Verifier::new(cfg).await.unwrap(), users)
}

fn claims(template: &Value) -> Value {
    let mut claims = serde_json::Map::new();
    for (key, value) in template.as_object().unwrap() {
        match value {
            Value::Null => {}
            Value::String(text) if text == "<issuer>" => {
                claims.insert(key.clone(), json!(ISSUER));
            }
            value => {
                claims.insert(key.clone(), value.clone());
            }
        }
    }
    Value::Object(claims)
}
