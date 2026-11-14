use std::sync::Arc;

use porte::jwt::{Claims, Profile};
use porte::oidc::ProvisionError;
use porte::{IdentityStore, StoredIdentity};
use serde_json::{Value, json};

use crate::common::idp::ISSUER;
use crate::common::kit::{accounts, config_from, oidc_env};
use crate::common::ledger::Ledger;
use crate::common::scripted::ScriptedUsers;
use crate::common::stores::Identities;
use crate::common::vectors::{cases, load};

const SUBJECT: &str = "registre-sub";
const EXISTING: i64 = 7;

#[tokio::test]
async fn provision_bearer_vector() {
    for case in cases(&load("provision_bearer")) {
        let input = &case["input"];
        let mut cfg = config_from(&oidc_env(&[]));
        cfg.trust_email_without_verified_claim = input["trust_email_without_verified_claim"].as_bool().unwrap_or(false);
        if input["roles_scope"].as_bool().unwrap_or(false) {
            cfg.claims_scope = "facile".into();
        }
        let identities = Arc::new(Identities::default());
        if input["existing_account"].as_bool().unwrap_or(false) {
            let row = StoredIdentity {
                user_id: EXISTING,
                provider: ISSUER.into(),
                subject: SUBJECT.into(),
                ..StoredIdentity::default()
            };
            identities.save(&row).await.unwrap();
        }
        let users = Arc::new(ScriptedUsers::new(EXISTING + 1, input["store"].as_str().unwrap_or_default()));
        let kit = accounts(&cfg, identities, users.clone()).await.with_erased(ledger(input));
        let got = match kit.provision_bearer(&token(input)).await {
            Ok(identity) => json!({ "outcome": "account", "user_id_is_existing": identity.user_id == EXISTING }),
            Err(ProvisionError::Refused(_)) => json!({ "outcome": "refused", "erased": false }),
            Err(ProvisionError::Erased) => json!({ "outcome": "refused", "erased": true }),
            Err(ProvisionError::Store(_)) => json!({ "outcome": "failed" }),
        };
        let mut got = got;
        got["upserts"] = json!(users.calls());
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}

fn ledger(input: &Value) -> Arc<Ledger> {
    let ledger = Arc::new(Ledger::default());
    match input["erasures"].as_str() {
        Some("erased") => ledger.erased.lock().unwrap().insert(format!("{ISSUER}|{SUBJECT}")),
        Some("fails") => {
            *ledger.fail.lock().unwrap() = true;
            true
        }
        _ => false,
    };
    ledger
}

fn token(input: &Value) -> Claims {
    let roles = input["roles"].as_array().map(|roles| roles.iter().map(|r| r.as_str().unwrap().to_owned()).collect());
    Claims {
        subject: SUBJECT.into(),
        email: input["email"].as_str().unwrap_or_default().to_owned(),
        name: String::new(),
        roles,
        scopes: Vec::new(),
        actor: String::new(),
        audience: Vec::new(),
        client_id: String::new(),
        id: String::new(),
        expires_at: time::OffsetDateTime::now_utc(),
        profile: Profile { email_verified: input["email_verified"].as_bool(), ..Profile::default() },
    }
}
