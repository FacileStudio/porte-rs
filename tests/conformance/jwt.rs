use std::sync::Arc;

use porte::jwt::{Claims, Config, JwtError, Verifier};
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::common::idp::{ISSUER, fixture_client};
use crate::common::vectors::{cases, load};

#[tokio::test]
async fn jwt_vector() {
    let vector = load("jwt");
    let now = OffsetDateTime::from_unix_timestamp(vector["fixtures"]["now"].as_i64().unwrap()).unwrap();
    assert_eq!(vector["fixtures"]["leeway_seconds"], json!(porte::jwt::LEEWAY.as_secs()));
    for case in cases(&vector) {
        let extra: Vec<String> = serde_json::from_value(case["input"]["extra_audiences"].clone()).unwrap_or_default();
        let config = Config {
            issuer: ISSUER.into(),
            audience: "app-client".into(),
            extra_audiences: extra,
            cache_ttl: std::time::Duration::ZERO,
            http: fixture_client(),
            now: Some(Arc::new(move || now)),
        };
        let verifier = Verifier::new(config).await.unwrap();
        let got = match verifier.verify(case["input"]["token"].as_str().unwrap()).await {
            Ok(claims) => json!({ "claims": view(&claims), "reason": null, "valid": true }),
            Err(error) => json!({ "reason": reason(&error), "valid": false }),
        };
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}

fn reason(error: &JwtError) -> &'static str {
    match error {
        JwtError::Malformed => "malformed",
        JwtError::Algorithm(_) => "algorithm",
        JwtError::UnknownKey(_) => "unknown_key",
        JwtError::Signature => "signature",
        JwtError::Issuer(_) => "issuer",
        JwtError::Audience => "audience",
        JwtError::Expired => "expired",
        JwtError::NotYetValid => "not_yet_valid",
        JwtError::IssuedInFuture => "issued_in_future",
        JwtError::Fetch(_) | JwtError::Config(_) => "unclassified",
    }
}

fn view(claims: &Claims) -> Value {
    json!({
        "actor": claims.actor, "audience": claims.audience, "client_id": claims.client_id,
        "email": claims.email, "expires_at": claims.expires_at.unix_timestamp(), "id": claims.id,
        "name": claims.name, "roles": claims.roles.clone().unwrap_or_default(), "scopes": claims.scopes,
        "subject": claims.subject,
        "profile": {
            "email_verified": claims.profile.email_verified, "locale": claims.profile.locale,
            "picture": claims.profile.picture, "preferred_username": claims.profile.preferred_username,
        },
    })
}
