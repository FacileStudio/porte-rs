#![cfg(feature = "pg")]

mod common;

use common::db::{pool, unique};
use porte::pg::{Store, TokenSealer};
use porte::{Claims, StoreError, StoredIdentity, TokenSet};

const ISSUER: &str = "https://sso.test";

fn claims(subject: &str, email: &str, verified: bool) -> Claims {
    Claims {
        provider: ISSUER.into(),
        subject: subject.into(),
        email: email.into(),
        email_verified: verified,
        name: "Ann".into(),
        ..Claims::default()
    }
}

#[tokio::test]
async fn upsert_matches_on_the_subject_and_links_only_a_verified_email() {
    let Some(pool) = pool().await else { return };
    let users = Store::new(pool).users();
    let email = unique("ann@x.test").to_lowercase();
    let first = users.upsert_from_oidc(&claims(&unique("s"), &email, true)).await.unwrap();
    let subject = unique("s");
    let unverified = users.upsert_from_oidc(&claims(&subject, &email, false)).await;
    assert!(matches!(unverified, Err(StoreError::Other(_))), "an unverified address linked an account");
    let renamed = claims("unchanged", &format!("  {}  ", email.to_uppercase()), true);
    let second = users.upsert_from_oidc(&Claims { subject: subject.clone(), ..renamed }).await;
    assert!(second.is_err(), "a second subject of one provider linked the same account");
    let again = users.upsert_from_oidc(&claims(&unique("s"), &unique("bob@x.test"), false)).await.unwrap();
    assert_ne!(again, first);
}

#[tokio::test]
async fn a_verified_login_takes_over_an_unverified_account_and_purges_it() {
    let Some(pool) = pool().await else { return };
    let store = Store::new(pool.clone());
    let email = unique("eve@x.test").to_lowercase();
    let squatter: i64 =
        sqlx::query_scalar("INSERT INTO porte_users (email, email_verified) VALUES ($1, false) RETURNING id")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("INSERT INTO porte_identities (user_id, provider, subject) VALUES ($1, 'other', 'x')")
        .bind(squatter)
        .execute(&pool)
        .await
        .unwrap();
    let owner = store.users().upsert_from_oidc(&claims(&unique("s"), &email, true)).await.unwrap();
    assert_eq!(owner, squatter);
    let left: Vec<String> = sqlx::query_scalar("SELECT provider FROM porte_identities WHERE user_id = $1")
        .bind(owner)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(left, vec![ISSUER.to_owned()], "the squatter's identities survived the takeover");
}

#[tokio::test]
async fn save_refuses_to_move_an_identity_between_accounts() {
    let Some(pool) = pool().await else { return };
    let store = Store::new(pool);
    let subject = unique("s");
    let owner = store.users().upsert_from_oidc(&claims(&subject, &unique("o@x.test"), true)).await.unwrap();
    let thief = store.users().upsert_from_oidc(&claims(&unique("s"), &unique("t@x.test"), true)).await.unwrap();
    let stolen = StoredIdentity {
        user_id: thief,
        provider: ISSUER.into(),
        subject: subject.clone(),
        ..StoredIdentity::default()
    };
    assert!(matches!(store.identities().save(&stolen).await, Err(StoreError::NotFound)));
    assert_eq!(store.identities().find(ISSUER, &subject).await.unwrap().user_id, owner);
}

#[tokio::test]
async fn sealed_tokens_never_reach_the_table_in_clear() {
    let Some(pool) = pool().await else { return };
    let sealer = TokenSealer::parse(&"11".repeat(32)).unwrap();
    let store = Store::new(pool.clone()).with_token_sealer(sealer);
    let subject = unique("s");
    let user_id = store.users().upsert_from_oidc(&claims(&subject, &unique("k@x.test"), true)).await.unwrap();
    let tokens = TokenSet { access_token: "access-1".into(), refresh_token: "refresh-1".into(), expiry: None };
    let identity = StoredIdentity {
        user_id,
        provider: ISSUER.into(),
        subject: subject.clone(),
        tokens,
        roles: Some(vec!["admin".into()]),
        ..StoredIdentity::default()
    };
    store.identities().save(&identity).await.unwrap();
    let raw: String = sqlx::query_scalar("SELECT refresh_token FROM porte_identities WHERE subject = $1")
        .bind(&subject)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(raw.starts_with("pv1:"), "stored {raw}");
    let read = store.identities().find(ISSUER, &subject).await.unwrap();
    assert_eq!((read.tokens.refresh_token.as_str(), read.roles), ("refresh-1", Some(vec!["admin".to_owned()])));
    let plain = Store::new(pool).identities().find(ISSUER, &subject).await.unwrap();
    assert_eq!(plain.tokens.refresh_token, "", "a store without the key read a sealed token");
}

#[tokio::test]
async fn erase_drops_the_identity_and_its_sessions_but_keeps_the_user() {
    let Some(pool) = pool().await else { return };
    let store = Store::new(pool.clone());
    let subject = unique("s");
    let user_id = store.users().upsert_from_oidc(&claims(&subject, &unique("z@x.test"), true)).await.unwrap();
    sqlx::query("INSERT INTO porte_sessions (token_hash, user_id) VALUES ($1, $2)")
        .bind(unique("h"))
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    store.erase_identity(ISSUER, &subject).await.unwrap();
    store.erase_identity(ISSUER, &subject).await.unwrap();
    assert!(matches!(store.identities().find(ISSUER, &subject).await, Err(StoreError::NotFound)));
    assert!(store.sessions().list_by_user(user_id).await.unwrap().is_empty());
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM porte_users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 1);
}

#[tokio::test]
async fn reseal_seals_plaintext_rows_once() {
    let Some(pool) = pool().await else { return };
    let plain = Store::new(pool.clone());
    let subject = unique("s");
    let user_id = plain.users().upsert_from_oidc(&claims(&subject, &unique("r@x.test"), true)).await.unwrap();
    let tokens = TokenSet { access_token: "a".into(), refresh_token: "r".into(), expiry: None };
    plain
        .identities()
        .save(&StoredIdentity {
            user_id,
            provider: ISSUER.into(),
            subject: subject.clone(),
            tokens,
            ..StoredIdentity::default()
        })
        .await
        .unwrap();
    let sealed = plain.clone().with_token_sealer(TokenSealer::parse(&"22".repeat(32)).unwrap());
    assert!(sealed.reseal_identities().await.unwrap() >= 1);
    sealed.reseal_identities().await.unwrap();
    let read = sealed.identities().find(ISSUER, &subject).await.unwrap();
    assert_eq!(read.tokens.refresh_token, "r");
    assert!(plain.reseal_identities().await.is_err());
}

#[tokio::test]
async fn find_by_user_returns_the_subject_at_one_provider() {
    let Some(pool) = pool().await else { return };
    let store = Store::new(pool.clone());
    let subject = unique("s");
    let user = store.users().upsert_from_oidc(&claims(&subject, &unique("f@x.test"), true)).await.unwrap();
    sqlx::query("INSERT INTO porte_identities (user_id, provider, subject) VALUES ($1, 'local', $2)")
        .bind(user)
        .bind(user.to_string())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(store.find_by_user(ISSUER, user).await.unwrap(), (ISSUER.to_owned(), subject));
    assert_eq!(store.find_by_user("local", user).await.unwrap(), ("local".to_owned(), user.to_string()));
    assert!(matches!(store.find_by_user("https://other.test", user).await, Err(StoreError::NotFound)));
    assert!(matches!(store.find_by_user(ISSUER, i64::MAX).await, Err(StoreError::NotFound)));
}
