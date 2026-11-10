#![cfg(feature = "pg")]

mod common;

use std::time::Duration;

use common::db::{pool, unique, user};
use porte::pg::{SCHEMA, Store};
use porte::{LoginCode, Session, StoreError};
use time::OffsetDateTime;

fn session(user_id: i64, label: &str, expires_in: Option<i64>) -> Session {
    let now = OffsetDateTime::now_utc();
    Session {
        token_hash: unique("hash"),
        user_id,
        label: label.to_owned(),
        created_at: Some(now),
        last_used_at: Some(now - Duration::from_secs(120)),
        expires_at: expires_in.map(|seconds| now + time::Duration::seconds(seconds)),
        ..Session::default()
    }
}

#[test]
fn the_test_migration_is_the_schema() {
    let migration = include_str!("migrations/0001_porte.sql");
    assert_eq!(migration, SCHEMA, "tests/migrations/0001_porte.sql drifted from porte::pg::SCHEMA");
}

#[tokio::test]
async fn sessions_round_trip_and_touch_coalesces() {
    let Some(pool) = pool().await else { return };
    let store = Store::new(pool.clone()).sessions();
    let owner = user(&pool, &unique("a@x.test")).await;
    let created = store.create(session(owner, "", Some(3600))).await.unwrap();
    assert!(created.id > 0);
    let found = store.find(&created.token_hash).await.unwrap();
    assert_eq!((found.user_id, found.id), (owner, created.id));
    let first = OffsetDateTime::now_utc();
    store.touch(&created.token_hash, first).await.unwrap();
    store.touch(&created.token_hash, first + Duration::from_secs(10)).await.unwrap();
    let touched = store.find(&created.token_hash).await.unwrap();
    assert_eq!(touched.last_used_at.unwrap().unix_timestamp(), first.unix_timestamp());
    assert!(matches!(store.find("missing").await, Err(StoreError::NotFound)));
    store.delete(&created.token_hash).await.unwrap();
    assert!(matches!(store.delete(&created.token_hash).await, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn revocations_spare_what_they_must() {
    let Some(pool) = pool().await else { return };
    let store = Store::new(pool.clone()).sessions();
    let (owner, other) = (user(&pool, &unique("b@x.test")).await, user(&pool, &unique("c@x.test")).await);
    let kept = store.create(session(owner, "", Some(3600))).await.unwrap();
    store.create(session(owner, "", Some(3600))).await.unwrap();
    let token = store.create(session(owner, "ci", None)).await.unwrap();
    let theirs = store.create(session(other, "", Some(3600))).await.unwrap();
    assert_eq!(store.delete_logins(owner, kept.id).await.unwrap(), 1);
    assert_eq!(store.list_by_user(owner).await.unwrap().len(), 2);
    assert!(matches!(store.delete_by_id(owner, theirs.id).await, Err(StoreError::NotFound)));
    store.delete_by_id(owner, token.id).await.unwrap();
    assert_eq!(store.delete_by_user(owner).await.unwrap(), 1);
    assert_eq!(store.list_by_user(other).await.unwrap().len(), 1);
}

#[tokio::test]
async fn expired_sessions_are_swept_and_named_tokens_are_not() {
    let Some(pool) = pool().await else { return };
    let store = Store::new(pool.clone()).sessions();
    let owner = user(&pool, &unique("d@x.test")).await;
    let dead = store.create(session(owner, "", Some(-60))).await.unwrap();
    let token = store.create(session(owner, "nightly", None)).await.unwrap();
    store.delete_expired(OffsetDateTime::now_utc()).await.unwrap();
    assert!(matches!(store.find(&dead.token_hash).await, Err(StoreError::NotFound)));
    assert!(store.find(&token.token_hash).await.is_ok());
}

#[tokio::test]
async fn a_bound_session_needs_its_identity() {
    let Some(pool) = pool().await else { return };
    let store = Store::new(pool.clone()).sessions();
    let owner = user(&pool, &unique("e@x.test")).await;
    let mut bound = session(owner, "", Some(3600));
    bound.provider = "https://sso.test".into();
    bound.subject = unique("sub");
    assert!(matches!(store.create(bound.clone()).await, Err(StoreError::NotFound)));
    sqlx::query("INSERT INTO porte_identities (user_id, provider, subject) VALUES ($1, $2, $3)")
        .bind(owner)
        .bind(&bound.provider)
        .bind(&bound.subject)
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.create(bound).await.is_ok());
}

#[tokio::test]
async fn a_login_code_redeems_once() {
    let Some(pool) = pool().await else { return };
    let store = Store::new(pool.clone()).login_codes();
    let owner = user(&pool, &unique("f@x.test")).await;
    let expires_at = OffsetDateTime::now_utc() + Duration::from_secs(60);
    let code = LoginCode {
        code_hash: unique("code"),
        user_id: owner,
        expires_at,
        provider: String::new(),
        subject: String::new(),
    };
    store.create(&code).await.unwrap();
    assert_eq!(store.consume(&code.code_hash).await.unwrap().user_id, owner);
    assert!(matches!(store.consume(&code.code_hash).await, Err(StoreError::CodeConsumed)));
    assert!(matches!(store.consume("never-issued").await, Err(StoreError::NotFound)));
}
