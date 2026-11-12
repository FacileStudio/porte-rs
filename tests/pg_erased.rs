#![cfg(all(feature = "pg", feature = "directory"))]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::db::{pool, unique};
use common::registre::{Blob, Erasures, ISSUER, Registre, client};
use porte::Claims;
use porte::directory::Deletions;
use porte::pg::Store;

fn claims(subject: &str) -> Claims {
    Claims {
        provider: ISSUER.into(),
        subject: subject.into(),
        email: unique("p@x.test").to_lowercase(),
        email_verified: true,
        ..Claims::default()
    }
}

#[tokio::test]
async fn an_account_recreated_after_the_erasure_is_erased_again_without_a_restart() {
    let Some(pool) = pool().await else { return };
    let store = Store::new(pool);
    let (alice, bob) = (unique("alice"), unique("bob"));
    store.users().upsert_from_oidc(&claims(&alice)).await.unwrap();
    store.users().upsert_from_oidc(&claims(&bob)).await.unwrap();
    let registre = Arc::new(Registre::default());
    registre.deleted.lock().unwrap().push((alice.clone(), "2026-11-01T10:00:00Z".into()));
    let (app, blob) = (Arc::new(Erasures::default()), Arc::new(Blob::default()));
    let deletions = Deletions::new(client(&registre), app, Some(Arc::new(store.clone())), Some(blob), Duration::ZERO)
        .with_holds(Arc::new(store.clone()));
    deletions.poll().await.unwrap();
    assert!(!store.holds_identity(ISSUER, &alice).await.unwrap(), "the erasure left alice's identity");
    store.users().upsert_from_oidc(&claims(&alice)).await.unwrap();
    assert!(store.holds_identity(ISSUER, &alice).await.unwrap(), "the re-created account is not seen");
    deletions.poll().await.unwrap();
    assert!(!store.holds_identity(ISSUER, &alice).await.unwrap(), "the re-created account survived the poll");
    assert!(store.holds_identity(ISSUER, &bob).await.unwrap(), "someone else was erased");
    assert!(!store.holds_identity("https://other.test", &bob).await.unwrap(), "the provider matched loosely");
    assert!(deletions.erased(ISSUER, &alice).await.unwrap());
}
