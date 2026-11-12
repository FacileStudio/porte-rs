#![cfg(feature = "directory")]

mod common;

use std::time::Duration;

use common::erasure::{Setup, notice, push};
use common::registre::{ISSUER, client};
use porte::ErasedSubjects;
use porte::directory::Deletions;

#[tokio::test]
async fn an_account_recreated_after_the_erasure_is_erased_again_on_push() {
    let setup = Setup::new();
    let deletions = setup.holding();
    let token = notice("alice");
    assert_eq!(push(&deletions, &token).await, 202);
    setup.accounts.set("alice", true);
    assert_eq!(push(&deletions, &token).await, 202);
    setup.accounts.set("alice", false);
    assert_eq!(push(&deletions, &token).await, 202);
    assert_eq!((setup.calls("app", "alice"), setup.calls("porte", "alice")), (2, 2));
}

#[tokio::test]
async fn an_account_recreated_after_the_erasure_is_erased_again_on_poll_and_nobody_else() {
    let setup = Setup::new();
    for (sub, at) in [("bob", "2026-11-01T10:00:00Z"), ("alice", "2026-11-01T10:00:01Z")] {
        setup.registre.deleted.lock().unwrap().push((sub.into(), at.into()));
    }
    let deletions = setup.holding();
    deletions.poll().await.unwrap();
    setup.accounts.set("alice", true);
    deletions.poll().await.unwrap();
    assert_eq!((setup.calls("app", "alice"), setup.calls("app", "bob")), (2, 1));
}

#[tokio::test]
async fn without_holds_a_recreated_account_is_skipped_as_before() {
    let setup = Setup::new();
    let deletions = setup.plain();
    let token = notice("alice");
    push(&deletions, &token).await;
    setup.accounts.set("alice", true);
    assert_eq!(push(&deletions, &token).await, 202);
    assert_eq!(setup.calls("app", "alice"), 1);
}

#[tokio::test]
async fn a_failed_holds_check_fails_the_push_and_the_retry_erases() {
    let setup = Setup::new();
    let deletions = setup.holding();
    let token = notice("alice");
    push(&deletions, &token).await;
    setup.accounts.set("alice", true);
    *setup.accounts.fail.lock().unwrap() = true;
    assert_eq!(push(&deletions, &token).await, 500);
    *setup.accounts.fail.lock().unwrap() = false;
    assert_eq!(push(&deletions, &token).await, 202);
    assert_eq!(setup.calls("app", "alice"), 2);
}

#[tokio::test]
async fn erased_reads_the_shared_state_on_every_call() {
    let setup = Setup::new();
    let (receiver, replica) = (setup.plain(), setup.plain());
    assert!(!replica.erased(ISSUER, "alice").await.unwrap());
    push(&receiver, &notice("alice")).await;
    let slash = format!("{ISSUER}/");
    let cases = [
        (ISSUER, "alice", true),
        (&slash, "alice", true),
        (ISSUER, "bob", false),
        ("https://other.test", "alice", false),
        (ISSUER, "", false),
    ];
    for (provider, subject, want) in cases {
        assert_eq!(replica.erased(provider, subject).await.unwrap(), want, "erased({provider:?}, {subject:?})");
    }
    let trait_object: &dyn ErasedSubjects = &replica;
    assert!(trait_object.erased(ISSUER, "alice").await.unwrap());
    let memory_only = Deletions::new(client(&setup.registre), setup.erasures.clone(), None, None, Duration::ZERO);
    push(&memory_only, &notice("carol")).await;
    assert!(!memory_only.erased(ISSUER, "carol").await.unwrap(), "a receiver without a StateStore answered erased");
}
