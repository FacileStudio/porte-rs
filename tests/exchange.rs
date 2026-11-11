#![cfg(feature = "exchange")]

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::exchange::{bulle, courrier, setup};
use porte::exchange::Target;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_audiences_refresh_once() {
    let f = setup();
    let before = f.ids.refresh_token(7);
    let tasks: Vec<_> = (0..40)
        .map(|i| {
            let (ex, target) = (f.ex.clone(), if i % 2 == 0 { bulle() } else { courrier() });
            tokio::spawn(async move {
                let token = ex.token(7, &target).await.unwrap();
                assert!(token.starts_with(&format!("x-{}-", target.audience)), "{token}");
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(f.registre.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(f.registre.exchanges.load(Ordering::SeqCst), 2);
    assert!(!f.registre.overlapping.load(Ordering::SeqCst));
    let after = f.ids.refresh_token(7);
    assert!(after != before && !after.is_empty());
}

#[tokio::test]
async fn a_token_is_cached_until_its_expiry_minus_the_margin() {
    let f = setup();
    let first = f.ex.token(7, &bulle()).await.unwrap();
    f.advance(time::Duration::minutes(4));
    assert_eq!(f.ex.token(7, &Target::new("bulle", ["bulle.write", "bulle.read"])).await.unwrap(), first);
    f.advance(time::Duration::seconds(31));
    let renewed = f.ex.token(7, &bulle()).await.unwrap();
    assert_ne!(renewed, first);
    assert_eq!(f.registre.refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_rejected_subject_refreshes_once() {
    let f = setup();
    f.ex.token(7, &bulle()).await.unwrap();
    f.registre.revoke_access();
    f.ex.forget(7, &bulle());
    f.ex.token(7, &bulle()).await.unwrap();
    assert_eq!(f.registre.refreshes.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_rotation_by_another_replica_is_picked_up() {
    let f = setup();
    let stale = f.ids.refresh_token(7);
    f.registre.ledger.lock().unwrap().refresh.remove(&stale);
    f.ids.set_refresh_token(7, f.registre.seed());
    *f.ids.stale.lock().unwrap() = stale;
    f.ex.token(7, &bulle()).await.unwrap();
    assert_eq!(f.registre.refreshes.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_cancelled_caller_still_persists_the_rotation() {
    let f = setup();
    let before = f.ids.refresh_token(7);
    let cancelled = tokio::time::timeout(Duration::from_millis(5), f.ex.token(7, &bulle())).await;
    assert!(cancelled.is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_ne!(f.ids.refresh_token(7), before);
    f.ex.token(7, &bulle()).await.unwrap();
}

#[tokio::test]
async fn an_unsaved_rotation_is_kept_in_memory() {
    let f = setup();
    f.ids.failing.store(true, Ordering::SeqCst);
    f.ex.token(7, &bulle()).await.unwrap();
    f.ids.failing.store(false, Ordering::SeqCst);
    f.registre.revoke_access();
    f.ex.forget(7, &bulle());
    f.ex.token(7, &bulle()).await.unwrap();
    assert_eq!(f.ids.saves.load(Ordering::SeqCst), 1);
}
