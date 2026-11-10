#![cfg(feature = "directory")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::registre::{Blob, Erasures, ISSUER, Registre, client};
use porte::directory::Deletions;
use serde_json::{Value, json};

fn deletions(registre: &Arc<Registre>, erasures: &Arc<Erasures>, blob: &Arc<Blob>) -> Deletions {
    Deletions::new(client(registre), erasures.clone(), Some(erasures.clone()), Some(blob.clone()), Duration::ZERO)
}

fn setup() -> (Arc<Registre>, Arc<Erasures>, Arc<Blob>) {
    (Arc::new(Registre::default()), Arc::new(Erasures::default()), Arc::new(Blob::default()))
}

#[tokio::test]
async fn a_poll_erases_the_app_first_then_porte_and_only_once() {
    let (registre, erasures, blob) = setup();
    registre.deleted.lock().unwrap().push(("u1".into(), "2026-11-01T10:00:00Z".into()));
    let deletions = deletions(&registre, &erasures, &blob);
    deletions.poll().await.unwrap();
    deletions.poll().await.unwrap();
    assert_eq!(*erasures.calls.lock().unwrap(), vec![format!("app {ISSUER} u1"), format!("porte {ISSUER} u1")]);
    let state: Value = serde_json::from_slice(&blob.0.lock().unwrap()).unwrap();
    assert_eq!(state["cursor"], json!(1_793_527_200));
    let asked = registre.asked.lock().unwrap().last().cloned().unwrap();
    assert!(asked.contains("since=2026-11-01T09%3A59%3A00Z"), "the cursor did not overlap by a minute: {asked}");
}

#[tokio::test]
async fn a_failure_keeps_the_person_pending_and_the_cursor_before_it() {
    let (registre, erasures, blob) = setup();
    for (sub, at) in [("u1", "2026-11-01T10:00:00Z"), ("u2", "2026-11-01T11:00:00Z"), ("u3", "2026-11-01T12:00:00Z")] {
        registre.deleted.lock().unwrap().push((sub.into(), at.into()));
    }
    *erasures.refuse.lock().unwrap() = Some("u2".into());
    let deletions = deletions(&registre, &erasures, &blob);
    assert!(deletions.poll().await.is_err());
    let state: Value = serde_json::from_slice(&blob.0.lock().unwrap()).unwrap();
    assert_eq!(state["cursor"], json!(1_793_527_200), "the cursor moved past the failed person");
    *erasures.refuse.lock().unwrap() = None;
    deletions.poll().await.unwrap();
    let app_calls: Vec<String> =
        erasures.calls.lock().unwrap().iter().filter(|c| c.starts_with("app")).cloned().collect();
    assert_eq!(app_calls.len(), 3, "a handled person was erased twice or the failed one never: {app_calls:?}");
}
