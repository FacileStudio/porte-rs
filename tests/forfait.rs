#![cfg(feature = "forfait")]

mod common;

use common::forfait::{MAILBOXES, RECORDING, snapshot, store};
use porte::forfait::{CheckError, Feature, Scope, Store, upgrade_url};
use serde_json::json;

#[test]
fn it_fails_open_until_an_authoritative_snapshot() {
    let store = store();
    assert_eq!(store.limit(&Scope::space("sp-1"), MAILBOXES), -1);
    assert!(store.enabled(&Scope::person("sub-1"), RECORDING));
    store.apply(&snapshot(3, 0, json!(5)));
    assert_eq!(store.limit(&Scope::space("sp-1"), MAILBOXES), -1);
    store.apply(&snapshot(3, 1, json!(5)));
    assert_eq!(store.limit(&Scope::space("sp-1"), MAILBOXES), 5);
    assert!(store.enabled(&Scope::space("sp-1"), RECORDING));
    assert_eq!(store.limit(&Scope::person("sub-1"), MAILBOXES), -1);
    assert_eq!(store.limit(&Scope::person("nobody"), MAILBOXES), 1);
    assert!(!store.enabled(&Scope::space("sp-2"), RECORDING));
    assert_eq!(store.limit(&Scope::space("sp-1"), RECORDING), 0);
    assert_eq!(store.limit(&Scope::space("sp-1"), "nuage.storage_gb"), 0);
}

#[test]
fn malformed_values_read_as_defaults() {
    let store = store();
    for bad in [json!(1.5), json!(-2), json!(null), json!("5"), json!(u64::MAX)] {
        store.apply(&snapshot(1, 1, bad));
        assert_eq!(store.limit(&Scope::space("sp-1"), MAILBOXES), 1);
        store.reset();
    }
    let mut crowded = snapshot(1, 1, json!(9));
    for i in 0..200 {
        crowded.spaces[0].entitlements.insert(format!("app.k{i}"), json!(true));
    }
    store.apply(&crowded);
    assert_eq!(store.limit(&Scope::space("sp-1"), MAILBOXES), 1);
    let skipped =
        Store::new([Feature::limit("Bad Key", 3), Feature::limit(MAILBOXES, 2), Feature::limit(MAILBOXES, 9)]);
    skipped.apply(&snapshot(1, 1, json!(null)));
    assert_eq!(skipped.limit(&Scope::space("sp-1"), MAILBOXES), 2);
    assert_eq!(skipped.limit(&Scope::space("sp-1"), "Bad Key"), 0);
}

#[test]
fn check_refuses_over_the_ceiling_only() {
    let store = store();
    store.apply(&snapshot(1, 1, json!(5)));
    let space = Scope::space("sp-1");
    assert_eq!(store.check(&space, MAILBOXES, 4, 1), Ok(()));
    assert_eq!(store.check(&space, MAILBOXES, 9, 0), Ok(()));
    assert_eq!(store.check(&Scope::person("sub-1"), MAILBOXES, i64::MAX, 1), Ok(()));
    assert_eq!(store.check(&space, MAILBOXES, -1, 1), Err(CheckError::InvalidUsage));
    let refused = store.check(&space, MAILBOXES, i64::MAX, i64::MAX).unwrap_err();
    assert_eq!(
        refused,
        CheckError::Limit { key: MAILBOXES.into(), limit: 5, upgrade_url: "https://sso.test/spaces/sp-1".into() }
    );
    let envelope = tronc::Error::from(refused);
    assert_eq!(envelope.code.status(), 402);
    assert_eq!(envelope.upgrade_url.as_deref(), Some("https://sso.test/spaces/sp-1"));
    assert!(store.check(&space, "nuage.storage_gb", 0, 1).is_err());
}

#[test]
fn the_upgrade_url_escapes_the_space() {
    assert_eq!(upgrade_url("https://sso.test", ""), "https://sso.test/spaces");
    assert_eq!(upgrade_url("https://sso.test/", "a b/c"), "https://sso.test/spaces/a%20b%2Fc");
}
