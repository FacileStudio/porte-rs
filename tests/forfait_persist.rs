#![cfg(feature = "forfait")]

mod common;

use common::forfait::{MAILBOXES, RECORDING, snapshot, store};
use porte::forfait::{ImportError, Scope};
use serde_json::json;

#[test]
fn an_older_snapshot_is_refused_until_reset() {
    let store = store();
    store.apply(&snapshot(5, 2, json!(5)));
    store.apply(&snapshot(9, 1, json!(7)));
    store.apply(&snapshot(4, 2, json!(7)));
    assert_eq!(store.limit(&Scope::space("sp-1"), MAILBOXES), 5);
    store.apply(&snapshot(1, 3, json!(7)));
    assert_eq!(store.limit(&Scope::space("sp-1"), MAILBOXES), 7);
    store.reset();
    assert_eq!(store.limit(&Scope::space("sp-1"), MAILBOXES), -1);
    store.apply(&snapshot(1, 1, json!(2)));
    assert_eq!(store.limit(&Scope::space("sp-1"), MAILBOXES), 2);
}

#[test]
fn export_and_import_carry_the_state_across_a_restart() {
    let first = store();
    let unsynced = first.export();
    first.apply(&snapshot(5, 2, json!(5)));
    let saved = first.export();
    assert_eq!(first.import(&saved), Err(ImportError::AlreadyApplied));
    let restarted = store();
    restarted.import(&unsynced).unwrap();
    assert_eq!(restarted.limit(&Scope::space("sp-1"), MAILBOXES), -1);
    restarted.import(&saved).unwrap();
    assert_eq!(restarted.limit(&Scope::space("sp-1"), MAILBOXES), 5);
    assert!(restarted.enabled(&Scope::space("sp-1"), RECORDING));
    restarted.apply(&snapshot(9, 1, json!(7)));
    assert_eq!(restarted.limit(&Scope::space("sp-1"), MAILBOXES), 5);
    let fresh = store();
    assert_eq!(fresh.import(b"  "), Ok(()));
    for bad in [
        &b"{\"version\":2,\"snapshot_version\":0,\"entitlements_revision\":0,\"spaces\":null,\"people\":null}"[..],
        b"{\"version\":1,\"extra\":1}",
        b"[]",
    ] {
        assert!(matches!(fresh.import(bad), Err(ImportError::Invalid(_))));
    }
}
