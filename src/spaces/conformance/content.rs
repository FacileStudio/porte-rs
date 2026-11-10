use std::collections::HashMap;

use super::{Failures, Fixture, SPACE_A, SPACE_B, USER_ADMIN, USER_CO_OWNER, USER_MEMBER, USER_OUTSIDER, USER_OWNER};
use crate::spaces::{Membership, SpaceError};

pub(crate) async fn absence_is_error(f: &Fixture) -> Failures {
    let store = f.guard.store();
    let mut failures = Vec::new();
    let mut check = |ok: bool, message: &str| {
        if !ok {
            failures.push(format!("absence is an error: {message}"))
        }
    };
    check(
        store.membership(SPACE_A, USER_OUTSIDER).await == Err(SpaceError::NotMember),
        "a missing row is not NotMember",
    );
    check(store.membership(SPACE_B, USER_ADMIN).await == Err(SpaceError::NotMember), "a row crossed spaces");
    check(store.count_role(SPACE_B, &f.top).await == Ok(2), "count_role(B, top) is not 2");
    check(store.count_role(SPACE_A, &f.top).await == Ok(1), "count_role(A, top) is not 1");
    check(f.guard.spaces(USER_OUTSIDER).await.is_ok_and(|held| held.is_empty()), "a non-member holds spaces");
    failures
}

pub(crate) async fn rows_are_faithful(f: &Fixture) -> Failures {
    let store = f.guard.store();
    let mut failures = Vec::new();
    for want in &f.rows {
        match store.membership(&want.space_id, &want.user_id).await {
            Ok(got) if &got == want => {}
            got => failures.push(format!(
                "the store returns its own rows: membership({}, {}) = {got:?}, want {want:?}",
                want.space_id, want.user_id
            )),
        }
    }
    for user in [USER_OWNER, USER_ADMIN, USER_MEMBER, USER_CO_OWNER, USER_OUTSIDER] {
        let want: Vec<Membership> = f.rows.iter().filter(|row| row.user_id == user).cloned().collect();
        let listed = store.memberships(user).await.unwrap_or_default();
        let held = f.guard.spaces(user).await.unwrap_or_default();
        for (what, got) in [("memberships", listed), ("spaces", held)] {
            if !same_rows(&got, &want) {
                failures.push(format!("the store returns its own rows: {what}({user}) = {got:?}, want {want:?}"));
            }
        }
    }
    failures
}

fn same_rows(got: &[Membership], want: &[Membership]) -> bool {
    let mut counts: HashMap<&Membership, i64> = HashMap::new();
    want.iter().for_each(|row| *counts.entry(row).or_default() += 1);
    got.iter().for_each(|row| *counts.entry(row).or_default() -= 1);
    got.len() == want.len() && counts.values().all(|count| *count == 0)
}
