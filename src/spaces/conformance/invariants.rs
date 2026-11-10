use super::{Failures, Fixture, SPACE_A, SPACE_B, USER_ADMIN, USER_MEMBER, USER_OUTSIDER, USER_OWNER};
use crate::spaces::{Scope, SpaceError};

pub(crate) async fn only_key(f: &Fixture) -> Failures {
    let mut failures = Vec::new();
    let mut check = |ok: bool, message: &str| {
        if !ok {
            failures.push(format!("membership is the only key: {message}"))
        }
    };
    let outsider = f.guard.resolve(USER_OUTSIDER, SPACE_A).await;
    check(outsider == Err(SpaceError::NotMember), "resolve for a non-member is not NotMember");
    let required = f.guard.require(USER_OUTSIDER, SPACE_A, &f.bottom).await;
    check(required == Err(SpaceError::NotMember), "require for a non-member is not NotMember");
    let member = f.guard.require(USER_MEMBER, SPACE_A, &f.bottom).await;
    check(
        member.as_ref().is_ok_and(|s| s.role == f.bottom && s.resolved()),
        "require at the bottom rank failed for its holder",
    );
    let above = f.guard.require(USER_MEMBER, SPACE_A, &f.middle).await;
    check(above == Err(SpaceError::Forbidden), "the bottom rank passed a middle-rank requirement");
    failures
}

pub(crate) async fn space_id_checked(f: &Fixture) -> Failures {
    let mut failures = Vec::new();
    let mut check = |ok: bool, message: &str| {
        if !ok {
            failures.push(format!("a space id is checked: {message}"))
        }
    };
    check(!Scope::default().personal() && !Scope::default().resolved(), "the default Scope reports resolved");
    let personal = f.guard.resolve(USER_OWNER, "").await;
    check(
        personal.as_ref().is_ok_and(|s| s.personal() && s.role.0.is_empty() && s.user_id == USER_OWNER),
        "an empty space id is not a personal scope for that user",
    );
    check(f.guard.resolve("", "").await == Err(SpaceError::NotMember), "a scope resolved with no user");
    check(
        f.guard.require(USER_OWNER, "", &f.bottom).await == Err(SpaceError::NotMember),
        "require passed on personal scope",
    );
    let scoped = f.guard.resolve(USER_ADMIN, SPACE_A).await;
    check(
        scoped.as_ref().is_ok_and(|s| s.space_id == SPACE_A && s.role == f.middle),
        "resolve lost the space or the role",
    );
    check(f.guard.resolve(USER_ADMIN, SPACE_B).await == Err(SpaceError::NotMember), "a member of A resolved in B");
    failures
}

pub(crate) async fn reachable_owner(f: &Fixture) -> Failures {
    let cases = [
        (USER_OWNER, SPACE_A, Err(SpaceError::SoleOwner), "the sole top rank could leave"),
        (USER_OWNER, SPACE_B, Ok(()), "one of two top ranks could not leave"),
        (USER_MEMBER, SPACE_A, Ok(()), "the bottom rank could not leave"),
        (USER_ADMIN, SPACE_A, Ok(()), "the middle rank could not leave"),
        (USER_OUTSIDER, SPACE_A, Err(SpaceError::NotMember), "a non-member could leave"),
        (USER_OWNER, "", Err(SpaceError::NotMember), "leaving no space succeeded"),
    ];
    let mut failures = Vec::new();
    for (user, space, want, message) in cases {
        if f.guard.can_leave(user, space).await != want {
            failures.push(format!("a space keeps a reachable owner: {message}"));
        }
    }
    failures
}
