use super::{Failures, Fixture, SPACE_A, USER_ADMIN, USER_MEMBER, USER_OUTSIDER, USER_OWNER};
use crate::spaces::{Role, Scope};

type Case<'a> = (&'static str, &'a Scope, &'a Role, bool);

struct Actors {
    top: Scope,
    middle: Scope,
    bottom: Scope,
    personal: Scope,
    forged: Scope,
    unresolved: Scope,
    unranked: Role,
}

pub(crate) async fn no_escalation(f: &Fixture) -> Failures {
    let Some(actors) = actors(f).await else {
        return vec!["no privilege escalation: the fixture scopes did not resolve".into()];
    };
    let mut failures = Vec::new();
    for (name, actor, target, want) in cases(f, &actors) {
        if f.guard.assignable_by(actor, target) != want {
            failures.push(format!("no privilege escalation: {name}"));
        }
    }
    if f.guard.assignable_over(&actors.middle, &f.top, &f.bottom) {
        failures.push("no privilege escalation: the middle rank demoted the top rank".into());
    }
    if !f.guard.assignable_over(&actors.middle, &f.bottom, &f.middle) {
        failures.push("no privilege escalation: the middle rank could not promote the bottom rank to a peer".into());
    }
    failures
}

async fn actors(f: &Fixture) -> Option<Actors> {
    Some(Actors {
        top: f.guard.resolve(USER_OWNER, SPACE_A).await.ok()?,
        middle: f.guard.resolve(USER_ADMIN, SPACE_A).await.ok()?,
        bottom: f.guard.resolve(USER_MEMBER, SPACE_A).await.ok()?,
        personal: f.guard.resolve(USER_OWNER, "").await.ok()?,
        forged: Scope { user_id: USER_OUTSIDER.into(), space_id: SPACE_A.into(), role: f.top.clone(), resolved: false },
        unresolved: Scope::default(),
        unranked: Role::from("porte-conformance-unranked"),
    })
}

fn cases<'a>(f: &'a Fixture, a: &'a Actors) -> [Case<'a>; 10] {
    [
        ("the middle rank cannot mint the top", &a.middle, &f.top, false),
        ("the bottom rank cannot mint the middle", &a.bottom, &f.middle, false),
        ("the bottom rank cannot mint the top", &a.bottom, &f.top, false),
        ("the middle rank may appoint a peer", &a.middle, &f.middle, true),
        ("the middle rank may grant below itself", &a.middle, &f.bottom, true),
        ("the top rank may grant its own", &a.top, &f.top, true),
        ("no rank grants an unranked role", &a.top, &a.unranked, false),
        ("personal scope grants nothing", &a.personal, &f.bottom, false),
        ("the default Scope grants nothing", &a.unresolved, &f.bottom, false),
        ("a hand-built Scope grants nothing", &a.forged, &f.top, false),
    ]
}
