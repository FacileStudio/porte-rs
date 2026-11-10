use std::collections::BTreeMap;
use std::sync::Arc;

use porte::spaces::{Guard, Ladder, Membership, Memory, Role, Scope, Seeder, SpaceError};
use serde_json::{Value, json};

use crate::common::vectors::{cases, load};

async fn guard(vector: &Value) -> Guard {
    let store = Memory::default();
    for row in vector["fixtures"]["memberships"].as_array().unwrap() {
        let text = |key: &str| row[key].as_str().unwrap().to_owned();
        store
            .seed(&Membership { space_id: text("space"), user_id: text("user"), role: Role(text("role")) })
            .await
            .unwrap();
    }
    Guard::new(Arc::new(store))
}

async fn actors(guard: &Guard) -> BTreeMap<&'static str, Scope> {
    let mut scopes = BTreeMap::from([("unresolved", Scope::default())]);
    for (name, user, space) in
        [("owner", "owner", "s1"), ("admin", "admin", "s1"), ("member", "member", "s1"), ("personal", "owner", "")]
    {
        scopes.insert(name, guard.resolve(user, space).await.unwrap());
    }
    scopes
}

fn code(error: &SpaceError) -> Value {
    Value::from(match error {
        SpaceError::NotMember => "not_member",
        SpaceError::Forbidden => "forbidden",
        SpaceError::SoleOwner => "sole_owner",
        SpaceError::UnknownRole => "unknown_role",
        SpaceError::Store(message) => message.as_str(),
    })
}

#[tokio::test]
async fn spaces_ladder_vector() {
    let vector = load("spaces_ladder");
    let ladder: Vec<String> = Ladder::default().roles().into_iter().map(|role| role.0).collect();
    assert_eq!(vector["fixtures"]["ladder"], json!(ladder));
    let guard = guard(&vector).await;
    let scopes = actors(&guard).await;
    for case in cases(&vector) {
        let input = &case["input"];
        let role = |key: &str| Role(input[key].as_str().unwrap_or_default().to_owned());
        let text = |key: &str| input[key].as_str().unwrap_or_default().to_owned();
        let got = match input["kind"].as_str().unwrap() {
            "at_least" => json!({ "allowed": Ladder::default().at_least(&role("have"), &role("min")) }),
            "assignable_by" => {
                json!({ "allowed": guard.assignable_by(&scopes[text("actor").as_str()], &role("target")) })
            }
            "assignable_over" => {
                let actor = &scopes[text("actor").as_str()];
                json!({ "allowed": guard.assignable_over(actor, &role("current"), &role("target")) })
            }
            "require" => match guard.require(&text("user"), &text("space"), &role("min")).await {
                Ok(scope) => json!({ "error": null, "role": scope.role.0 }),
                Err(error) => json!({ "error": code(&error), "role": "" }),
            },
            _ => json!({ "error": guard.can_leave(&text("user"), &text("space")).await.err().map(|e| code(&e)) }),
        };
        assert_eq!(got, case["want"], "{}", case["name"]);
    }
}
