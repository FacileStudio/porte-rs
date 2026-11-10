#![cfg(feature = "spaces")]

use std::sync::Arc;

use porte::spaces::{Guard, Membership, Memory, Role, SpaceError, Store};

struct WrongRow(Membership);

#[async_trait::async_trait]
impl Store for WrongRow {
    async fn membership(&self, _: &str, _: &str) -> Result<Membership, SpaceError> {
        Ok(self.0.clone())
    }

    async fn memberships(&self, _: &str) -> Result<Vec<Membership>, SpaceError> {
        Ok(vec![self.0.clone()])
    }

    async fn count_role(&self, _: &str, _: &Role) -> Result<usize, SpaceError> {
        Ok(1)
    }
}

#[tokio::test]
async fn resolve_refuses_a_row_for_another_space_or_an_unranked_role() {
    let other = Membership { space_id: "other-space".into(), user_id: "u".into(), role: Role::owner() };
    assert_eq!(Guard::new(Arc::new(WrongRow(other))).resolve("u", "s").await, Err(SpaceError::NotMember));
    let root = Membership { space_id: "s".into(), user_id: "u".into(), role: Role::from("root") };
    assert_eq!(Guard::new(Arc::new(WrongRow(root))).resolve("u", "s").await, Err(SpaceError::UnknownRole));
    let guard = Guard::new(Arc::new(Memory::default()));
    assert_eq!(guard.require("u", "s", &Role::from("root")).await, Err(SpaceError::UnknownRole));
}
