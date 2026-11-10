#![cfg(feature = "spaces")]

use std::sync::RwLock;

use porte::spaces::{Membership, Memory, Role, Seeder, SpaceError, Store, conformance};

#[tokio::test]
async fn the_memory_store_passes_the_conformance_suite() {
    let result = conformance::run(|| async { Memory::default() }).await;
    assert!(result.is_ok(), "{:#?}", result.unwrap_err());
}

#[derive(Default)]
struct Unscoped {
    rows: RwLock<Vec<Membership>>,
}

#[async_trait::async_trait]
impl Store for Unscoped {
    async fn membership(&self, space_id: &str, user_id: &str) -> Result<Membership, SpaceError> {
        let rows = self.rows.read().unwrap();
        let first = rows.iter().find(|row| row.user_id == user_id).ok_or(SpaceError::NotMember)?;
        Ok(Membership { space_id: space_id.into(), user_id: user_id.into(), role: first.role.clone() })
    }

    async fn memberships(&self, user_id: &str) -> Result<Vec<Membership>, SpaceError> {
        Ok(self.rows.read().unwrap().iter().filter(|row| row.user_id == user_id).cloned().collect())
    }

    async fn count_role(&self, space_id: &str, role: &Role) -> Result<usize, SpaceError> {
        Ok(self.rows.read().unwrap().iter().filter(|row| row.space_id == space_id && &row.role == role).count())
    }
}

#[async_trait::async_trait]
impl Seeder for Unscoped {
    async fn seed(&self, member: &Membership) -> Result<(), SpaceError> {
        self.rows.write().unwrap().push(member.clone());
        Ok(())
    }
}

#[tokio::test]
async fn a_lookup_missing_the_space_id_in_its_where_fails_the_suite() {
    let failures = conformance::run(|| async { Unscoped::default() }).await.expect_err("an unscoped store passed");
    assert!(failures.iter().any(|failure| failure.contains("user-co-owner")), "{failures:#?}");
}
