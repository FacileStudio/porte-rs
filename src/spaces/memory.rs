use std::sync::RwLock;

use super::{Membership, Role, Seeder, SpaceError, Store};

/// An in-memory [`Store`], honest by construction, for tests and the conformance suite.
#[derive(Default)]
pub struct Memory {
    members: RwLock<Vec<Membership>>,
}

#[async_trait::async_trait]
impl Store for Memory {
    async fn membership(&self, space_id: &str, user_id: &str) -> Result<Membership, SpaceError> {
        let members = self.members.read().unwrap_or_else(|poison| poison.into_inner());
        let found = members.iter().find(|m| m.space_id == space_id && m.user_id == user_id);
        found.cloned().ok_or(SpaceError::NotMember)
    }

    async fn memberships(&self, user_id: &str) -> Result<Vec<Membership>, SpaceError> {
        let members = self.members.read().unwrap_or_else(|poison| poison.into_inner());
        Ok(members.iter().filter(|m| m.user_id == user_id).cloned().collect())
    }

    async fn count_role(&self, space_id: &str, role: &Role) -> Result<usize, SpaceError> {
        let members = self.members.read().unwrap_or_else(|poison| poison.into_inner());
        Ok(members.iter().filter(|m| m.space_id == space_id && &m.role == role).count())
    }
}

#[async_trait::async_trait]
impl Seeder for Memory {
    async fn seed(&self, member: &Membership) -> Result<(), SpaceError> {
        let mut members = self.members.write().unwrap_or_else(|poison| poison.into_inner());
        match members.iter_mut().find(|m| m.space_id == member.space_id && m.user_id == member.user_id) {
            Some(existing) => *existing = member.clone(),
            None => members.push(member.clone()),
        }
        Ok(())
    }
}
