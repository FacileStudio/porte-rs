use std::sync::Arc;

use super::{Ladder, Membership, Role, Scope, SpaceError, Store};

/// Resolves membership and enforces ranks over the app's [`Store`].
#[derive(Clone)]
pub struct Guard {
    store: Arc<dyn Store>,
    pub(crate) ladder: Ladder,
}

impl Guard {
    /// A guard over `store` with the default ladder.
    pub fn new(store: Arc<dyn Store>) -> Guard {
        Guard { store, ladder: Ladder::default() }
    }

    /// The same guard with another ladder.
    pub fn with_ladder(self, ladder: Ladder) -> Guard {
        Guard { ladder, ..self }
    }

    /// The caller's scope in `space_id`, or personal scope for an empty space id. The scope is
    /// built from the asked ids, and a row naming other ids is [`SpaceError::NotMember`].
    pub async fn resolve(&self, user_id: &str, space_id: &str) -> Result<Scope, SpaceError> {
        if user_id.is_empty() {
            return Err(SpaceError::NotMember);
        }
        if space_id.is_empty() {
            return Ok(Scope { user_id: user_id.into(), resolved: true, ..Scope::default() });
        }
        let member = self.store.membership(space_id, user_id).await?;
        if member.space_id != space_id || member.user_id != user_id {
            return Err(SpaceError::NotMember);
        }
        if !self.ladder.valid(&member.role) {
            return Err(SpaceError::UnknownRole);
        }
        Ok(Scope { user_id: user_id.into(), space_id: space_id.into(), role: member.role, resolved: true })
    }

    /// The caller's scope when they hold at least `min` in `space_id`. An empty space id is
    /// refused: personal scope never passes a rank.
    pub async fn require(&self, user_id: &str, space_id: &str, min: &Role) -> Result<Scope, SpaceError> {
        if !self.ladder.valid(min) {
            return Err(SpaceError::UnknownRole);
        }
        if space_id.is_empty() {
            return Err(SpaceError::NotMember);
        }
        let scope = self.resolve(user_id, space_id).await?;
        if !self.ladder.at_least(&scope.role, min) {
            return Err(SpaceError::Forbidden);
        }
        Ok(scope)
    }

    /// Whether the caller may leave `space_id`: [`SpaceError::SoleOwner`] when they are its
    /// only holder of the top rank.
    pub async fn can_leave(&self, user_id: &str, space_id: &str) -> Result<(), SpaceError> {
        if space_id.is_empty() {
            return Err(SpaceError::NotMember);
        }
        let scope = self.resolve(user_id, space_id).await?;
        let top = self.ladder.top();
        if scope.role != top {
            return Ok(());
        }
        match self.store.count_role(space_id, &top).await? {
            0 | 1 => Err(SpaceError::SoleOwner),
            _ => Ok(()),
        }
    }

    /// Every space the caller belongs to, dropping rows that name another user, no space, or
    /// an unranked role.
    pub async fn spaces(&self, user_id: &str) -> Result<Vec<Membership>, SpaceError> {
        if user_id.is_empty() {
            return Err(SpaceError::NotMember);
        }
        let all = self.store.memberships(user_id).await?;
        let kept =
            all.into_iter().filter(|m| m.user_id == user_id && !m.space_id.is_empty() && self.ladder.valid(&m.role));
        Ok(kept.collect())
    }

    /// The ladder in use.
    pub fn ladder(&self) -> &Ladder {
        &self.ladder
    }

    /// The store the guard reads.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }
}
