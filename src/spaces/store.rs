use super::{Membership, Role, SpaceError};

/// The app's membership rows.
#[async_trait::async_trait]
pub trait Store: Send + Sync {
    /// One row, or [`SpaceError::NotMember`]. Every field comes from the row, never from the
    /// arguments, and the lookup filters on both ids.
    async fn membership(&self, space_id: &str, user_id: &str) -> Result<Membership, SpaceError>;
    /// Every row of one user.
    async fn memberships(&self, user_id: &str) -> Result<Vec<Membership>, SpaceError>;
    /// How many members of `space_id` hold `role`.
    async fn count_role(&self, space_id: &str, role: &Role) -> Result<usize, SpaceError>;
}

/// A store the conformance suite can fill.
#[async_trait::async_trait]
pub trait Seeder: Store {
    /// Inserts or replaces one row.
    async fn seed(&self, member: &Membership) -> Result<(), SpaceError>;
}
