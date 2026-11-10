//! Space membership, a port of Go `porte/spaces`: who may act in a space, at what rank.
//!
//! Registre owns spaces; an app mirrors them through `directory` and answers membership from
//! its own rows. [`Guard`] is the only way to a resolved [`Scope`], so a scope carrying a space
//! id is proof of membership in it.

mod assign;
pub mod conformance;
mod guard;
mod ladder;
mod memory;
mod store;

pub use guard::Guard;
pub use ladder::Ladder;
pub use memory::Memory;
pub use store::{Seeder, Store};

/// A rank in a space. The default ladder is `member < admin < owner`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Role(pub String);

impl Role {
    /// The top of the default ladder.
    pub fn owner() -> Role {
        Role("owner".into())
    }

    /// The middle of the default ladder.
    pub fn admin() -> Role {
        Role("admin".into())
    }

    /// The bottom of the default ladder.
    pub fn member() -> Role {
        Role("member".into())
    }

    /// The role's name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Role {
    fn from(name: &str) -> Role {
        Role(name.to_owned())
    }
}

/// One row: `user_id` holds `role` in `space_id`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Membership {
    /// The space.
    pub space_id: String,
    /// The member, as the app keys its users.
    pub user_id: String,
    /// The rank.
    pub role: Role,
}

/// What [`Guard::resolve`] hands back. Only the guard can build a resolved one; the default is
/// unresolved and grants nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    /// The caller.
    pub user_id: String,
    /// The space, empty for personal scope.
    pub space_id: String,
    /// The caller's rank there, empty for personal scope.
    pub role: Role,
    resolved: bool,
}

impl Scope {
    /// Whether the guard built this scope.
    pub fn resolved(&self) -> bool {
        self.resolved
    }

    /// Whether this is a resolved personal scope: no space, no role.
    pub fn personal(&self) -> bool {
        self.resolved && self.space_id.is_empty()
    }
}

/// Why the guard refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpaceError {
    /// Not a member of this space, or no user or space at all.
    #[error("spaces: not a member of this space")]
    NotMember,
    /// A member, below the rank asked for.
    #[error("spaces: insufficient role in this space")]
    Forbidden,
    /// Leaving would leave the space without an owner.
    #[error("spaces: the space would be left without an owner")]
    SoleOwner,
    /// A role the ladder does not rank.
    #[error("spaces: unknown role")]
    UnknownRole,
    /// The store failed.
    #[error("spaces: {0}")]
    Store(String),
}
