//! A port of Go `spacestest.Conformance`: run it against the app's [`Store`] in a test.
//!
//! ```ignore
//! let result = porte::spaces::conformance::run(|| async { fresh_store().await }).await;
//! assert!(result.is_ok(), "{:#?}", result.unwrap_err());
//! ```
//!
//! It catches a lookup not scoped to the space (`UserCoOwner` holds the top rank in B and the
//! bottom rank in A, so a store answering with the user's first row gets the role wrong). It
//! cannot catch a store that echoes its arguments as ids: refuse that in review.

mod assign;
mod content;
mod invariants;

use std::future::Future;
use std::sync::Arc;

use super::{Guard, Ladder, Membership, Role, Seeder};

/// The first fixture space.
pub const SPACE_A: &str = "space-a";
/// The second fixture space.
pub const SPACE_B: &str = "space-b";
/// Top rank in A and B.
pub const USER_OWNER: &str = "user-owner";
/// Middle rank in A.
pub const USER_ADMIN: &str = "user-admin";
/// Bottom rank in A.
pub const USER_MEMBER: &str = "user-member";
/// Top rank in B, bottom rank in A.
pub const USER_CO_OWNER: &str = "user-co-owner";
/// No row anywhere.
pub const USER_OUTSIDER: &str = "user-outsider";

pub(crate) struct Fixture {
    pub(crate) guard: Guard,
    pub(crate) rows: Vec<Membership>,
    pub(crate) top: Role,
    pub(crate) middle: Role,
    pub(crate) bottom: Role,
}

pub(crate) type Failures = Vec<String>;

/// Runs every check against fresh stores from `new_store` with the default ladder, and returns
/// every failure.
pub async fn run<S, F, Fut>(new_store: F) -> Result<(), Vec<String>>
where
    S: Seeder + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_with_ladder(new_store, Ladder::default()).await
}

/// [`run`] with another ladder of at least three ranks.
pub async fn run_with_ladder<S, F, Fut>(new_store: F, ladder: Ladder) -> Result<(), Vec<String>>
where
    S: Seeder + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    if ladder.roles().len() < 3 {
        return Err(vec![format!("the ladder ranks {} roles, the suite needs three", ladder.roles().len())]);
    }
    let mut failures = Vec::new();
    failures.extend(invariants::only_key(&seeded(new_store().await, &ladder).await?).await);
    failures.extend(invariants::space_id_checked(&seeded(new_store().await, &ladder).await?).await);
    failures.extend(invariants::reachable_owner(&seeded(new_store().await, &ladder).await?).await);
    failures.extend(assign::no_escalation(&seeded(new_store().await, &ladder).await?).await);
    failures.extend(content::absence_is_error(&seeded(new_store().await, &ladder).await?).await);
    failures.extend(content::rows_are_faithful(&seeded(new_store().await, &ladder).await?).await);
    if failures.is_empty() { Ok(()) } else { Err(failures) }
}

async fn seeded<S: Seeder + 'static>(store: S, ladder: &Ladder) -> Result<Fixture, Vec<String>> {
    let roles = ladder.roles();
    let (top, middle, bottom) = (roles[roles.len() - 1].clone(), roles[roles.len() - 2].clone(), roles[0].clone());
    let row = |space: &str, user: &str, role: &Role| Membership {
        space_id: space.into(),
        user_id: user.into(),
        role: role.clone(),
    };
    let rows = vec![
        row(SPACE_A, USER_OWNER, &top),
        row(SPACE_A, USER_ADMIN, &middle),
        row(SPACE_A, USER_MEMBER, &bottom),
        row(SPACE_B, USER_OWNER, &top),
        row(SPACE_B, USER_CO_OWNER, &top),
        row(SPACE_A, USER_CO_OWNER, &bottom),
    ];
    for member in &rows {
        store
            .seed(member)
            .await
            .map_err(|error| vec![format!("seed {}/{}: {error}", member.space_id, member.user_id)])?;
    }
    let guard = Guard::new(Arc::new(store)).with_ladder(ladder.clone());
    Ok(Fixture { guard, rows, top, middle, bottom })
}
