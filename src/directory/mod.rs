//! The Registre directory, a port of Go `porte/directory`: the space snapshot, the sync loop
//! and the account deletions.
//!
//! Registre owns spaces. An app pulls `GET {issuer}/api/directory/snapshot` with its own client
//! credentials, applies it to its tables through [`Apply`], and mounts the nudge at
//! [`SYNC_PATH`] and the deletion receiver at [`DELETIONS_PATH`].

mod client;
mod deletions;
mod keys;
mod poll;
mod push;
mod snapshot;
mod state;
mod syncer;

use std::time::Duration;

pub use client::Client;
pub use deletions::{Deletions, IdentityEraser, PersonDeleted};
pub use snapshot::{Deleted, Member, Person, Snapshot, Space};
pub use state::StateStore;
pub use syncer::{Apply, Syncer};

/// The member rank.
pub const ROLE_MEMBER: &str = "member";
/// The admin rank.
pub const ROLE_ADMIN: &str = "admin";
/// The owner rank.
pub const ROLE_OWNER: &str = "owner";
/// The largest snapshot porte reads, 8 MiB.
pub const MAX_SNAPSHOT_BYTES: usize = 8 << 20;
/// Where Registre nudges the app to pull again.
pub const SYNC_PATH: &str = "/api/registre/sync";
/// Where Registre pushes a signed deletion notice.
pub const DELETIONS_PATH: &str = "/api/registre/deletions";
/// How often the loops pull without a nudge.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// How far back deletions are kept by Registre and looked for on a first poll.
pub const DELETION_RETENTION: Duration = Duration::from_secs(60 * 24 * 3600);
/// The event a deletion notice carries.
pub const USER_DELETED_EVENT: &str = "https://schemas.facile.studio/event/user-deleted";

/// Why the directory could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DirectoryError {
    /// Registre did not answer 200, or answered something unreadable.
    #[error("directory: registre unavailable: {0}")]
    Unavailable(String),
    /// The snapshot is larger than [`MAX_SNAPSHOT_BYTES`].
    #[error("directory: snapshot exceeds MAX_SNAPSHOT_BYTES")]
    TooLarge,
    /// The app's callback, its store or porte's erase failed.
    #[error("directory: {0}")]
    Failed(String),
}
