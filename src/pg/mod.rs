//! The identity tables over PostgreSQL, through `sqlx`.
//!
//! [`SCHEMA`] is Go `pg.Schema` byte for byte. An app applies it from its own first migration;
//! porte never applies it at boot outside tests.

mod codes;
mod erase;
mod identities;
mod linking;
mod locks;
mod reseal;
mod revocations;
mod rows;
mod sealer;
mod secret;
mod sessions;
mod tables;
mod users;

use std::sync::Arc;

use sqlx::PgPool;

pub use sealer::{TokenSealer, TokenUnreadable};

use tables::TableSet;

/// The identity tables, byte for byte Go `pg.Schema` at v0.16.1.
pub const SCHEMA: &str = include_str!("schema.sql");

/// The four stores over one pool. Clone it freely.
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
    tables: Arc<TableSet>,
    sealer: Option<Arc<TokenSealer>>,
}

impl Store {
    /// Stores over `pool`, with OIDC tokens stored in the clear.
    pub fn new(pool: PgPool) -> Self {
        Store { pool, tables: Arc::new(TableSet::default()), sealer: None }
    }

    /// Seals `porte_identities.access_token` and `refresh_token` with `sealer`. `None` leaves
    /// them in the clear, which is what an empty `PORTE_TOKEN_KEY` means.
    pub fn with_token_sealer(mut self, sealer: Option<TokenSealer>) -> Self {
        self.sealer = sealer.map(Arc::new);
        self
    }

    /// The pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// This store as the app's [`crate::UserStore`].
    pub fn users(&self) -> Arc<dyn crate::UserStore> {
        Arc::new(self.clone())
    }

    /// This store as the [`crate::IdentityStore`].
    pub fn identities(&self) -> Arc<dyn crate::IdentityStore> {
        Arc::new(self.clone())
    }

    /// This store as the [`crate::SessionStore`].
    pub fn sessions(&self) -> Arc<dyn crate::SessionStore> {
        Arc::new(self.clone())
    }

    /// This store as the [`crate::LoginCodeStore`].
    pub fn login_codes(&self) -> Arc<dyn crate::LoginCodeStore> {
        Arc::new(self.clone())
    }
}

/// Applies [`SCHEMA`]. For tests and local development: an app ships it as a migration.
pub async fn ensure_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(SCHEMA).execute(pool).await.map(|_| ())
}
