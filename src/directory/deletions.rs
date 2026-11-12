use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::keys::KeySet;
use super::state::{DeletionState, StateStore};
use super::{Client, DEFAULT_INTERVAL, DirectoryError};

/// The app's half of an erasure: delete what the app holds for this person. It runs before
/// porte's own rows go, so the app can still resolve the account from them.
#[async_trait::async_trait]
pub trait PersonDeleted: Send + Sync {
    /// Erases the app's data for `(provider, subject)`.
    async fn on_person_deleted(&self, provider: &str, subject: &str) -> Result<(), DirectoryError>;
}

/// porte's half of an erasure: the identity, its sessions and codes. `pg::Store` implements it.
#[async_trait::async_trait]
pub trait IdentityEraser: Send + Sync {
    /// Erases porte's rows for `(provider, subject)`.
    async fn erase_identity(&self, provider: &str, subject: &str) -> Result<(), DirectoryError>;
}

/// Whether an account holds an identity again after its erasure. `pg::Store` implements it.
#[async_trait::async_trait]
pub trait IdentityHolder: Send + Sync {
    /// Whether an account holds `(provider, subject)`, matching the provider exactly.
    async fn holds_identity(&self, provider: &str, subject: &str) -> Result<bool, DirectoryError>;
}

/// Polls Registre for erased people and receives its signed pushes, calling the app and then
/// porte once per person and persisting a cursor. Clone it freely; run it in one replica.
#[derive(Clone)]
pub struct Deletions {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub(crate) client: Client,
    pub(crate) on_deleted: Arc<dyn PersonDeleted>,
    pub(crate) eraser: Option<Arc<dyn IdentityEraser>>,
    pub(crate) holds: RwLock<Option<Arc<dyn IdentityHolder>>>,
    pub(crate) store: Option<Arc<dyn StateStore>>,
    pub(crate) interval: Duration,
    pub(crate) state: Mutex<Option<DeletionState>>,
    pub(crate) keys: KeySet,
}

impl Deletions {
    /// Deletions read with `client`, erased through `on_deleted` then `eraser`, with the cursor
    /// kept in `store` (`None` keeps it in memory only). A zero interval means the default.
    pub fn new(
        client: Client,
        on_deleted: Arc<dyn PersonDeleted>,
        eraser: Option<Arc<dyn IdentityEraser>>,
        store: Option<Arc<dyn StateStore>>,
        interval: Duration,
    ) -> Deletions {
        let interval = if interval.is_zero() { DEFAULT_INTERVAL } else { interval };
        let inner = Inner {
            client,
            on_deleted,
            eraser,
            holds: RwLock::new(None),
            store,
            interval,
            state: Mutex::new(None),
            keys: KeySet::default(),
        };
        Deletions { inner: Arc::new(inner) }
    }

    /// Erases a handled person again when `holds` reports that an account came back for them (a
    /// sign-in, a provisioning call or a bearer token that raced the erasure), on push and on
    /// poll, with no restart: Go `Deletions.Holds`. Without it a handled subject is skipped.
    /// Every clone shares the setting.
    pub fn with_holds(self, holds: Arc<dyn IdentityHolder>) -> Deletions {
        *self.inner.holds.write().unwrap_or_else(PoisonError::into_inner) = Some(holds);
        self
    }

    /// Polls at once, then every interval, until `shutdown` is cancelled.
    pub async fn run(&self, shutdown: CancellationToken) {
        let mut ticker = tokio::time::interval(self.inner.interval);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            if let Err(error) = self.poll().await {
                tracing::warn!(%error, "directory: deletion poll failed, will retry");
            }
        }
    }

    pub(crate) async fn handle(&self, state: &mut DeletionState, subject: &str) -> Result<(), DirectoryError> {
        if state.done(subject) && !self.held_again(subject).await? {
            return Ok(());
        }
        let issuer = &self.inner.client.issuer;
        let failed = |what: &str, error: DirectoryError| DirectoryError::Failed(format!("{what} {subject}: {error}"));
        self.inner.on_deleted.on_person_deleted(issuer, subject).await.map_err(|error| failed("erase", error))?;
        if let Some(eraser) = &self.inner.eraser {
            eraser.erase_identity(issuer, subject).await.map_err(|error| failed("erase porte rows of", error))?;
        }
        state.record(subject, time::OffsetDateTime::now_utc());
        Ok(())
    }
}
