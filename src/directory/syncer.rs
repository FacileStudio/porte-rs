use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use axum::routing::{MethodRouter, post};
use http::StatusCode;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use super::{Client, DEFAULT_INTERVAL, DirectoryError, Snapshot};

const DEBOUNCE: Duration = Duration::from_secs(2);

/// Writes a snapshot into the app's tables. Called once per new version. Never hard-delete the data
/// of a space the snapshot no longer lists: move it to the trash (see the module docs).
#[async_trait::async_trait]
pub trait Apply: Send + Sync {
    /// Applies the whole snapshot, in one transaction.
    async fn apply(&self, snapshot: &Snapshot) -> Result<(), DirectoryError>;
}

/// Keeps the app's spaces in step with Registre: a pull at boot, every interval, and two
/// seconds after a nudge. Clone it freely; run it in exactly one replica.
#[derive(Clone)]
pub struct Syncer {
    inner: Arc<Inner>,
}

struct Inner {
    client: Client,
    apply: Arc<dyn Apply>,
    interval: Duration,
    applied: AtomicI64,
    syncing: Mutex<()>,
    nudges: mpsc::Sender<()>,
    pending: Mutex<mpsc::Receiver<()>>,
}

impl Syncer {
    /// A syncer pulling with `client` into `apply`. A zero interval means [`DEFAULT_INTERVAL`].
    pub fn new(client: Client, apply: Arc<dyn Apply>, interval: Duration) -> Syncer {
        let (nudges, pending) = mpsc::channel(1);
        let interval = if interval.is_zero() { DEFAULT_INTERVAL } else { interval };
        let inner = Inner {
            client,
            apply,
            interval,
            applied: AtomicI64::new(0),
            syncing: Mutex::new(()),
            nudges,
            pending: Mutex::new(pending),
        };
        Syncer { inner: Arc::new(inner) }
    }

    /// `POST` answers 202 and wakes the loop; other methods are 405. The nudge carries nothing
    /// and is trusted for nothing: the pull authenticates on its own.
    pub fn nudge_route<S: Clone + Send + Sync + 'static>(&self) -> MethodRouter<S> {
        let syncer = self.clone();
        post(move || async move {
            syncer.nudge();
            StatusCode::ACCEPTED
        })
    }

    /// Wakes the loop. Nudges arriving while one is pending fold into it.
    pub fn nudge(&self) {
        let _ = self.inner.nudges.try_send(());
    }

    /// Pulls now, unless the snapshot's version is the one already applied.
    pub async fn sync(&self) -> Result<(), DirectoryError> {
        let _running = self.inner.syncing.lock().await;
        let snapshot = self.inner.client.snapshot().await?;
        if snapshot.version != 0 && snapshot.version == self.inner.applied.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.inner.apply.apply(&snapshot).await?;
        self.inner.applied.store(snapshot.version, Ordering::SeqCst);
        Ok(())
    }

    /// The loop: a pull at boot, then on every tick and two seconds after a nudge, until
    /// `shutdown` is cancelled. A failed pull keeps the last applied spaces.
    pub async fn run(&self, shutdown: CancellationToken) {
        let mut pending = self.inner.pending.lock().await;
        let mut ticker =
            tokio::time::interval_at(tokio::time::Instant::now() + self.inner.interval, self.inner.interval);
        self.pull().await;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {}
                _ = pending.recv() => {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(DEBOUNCE) => {}
                    }
                    let _ = pending.try_recv();
                }
            }
            self.pull().await;
        }
    }

    async fn pull(&self) {
        if let Err(error) = self.sync().await {
            tracing::warn!(%error, "directory: sync failed, keeping the last applied spaces");
        }
    }
}
