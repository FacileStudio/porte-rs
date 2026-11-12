use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::deletions::Deletions;
use super::{DELETION_RETENTION, DirectoryError};

const OVERLAP: Duration = Duration::from_secs(60);

/// Where the deletion cursor lives: one opaque blob the app keeps, in a one-row table.
#[async_trait::async_trait]
pub trait StateStore: Send + Sync {
    /// The blob, empty when nothing was saved yet.
    async fn load(&self) -> Result<Vec<u8>, DirectoryError>;
    /// Replaces the blob.
    async fn save(&self, state: &[u8]) -> Result<(), DirectoryError>;
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct DeletionState {
    #[serde(with = "time::serde::timestamp::option")]
    pub(crate) cursor: Option<OffsetDateTime>,
    done: BTreeMap<String, i64>,
}

impl DeletionState {
    pub(crate) fn since(&self) -> OffsetDateTime {
        match self.cursor {
            Some(cursor) => cursor - OVERLAP,
            None => OffsetDateTime::now_utc() - DELETION_RETENTION,
        }
    }

    pub(crate) fn decode(raw: &[u8]) -> Result<DeletionState, DirectoryError> {
        match raw.is_empty() {
            true => Ok(DeletionState::default()),
            false => serde_json::from_slice(raw)
                .map_err(|error| DirectoryError::Failed(format!("decode the deletion state: {error}"))),
        }
    }

    pub(crate) fn done(&self, subject: &str) -> bool {
        self.done.contains_key(subject)
    }

    pub(crate) fn record(&mut self, subject: &str, now: OffsetDateTime) {
        self.done.insert(subject.to_owned(), now.unix_timestamp());
        let horizon = (now - DELETION_RETENTION - OVERLAP).unix_timestamp();
        self.done.retain(|_, at| *at >= horizon);
    }
}

impl Deletions {
    pub(crate) async fn load(&self, slot: &mut Option<DeletionState>) -> Result<DeletionState, DirectoryError> {
        if let Some(state) = slot {
            return Ok(state.clone());
        }
        let raw = match &self.inner.store {
            Some(store) => {
                store.load().await.map_err(|e| DirectoryError::Failed(format!("load the deletion state: {e}")))?
            }
            None => Vec::new(),
        };
        let state = DeletionState::decode(&raw)?;
        *slot = Some(state.clone());
        Ok(state)
    }

    pub(crate) async fn persist(
        &self,
        slot: &mut Option<DeletionState>,
        state: &DeletionState,
    ) -> Result<(), DirectoryError> {
        let Some(store) = &self.inner.store else {
            *slot = Some(state.clone());
            return Ok(());
        };
        let raw = serde_json::to_vec(state).unwrap_or_default();
        match store.save(&raw).await {
            Ok(()) => {
                *slot = Some(state.clone());
                Ok(())
            }
            Err(error) => {
                *slot = None;
                Err(DirectoryError::Failed(format!("save the deletion state: {error}")))
            }
        }
    }
}
