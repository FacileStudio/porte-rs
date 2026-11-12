use super::DirectoryError;
use super::deletions::Deletions;
use super::state::DeletionState;
use crate::{ErasedSubjects, StoreError};

impl Deletions {
    pub(crate) async fn held_again(&self, subject: &str) -> Result<bool, DirectoryError> {
        let holds = self.inner.holds.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let Some(holds) = holds else { return Ok(false) };
        let held = holds.holds_identity(&self.inner.client.issuer, subject).await.map_err(|error| {
            DirectoryError::Failed(format!("check whether {subject} holds an account again: {error}"))
        })?;
        if held {
            tracing::warn!(subject, "directory: an erased subject holds an account again, erasing it again");
        }
        Ok(held)
    }

    /// Whether Registre erased the person behind `(provider, subject)` and this app handled it,
    /// so the app can refuse that identity an account again: Go `Deletions.Erased`, behind
    /// [`ErasedSubjects`] for `oidc::Kit::with_erased`.
    ///
    /// It reads the `StateStore` on every call, never the copy the poll and the push hold, so a
    /// replica that does not run the receiver answers the same and a sign-in never waits for a
    /// poll. A provider other than the client's issuer (with or without one trailing slash), an
    /// empty subject and no `StateStore` answer `false`. A subject stays erased for at least
    /// [`super::DELETION_RETENTION`] after it was last handled.
    pub async fn erased(&self, provider: &str, subject: &str) -> Result<bool, DirectoryError> {
        let Some(store) = &self.inner.store else { return Ok(false) };
        if subject.is_empty() || trim_issuer(provider) != trim_issuer(&self.inner.client.issuer) {
            return Ok(false);
        }
        let raw = store.load().await.map_err(|e| DirectoryError::Failed(format!("load the deletion state: {e}")))?;
        Ok(DeletionState::decode(&raw)?.done(subject))
    }
}

#[async_trait::async_trait]
impl ErasedSubjects for Deletions {
    async fn erased(&self, provider: &str, subject: &str) -> Result<bool, StoreError> {
        Deletions::erased(self, provider, subject).await.map_err(StoreError::other)
    }
}

fn trim_issuer(issuer: &str) -> &str {
    issuer.strip_suffix('/').unwrap_or(issuer)
}
