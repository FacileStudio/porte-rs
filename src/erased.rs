//! The erased-subject guard: what lets porte refuse an account to a person the app erased.

use crate::StoreError;

/// The cause porte wraps when it refuses a sign-in or an account for an identity the app
/// already erased: Go `porte.ErrSubjectErased`. The refusal is a tronc `permission_denied`
/// (403) carrying this as its cause; [`SubjectErased::caused`] tells it apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("porte: this identity was erased")]
pub struct SubjectErased;

impl SubjectErased {
    /// Whether `error` is the erased-subject refusal, Go's `errors.Is(err, ErrSubjectErased)`.
    pub fn caused(error: &tronc::Error) -> bool {
        error.cause.as_deref().is_some_and(|cause| cause.is::<SubjectErased>())
    }
}

/// Answers whether an identity belongs to a person the app has erased: Go
/// `porte.ErasedSubjects`. `directory::Deletions` implements it from its `StateStore`.
#[async_trait::async_trait]
pub trait ErasedSubjects: Send + Sync {
    /// Whether Registre erased the person behind `(provider, subject)` and the app handled it.
    async fn erased(&self, provider: &str, subject: &str) -> Result<bool, StoreError>;
}
