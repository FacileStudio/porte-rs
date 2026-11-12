use std::sync::PoisonError;

use tronc::{Code, Error};

use super::Kit;
use crate::{Claims, SubjectErased};

impl Kit {
    pub(crate) async fn refuse_erased(&self, claims: &Claims) -> Result<(), Error> {
        let erased = self.inner.erased.read().unwrap_or_else(PoisonError::into_inner).clone();
        let Some(erased) = erased else { return Ok(()) };
        match erased.erased(&claims.provider, &claims.subject).await {
            Ok(false) => Ok(()),
            Ok(true) => {
                let mut refused = Error::new(Code::PermissionDenied, "this account was deleted");
                refused.cause = Some(Box::new(SubjectErased));
                Err(refused)
            }
            Err(error) => Err(Error::internal("failed to check the identity against the erasures", error)),
        }
    }
}
