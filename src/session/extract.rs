use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use http::request::Parts;
use tronc::Error;

use crate::Identity;

impl<S: Send + Sync> FromRequestParts<S> for Identity {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Identity>().cloned().ok_or_else(|| Error::unauthorized("missing auth"))
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for Identity {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Identity>().cloned())
    }
}
