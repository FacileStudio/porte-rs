use axum::response::{IntoResponse, Response};
use http::header::{CACHE_CONTROL, LOCATION};
use http::{HeaderValue, StatusCode};
use tronc::{Code, Error};

use crate::{Config, StoreError};

pub(crate) const GENERIC: &str = "could not sign you in";

pub(crate) fn redirect(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(LOCATION, value);
    }
    response
}

pub(crate) fn fail(cfg: &Config, reason: &str) -> Response {
    redirect(&cfg.login_failure(reason))
}

pub(crate) fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(crate) fn caller_error(error: &Error) -> bool {
    matches!(error.code, Code::InvalidArgument | Code::AlreadyExists | Code::Unauthenticated | Code::PermissionDenied)
}

pub(crate) fn reason(error: &Error) -> String {
    if caller_error(error) { error.message.clone() } else { GENERIC.to_owned() }
}

pub(crate) fn from_store(error: StoreError) -> Error {
    match error {
        StoreError::Refused(refused) => refused,
        other => Error::internal(GENERIC, other),
    }
}
