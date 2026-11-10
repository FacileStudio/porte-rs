use http::Method;

use super::request::RequestView;
use crate::{CSRF_HEADER_NAME, StoreError};

pub(crate) fn tls_or_forwarded(req: &(impl RequestView + ?Sized)) -> bool {
    let view = req.view();
    if view.extensions.get::<tronc::http::Tls>().is_some() {
        return true;
    }
    view.headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|proto| proto.eq_ignore_ascii_case("https"))
}

pub(crate) fn mutating(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

pub(crate) fn has_csrf_header(req: &(impl RequestView + ?Sized)) -> bool {
    req.view().headers.get(CSRF_HEADER_NAME).is_some_and(|value| !value.is_empty())
}

pub(crate) fn jwt_shaped(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3 && parts.iter().all(|part| !part.is_empty())
}

pub(crate) fn ignore_missing(error: StoreError) -> Result<(), StoreError> {
    match error {
        StoreError::NotFound => Ok(()),
        other => Err(other),
    }
}
