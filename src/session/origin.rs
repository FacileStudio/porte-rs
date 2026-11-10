use tronc::Error;
use url::Url;

use super::Manager;
use super::request::RequestView;
use crate::SESSION_COOKIE_NAME;

impl Manager {
    /// The CSRF rule for a WebSocket upgrade, which is a GET and so escapes the header rule.
    ///
    /// A request carrying the session cookie must send an `Origin` whose scheme, host and port
    /// match the request's `Host` (https when the cookie is `Secure`), or the success URL's
    /// origin. A request without the cookie is a bearer client and is exempt, as it is from the
    /// CSRF header. Every WebSocket route calls it before upgrading.
    pub fn check_origin(&self, req: &(impl RequestView + ?Sized)) -> Result<(), Error> {
        if self.read_cookie(req, SESSION_COOKIE_NAME).is_none() {
            return Ok(());
        }
        let origin = req
            .view()
            .headers
            .get(http::header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| Error::forbidden("missing Origin header"))?;
        if self.same_host(req, origin) || same_origin(origin, &self.config().success_url) {
            return Ok(());
        }
        Err(Error::forbidden("cross-origin WebSocket refused"))
    }

    fn same_host(&self, req: &(impl RequestView + ?Sized), origin: &str) -> bool {
        let host = req.view().headers.get(http::header::HOST).and_then(|value| value.to_str().ok());
        let scheme = if self.secure(req) { "https" } else { "http" };
        host.is_some_and(|host| same_origin(origin, &format!("{scheme}://{host}")))
    }
}

fn same_origin(origin: &str, expected: &str) -> bool {
    match (Url::parse(origin), Url::parse(expected)) {
        (Ok(origin), Ok(expected)) => {
            origin.has_host()
                && origin.origin() == expected.origin()
                && origin.path() == "/"
                && origin.query().is_none()
        }
        _ => false,
    }
}
