use http::header::SET_COOKIE;
use http::{HeaderMap, HeaderValue};

use super::Manager;
use super::cookie_parse::cookie_value;
use super::request::RequestView;
use super::rules::tls_or_forwarded;
use crate::SESSION_COOKIE_NAME;

const HOST_PREFIX: &str = "__Host-";

impl Manager {
    /// Whether this request gets `Secure` cookies: the config says https, the connection is
    /// TLS, or `X-Forwarded-Proto` is `https` in any case.
    pub fn secure(&self, req: &(impl RequestView + ?Sized)) -> bool {
        self.config().https() || tls_or_forwarded(req)
    }

    /// Reads a cookie by base name. Over https only `__Host-<base>` is read, plus the bare name
    /// when `accept_legacy_cookie` is set. Empty values do not count.
    pub fn read_cookie(&self, req: &(impl RequestView + ?Sized), base: &str) -> Option<String> {
        let prefixed = format!("{HOST_PREFIX}{base}");
        let names: Vec<&str> = match (self.secure(req), self.config().accept_legacy_cookie) {
            (false, _) => vec![base],
            (true, false) => vec![&prefixed],
            (true, true) => vec![&prefixed, base],
        };
        names.into_iter().find_map(|name| cookie_value(req.view().headers, name).filter(|value| !value.is_empty()))
    }

    /// A `Set-Cookie` value: `Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure` and the `__Host-`
    /// prefix derived. A negative `max_age` expires the cookie.
    pub fn set_cookie(&self, req: &(impl RequestView + ?Sized), base: &str, value: &str, max_age: i64) -> HeaderValue {
        let secure = self.secure(req);
        let name = if secure { format!("{HOST_PREFIX}{base}") } else { base.to_owned() };
        header(&format_cookie(&name, value, max_age, secure))
    }

    /// The `Set-Cookie` values that expire a cookie, under both spellings over https so a
    /// legacy cookie does not survive.
    pub fn clear_cookie(&self, req: &(impl RequestView + ?Sized), base: &str) -> Vec<HeaderValue> {
        let mut values = vec![self.set_cookie(req, base, "", -1)];
        if self.secure(req) {
            values.push(header(&format_cookie(base, "", -1, true)));
        }
        values
    }

    /// The session cookie, `Max-Age` = the session TTL.
    pub fn session_cookie(&self, req: &(impl RequestView + ?Sized), token: &str) -> HeaderValue {
        let max_age = i64::try_from(self.config().session_ttl.as_secs()).unwrap_or(i64::MAX);
        self.set_cookie(req, SESSION_COOKIE_NAME, token, max_age)
    }
}

/// Appends `Set-Cookie` values to a header map.
pub fn append_cookies(out: &mut HeaderMap, values: impl IntoIterator<Item = HeaderValue>) {
    for value in values {
        out.append(SET_COOKIE, value);
    }
}

fn header(cookie: &str) -> HeaderValue {
    HeaderValue::from_str(cookie).unwrap_or_else(|_| HeaderValue::from_static("invalid=; Max-Age=0"))
}

fn format_cookie(name: &str, value: &str, max_age: i64, secure: bool) -> String {
    let mut cookie = format!("{name}={value}; Path=/");
    match max_age {
        age if age > 0 => cookie.push_str(&format!("; Max-Age={age}")),
        age if age < 0 => cookie.push_str("; Max-Age=0"),
        _ => {}
    }
    cookie.push_str("; HttpOnly");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie.push_str("; SameSite=Lax");
    cookie
}
