use std::future::Future;

use http::header::AUTHORIZATION;
use tronc::Error;

use crate::Identity;
use crate::session::RequestView;

/// Why [`account_exists`] found no account, as Go `mcpauth.ErrNoAccount`: the token did not come
/// from [`super::Verifier`], or its account is gone. The lookup's error, when there is one, is
/// its source.
#[derive(Debug, thiserror::Error)]
#[error("porte/mcpauth: the token names no account{}", .0.as_ref().map(|cause| format!(": {cause}")).unwrap_or_default())]
pub struct NoAccount(#[source] pub Option<Box<dyn std::error::Error + Send + Sync>>);

/// The person behind a confirm page request, as Go `mcpauth.RequireOwnSession`.
///
/// It passes only [`Identity::browser_session`]: the session cookie carrying a token a browser
/// login minted. It refuses a bearer of any kind (an opaque session, a named API token, a JWT,
/// delegated or not), a named API token or a CLI, device or mobile session token sent as a
/// cookie, a machine token, and a cookie that comes with an `Authorization` header. A cookie
/// issued before porte-rs 0.8.0 carries no browser mark, so it is refused until the person signs
/// in again. A request with no porte identity is a 401 `missing auth`; every other refusal is
/// the one 403 [`tronc::mcp::delegated`], decided on every condition at once, so the answer
/// says nothing about which one failed. Hand it to `tronc::mcp::PendingPage::new` as the `user`
/// hook, behind the session middleware.
pub fn require_own_session(req: &(impl RequestView + ?Sized)) -> Result<Identity, Error> {
    let view = req.view();
    let identity = view.extensions.get::<Identity>().ok_or_else(|| Error::unauthorized("missing auth"))?;
    let own = identity.browser_session && identity.session_id != 0 && identity.user_id != 0;
    let delegated = !identity.actor.is_empty() || !identity.subject.is_empty() || !identity.scopes.is_empty();
    let bearer = view.headers.contains_key(AUTHORIZATION);
    if !own || delegated || bearer {
        return Err(tronc::mcp::delegated());
    }
    Ok(identity.clone())
}

/// Reads the account a verified MCP token speaks for with `lookup`, such as the app store's
/// user read, so a tool never runs for an account erased or deleted after the token was minted,
/// as Go `mcpauth.AccountExists`. `info` is the `tronc::mcp::TokenInfo` the verifier put in the
/// request extensions (`call.parts.extensions.get()`). It answers [`NoAccount`] when `info` is
/// missing, names no account id, or `lookup` fails.
pub async fn account_exists<T, E, F, Fut>(info: Option<&tronc::mcp::TokenInfo>, lookup: F) -> Result<T, NoAccount>
where
    F: FnOnce(i64) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let user_id =
        info.and_then(|info| info.user_id.parse::<i64>().ok()).filter(|id| *id != 0).ok_or(NoAccount(None))?;
    lookup(user_id).await.map_err(|error| NoAccount(Some(error.into())))
}
