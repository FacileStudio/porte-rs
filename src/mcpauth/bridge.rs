use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use http::request::Parts;
use tronc::mcp::{EXTRA_ACTOR, EXTRA_CLIENT_ID, VerifyFuture};

use super::{TokenInfo, Verifier, VerifyError};

impl From<VerifyError> for tronc::mcp::VerifyError {
    fn from(error: VerifyError) -> Self {
        match error {
            VerifyError::InvalidToken => tronc::mcp::VerifyError::Invalid,
            VerifyError::Unavailable => tronc::mcp::VerifyError::Unavailable,
        }
    }
}

impl From<TokenInfo> for tronc::mcp::TokenInfo {
    fn from(info: TokenInfo) -> Self {
        let expires =
            SystemTime::UNIX_EPOCH + Duration::from_secs(info.expiration.unix_timestamp().max(0).unsigned_abs());
        let extra = HashMap::from([(EXTRA_CLIENT_ID.to_owned(), info.client_id), (EXTRA_ACTOR.to_owned(), info.actor)]);
        tronc::mcp::TokenInfo { user_id: info.user_id, scopes: info.scopes, expires_at: Some(expires), extra }
    }
}

impl tronc::mcp::Verifier for Verifier {
    fn verify<'a>(&'a self, token: &'a str, _request: &'a Parts) -> VerifyFuture<'a> {
        Box::pin(async move { Verifier::verify(self, token).await.map(Into::into).map_err(Into::into) })
    }
}
