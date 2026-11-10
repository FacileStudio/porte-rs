use std::time::Duration;

use axum::body::to_bytes;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, any};
use http::{Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

use super::deletions::Deletions;
use super::keys::Lookup;
use super::{DirectoryError, USER_DELETED_EVENT};
use crate::jose::{audience, decode_object, split};

const SECEVENT_TYPE: &str = "secevent+jwt";
const MAX_NOTICE_SIZE: usize = 16 << 10;
const CLOCK_LEEWAY: Duration = Duration::from_secs(60);
const MAX_NOTICE_LIFE: Duration = Duration::from_secs(3600);

#[derive(Default, Deserialize)]
#[serde(default)]
struct Notice {
    iss: Option<String>,
    aud: Option<Value>,
    sub: Option<String>,
    iat: Option<i64>,
    exp: Option<i64>,
    events: Option<std::collections::HashMap<String, Value>>,
}

enum Refusal {
    Bad,
    Unavailable,
}

impl Deletions {
    /// The push receiver at [`super::DELETIONS_PATH`]: a `secevent+jwt` RS256 notice from the
    /// issuer, for this client, inside a short window, carrying the user-deleted event. 202 once
    /// erased, 400 for anything else, 503 when the keys cannot be fetched, 405 for a non-POST.
    pub fn route<S: Clone + Send + Sync + 'static>(&self) -> MethodRouter<S> {
        let deletions = self.clone();
        any(move |request: Request| async move { deletions.receive(request).await })
    }

    async fn receive(&self, request: Request) -> Response {
        if request.method() != Method::POST {
            return (StatusCode::METHOD_NOT_ALLOWED, [(http::header::ALLOW, "POST")]).into_response();
        }
        let Ok(raw) = to_bytes(request.into_body(), MAX_NOTICE_SIZE).await else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let subject = match self.verify(String::from_utf8_lossy(&raw).trim(), OffsetDateTime::now_utc()).await {
            Ok(subject) => subject,
            Err(Refusal::Unavailable) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            Err(Refusal::Bad) => return StatusCode::BAD_REQUEST.into_response(),
        };
        match self.erase_pushed(&subject).await {
            Ok(()) => StatusCode::ACCEPTED.into_response(),
            Err(error) => {
                tracing::warn!(%error, "directory: erase from a pushed notice failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }

    async fn erase_pushed(&self, subject: &str) -> Result<(), DirectoryError> {
        let mut slot = self.inner.state.lock().await;
        let mut state = self.load(&mut slot).await?;
        self.handle(&mut state, subject).await?;
        self.persist(&mut slot, &state).await
    }

    async fn verify(&self, token: &str, now: OffsetDateTime) -> Result<String, Refusal> {
        let parts = split(token).map_err(|_| Refusal::Bad)?;
        let typ = parts.header.typ.as_ref().and_then(Value::as_str);
        if parts.header.alg != "RS256" || typ != Some(SECEVENT_TYPE) {
            return Err(Refusal::Bad);
        }
        let key = match self.inner.keys.lookup(&self.inner.client, &parts.header.kid).await {
            Ok(Lookup::Found(key)) => key,
            Ok(Lookup::Unknown) => return Err(Refusal::Bad),
            Err(_) => return Err(Refusal::Unavailable),
        };
        if !crate::rs256::verify(&key, &parts.signing_input, &parts.signature) {
            return Err(Refusal::Bad);
        }
        let notice: Notice = decode_object(&parts.payload).map_err(|_| Refusal::Bad)?;
        self.acceptable(notice, now).ok_or(Refusal::Bad)
    }

    fn acceptable(&self, notice: Notice, now: OffsetDateTime) -> Option<String> {
        let client = &self.inner.client;
        let at = |unix: Option<i64>| OffsetDateTime::from_unix_timestamp(unix.unwrap_or(0)).ok();
        let (issued, expires) = (at(notice.iat)?, at(notice.exp)?);
        let subject = notice.sub.unwrap_or_default();
        let ok = notice.events.unwrap_or_default().contains_key(USER_DELETED_EVENT)
            && !subject.is_empty()
            && notice.iss.unwrap_or_default().trim_end_matches('/') == client.issuer.trim_end_matches('/')
            && audience(notice.aud).ok()?.contains(&client.client_id)
            && expires > now - CLOCK_LEEWAY
            && issued <= now + CLOCK_LEEWAY
            && expires - issued <= MAX_NOTICE_LIFE;
        ok.then_some(subject)
    }
}
