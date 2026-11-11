use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::snapshot::{Deleted, Snapshot, decode};
use super::{DirectoryError, MAX_SNAPSHOT_BYTES};
use crate::http_client::{BodyLimit, HttpClient};
use crate::query::query_escape;

/// Reads Registre's directory with this app's client credentials.
#[derive(Clone)]
pub struct Client {
    /// The issuer URL, with or without a trailing slash.
    pub issuer: String,
    /// This app's client id.
    pub client_id: String,
    /// Its secret.
    pub client_secret: String,
    /// The outbound HTTP.
    pub http: HttpClient,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct DeletedList {
    deleted: Option<Vec<DeletedRow>>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct DeletedRow {
    sub: Option<String>,
    deleted_at: Option<String>,
}

impl Client {
    /// `GET /api/directory/snapshot`. A non-200, a network error or a body that does not decode
    /// is [`DirectoryError::Unavailable`]; a body over 8 MiB is [`DirectoryError::TooLarge`].
    pub async fn snapshot(&self) -> Result<Snapshot, DirectoryError> {
        decode(&self.fetch("/api/directory/snapshot").await?)
    }

    /// `GET /api/directory/deletions?since=…`: the people Registre erased since `since`.
    pub async fn deletions(&self, since: OffsetDateTime) -> Result<Vec<Deleted>, DirectoryError> {
        let since = since.to_offset(time::UtcOffset::UTC).format(&Rfc3339).unwrap_or_default();
        let body = self.fetch(&format!("/api/directory/deletions?since={}", query_escape(&since))).await?;
        if body.len() > MAX_SNAPSHOT_BYTES {
            return Err(DirectoryError::Unavailable("deletions body too large".into()));
        }
        let unavailable = |error: String| DirectoryError::Unavailable(format!("decode the deletions: {error}"));
        let list: DeletedList = tronc::json::decode(&body, MAX_SNAPSHOT_BYTES).map_err(|e| unavailable(e.message))?;
        list.deleted.unwrap_or_default().into_iter().map(|row| deleted(row).map_err(unavailable)).collect()
    }

    async fn fetch(&self, path: &str) -> Result<Vec<u8>, DirectoryError> {
        let basic = STANDARD.encode(format!("{}:{}", self.client_id, self.client_secret));
        let url = format!("{}{path}", self.issuer.trim_end_matches('/'));
        let request = http::Request::get(&url)
            .header(http::header::AUTHORIZATION, format!("Basic {basic}"))
            .header(http::header::CONTENT_TYPE, "application/json")
            .extension(BodyLimit(MAX_SNAPSHOT_BYTES))
            .body(Vec::new())
            .map_err(|error| DirectoryError::Unavailable(error.to_string()))?;
        let response = self.http.send(request).await.map_err(|error| DirectoryError::Unavailable(error.to_string()))?;
        if response.status() != http::StatusCode::OK {
            return Err(DirectoryError::Unavailable(format!("{path} answered {}", response.status().as_u16())));
        }
        Ok(response.into_body())
    }
}

fn deleted(row: DeletedRow) -> Result<Deleted, String> {
    let at = row.deleted_at.unwrap_or_default();
    let deleted_at = match at.as_str() {
        "" => OffsetDateTime::UNIX_EPOCH,
        text => OffsetDateTime::parse(text, &Rfc3339).map_err(|error| format!("deleted_at {at:?}: {error}"))?,
    };
    Ok(Deleted { subject: row.sub.unwrap_or_default(), deleted_at })
}
