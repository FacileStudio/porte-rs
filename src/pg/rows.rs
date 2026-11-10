use sqlx::Row;
use sqlx::postgres::PgRow;

use super::TokenSealer;
use super::sealer::open_or_empty;
use crate::{Session, StoreError, StoredIdentity, TokenSet};

pub(crate) const IDENTITY_COLUMNS: &str = "user_id, provider, subject, password_hash, access_token, refresh_token, \
     token_expiry, roles, roles_synced_at, synced_at";

pub(crate) const SESSION_COLUMNS: &str = "id, token_hash, user_id, label, created_at, last_used_at, expires_at";

pub(crate) fn identity(row: &PgRow, sealer: Option<&TokenSealer>) -> Result<StoredIdentity, sqlx::Error> {
    let roles: Option<serde_json::Value> = row.try_get("roles")?;
    let roles = match roles {
        Some(value) if !value.is_null() => {
            Some(serde_json::from_value(value).map_err(|error| sqlx::Error::Decode(error.into()))?)
        }
        _ => None,
    };
    let access: String = row.try_get("access_token")?;
    let refresh: String = row.try_get("refresh_token")?;
    Ok(StoredIdentity {
        user_id: row.try_get("user_id")?,
        provider: row.try_get("provider")?,
        subject: row.try_get("subject")?,
        password_hash: row.try_get("password_hash")?,
        tokens: TokenSet {
            access_token: open_or_empty(sealer, &access),
            refresh_token: open_or_empty(sealer, &refresh),
            expiry: row.try_get("token_expiry")?,
        },
        roles,
        roles_synced_at: row.try_get("roles_synced_at")?,
        synced_at: row.try_get("synced_at")?,
    })
}

pub(crate) fn session(row: &PgRow) -> Result<Session, sqlx::Error> {
    Ok(Session {
        id: row.try_get("id")?,
        token_hash: row.try_get("token_hash")?,
        user_id: row.try_get("user_id")?,
        label: row.try_get("label")?,
        created_at: Some(row.try_get("created_at")?),
        last_used_at: Some(row.try_get("last_used_at")?),
        expires_at: row.try_get("expires_at")?,
        ..Session::default()
    })
}

pub(crate) fn roles_json(roles: Option<&Vec<String>>) -> Option<serde_json::Value> {
    roles.map(|roles| serde_json::Value::from(roles.clone()))
}

pub(crate) fn require_one(result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>) -> Result<(), StoreError> {
    match result {
        Ok(done) if done.rows_affected() == 0 => Err(StoreError::NotFound),
        Ok(_) => Ok(()),
        Err(error) => Err(StoreError::other(error)),
    }
}
