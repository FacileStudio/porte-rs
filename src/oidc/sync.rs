use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde_json::Value;
use tronc::Error;

use super::Kit;
use super::claims::{Profile, decode};
use super::failure::from_store;
use crate::wire::SyncProfileResponse;
use crate::{DEFAULT_PROFILE_SYNC_INTERVAL, Identity, StoredIdentity, TokenSet, secure_compare};

impl Kit {
    pub(crate) async fn sync_profile(&self, request: Request) -> Response {
        let Some(identity) = request.extensions().get::<Identity>().cloned() else {
            return Error::unauthorized("missing auth").into_response();
        };
        match self.sync(&identity).await {
            Ok(synced) => tronc::json::write(StatusCode::OK, &SyncProfileResponse { synced }),
            Err(error) => error.into_response(),
        }
    }

    async fn sync(&self, identity: &Identity) -> Result<bool, Error> {
        let stored = self.identity_for(identity.user_id).await;
        let mut stored = match stored.map_err(|error| Error::internal("failed to load the identity", error))? {
            Some(stored) if !stored.tokens.access_token.is_empty() => stored,
            _ => return Ok(false),
        };
        if stored.synced_at.is_some_and(|at| self.now() - at < DEFAULT_PROFILE_SYNC_INTERVAL) {
            return Ok(false);
        }
        let Ok((tokens, info)) = self.fetch_profile(&stored.tokens).await else {
            tracing::warn!(user_id = identity.user_id, "porte: profile sync failed, clearing tokens");
            stored.tokens = TokenSet::default();
            stored.synced_at = Some(self.now());
            if let Err(error) = self.inner.identities.save(&stored).await {
                tracing::warn!(%error, "porte: failed to clear the dead tokens");
            }
            return Ok(false);
        };
        let subject = info.get("sub").and_then(Value::as_str).unwrap_or_default();
        if !secure_compare(subject, &stored.subject) {
            tracing::warn!(
                user_id = identity.user_id,
                "porte: userinfo returned a different subject, refusing the sync"
            );
            return Err(Error::unauthorized("the userinfo response is for a different subject"));
        }
        stored.tokens = tokens;
        self.apply_profile(identity, stored, &info).await.map(|()| true)
    }

    async fn apply_profile(&self, identity: &Identity, mut stored: StoredIdentity, info: &Value) -> Result<(), Error> {
        let bytes = serde_json::to_vec(info).unwrap_or_default();
        let profile: Profile = decode(&bytes).map_err(|e| Error::internal("failed to parse the userinfo claims", e))?;
        let mut claims = self.profile_claims(&stored.subject, profile);
        claims.provider = stored.provider.clone();
        claims.roles = stored.roles.clone();
        claims.extra =
            self.config().extra_claims.iter().filter_map(|n| info.get(n).map(|v| (n.clone(), v.clone()))).collect();
        if claims.email.is_empty() {
            claims.email = identity.email.clone();
        }
        claims.tokens = stored.tokens.clone();
        self.refuse_erased(&claims).await?;
        self.inner.users.upsert_from_oidc(&claims).await.map_err(from_store)?;
        stored.synced_at = Some(self.now());
        self.inner
            .identities
            .save(&stored)
            .await
            .map_err(|error| Error::internal("failed to record the identity", error))
    }

    async fn fetch_profile(&self, tokens: &TokenSet) -> Result<(TokenSet, Value), String> {
        let tokens = self.fresh(tokens).await?;
        let info = self.userinfo(&tokens.access_token).await?;
        Ok((tokens, info))
    }

    async fn userinfo(&self, access_token: &str) -> Result<Value, String> {
        let endpoint = self.provider().map(|p| p.userinfo_endpoint.clone()).unwrap_or_default();
        let request = http::Request::get(endpoint)
            .header(http::header::AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Vec::new())
            .map_err(|error| error.to_string())?;
        let response = self.inner.http.send(request).await.map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!("userinfo answered {}", response.status().as_u16()));
        }
        serde_json::from_slice(response.body()).map_err(|error| error.to_string())
    }

    pub(crate) async fn identity_for(&self, user_id: i64) -> Result<Option<StoredIdentity>, crate::StoreError> {
        match self.inner.identities.list_by_user(user_id).await {
            Ok(rows) => Ok(rows.into_iter().find(|row| row.provider == self.config().issuer)),
            Err(crate::StoreError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }
}
