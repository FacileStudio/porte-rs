use super::Store;
use super::sealer::open;
use crate::StoreError;

const RESEAL_BATCH: i64 = 200;

struct TokenRow {
    provider: String,
    subject: String,
    access: String,
    refresh: String,
}

impl Store {
    /// Seals the plaintext tokens left from before sealing was on, in batches. Idempotent,
    /// never blanks a row, and loses to a concurrent save. Returns the rows rewritten.
    pub async fn reseal_identities(&self) -> Result<u64, StoreError> {
        if self.sealer.as_deref().is_none() {
            return Err(StoreError::other("porte/pg: reseal needs a token sealer"));
        }
        let (mut total, mut after) = (0, (String::new(), String::new()));
        loop {
            let rows = self.token_batch(&after).await?;
            for row in &rows {
                total += self.reseal_row(row).await?;
            }
            match rows.last() {
                Some(last) if rows.len() as i64 == RESEAL_BATCH => {
                    after = (last.provider.clone(), last.subject.clone())
                }
                _ => return Ok(total),
            }
        }
    }

    async fn token_batch(&self, after: &(String, String)) -> Result<Vec<TokenRow>, StoreError> {
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT provider, subject, access_token, refresh_token FROM porte_identities
              WHERE (provider, subject) > ($1, $2) AND (access_token <> '' OR refresh_token <> '')
              ORDER BY provider, subject LIMIT $3",
        )
        .bind(&after.0)
        .bind(&after.1)
        .bind(RESEAL_BATCH)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::other)?;
        Ok(rows
            .into_iter()
            .map(|(provider, subject, access, refresh)| TokenRow { provider, subject, access, refresh })
            .collect())
    }

    async fn reseal_row(&self, row: &TokenRow) -> Result<u64, StoreError> {
        let (access, access_changed) = self.reseal_value(&row.access);
        let (refresh, refresh_changed) = self.reseal_value(&row.refresh);
        if !access_changed && !refresh_changed {
            return Ok(0);
        }
        sqlx::query(
            "UPDATE porte_identities SET access_token = $3, refresh_token = $4
              WHERE provider = $1 AND subject = $2 AND access_token = $5 AND refresh_token = $6",
        )
        .bind(&row.provider)
        .bind(&row.subject)
        .bind(access)
        .bind(refresh)
        .bind(&row.access)
        .bind(&row.refresh)
        .execute(&self.pool)
        .await
        .map(|done| done.rows_affected())
        .map_err(StoreError::other)
    }

    fn reseal_value(&self, stored: &str) -> (String, bool) {
        let Some(sealer) = self.sealer.as_deref() else { return (stored.to_owned(), false) };
        match open(Some(sealer), stored) {
            Ok((plain, false)) if !stored.is_empty() => match sealer.seal(&plain) {
                Ok(sealed) => (sealed, true),
                Err(_) => (stored.to_owned(), false),
            },
            _ => (stored.to_owned(), false),
        }
    }
}
