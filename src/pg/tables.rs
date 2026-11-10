use sqlx::PgConnection;
use std::sync::Mutex;

use crate::StoreError;

const OPTIONAL_TABLES: [&str; 2] = ["porte_login_codes", "porte_magic_links"];

#[derive(Default)]
pub(crate) struct TableSet {
    present: Mutex<Option<Vec<&'static str>>>,
}

impl TableSet {
    pub(crate) async fn user_tables(
        &self,
        conn: &mut PgConnection,
        required: &[&'static str],
    ) -> Result<Vec<&'static str>, StoreError> {
        let known = self.present.lock().unwrap_or_else(|poison| poison.into_inner()).clone();
        let present = match known {
            Some(present) => present,
            None => {
                let present = lookup(conn).await?;
                *self.present.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(present.clone());
                present
            }
        };
        Ok(required.iter().copied().chain(present).collect())
    }
}

async fn lookup(conn: &mut PgConnection) -> Result<Vec<&'static str>, StoreError> {
    let mut present = Vec::new();
    for table in OPTIONAL_TABLES {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&mut *conn)
            .await
            .map_err(StoreError::other)?;
        if exists {
            present.push(table);
        }
    }
    Ok(present)
}
