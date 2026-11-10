use std::path::Path;

use sqlx::PgPool;
use sqlx::migrate::Migrator;

pub async fn pool() -> Option<PgPool> {
    let migrator = Migrator::new(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/migrations")).await.unwrap();
    tronc::testdb::pool("porte_test", &migrator).await
}

pub fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", porte::new_token().unwrap())
}

pub async fn user(pool: &PgPool, email: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO porte_users (email, email_verified) VALUES ($1, true) RETURNING id")
        .bind(email)
        .fetch_one(pool)
        .await
        .unwrap()
}
