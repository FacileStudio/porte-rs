//! A sign-in app for the owner's manual check against Registre: `/api/auth/*`, `/api/me`, on
//! `127.0.0.1:$PORT` (8080 by default).
//!
//! ```sh
//! DATABASE_URL=postgres://… OIDC_ISSUER=https://sso.facile.studio OIDC_CLIENT_ID=… \
//! OIDC_CLIENT_SECRET=… OIDC_REDIRECT_URL=http://localhost:8080/api/auth/oidc/callback \
//! OIDC_SUCCESS_URL=http://localhost:8080/api/me cargo run --example signin --all-features
//! ```

use std::error::Error;

use axum::Router;
use axum::routing::get;
use porte::{Config, Identity, oidc, pg, session};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let vars = tronc::env::Vars::process();
    let config = Config::from_vars(&vars)?;
    let pool = sqlx::PgPool::connect(&vars.required("DATABASE_URL")?).await?;
    pg::ensure_schema(&pool).await?;
    let store = pg::Store::new(pool).with_token_sealer(pg::TokenSealer::parse(&vars.string("PORTE_TOKEN_KEY", ""))?);
    let sessions = session::Manager::new(&config, session::Deps { sessions: store.sessions(), now: None });
    let deps = oidc::Deps {
        users: store.users(),
        identities: store.identities(),
        codes: store.login_codes(),
        sessions: sessions.clone(),
        config_extra: None,
        http: None,
        now: None,
    };
    let kit = oidc::Kit::new(&config, deps).await?;
    let me =
        get(|me: Identity| async move { format!("signed in as user {} (session {})\n", me.user_id, me.session_id) });
    let api = Router::new()
        .route("/me", me)
        .route_layer(sessions.require_auth())
        .merge(sessions.routes())
        .merge(kit.routes());
    let port: u16 = vars.string("PORT", "8080").parse()?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    axum::serve(listener, Router::new().nest("/api", api)).await?;
    Ok(())
}
