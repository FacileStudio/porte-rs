use std::time::Duration;

use crate::{DEFAULT_CLAIMS_TTL, DEFAULT_LOGIN_CODE_TTL, DEFAULT_SESSION_IDLE_TTL, DEFAULT_SESSION_TTL};

/// The environment contract, field for field the Go `porte.Config` minus the mobile flow.
///
/// [`Config::from_vars`] reads the suite variable names. Zero durations mean the defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// `OIDC_ISSUER`. Its presence is what enables OIDC.
    pub issuer: String,
    /// `OIDC_CLIENT_ID`.
    pub client_id: String,
    /// `OIDC_CLIENT_SECRET`.
    pub client_secret: String,
    /// `OIDC_REDIRECT_URL`, as registered on the provider.
    pub redirect_url: String,
    /// `OIDC_SUCCESS_URL`, where the browser lands after a successful callback.
    pub success_url: String,
    /// Where a failed browser login lands, with the reason in `error`. Empty means `/login` on
    /// the success URL's origin.
    pub failure_url: String,
    /// `OIDC_APP_NAME`, the name on the CLI code page.
    pub app_name: String,
    /// `OIDC_LOGO_URL`, the logo on the CLI code page.
    pub logo_url: String,
    /// `SSO_ONLY`. `GET /auth/config` reports `sso_only` true when this or OIDC is on.
    pub sso_only: bool,
    /// `OIDC_MACHINE_AUDIENCE`: arms offline verification of bearer JWTs for this audience.
    pub machine_audience: String,
    /// `OIDC_SCOPE_PREFIX`: gates bearer JWTs on `<prefix>.read` and `<prefix>.write`.
    pub scope_prefix: String,
    /// `OIDC_CLI_AUDIENCE`: mounts `POST /auth/oidc/device/exchange` for this CLI client id.
    pub cli_audience: String,
    /// Lets a token with no `email_verified` claim match an existing account by address.
    pub trust_email_without_verified_claim: bool,
    /// `OIDC_CLAIMS_SCOPE`: the scope carrying the `roles` claim. Empty disables roles.
    pub claims_scope: String,
    /// Scopes requested on top of the standard four.
    pub extra_scopes: Vec<String>,
    /// Top-level claims copied raw into `Claims::extra`.
    pub extra_claims: Vec<String>,
    /// Browser session lifetime. Zero means [`DEFAULT_SESSION_TTL`].
    pub session_ttl: Duration,
    /// How long a cached role claim is trusted. Zero means [`DEFAULT_CLAIMS_TTL`].
    pub claims_ttl: Duration,
    /// Window for a CLI to exchange its one-time code. Zero means [`DEFAULT_LOGIN_CODE_TTL`].
    pub login_code_ttl: Duration,
    /// Idle window of a browser session. `None` means [`DEFAULT_SESSION_IDLE_TTL`];
    /// `Some(Duration::ZERO)` disables it, as a negative value does in Go.
    pub session_idle_ttl: Option<Duration>,
    /// Also read the unprefixed `session` cookie over https, for one migration.
    pub accept_legacy_cookie: bool,
}

impl Config {
    /// Reads the suite variables: `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
    /// `OIDC_REDIRECT_URL`, `OIDC_SUCCESS_URL`, `OIDC_APP_NAME`, `OIDC_LOGO_URL`,
    /// `OIDC_CLAIMS_SCOPE`, `OIDC_MACHINE_AUDIENCE`, `OIDC_SCOPE_PREFIX`, `OIDC_CLI_AUDIENCE`,
    /// `SSO_ONLY`.
    pub fn from_vars(vars: &tronc::env::Vars) -> Result<Self, tronc::env::EnvError> {
        let text = |key: &str| vars.string(key, "").trim().to_owned();
        Ok(Config {
            issuer: text("OIDC_ISSUER"),
            client_id: text("OIDC_CLIENT_ID"),
            client_secret: text("OIDC_CLIENT_SECRET"),
            redirect_url: text("OIDC_REDIRECT_URL"),
            success_url: text("OIDC_SUCCESS_URL"),
            app_name: text("OIDC_APP_NAME"),
            logo_url: text("OIDC_LOGO_URL"),
            claims_scope: text("OIDC_CLAIMS_SCOPE"),
            machine_audience: text("OIDC_MACHINE_AUDIENCE"),
            scope_prefix: text("OIDC_SCOPE_PREFIX"),
            cli_audience: text("OIDC_CLI_AUDIENCE"),
            sso_only: vars.bool("SSO_ONLY", false)?,
            ..Config::default()
        })
    }

    /// Whether OIDC is configured at all.
    pub fn enabled(&self) -> bool {
        !self.issuer.is_empty()
    }

    /// Whether to request and verify the roles claim.
    pub fn claims_enabled(&self) -> bool {
        !self.claims_scope.is_empty()
    }

    /// Whether the app is served over TLS, read off the redirect or success URL. It decides the
    /// `Secure` attribute and the `__Host-` prefix, upward only.
    pub fn https(&self) -> bool {
        let https = |value: &str| value.to_ascii_lowercase().starts_with("https://");
        https(&self.redirect_url) || https(&self.success_url)
    }

    /// The idle window, or zero when it is disabled.
    pub fn idle_timeout(&self) -> Duration {
        self.session_idle_ttl.unwrap_or(DEFAULT_SESSION_IDLE_TTL)
    }

    /// The scopes to request: `openid email profile offline_access`, then the claims scope, then
    /// the extra scopes.
    pub fn scopes(&self) -> Vec<String> {
        let mut scopes: Vec<String> = ["openid", "email", "profile", "offline_access"].map(String::from).into();
        if self.claims_enabled() {
            scopes.push(self.claims_scope.clone());
        }
        scopes.extend(self.extra_scopes.iter().cloned());
        scopes
    }

    /// A copy with zero durations replaced by their defaults.
    pub fn resolved(&self) -> Config {
        let pick = |value: Duration, default: Duration| if value.is_zero() { default } else { value };
        Config {
            session_ttl: pick(self.session_ttl, DEFAULT_SESSION_TTL),
            claims_ttl: pick(self.claims_ttl, DEFAULT_CLAIMS_TTL),
            login_code_ttl: pick(self.login_code_ttl, DEFAULT_LOGIN_CODE_TTL),
            ..self.clone()
        }
    }
}
