use url::Url;

use crate::config::Config;
use crate::query::{encode_sorted, query_escape};
use crate::{ConfigError, DEFAULT_APP_NAME};

impl Config {
    /// Rejects a half-configured provider at startup, naming every missing variable at once.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled() {
            return self.validate_without_issuer();
        }
        if !self.scope_prefix.is_empty() && self.machine_audience.is_empty() {
            return Err(ConfigError::new(
                "OIDC_SCOPE_PREFIX is set but OIDC_MACHINE_AUDIENCE is empty — there is no bearer JWT to gate",
            ));
        }
        match Url::parse(&self.issuer) {
            Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some_and(|h| !h.is_empty()) => {}
            _ => {
                return Err(ConfigError::new(format!(
                    "OIDC_ISSUER must be an absolute http(s) URL, got {:?}",
                    self.issuer
                )));
            }
        }
        self.require_client()
    }

    fn require_client(&self) -> Result<(), ConfigError> {
        let mut missing: Vec<&str> = [
            ("OIDC_CLIENT_ID", &self.client_id),
            ("OIDC_CLIENT_SECRET", &self.client_secret),
            ("OIDC_REDIRECT_URL", &self.redirect_url),
            ("OIDC_SUCCESS_URL", &self.success_url),
        ]
        .into_iter()
        .filter(|(_, value)| value.trim().is_empty())
        .map(|(name, _)| name)
        .collect();
        if missing.is_empty() {
            return Ok(());
        }
        missing.sort_unstable();
        let verb = if missing.len() == 1 { "is" } else { "are" };
        Err(ConfigError::new(format!("OIDC_ISSUER is set but {} {verb} empty", missing.join(", "))))
    }

    fn validate_without_issuer(&self) -> Result<(), ConfigError> {
        for (name, value) in [
            ("OIDC_MACHINE_AUDIENCE", &self.machine_audience),
            ("OIDC_CLI_AUDIENCE", &self.cli_audience),
            ("OIDC_SCOPE_PREFIX", &self.scope_prefix),
        ] {
            if !value.is_empty() {
                return Err(ConfigError::new(format!(
                    "{name} is set but OIDC_ISSUER is empty — verifying a token audience needs a provider"
                )));
            }
        }
        Ok(())
    }

    /// The URL a failed browser login lands on, with `reason` in an `error` query parameter.
    pub fn login_failure(&self, reason: &str) -> String {
        let fallback = || format!("/login?error={}", query_escape(reason));
        let target = if self.failure_url.is_empty() {
            match Url::parse(&self.success_url) {
                Ok(mut origin) => {
                    origin.set_path("/login");
                    origin.set_query(None);
                    origin.set_fragment(None);
                    origin
                }
                Err(_) => return fallback(),
            }
        } else {
            match Url::parse(&self.failure_url) {
                Ok(url) => url,
                Err(_) => return fallback(),
            }
        };
        with_error(target, reason)
    }

    /// The name on porte's own pages: the app name, then the success URL's first DNS label
    /// capitalised, then [`DEFAULT_APP_NAME`].
    pub fn app_label(&self) -> String {
        let name = self.app_name.trim();
        if !name.is_empty() {
            return name.to_owned();
        }
        let host = Url::parse(&self.success_url).ok().and_then(|url| url.host_str().map(str::to_owned));
        let label = host.as_deref().and_then(|host| host.split('.').next()).unwrap_or_default();
        let mut chars = label.chars();
        match chars.next() {
            Some(first) if first.is_alphabetic() => first.to_uppercase().chain(chars).collect(),
            _ => DEFAULT_APP_NAME.to_owned(),
        }
    }

    /// The logo for those pages: the logo URL, then the success URL's origin plus `/logo.svg`.
    pub fn logo(&self) -> String {
        let logo = self.logo_url.trim();
        if !logo.is_empty() {
            return logo.to_owned();
        }
        match Url::parse(&self.success_url) {
            Ok(mut origin) if origin.has_host() => {
                origin.set_path("/logo.svg");
                origin.set_query(None);
                origin.set_fragment(None);
                origin.to_string()
            }
            _ => String::new(),
        }
    }
}

fn with_error(mut target: Url, reason: &str) -> String {
    let mut pairs: Vec<(String, String)> =
        target.query_pairs().filter(|(key, _)| key != "error").map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    pairs.push(("error".to_owned(), reason.to_owned()));
    target.set_query(None);
    format!("{target}?{}", encode_sorted(&pairs))
}
