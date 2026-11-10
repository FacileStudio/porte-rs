use serde::Deserialize;
use serde_json::Value;

use super::Kit;
use crate::jwt::claims::verified_claim;
use crate::{Claims, normalize_locale};

#[derive(Default, Deserialize)]
#[serde(default)]
pub(crate) struct Profile {
    email: Option<String>,
    email_verified: Option<Value>,
    name: Option<String>,
    preferred_username: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
    locale: Option<Value>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RolesOnly {
    roles: Option<Vec<String>>,
}

impl Kit {
    /// The normalised claims of a verified payload, as Go `claimsFromIDToken`.
    pub(crate) fn claims_from(&self, subject: &str, payload: &Value, roles: bool) -> Result<Claims, String> {
        let bytes = serde_json::to_vec(payload).map_err(|error| error.to_string())?;
        let profile: Profile = decode(&bytes).map_err(|error| format!("cannot parse ID token claims: {error}"))?;
        let mut claims = self.profile_claims(subject, profile);
        if roles && self.config().claims_enabled() {
            let found: RolesOnly = decode(&bytes).map_err(|error| format!("cannot parse the roles claim: {error}"))?;
            claims.roles = Some(found.roles.ok_or_else(|| {
                format!(
                    "scope {:?} was granted but no roles claim arrived — the provider is missing its scope mapping",
                    self.config().claims_scope
                )
            })?);
        }
        claims.extra = self.extra_claims(payload);
        Ok(claims)
    }

    pub(crate) fn profile_claims(&self, subject: &str, profile: Profile) -> Claims {
        let text = |value: Option<String>| value.unwrap_or_default();
        Claims {
            provider: self.config().issuer.clone(),
            subject: subject.to_owned(),
            email: normalize_email(&text(profile.email)),
            email_verified: self.email_trusted(verified_claim(profile.email_verified.as_ref())),
            name: text(profile.name),
            preferred_username: text(profile.preferred_username),
            given_name: text(profile.given_name),
            family_name: text(profile.family_name),
            picture: text(profile.picture),
            locale: locale_claim(profile.locale.as_ref()),
            ..Claims::default()
        }
    }

    /// An asserted claim answers for itself; silence counts only when the config trusts it.
    pub(crate) fn email_trusted(&self, asserted: Option<bool>) -> bool {
        asserted.unwrap_or(self.config().trust_email_without_verified_claim)
    }

    fn extra_claims(&self, payload: &Value) -> std::collections::BTreeMap<String, Value> {
        let names = &self.config().extra_claims;
        names.iter().filter_map(|name| payload.get(name).map(|value| (name.clone(), value.clone()))).collect()
    }
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    tronc::json::decode(bytes, usize::MAX).map_err(|error| error.message)
}

pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

pub(crate) fn locale_claim(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).map(normalize_locale).unwrap_or_default()
}
