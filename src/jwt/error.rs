/// Why a token was refused. Every variant but [`JwtError::Fetch`] and [`JwtError::Config`] is a
/// bad token; those two mean the issuer could not be asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    /// Not three base64url segments, or a segment is not JSON of the right shape.
    #[error("porte/jwt: invalid token: malformed")]
    Malformed,
    /// The header names another algorithm than RS256.
    #[error("porte/jwt: invalid token: signing algorithm {0:?} is not accepted")]
    Algorithm(String),
    /// No published key carries the token's `kid`.
    #[error("porte/jwt: invalid token: no key for kid {0:?}")]
    UnknownKey(String),
    /// The signature does not verify.
    #[error("porte/jwt: invalid token: bad signature")]
    Signature,
    /// `iss` is not the configured issuer.
    #[error("porte/jwt: invalid token: issuer {0:?} is not the configured one")]
    Issuer(String),
    /// `aud` names neither the audience nor an extra one.
    #[error("porte/jwt: invalid token: audience")]
    Audience,
    /// `exp` is past, with the leeway. A missing `exp` is expired.
    #[error("porte/jwt: invalid token: token expired")]
    Expired,
    /// `nbf` is in the future, with the leeway.
    #[error("porte/jwt: invalid token: token is not valid yet")]
    NotYetValid,
    /// `iat` is in the future, with the leeway.
    #[error("porte/jwt: invalid token: token was issued in the future")]
    IssuedInFuture,
    /// Discovery or the key fetch failed.
    #[error("porte/jwt: {0}")]
    Fetch(String),
    /// The verifier was built without an issuer or an audience.
    #[error("porte/jwt: {0}")]
    Config(String),
}

impl JwtError {
    /// Whether the token itself is bad, as opposed to the issuer being unreachable.
    pub fn is_invalid(&self) -> bool {
        !matches!(self, JwtError::Fetch(_) | JwtError::Config(_))
    }
}
