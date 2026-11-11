/// Why no token was minted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExchangeError {
    /// The user holds no Registre grant the app can use: no stored refresh token, or one Registre
    /// no longer accepts. Only a new sign-in fixes it. As a [`tronc::Error`] it is
    /// `failed_precondition`, 412, with a message telling the user what to do.
    #[error("Your Facile session has expired. Sign in again to reconnect it.")]
    Reconnect,
    /// The request carries no authenticated porte identity, so a [`super::Source`] has nobody to
    /// act for. As a [`tronc::Error`] it is `unauthenticated`, 401.
    #[error("not authenticated")]
    NoUser,
    /// Registre could not be reached: a network error, a timeout, a 5xx or an unreadable answer.
    #[error("exchange: registre is unavailable: {0}")]
    Unavailable(String),
    /// Registre refused the request for a reason other than a dead grant: `invalid_scope` when
    /// the app's seed entry does not grant the scopes, `unauthorized_client` or `invalid_target`
    /// when it may not exchange for the audience, `invalid_client` when the app's credentials are
    /// wrong. `code` is `unknown` when the answer named none.
    #[error("exchange: registre refused the request ({status} {code})")]
    Refused {
        /// The HTTP status.
        status: u16,
        /// The OAuth error code.
        code: String,
    },
    /// The identity store failed.
    #[error("exchange: reading the identities: {0}")]
    Identities(String),
}

impl From<ExchangeError> for tronc::Error {
    fn from(error: ExchangeError) -> Self {
        match error {
            ExchangeError::Reconnect => tronc::Error::failed(error.to_string()),
            ExchangeError::NoUser => tronc::Error::unauthorized(error.to_string()),
            other => tronc::Error::internal("internal error", other),
        }
    }
}
