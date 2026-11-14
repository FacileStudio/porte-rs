//! MCP auth, a port of Go `porte/mcpauth`: an OAuth 2.1 resource server for an app's `/mcp`.
//!
//! A token is an RS256 JWT from the issuer whose `aud` names the resource byte for byte (or the
//! app's client id on a delegated token), mapped to the local account by `(iss, sub)`. Every
//! refusal is the same `invalid token`. `/mcp` is never plan-gated.
//!
//! [`Verifier`] implements `tronc::mcp::Verifier`, so an app hands it to `tronc::mcp::Options`
//! as is: `TokenInfo::client_id`, `actor` and `subject` travel in `extra` under `EXTRA_CLIENT_ID`,
//! `EXTRA_ACTOR` and `EXTRA_SUBJECT`, `InvalidToken` becomes `Invalid` (401) and `Unavailable` stays a 500.

mod bridge;
mod config;
mod info;
mod metadata;
mod own;
mod require;
mod scopes;
mod verifier;

pub use info::{BULLE_CLIENT_ID, TokenInfo, identity, third_party};
pub use metadata::{ProtectedResourceMetadata, metadata_route, metadata_url, protected_resource_metadata};
pub use own::{NoAccount, account_exists, require_own_session};
pub use require::{Require, RequireLayer, RequireOptions};
pub use scopes::{Scopes, has_scope, scopes_for};
pub use verifier::{Config, Verifier, VerifyError};
