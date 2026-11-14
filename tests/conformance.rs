mod common;

#[cfg(feature = "oidc")]
#[path = "conformance/backchannel.rs"]
mod backchannel;
#[path = "conformance/csrf.rs"]
mod csrf;
#[cfg(feature = "directory")]
#[path = "conformance/directory_erased.rs"]
mod directory_erased;
#[cfg(feature = "directory")]
#[path = "conformance/directory_snapshot.rs"]
mod directory_snapshot;
#[cfg(feature = "exchange")]
#[path = "conformance/exchange_errors.rs"]
mod exchange_errors;
#[cfg(feature = "oidc")]
#[path = "conformance/jwt.rs"]
mod jwt;
#[cfg(feature = "mcp")]
#[path = "conformance/mcpauth_tokens.rs"]
mod mcpauth_tokens;
#[path = "conformance/p1.rs"]
mod p1;
#[cfg(feature = "oidc")]
#[path = "conformance/pkce.rs"]
mod pkce;
#[cfg(feature = "oidc")]
#[path = "conformance/provision_bearer.rs"]
mod provision_bearer;
#[cfg(feature = "oidc")]
#[path = "conformance/routes.rs"]
mod routes;
#[path = "conformance/schema.rs"]
mod schema;
#[cfg(feature = "oidc")]
#[path = "conformance/scope_gate.rs"]
mod scope_gate;
#[cfg(feature = "pg")]
#[path = "conformance/sealer.rs"]
mod sealer;
#[cfg(feature = "spaces")]
#[path = "conformance/spaces_ladder.rs"]
mod spaces_ladder;
