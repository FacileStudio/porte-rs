mod common;

#[cfg(feature = "oidc")]
#[path = "conformance/backchannel.rs"]
mod backchannel;
#[path = "conformance/csrf.rs"]
mod csrf;
#[cfg(feature = "oidc")]
#[path = "conformance/jwt.rs"]
mod jwt;
#[path = "conformance/p1.rs"]
mod p1;
#[cfg(feature = "oidc")]
#[path = "conformance/pkce.rs"]
mod pkce;
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
