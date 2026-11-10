#![allow(dead_code)]

#[cfg(feature = "oidc")]
pub mod codes;
#[cfg(feature = "pg")]
pub mod db;
#[cfg(feature = "oidc")]
pub mod flow;
pub mod harness;
pub mod http;
#[cfg(feature = "oidc")]
pub mod idp;
#[cfg(feature = "oidc")]
pub mod kit;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod memory;
#[cfg(feature = "oidc")]
pub mod provider;
#[cfg(feature = "oidc")]
pub mod provider_endpoints;
#[cfg(feature = "directory")]
pub mod registre;
pub mod revocations;
#[cfg(any(feature = "oidc", feature = "directory"))]
pub mod sign;
#[cfg(feature = "oidc")]
pub mod stores;
pub mod vectors;
