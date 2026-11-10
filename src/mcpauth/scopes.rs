use super::TokenInfo;

/// An app's two MCP scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scopes {
    /// `<prefix>.read`.
    pub read: String,
    /// `<prefix>.write`, which implies read.
    pub write: String,
}

impl Scopes {
    /// Read, then write.
    pub fn list(&self) -> Vec<String> {
        vec![self.read.clone(), self.write.clone()]
    }
}

/// `<prefix>.read` and `<prefix>.write`.
pub fn scopes_for(prefix: &str) -> Scopes {
    Scopes { read: format!("{prefix}.read"), write: format!("{prefix}.write") }
}

/// Whether the token grants `scope`.
pub fn has_scope(info: Option<&TokenInfo>, scope: &str) -> bool {
    info.is_some_and(|info| info.scopes.iter().any(|granted| granted == scope))
}

pub(crate) fn with_implied_read(granted: Vec<String>, scopes: &Scopes) -> Vec<String> {
    if !granted.contains(&scopes.write) || granted.contains(&scopes.read) {
        return granted;
    }
    let mut granted = granted;
    granted.push(scopes.read.clone());
    granted
}
