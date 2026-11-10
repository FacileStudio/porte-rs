use super::Role;

/// The ranks, lowest first. A role absent from the ladder ranks nowhere and passes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ladder {
    ascending: Vec<Role>,
}

impl Ladder {
    /// A ladder from the lowest rank up. Empty and repeated roles are dropped.
    pub fn new(ascending: &[Role]) -> Ladder {
        let mut order: Vec<Role> = Vec::new();
        for role in ascending {
            if !role.0.is_empty() && !order.contains(role) {
                order.push(role.clone());
            }
        }
        Ladder { ascending: order }
    }

    /// Whether the ladder ranks `role`.
    pub fn valid(&self, role: &Role) -> bool {
        self.ascending.contains(role)
    }

    /// Whether `have` ranks at or above `min`. False when either is unranked.
    pub fn at_least(&self, have: &Role, min: &Role) -> bool {
        let rank = |role: &Role| self.ascending.iter().position(|ranked| ranked == role);
        matches!((rank(have), rank(min)), (Some(held), Some(floor)) if held >= floor)
    }

    /// The highest rank, the one a space must keep a holder of.
    pub fn top(&self) -> Role {
        self.ascending.last().cloned().unwrap_or_default()
    }

    /// The ranks, lowest first.
    pub fn roles(&self) -> Vec<Role> {
        self.ascending.clone()
    }
}

impl Default for Ladder {
    fn default() -> Ladder {
        Ladder::new(&[Role::member(), Role::admin(), Role::owner()])
    }
}
