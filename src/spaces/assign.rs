use super::{Guard, Role, Scope};

impl Guard {
    /// Whether `actor` may grant `target`: only a resolved, non-personal scope, at or above it.
    pub fn assignable_by(&self, actor: &Scope, target: &Role) -> bool {
        actor.resolved() && !actor.personal() && self.ladder().at_least(&actor.role, target)
    }

    /// Whether `actor` may move someone holding `current` to `target`: both at or below the
    /// actor, so an admin can neither mint an owner nor demote one.
    pub fn assignable_over(&self, actor: &Scope, current: &Role, target: &Role) -> bool {
        self.ladder().valid(current) && self.assignable_by(actor, current) && self.assignable_by(actor, target)
    }
}
