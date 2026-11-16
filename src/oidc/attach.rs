use super::Kit;
use crate::Identity;
use crate::session::ClaimsSource;

#[async_trait::async_trait]
impl ClaimsSource for Kit {
    async fn attach(&self, identity: &mut Identity) {
        self.admit(identity).await;
    }

    async fn admit(&self, identity: &mut Identity) -> bool {
        if !self.config().claims_enabled() {
            return true;
        }
        let Some(stored) = self.stored_roles(identity.user_id).await else { return true };
        if stored.roles_stale(self.now(), self.config().claims_ttl) {
            return self.reverify(identity).await;
        }
        super::roles::show(identity, &stored);
        true
    }
}
