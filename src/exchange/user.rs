use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use time::OffsetDateTime;
use tokio::sync::OwnedMutexGuard;

use super::Inner;

pub(super) type Held = OwnedMutexGuard<()>;

#[derive(Clone, Default)]
pub(super) struct Cached {
    pub(super) value: String,
    pub(super) expiry: Option<OffsetDateTime>,
}

#[derive(Default)]
pub(super) struct State {
    pub(super) subject: Cached,
    pub(super) pending: String,
    pub(super) tokens: HashMap<String, Cached>,
}

#[derive(Default)]
pub(super) struct User {
    pub(super) lock: Arc<tokio::sync::Mutex<()>>,
    state: Mutex<State>,
}

impl User {
    pub(super) fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    pub(super) fn forget(&self, key: &str) {
        self.state().tokens.remove(key);
    }

    pub(super) fn set_subject(&self, token: Cached) {
        self.state().subject = token;
    }

    pub(super) fn set_pending(&self, token: String) {
        self.state().pending = token;
    }
}

impl Inner {
    pub(super) fn user(&self, user_id: i64) -> Arc<User> {
        let mut users = self.users.lock().unwrap_or_else(|poison| poison.into_inner());
        users.entry(user_id).or_default().clone()
    }

    pub(super) fn usable(&self, token: &Cached) -> bool {
        !token.value.is_empty() && token.expiry.is_some_and(|expiry| self.now() + self.margin < expiry)
    }

    pub(super) fn cached(&self, user: &User, key: &str) -> Option<String> {
        let state = user.state();
        state.tokens.get(key).filter(|token| self.usable(token)).map(|token| token.value.clone())
    }
}
