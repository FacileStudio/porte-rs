use time::{Duration, OffsetDateTime};

use super::deletions::Deletions;
use super::state::DeletionState;
use super::{Deleted, DirectoryError};

const LIST_LIMIT: usize = 1000;

#[derive(Default)]
struct PollResult {
    handled: Vec<OffsetDateTime>,
    failed: Option<OffsetDateTime>,
    errors: Vec<DirectoryError>,
}

impl Deletions {
    /// Pages through every deletion since the cursor, erases each person once, and advances the
    /// cursor only past people handled before the earliest failure. Every failure is returned.
    pub async fn poll(&self) -> Result<(), DirectoryError> {
        let mut slot = self.inner.state.lock().await;
        let mut state = self.load(&mut slot).await?;
        let mut result = self.drain(&mut slot, &mut state).await;
        if slot.is_none() {
            return joined(result.errors);
        }
        if let Some(cursor) = cursor_after(&result.handled, result.failed)
            && state.cursor.is_none_or(|current| cursor > current)
        {
            state.cursor = Some(cursor);
            if let Err(error) = self.persist(&mut slot, &state).await {
                result.errors.push(error);
            }
        }
        joined(result.errors)
    }

    async fn drain(&self, slot: &mut Option<DeletionState>, state: &mut DeletionState) -> PollResult {
        let mut result = PollResult::default();
        let mut since = state.since();
        loop {
            let list = match self.inner.client.deletions(since).await {
                Ok(list) => list,
                Err(error) => {
                    result.errors.push(error);
                    return result;
                }
            };
            self.handle_all(state, &list, &mut result).await;
            if let Err(error) = self.persist(slot, state).await {
                result.errors.push(error);
                return result;
            }
            match next_page(&list, since) {
                Ok(Some(next)) => since = next,
                Ok(None) => return result,
                Err(error) => {
                    result.errors.push(error);
                    return result;
                }
            }
        }
    }

    async fn handle_all(&self, state: &mut DeletionState, list: &[Deleted], result: &mut PollResult) {
        for person in list {
            match self.handle(state, &person.subject).await {
                Ok(()) => result.handled.push(person.deleted_at),
                Err(error) => {
                    result.errors.push(error);
                    result.failed = Some(result.failed.map_or(person.deleted_at, |at| at.min(person.deleted_at)));
                }
            }
        }
    }
}

fn next_page(list: &[Deleted], since: OffsetDateTime) -> Result<Option<OffsetDateTime>, DirectoryError> {
    let Some(last) = list.last().filter(|_| list.len() >= LIST_LIMIT) else { return Ok(None) };
    let next = last.deleted_at - Duration::microseconds(1);
    if next <= since {
        return Err(DirectoryError::Failed(format!(
            "{LIST_LIMIT} or more deletion notices share one timestamp, the rest cannot be listed"
        )));
    }
    Ok(Some(next))
}

fn cursor_after(handled: &[OffsetDateTime], failed: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
    handled.iter().copied().filter(|at| failed.is_none_or(|failed| *at < failed)).max()
}

fn joined(errors: Vec<DirectoryError>) -> Result<(), DirectoryError> {
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.into_iter().next().unwrap_or(DirectoryError::Failed(String::new()))),
        _ => Err(DirectoryError::Failed(errors.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n"))),
    }
}
