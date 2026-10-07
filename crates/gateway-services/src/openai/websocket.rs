//! Per-connection serial turn accounting, independent of socket implementation.

use super::OpenAiError;

/// One downstream connection owns one upstream account and one active response.
#[derive(Debug, Default)]
pub struct WebSocketSession {
    account: Option<String>,
    turn: Option<Turn>,
    next_turn: u64,
}

#[derive(Debug)]
struct Turn {
    id: u64,
    committed: bool,
}

impl WebSocketSession {
    /// Begin a turn only after the caller has obtained fresh permissions and a Lease.
    ///
    /// # Errors
    /// Rejects concurrent turns and account switching on an established connection.
    pub fn begin(&mut self, account: &str) -> Result<u64, OpenAiError> {
        if self.turn.is_some() || account.is_empty() {
            return Err(OpenAiError::InvalidRequest);
        }
        if self.account.as_deref().is_some_and(|bound| bound != account) {
            return Err(OpenAiError::ContinuationUnavailable);
        }
        let id = self.next_turn.checked_add(1).ok_or(OpenAiError::InvalidRequest)?;
        self.next_turn = id;
        self.account = Some(account.to_owned());
        self.turn = Some(Turn { id, committed: false });
        Ok(id)
    }

    /// Mark the first client-visible event; this permanently fences replay for the turn.
    ///
    /// # Errors
    /// Rejects stale events from earlier turns.
    pub fn commit(&mut self, id: u64) -> Result<(), OpenAiError> {
        let turn = self
            .turn
            .as_mut()
            .filter(|turn| turn.id == id)
            .ok_or(OpenAiError::InvalidRequest)?;
        turn.committed = true;
        Ok(())
    }

    /// A retry still needs the request portability check and bounded retry budget.
    #[must_use]
    pub fn replay_allowed(&self, id: u64) -> bool {
        self.turn.as_ref().is_some_and(|turn| turn.id == id && !turn.committed)
    }

    /// Finish or cancel exactly once. The caller releases execution resources on true.
    pub fn finish(&mut self, id: u64) -> bool {
        if self.turn.as_ref().is_some_and(|turn| turn.id == id) {
            self.turn = None;
            true
        } else {
            false
        }
    }

    /// Idle connections retain account affinity, but no executing turn.
    #[must_use]
    pub fn idle(&self) -> bool {
        self.turn.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_turns_commit_fence_and_idempotent_release() -> Result<(), OpenAiError> {
        let mut session = WebSocketSession::default();
        let first = session.begin("account-a")?;
        assert!(session.begin("account-a").is_err());
        assert!(session.replay_allowed(first));
        session.commit(first)?;
        assert!(!session.replay_allowed(first));
        assert!(session.finish(first));
        assert!(!session.finish(first));
        assert!(session.idle());
        assert_eq!(session.begin("account-b"), Err(OpenAiError::ContinuationUnavailable));
        let second = session.begin("account-a")?;
        assert!(!session.finish(first));
        assert!(session.finish(second));
        Ok(())
    }
}
