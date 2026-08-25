//! Replay-safe retry decisions independent from transport implementation.
#![allow(missing_docs, clippy::struct_excessive_bools)]

use std::time::Duration;

use gateway_domain::Portability;

/// Stable failure classes consumed by retry policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryErrorClass {
    /// OAuth access token was rejected.
    Authentication401,
    /// Upstream rate limit response.
    RateLimited429,
    /// Upstream overload response.
    Overloaded529,
    /// Other retryable upstream 5xx response.
    Upstream5xx,
    /// DNS/TCP/TLS/HTTP failure before response commit.
    NetworkBeforeCommit,
    /// Final client request error.
    FinalClient4xx,
    /// Other final failure.
    Other,
}

/// Credential strategy for a permitted Messages retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryStrategy {
    /// Refresh and retry the current Credential first.
    RefreshSameCredential,
    /// Rebuild from the credential-neutral request for another Credential.
    SwitchCredential,
    /// Retry the same Credential after bounded backoff.
    SameCredential,
}

/// Complete retry inputs frozen at the failure boundary.
#[derive(Clone, Debug)]
pub struct RetryContext<'a> {
    pub error: RetryErrorClass,
    pub portability: &'a Portability,
    pub response_committed: bool,
    pub body_replayable: bool,
    pub messages_attempts: u8,
    pub refresh_already_attempted: bool,
    pub same_credential_available: bool,
    pub alternate_credential_available: bool,
    pub remaining_deadline: Duration,
    pub min_retry_budget: Duration,
    pub proposed_backoff: Duration,
}

/// Auditable retry result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryDecision {
    pub allowed: bool,
    pub strategy: Option<RetryStrategy>,
    pub backoff: Duration,
    pub remaining_attempts: u8,
    pub reason: &'static str,
}

/// Three-attempt connection budget, independent from Messages submission attempts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionAttemptBudget {
    attempts: u8,
}

impl ConnectionAttemptBudget {
    /// Reserve the next DNS/TCP/TLS/HTTP connection attempt.
    pub fn begin(&mut self) -> bool {
        if self.attempts >= 3 {
            return false;
        }
        self.attempts += 1;
        true
    }

    /// Number of reserved connection attempts.
    #[must_use]
    pub fn attempts(self) -> u8 {
        self.attempts
    }
}

/// Evaluate a Messages retry. Connection-attempt accounting is deliberately separate.
#[must_use]
pub fn decide_retry(context: &RetryContext<'_>) -> RetryDecision {
    let attempts_left = 3_u8.saturating_sub(context.messages_attempts);
    if context.response_committed {
        return denied(attempts_left, "response_committed");
    }
    if !context.body_replayable {
        return denied(attempts_left, "body_not_replayable");
    }
    if attempts_left == 0 {
        return denied(0, "messages_attempt_budget_exhausted");
    }
    if context.remaining_deadline < context.min_retry_budget
        || context.proposed_backoff.saturating_add(context.min_retry_budget) > context.remaining_deadline
    {
        return denied(attempts_left, "insufficient_deadline");
    }

    let portable = matches!(context.portability, Portability::Portable);
    let strategy = match context.error {
        RetryErrorClass::Authentication401 if !context.refresh_already_attempted => {
            Some(RetryStrategy::RefreshSameCredential)
        }
        RetryErrorClass::Authentication401
        | RetryErrorClass::RateLimited429
        | RetryErrorClass::Overloaded529
        | RetryErrorClass::Upstream5xx
        | RetryErrorClass::NetworkBeforeCommit
            if portable && context.alternate_credential_available =>
        {
            Some(RetryStrategy::SwitchCredential)
        }
        RetryErrorClass::RateLimited429
        | RetryErrorClass::Overloaded529
        | RetryErrorClass::Upstream5xx
        | RetryErrorClass::NetworkBeforeCommit
            if context.same_credential_available =>
        {
            Some(RetryStrategy::SameCredential)
        }
        RetryErrorClass::FinalClient4xx
        | RetryErrorClass::Other
        | RetryErrorClass::Authentication401
        | RetryErrorClass::RateLimited429
        | RetryErrorClass::Overloaded529
        | RetryErrorClass::Upstream5xx
        | RetryErrorClass::NetworkBeforeCommit => None,
    };

    strategy.map_or_else(
        || denied(attempts_left, "no_retry_candidate"),
        |strategy| RetryDecision {
            allowed: true,
            strategy: Some(strategy),
            backoff: if strategy == RetryStrategy::SameCredential {
                context.proposed_backoff
            } else {
                Duration::ZERO
            },
            remaining_attempts: attempts_left,
            reason: "retry_allowed",
        },
    )
}

fn denied(remaining_attempts: u8, reason: &'static str) -> RetryDecision {
    RetryDecision {
        allowed: false,
        strategy: None,
        backoff: Duration::ZERO,
        remaining_attempts,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use gateway_domain::Portability;

    use super::{ConnectionAttemptBudget, RetryContext, RetryErrorClass, RetryStrategy, decide_retry};

    #[test]
    fn authentication_retries_same_credential_then_switches() {
        let portability = Portability::Portable;
        let mut context = RetryContext {
            error: RetryErrorClass::Authentication401,
            portability: &portability,
            response_committed: false,
            body_replayable: true,
            messages_attempts: 1,
            refresh_already_attempted: false,
            same_credential_available: true,
            alternate_credential_available: true,
            remaining_deadline: Duration::from_secs(30),
            min_retry_budget: Duration::from_secs(5),
            proposed_backoff: Duration::ZERO,
        };
        assert_eq!(
            decide_retry(&context).strategy,
            Some(RetryStrategy::RefreshSameCredential)
        );
        context.refresh_already_attempted = true;
        assert_eq!(decide_retry(&context).strategy, Some(RetryStrategy::SwitchCredential));
        assert_eq!(decide_retry(&context).backoff, Duration::ZERO);
    }

    #[test]
    fn switching_credential_never_inherits_the_failed_credential_backoff() {
        let portability = Portability::Portable;
        let context = RetryContext {
            error: RetryErrorClass::RateLimited429,
            portability: &portability,
            response_committed: false,
            body_replayable: true,
            messages_attempts: 1,
            refresh_already_attempted: false,
            same_credential_available: true,
            alternate_credential_available: true,
            remaining_deadline: Duration::from_mins(1),
            min_retry_budget: Duration::from_secs(5),
            proposed_backoff: Duration::from_secs(30),
        };
        let decision = decide_retry(&context);
        assert_eq!(decision.strategy, Some(RetryStrategy::SwitchCredential));
        assert_eq!(decision.backoff, Duration::ZERO);
    }

    #[test]
    fn commit_attempt_and_deadline_are_hard_retry_fences() {
        let portability = Portability::Portable;
        let mut context = RetryContext {
            error: RetryErrorClass::NetworkBeforeCommit,
            portability: &portability,
            response_committed: true,
            body_replayable: true,
            messages_attempts: 1,
            refresh_already_attempted: false,
            same_credential_available: true,
            alternate_credential_available: true,
            remaining_deadline: Duration::from_secs(30),
            min_retry_budget: Duration::from_secs(5),
            proposed_backoff: Duration::ZERO,
        };
        assert!(!decide_retry(&context).allowed);
        context.response_committed = false;
        context.messages_attempts = 3;
        assert!(!decide_retry(&context).allowed);
        context.messages_attempts = 1;
        context.remaining_deadline = Duration::from_secs(4);
        assert!(!decide_retry(&context).allowed);
    }

    #[test]
    fn connection_attempt_budget_is_independent_and_capped_at_three() {
        let mut budget = ConnectionAttemptBudget::default();
        assert!(budget.begin());
        assert!(budget.begin());
        assert!(budget.begin());
        assert!(!budget.begin());
        assert_eq!(budget.attempts(), 3);
    }
}
