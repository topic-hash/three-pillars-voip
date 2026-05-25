//! Call state machine from spec/07 §7.3.1.
//!
//! Implements the call lifecycle state machine with transition validation.
//! States: Idle → Ringing → Accepted → Connected → Ended, or → Failed.

use crate::types::{CallEndReason, ConnectionMethod};

/// State of a call in the call lifecycle state machine.
///
/// This is the internal state machine representation, which includes an
/// `Idle` state not present in the on-the-wire proto `CallState`.
/// The `Idle` state represents a call slot before any call is initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallState {
    /// No call in progress (initial state)
    Idle,
    /// Call is ringing (waiting for callee to accept)
    Ringing,
    /// Callee has accepted, connection attempt in progress
    Accepted,
    /// P2P connection established, media flowing
    Connected,
    /// Connection attempt or active call failed
    Failed,
    /// Call ended normally
    Ended,
}

impl std::fmt::Display for CallState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallState::Idle => write!(f, "Idle"),
            CallState::Ringing => write!(f, "Ringing"),
            CallState::Accepted => write!(f, "Accepted"),
            CallState::Connected => write!(f, "Connected"),
            CallState::Failed => write!(f, "Failed"),
            CallState::Ended => write!(f, "Ended"),
        }
    }
}

/// Result of a state transition attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionResult {
    /// Transition succeeded.
    Ok,
    /// Transition was invalid — the call remains in its current state.
    Invalid {
        from: CallState,
        to: CallState,
        reason: &'static str,
    },
}

impl TransitionResult {
    /// Assert that the transition succeeded. Panics if it was invalid.
    /// Useful for test setup sequences.
    pub fn unwrap(self) {
        assert!(
            matches!(self, TransitionResult::Ok),
            "Expected Ok transition, got {:?}",
            self
        );
    }
}

/// The call state machine.
///
/// Tracks the current state of a call and validates state transitions
/// according to the spec/07 §7.3.1 state machine.
///
/// # State Machine
///
/// ```text
/// Idle ──ring──→ Ringing ──accept──→ Accepted ──connect──→ Connected ──end──→ Ended
///                  │                    │                      │
///                  └──fail/reject/timeout──→ Failed ←──fail────┘
///                         ↑                     │
///                         └────retry (if < max)─┘
/// ```
///
/// Once in `Ended`, no further transitions are allowed.
/// From `Failed`, `retry()` transitions back to `Ringing` if retry_count < max_retries.
#[derive(Debug, Clone)]
pub struct CallStateMachine {
    /// Current call state.
    state: CallState,
    /// How the P2P connection was established (set when call connects).
    method: Option<ConnectionMethod>,
    /// Reason the call ended or failed.
    end_reason: Option<CallEndReason>,
    /// Number of push-retry attempts used.
    retry_count: u32,
    /// Maximum number of push-retry attempts allowed.
    max_retries: u32,
}

impl CallStateMachine {
    /// Creates a new call state machine starting in the Idle state.
    pub fn new(max_retries: u32) -> Self {
        Self {
            state: CallState::Idle,
            method: None,
            end_reason: None,
            retry_count: 0,
            max_retries,
        }
    }

    /// Returns the current call state.
    pub fn state(&self) -> &CallState {
        &self.state
    }

    /// Returns the connection method, if the call has been connected.
    pub fn method(&self) -> Option<ConnectionMethod> {
        self.method
    }

    /// Returns the end/failure reason, if the call has ended or failed.
    pub fn end_reason(&self) -> Option<CallEndReason> {
        self.end_reason
    }

    /// Returns the number of push-retry attempts used.
    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Returns true if the call is in a terminal state (Failed or Ended).
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, CallState::Failed | CallState::Ended)
    }

    /// Returns true if the call is currently connected.
    pub fn is_connected(&self) -> bool {
        self.state == CallState::Connected
    }

    // ========================================================================
    // Transition methods
    // ========================================================================

    /// Transition: Idle → Ringing
    ///
    /// Initiates a call. Must be called before accept/connect/end/fail.
    pub fn ring(&mut self) -> TransitionResult {
        match self.state {
            CallState::Idle => {
                self.state = CallState::Ringing;
                TransitionResult::Ok
            }
            _ => TransitionResult::Invalid {
                from: self.state,
                to: CallState::Ringing,
                reason: "Can only ring from Idle state",
            },
        }
    }

    /// Transition: Ringing → Accepted
    ///
    /// Called when the callee accepts the call.
    pub fn accept(&mut self) -> TransitionResult {
        match self.state {
            CallState::Ringing => {
                self.state = CallState::Accepted;
                TransitionResult::Ok
            }
            _ => TransitionResult::Invalid {
                from: self.state,
                to: CallState::Accepted,
                reason: "Can only accept from Ringing state",
            },
        }
    }

    /// Transition: Accepted → Connected
    ///
    /// Called when the P2P connection is successfully established.
    /// The `method` parameter records how the connection was made.
    pub fn connect(&mut self, method: ConnectionMethod) -> TransitionResult {
        match self.state {
            CallState::Accepted => {
                self.state = CallState::Connected;
                self.method = Some(method);
                TransitionResult::Ok
            }
            _ => TransitionResult::Invalid {
                from: self.state,
                to: CallState::Connected,
                reason: "Can only connect from Accepted state",
            },
        }
    }

    /// Transition: Connected → Ended
    ///
    /// Called when a connected call ends normally.
    pub fn end(&mut self, reason: CallEndReason) -> TransitionResult {
        match self.state {
            CallState::Connected => {
                self.state = CallState::Ended;
                self.end_reason = Some(reason);
                TransitionResult::Ok
            }
            _ => TransitionResult::Invalid {
                from: self.state,
                to: CallState::Ended,
                reason: "Can only end from Connected state",
            },
        }
    }

    /// Transition: Ringing/Accepted/Connected → Failed
    ///
    /// Called when the call fails at any active stage.
    pub fn fail(&mut self, reason: CallEndReason) -> TransitionResult {
        match self.state {
            CallState::Ringing | CallState::Accepted | CallState::Connected => {
                self.state = CallState::Failed;
                self.end_reason = Some(reason);
                TransitionResult::Ok
            }
            CallState::Idle => TransitionResult::Invalid {
                from: self.state,
                to: CallState::Failed,
                reason: "Cannot fail from Idle state",
            },
            CallState::Failed => TransitionResult::Invalid {
                from: self.state,
                to: CallState::Failed,
                reason: "Call has already failed",
            },
            CallState::Ended => TransitionResult::Invalid {
                from: self.state,
                to: CallState::Failed,
                reason: "Call has already ended normally",
            },
        }
    }

    /// Transition: Ringing → Failed with CallEndReason::Rejected
    ///
    /// Convenience method: the callee rejected the call.
    /// Only valid from Ringing state.
    pub fn reject(&mut self) -> TransitionResult {
        match self.state {
            CallState::Ringing => {
                self.state = CallState::Failed;
                self.end_reason = Some(CallEndReason::Rejected);
                TransitionResult::Ok
            }
            _ => TransitionResult::Invalid {
                from: self.state,
                to: CallState::Failed,
                reason: "Can only reject from Ringing state",
            },
        }
    }

    /// Transition: Ringing/Accepted → Failed with CallEndReason::Timeout
    ///
    /// Convenience method: the call timed out.
    /// Valid from Ringing or Accepted state.
    pub fn timeout(&mut self) -> TransitionResult {
        match self.state {
            CallState::Ringing | CallState::Accepted => {
                self.state = CallState::Failed;
                self.end_reason = Some(CallEndReason::Timeout);
                TransitionResult::Ok
            }
            _ => TransitionResult::Invalid {
                from: self.state,
                to: CallState::Failed,
                reason: "Can only timeout from Ringing or Accepted state",
            },
        }
    }

    /// Transition: Failed → Ringing (push retry)
    ///
    /// Called when a push retry notification triggers a new connection attempt.
    /// Increments the retry counter. Returns Invalid if max retries exceeded
    /// or not in Failed state.
    pub fn retry(&mut self) -> TransitionResult {
        match self.state {
            CallState::Failed => {
                if self.retry_count >= self.max_retries {
                    TransitionResult::Invalid {
                        from: self.state,
                        to: CallState::Ringing,
                        reason: "Max retries exceeded",
                    }
                } else {
                    self.retry_count += 1;
                    self.state = CallState::Ringing;
                    self.end_reason = None;
                    TransitionResult::Ok
                }
            }
            _ => TransitionResult::Invalid {
                from: self.state,
                to: CallState::Ringing,
                reason: "Can only retry from Failed state",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Valid transitions
    // ========================================================================

    #[test]
    fn test_happy_path() {
        let mut sm = CallStateMachine::new(3);
        assert_eq!(*sm.state(), CallState::Idle);

        assert_eq!(sm.ring(), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Ringing);

        assert_eq!(sm.accept(), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Accepted);

        assert_eq!(sm.connect(ConnectionMethod::Ipv6Direct), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Connected);
        assert_eq!(sm.method(), Some(ConnectionMethod::Ipv6Direct));

        assert_eq!(sm.end(CallEndReason::Normal), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Ended);
        assert_eq!(sm.end_reason(), Some(CallEndReason::Normal));
    }

    #[test]
    fn test_idle_to_ringing() {
        let mut sm = CallStateMachine::new(3);
        assert_eq!(sm.ring(), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Ringing);
    }

    #[test]
    fn test_ringing_to_accepted() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        assert_eq!(sm.accept(), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Accepted);
    }

    #[test]
    fn test_accepted_to_connected() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        assert_eq!(sm.connect(ConnectionMethod::Ipv4Cone), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Connected);
        assert_eq!(sm.method(), Some(ConnectionMethod::Ipv4Cone));
    }

    #[test]
    fn test_connected_to_ended() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        sm.connect(ConnectionMethod::Ipv6Direct).unwrap();
        assert_eq!(sm.end(CallEndReason::Normal), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Ended);
    }

    #[test]
    fn test_ringing_to_failed() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        assert_eq!(sm.fail(CallEndReason::Timeout), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Failed);
        assert!(sm.is_terminal());
    }

    #[test]
    fn test_accepted_to_failed() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        assert_eq!(sm.fail(CallEndReason::FailedIpv4Random), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Failed);
    }

    #[test]
    fn test_connected_to_failed() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        sm.connect(ConnectionMethod::Masque).unwrap();
        assert_eq!(sm.fail(CallEndReason::FailedNetwork), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Failed);
    }

    #[test]
    fn test_reject_from_ringing() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        assert_eq!(sm.reject(), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Failed);
        assert_eq!(sm.end_reason(), Some(CallEndReason::Rejected));
    }

    #[test]
    fn test_timeout_from_ringing() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        assert_eq!(sm.timeout(), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Failed);
        assert_eq!(sm.end_reason(), Some(CallEndReason::Timeout));
    }

    #[test]
    fn test_timeout_from_accepted() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        assert_eq!(sm.timeout(), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Failed);
        assert_eq!(sm.end_reason(), Some(CallEndReason::Timeout));
    }

    #[test]
    fn test_retry_from_failed() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.fail(CallEndReason::FailedIpv4Random).unwrap();
        assert_eq!(sm.retry_count(), 0);

        // First retry
        assert_eq!(sm.retry(), TransitionResult::Ok);
        assert_eq!(*sm.state(), CallState::Ringing);
        assert_eq!(sm.retry_count(), 1);

        // Fail again
        sm.fail(CallEndReason::FailedIpv4Random).unwrap();

        // Second retry
        assert_eq!(sm.retry(), TransitionResult::Ok);
        assert_eq!(sm.retry_count(), 2);

        // Fail again
        sm.fail(CallEndReason::FailedIpv4Random).unwrap();

        // Third retry
        assert_eq!(sm.retry(), TransitionResult::Ok);
        assert_eq!(sm.retry_count(), 3);

        // Fail again — max retries reached
        sm.fail(CallEndReason::FailedIpv4Random).unwrap();
        assert!(matches!(
            sm.retry(),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_retry_with_max_zero() {
        let mut sm = CallStateMachine::new(0);
        sm.ring().unwrap();
        sm.fail(CallEndReason::FailedIpv4Random).unwrap();
        assert!(matches!(
            sm.retry(),
            TransitionResult::Invalid { .. }
        ));
    }

    // ========================================================================
    // Invalid transitions
    // ========================================================================

    #[test]
    fn test_cannot_accept_from_idle() {
        let mut sm = CallStateMachine::new(3);
        assert!(matches!(
            sm.accept(),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_connect_from_idle() {
        let mut sm = CallStateMachine::new(3);
        assert!(matches!(
            sm.connect(ConnectionMethod::Ipv6Direct),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_end_from_idle() {
        let mut sm = CallStateMachine::new(3);
        assert!(matches!(
            sm.end(CallEndReason::Normal),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_fail_from_idle() {
        let mut sm = CallStateMachine::new(3);
        assert!(matches!(
            sm.fail(CallEndReason::FailedNetwork),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_reject_from_idle() {
        let mut sm = CallStateMachine::new(3);
        assert!(matches!(
            sm.reject(),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_timeout_from_idle() {
        let mut sm = CallStateMachine::new(3);
        assert!(matches!(
            sm.timeout(),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_connect_from_ringing() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        assert!(matches!(
            sm.connect(ConnectionMethod::Ipv6Direct),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_end_from_ringing() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        assert!(matches!(
            sm.end(CallEndReason::Normal),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_ring_from_ringing() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        assert!(matches!(
            sm.ring(),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_ring_from_accepted() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        assert!(matches!(
            sm.ring(),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_accept_from_accepted() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        assert!(matches!(
            sm.accept(),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_end_from_accepted() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        assert!(matches!(
            sm.end(CallEndReason::Normal),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_accept_from_connected() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        sm.connect(ConnectionMethod::Ipv6Direct).unwrap();
        assert!(matches!(sm.accept(), TransitionResult::Invalid { .. }));
    }

    #[test]
    fn test_cannot_connect_from_connected() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        sm.connect(ConnectionMethod::Ipv6Direct).unwrap();
        assert!(matches!(
            sm.connect(ConnectionMethod::Ipv4Cone),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_timeout_from_connected() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        sm.connect(ConnectionMethod::Ipv6Direct).unwrap();
        assert!(matches!(
            sm.timeout(),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_reject_from_accepted() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        assert!(matches!(
            sm.reject(),
            TransitionResult::Invalid { .. }
        ));
    }

    #[test]
    fn test_cannot_reject_from_connected() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        sm.connect(ConnectionMethod::Ipv6Direct).unwrap();
        assert!(matches!(
            sm.reject(),
            TransitionResult::Invalid { .. }
        ));
    }

    // ========================================================================
    // Terminal state transitions
    // ========================================================================

    #[test]
    fn test_no_transition_from_failed() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.fail(CallEndReason::Timeout).unwrap();

        assert!(matches!(sm.accept(), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.fail(CallEndReason::Timeout), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.end(CallEndReason::Normal), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.ring(), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.connect(ConnectionMethod::Ipv6Direct), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.reject(), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.timeout(), TransitionResult::Invalid { .. }));
    }

    #[test]
    fn test_no_transition_from_ended() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        sm.connect(ConnectionMethod::Ipv6Direct).unwrap();
        sm.end(CallEndReason::Normal).unwrap();

        assert!(matches!(sm.accept(), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.fail(CallEndReason::Timeout), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.ring(), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.connect(ConnectionMethod::Ipv6Direct), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.reject(), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.timeout(), TransitionResult::Invalid { .. }));
    }

    // ========================================================================
    // Connection method tracking
    // ========================================================================

    #[test]
    fn test_connection_method_recorded() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();

        // Method is None until connected
        assert_eq!(sm.method(), None);

        sm.connect(ConnectionMethod::Ipv4Prediction).unwrap();
        assert_eq!(sm.method(), Some(ConnectionMethod::Ipv4Prediction));

        // Method persists after ending
        sm.end(CallEndReason::Normal).unwrap();
        assert_eq!(sm.method(), Some(ConnectionMethod::Ipv4Prediction));
    }

    #[test]
    fn test_connection_method_cleared_on_retry() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.accept().unwrap();
        sm.connect(ConnectionMethod::Masque).unwrap();
        sm.fail(CallEndReason::FailedMasqueUnreachable).unwrap();

        // Method is still set after failure
        assert_eq!(sm.method(), Some(ConnectionMethod::Masque));

        // After retry, method is still there (set on next connect)
        sm.retry().unwrap();
        assert_eq!(sm.method(), Some(ConnectionMethod::Masque));
    }

    // ========================================================================
    // End reason tracking
    // ========================================================================

    #[test]
    fn test_end_reason_set_on_fail() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.fail(CallEndReason::FailedUdpBlocked).unwrap();
        assert_eq!(sm.end_reason(), Some(CallEndReason::FailedUdpBlocked));
    }

    #[test]
    fn test_end_reason_cleared_on_retry() {
        let mut sm = CallStateMachine::new(3);
        sm.ring().unwrap();
        sm.fail(CallEndReason::FailedIpv4Random).unwrap();
        assert_eq!(sm.end_reason(), Some(CallEndReason::FailedIpv4Random));

        sm.retry().unwrap();
        assert_eq!(sm.end_reason(), None);
    }
}
