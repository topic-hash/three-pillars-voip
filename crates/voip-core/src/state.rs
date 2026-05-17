//! Call state machine from spec/07 §7.3.1.
//!
//! Implements the call lifecycle state machine with transition validation.
//! States: Ringing → Accepted → Connected → Ended, or → Failed.

use crate::error::VoipError;
use crate::types::{CallEndReason, CallState, ConnectionMethod};

/// Result of a state transition attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionResult {
    /// Transition succeeded.
    Ok,
    /// Transition was invalid — the call remains in its current state.
    Invalid {
        from: CallState,
        attempted: CallState,
        reason: &'static str,
    },
}

/// The call state machine.
///
/// Tracks the current state of a call and validates state transitions
/// according to the spec/07 §7.3.1 state machine.
///
/// # State Machine
///
/// ```text
/// Ringing ──accept──→ Accepted
/// Ringing ──fail────→ Failed
/// Accepted ──connect─→ Connected
/// Accepted ──fail────→ Failed
/// Connected ──end────→ Ended
/// Connected ──fail───→ Failed
/// ```
///
/// Once in `Failed` or `Ended`, no further transitions are allowed.
#[derive(Debug, Clone)]
pub struct CallStateMachine {
    /// Current call state.
    state: CallState,
    /// How the P2P connection was established (set when call connects).
    method: Option<ConnectionMethod>,
    /// Reason the call ended or failed.
    end_reason: Option<CallEndReason>,
    /// Number of push-retry attempts (0-3).
    retry_count: u32,
}

impl CallStateMachine {
    /// Creates a new call state machine in the Ringing state.
    pub fn new() -> Self {
        Self {
            state: CallState::Ringing,
            method: None,
            end_reason: None,
            retry_count: 0,
        }
    }

    /// Creates a call state machine at a specific state (for deserialization/testing).
    pub fn from_state(state: CallState) -> Self {
        Self {
            state,
            method: None,
            end_reason: None,
            retry_count: 0,
        }
    }

    /// Returns the current call state.
    pub fn state(&self) -> CallState {
        self.state
    }

    /// Returns the connection method, if the call has been connected.
    pub fn method(&self) -> Option<ConnectionMethod> {
        self.method
    }

    /// Returns the end/failure reason, if the call has ended or failed.
    pub fn end_reason(&self) -> Option<CallEndReason> {
        self.end_reason
    }

    /// Returns the number of push-retry attempts.
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
                attempted: CallState::Accepted,
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
            CallState::Ringing => TransitionResult::Invalid {
                from: self.state,
                attempted: CallState::Connected,
                reason: "Cannot connect from Ringing — must accept first",
            },
            _ => TransitionResult::Invalid {
                from: self.state,
                attempted: CallState::Connected,
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
                attempted: CallState::Ended,
                reason: "Can only end from Connected state",
            },
        }
    }

    /// Transition: Any non-terminal → Failed
    ///
    /// Called when the call fails at any stage.
    pub fn fail(&mut self, reason: CallEndReason) -> TransitionResult {
        match self.state {
            CallState::Ringing | CallState::Accepted | CallState::Connected => {
                self.state = CallState::Failed;
                self.end_reason = Some(reason);
                TransitionResult::Ok
            }
            CallState::Failed => TransitionResult::Invalid {
                from: self.state,
                attempted: CallState::Failed,
                reason: "Call has already failed",
            },
            CallState::Ended => TransitionResult::Invalid {
                from: self.state,
                attempted: CallState::Failed,
                reason: "Call has already ended normally",
            },
        }
    }

    /// Transition: Failed → Ringing (push retry)
    ///
    /// Called when a push retry notification triggers a new connection attempt.
    /// Increments the retry counter. Fails if max retries exceeded.
    pub fn retry(&mut self) -> Result<(), VoipError> {
        match self.state {
            CallState::Failed => {
                if self.retry_count >= 3 {
                    return Err(VoipError::RetryExhausted {
                        attempts: self.retry_count,
                    });
                }
                self.retry_count += 1;
                self.state = CallState::Ringing;
                self.end_reason = None;
                Ok(())
            }
            _ => Err(VoipError::InvalidStateTransition {
                from: self.state,
                to: CallState::Ringing,
                reason: "Can only retry from Failed state",
            }),
        }
    }

    /// Reject the call (convenience method).
    ///
    /// Transitions Ringing → Failed with CallEndReason::Rejected.
    pub fn reject(&mut self) -> TransitionResult {
        self.fail(CallEndReason::Rejected)
    }

    /// Timeout the call (convenience method).
    ///
    /// Transitions Ringing → Failed with CallEndReason::Timeout.
    pub fn timeout(&mut self) -> TransitionResult {
        self.fail(CallEndReason::Timeout)
    }
}

impl Default for CallStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_happy_path() {
        let mut sm = CallStateMachine::new();
        assert_eq!(sm.state(), CallState::Ringing);

        assert_eq!(sm.accept(), TransitionResult::Ok);
        assert_eq!(sm.state(), CallState::Accepted);

        assert_eq!(sm.connect(ConnectionMethod::Ipv6Direct), TransitionResult::Ok);
        assert_eq!(sm.state(), CallState::Connected);
        assert_eq!(sm.method(), Some(ConnectionMethod::Ipv6Direct));

        assert_eq!(sm.end(CallEndReason::Normal), TransitionResult::Ok);
        assert_eq!(sm.state(), CallState::Ended);
        assert_eq!(sm.end_reason(), Some(CallEndReason::Normal));
    }

    #[test]
    fn test_ringing_to_failed() {
        let mut sm = CallStateMachine::new();
        assert_eq!(sm.fail(CallEndReason::Timeout), TransitionResult::Ok);
        assert_eq!(sm.state(), CallState::Failed);
        assert!(sm.is_terminal());
    }

    #[test]
    fn test_accepted_to_failed() {
        let mut sm = CallStateMachine::new();
        sm.accept().unwrap();
        assert_eq!(sm.fail(CallEndReason::FailedIpv4Random), TransitionResult::Ok);
        assert_eq!(sm.state(), CallState::Failed);
    }

    #[test]
    fn test_connected_to_failed() {
        let mut sm = CallStateMachine::new();
        sm.accept().unwrap();
        sm.connect(ConnectionMethod::Masque).unwrap();
        assert_eq!(sm.fail(CallEndReason::FailedNetwork), TransitionResult::Ok);
        assert_eq!(sm.state(), CallState::Failed);
    }

    #[test]
    fn test_invalid_transitions() {
        let mut sm = CallStateMachine::new();

        // Cannot connect from Ringing
        assert!(matches!(
            sm.connect(ConnectionMethod::Ipv6Direct),
            TransitionResult::Invalid { .. }
        ));

        // Cannot end from Ringing
        assert!(matches!(
            sm.end(CallEndReason::Normal),
            TransitionResult::Invalid { .. }
        ));

        // Cannot accept from Connected
        sm.accept().unwrap();
        sm.connect(ConnectionMethod::Ipv6Direct).unwrap();
        assert!(matches!(sm.accept(), TransitionResult::Invalid { .. }));
    }

    #[test]
    fn test_no_transition_from_terminal() {
        let mut sm = CallStateMachine::new();
        sm.fail(CallEndReason::Timeout).unwrap();

        // Cannot transition out of Failed
        assert!(matches!(sm.accept(), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.fail(CallEndReason::Timeout), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.end(CallEndReason::Normal), TransitionResult::Invalid { .. }));
    }

    #[test]
    fn test_no_transition_from_ended() {
        let mut sm = CallStateMachine::new();
        sm.accept().unwrap();
        sm.connect(ConnectionMethod::Ipv6Direct).unwrap();
        sm.end(CallEndReason::Normal).unwrap();

        assert!(matches!(sm.accept(), TransitionResult::Invalid { .. }));
        assert!(matches!(sm.fail(CallEndReason::Timeout), TransitionResult::Invalid { .. }));
    }

    #[test]
    fn test_push_retry() {
        let mut sm = CallStateMachine::new();
        sm.fail(CallEndReason::FailedIpv4Random).unwrap();
        assert_eq!(sm.retry_count(), 0);

        // First retry
        sm.retry().unwrap();
        assert_eq!(sm.state(), CallState::Ringing);
        assert_eq!(sm.retry_count(), 1);

        // Fail again
        sm.fail(CallEndReason::FailedIpv4Random).unwrap();

        // Second retry
        sm.retry().unwrap();
        assert_eq!(sm.retry_count(), 2);

        // Third retry
        sm.fail(CallEndReason::FailedIpv4Random).unwrap();
        sm.retry().unwrap();
        assert_eq!(sm.retry_count(), 3);

        // Fourth retry should fail
        sm.fail(CallEndReason::FailedIpv4Random).unwrap();
        assert!(sm.retry().is_err());
    }

    #[test]
    fn test_reject_convenience() {
        let mut sm = CallStateMachine::new();
        assert_eq!(sm.reject(), TransitionResult::Ok);
        assert_eq!(sm.state(), CallState::Failed);
        assert_eq!(sm.end_reason(), Some(CallEndReason::Rejected));
    }

    #[test]
    fn test_timeout_convenience() {
        let mut sm = CallStateMachine::new();
        assert_eq!(sm.timeout(), TransitionResult::Ok);
        assert_eq!(sm.state(), CallState::Failed);
        assert_eq!(sm.end_reason(), Some(CallEndReason::Timeout));
    }

    #[test]
    fn test_connection_method_recorded() {
        let mut sm = CallStateMachine::new();
        sm.accept().unwrap();

        // Method is None until connected
        assert_eq!(sm.method(), None);

        sm.connect(ConnectionMethod::Ipv4Prediction).unwrap();
        assert_eq!(sm.method(), Some(ConnectionMethod::Ipv4Prediction));

        // Method persists after ending
        sm.end(CallEndReason::Normal).unwrap();
        assert_eq!(sm.method(), Some(ConnectionMethod::Ipv4Prediction));
    }
}
