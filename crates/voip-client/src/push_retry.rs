//! Push notification retry for failed connections.
//!
//! Per spec: when NAT prediction fails (both random), send PushRetry
//! to the signaling server which forwards it to the peer. This triggers
//! the peer to retry the call, possibly from a different network path.
//!
//! The retry uses exponential backoff: 5s, 15s, 45s (configurable).
//! Maximum retry attempts: 3 (configurable via VoIPConfig).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use tracing::{info, instrument, warn};

use voip_core::VoIPConfig;
use voip_core::types::CallEndReason;

use crate::error::ClientError;

// =============================================================================
// Push Retry Handler
// =============================================================================

/// Push notification retry for failed connections.
///
/// Per spec: when NAT prediction fails (both random), send PushRetry
/// to the signaling server which forwards it to the peer.
pub struct PushRetryHandler {
    /// VoIP configuration
    config: Arc<VoIPConfig>,
    /// Current retry attempt count
    retry_count: u32,
    /// Time of last retry
    last_retry: Option<Instant>,
}

impl PushRetryHandler {
    /// Create a new PushRetryHandler.
    pub fn new(config: Arc<VoIPConfig>) -> Self {
        Self {
            config,
            retry_count: 0,
            last_retry: None,
        }
    }

    /// Check if retry is possible (not exceeded max attempts).
    pub fn can_retry(&self) -> bool {
        self.retry_count < self.config.push_retry_max_attempts
    }

    /// Get the number of retry attempts made so far.
    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Get the delay before the next retry attempt.
    ///
    /// Uses exponential backoff based on the next attempt number:
    /// - Attempt 1: 5s  (initial_delay)
    /// - Attempt 2: 15s (initial_delay × backoff_multiplier)
    /// - Attempt 3: 45s (initial_delay × backoff_multiplier²)
    pub fn next_retry_delay(&self) -> Duration {
        let next_attempt = self.retry_count + 1;
        let delay_secs = self.config.retry_delay_secs(next_attempt);
        Duration::from_secs(delay_secs)
    }

    /// Record a retry attempt.
    pub fn record_retry(&mut self) {
        self.last_retry = Some(Instant::now());
        self.retry_count += 1;
        info!(
            attempt = self.retry_count,
            max_attempts = self.config.push_retry_max_attempts,
            "Retry attempt recorded"
        );
    }

    /// Create a PushRetry protobuf message.
    ///
    /// # Arguments
    ///
    /// * `call_id` — UUID of the call
    /// * `peer_id` — ID of the peer to notify
    /// * `reason` — Why the connection failed
    pub fn create_push_retry_message(
        &self,
        call_id: &str,
        peer_id: &str,
        reason: CallEndReason,
    ) -> voip_core::proto::signaling::PushRetry {
        let delay_ms = self.next_retry_delay().as_millis() as u64;

        voip_core::proto::signaling::PushRetry {
            call_id: call_id.to_string(),
            caller_id: String::new(), // Set by signaling server
            callee_id: peer_id.to_string(),
            reason: reason as i32,
            retry_attempt: self.retry_count + 1,
            retry_after_ms: delay_ms,
        }
    }

    /// Reset the retry state (e.g., after a successful connection).
    pub fn reset(&mut self) {
        self.retry_count = 0;
        self.last_retry = None;
        info!("Push retry state reset");
    }

    /// Get the time of the last retry attempt.
    pub fn last_retry(&self) -> Option<Instant> {
        self.last_retry
    }

    /// Get a reference to the config.
    pub fn config(&self) -> &VoIPConfig {
        &self.config
    }
}

// =============================================================================
// Retry Scheduler
// =============================================================================

/// Auto-retry scheduler with exponential backoff.
///
/// Schedules retry attempts at: 5s, 15s, 45s (configurable).
/// The scheduler runs in a background tokio task.
pub struct RetryScheduler {
    /// The retry handler that manages state
    handler: PushRetryHandler,
    /// Active scheduled retry task
    retry_task: Option<JoinHandle<()>>,
}

impl RetryScheduler {
    /// Create a new RetryScheduler.
    pub fn new(config: Arc<VoIPConfig>) -> Self {
        Self {
            handler: PushRetryHandler::new(config),
            retry_task: None,
        }
    }

    /// Schedule a retry attempt after the appropriate backoff delay.
    ///
    /// # Arguments
    ///
    /// * `call_id` — UUID of the call
    /// * `peer_id` — ID of the peer to retry
    /// * `reason` — Why the connection failed
    ///
    /// # Returns
    ///
    /// Ok(()) if the retry was scheduled, or an error if retries
    /// are exhausted or push retry is disabled.
    #[instrument(name = "schedule_retry", skip(self, call_id, peer_id))]
    pub async fn schedule_retry(
        &mut self,
        call_id: &str,
        peer_id: &str,
        reason: CallEndReason,
    ) -> Result<(), ClientError> {
        // Check if push retry is enabled
        if !self.handler.config().push_retry_enabled {
            return Err(ClientError::SignalingError(
                "Push retry is disabled".to_string(),
            ));
        }

        // Check if we can still retry
        if !self.handler.can_retry() {
            warn!(
                attempts = self.handler.retry_count(),
                max = self.handler.config().push_retry_max_attempts,
                "Max retry attempts exhausted"
            );
            return Err(ClientError::CallSetupTimeout(
                "Max retry attempts exhausted".to_string(),
            ));
        }

        // Only retry for appropriate reasons
        if !reason.should_retry() {
            warn!(
                reason = ?reason,
                "Reason does not warrant push retry"
            );
            return Err(ClientError::SignalingError(format!(
                "Reason {:?} does not warrant push retry",
                reason
            )));
        }

        // Cancel any existing retry task
        self.cancel();

        // Get the delay for this attempt
        let delay = self.handler.next_retry_delay();

        // Create the PushRetry message before spawning the task
        let push_msg = self.handler.create_push_retry_message(call_id, peer_id, reason);
        let retry_attempt = self.handler.retry_count() + 1;

        info!(
            attempt = retry_attempt,
            delay_secs = delay.as_secs(),
            call_id = %push_msg.call_id,
            peer_id = %push_msg.callee_id,
            "Scheduling push retry"
        );

        // Record the retry
        self.handler.record_retry();

        // Spawn a background task that waits and then performs the retry.
        // In a full implementation, this would send the PushRetry message
        // to the signaling server via QUIC/WebSocket.
        let task_call_id = call_id.to_string();
        let task_peer_id = peer_id.to_string();
        let task_attempt = retry_attempt;

        let handle = tokio::spawn(async move {
            tokio::time::sleep(delay).await;

            // In production, this would send the PushRetry message to the
            // signaling server. For now, we log the attempt.
            info!(
                attempt = task_attempt,
                call_id = %task_call_id,
                peer_id = %task_peer_id,
                "Push retry triggered (would send to signaling server)"
            );

            // The actual sending logic would be:
            // signaling_client.send_push_retry(push_msg).await
        });

        self.retry_task = Some(handle);

        Ok(())
    }

    /// Cancel any pending retry.
    pub fn cancel(&mut self) {
        if let Some(handle) = self.retry_task.take() {
            handle.abort();
            info!("Pending retry cancelled");
        }
    }

    /// Get a reference to the underlying handler.
    pub fn handler(&self) -> &PushRetryHandler {
        &self.handler
    }

    /// Get a mutable reference to the underlying handler.
    pub fn handler_mut(&mut self) -> &mut PushRetryHandler {
        &mut self.handler
    }

    /// Reset the retry state and cancel any pending retry.
    pub fn reset(&mut self) {
        self.cancel();
        self.handler.reset();
    }
}

impl Drop for RetryScheduler {
    fn drop(&mut self) {
        self.cancel();
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_retry_handler_new() {
        let config = Arc::new(VoIPConfig::default());
        let handler = PushRetryHandler::new(config);

        assert_eq!(handler.retry_count(), 0);
        assert!(handler.can_retry());
        assert!(handler.last_retry().is_none());
    }

    #[test]
    fn test_can_retry_within_max_attempts() {
        let config = Arc::new(VoIPConfig::default());
        let mut handler = PushRetryHandler::new(config);

        assert!(handler.can_retry());

        handler.record_retry(); // attempt 1
        assert!(handler.can_retry());

        handler.record_retry(); // attempt 2
        assert!(handler.can_retry());

        handler.record_retry(); // attempt 3
        assert!(!handler.can_retry()); // max reached
    }

    #[test]
    fn test_next_retry_delay_exponential_backoff() {
        let config = Arc::new(VoIPConfig::default());
        let mut handler = PushRetryHandler::new(config);

        // Default: 5s, 15s, 45s
        assert_eq!(handler.next_retry_delay(), Duration::from_secs(5));

        handler.record_retry(); // attempt 1
        assert_eq!(handler.next_retry_delay(), Duration::from_secs(15));

        handler.record_retry(); // attempt 2
        assert_eq!(handler.next_retry_delay(), Duration::from_secs(45));
    }

    #[test]
    fn test_record_retry() {
        let config = Arc::new(VoIPConfig::default());
        let mut handler = PushRetryHandler::new(config);

        assert_eq!(handler.retry_count(), 0);
        assert!(handler.last_retry().is_none());

        handler.record_retry();
        assert_eq!(handler.retry_count(), 1);
        assert!(handler.last_retry().is_some());

        handler.record_retry();
        assert_eq!(handler.retry_count(), 2);
    }

    #[test]
    fn test_reset() {
        let config = Arc::new(VoIPConfig::default());
        let mut handler = PushRetryHandler::new(config);

        handler.record_retry();
        handler.record_retry();
        assert_eq!(handler.retry_count(), 2);

        handler.reset();
        assert_eq!(handler.retry_count(), 0);
        assert!(handler.last_retry().is_none());
        assert!(handler.can_retry());
    }

    #[test]
    fn test_create_push_retry_message() {
        let config = Arc::new(VoIPConfig::default());
        let handler = PushRetryHandler::new(config);

        let msg = handler.create_push_retry_message(
            "call-123",
            "peer-456",
            CallEndReason::FailedIpv4Random,
        );

        assert_eq!(msg.call_id, "call-123");
        assert_eq!(msg.callee_id, "peer-456");
        assert_eq!(msg.reason, CallEndReason::FailedIpv4Random as i32);
        assert_eq!(msg.retry_attempt, 1);
        assert_eq!(msg.retry_after_ms, 5000); // 5s for first attempt
    }

    #[test]
    fn test_create_push_retry_message_subsequent_attempt() {
        let config = Arc::new(VoIPConfig::default());
        let mut handler = PushRetryHandler::new(config);

        handler.record_retry(); // attempt 1

        let msg = handler.create_push_retry_message(
            "call-123",
            "peer-456",
            CallEndReason::FailedIpv4Random,
        );

        assert_eq!(msg.retry_attempt, 2);
        assert_eq!(msg.retry_after_ms, 15000); // 15s for second attempt
    }

    #[test]
    fn test_push_retry_with_masque_unreachable_reason() {
        let config = Arc::new(VoIPConfig::default());
        let handler = PushRetryHandler::new(config);

        let msg = handler.create_push_retry_message(
            "call-789",
            "peer-abc",
            CallEndReason::FailedMasqueUnreachable,
        );

        assert_eq!(msg.reason, CallEndReason::FailedMasqueUnreachable as i32);
    }

    #[test]
    fn test_push_retry_disabled() {
        let mut config = VoIPConfig::default();
        config.push_retry_enabled = false;
        let config = Arc::new(config);

        let handler = PushRetryHandler::new(config);
        // Handler itself doesn't check push_retry_enabled,
        // that's the scheduler's job
        assert!(handler.can_retry());
    }

    #[tokio::test]
    async fn test_retry_scheduler_schedule() {
        let config = Arc::new(VoIPConfig::default());
        let mut scheduler = RetryScheduler::new(config);

        // Schedule a retry
        let result = scheduler.schedule_retry(
            "call-123",
            "peer-456",
            CallEndReason::FailedIpv4Random,
        ).await;

        assert!(result.is_ok());
        assert_eq!(scheduler.handler().retry_count(), 1);

        // Clean up
        scheduler.cancel();
    }

    #[tokio::test]
    async fn test_retry_scheduler_max_attempts() {
        let config = Arc::new(VoIPConfig::default());
        let mut scheduler = RetryScheduler::new(config);

        // Exhaust all retry attempts
        for _ in 0..3 {
            let result = scheduler.schedule_retry(
                "call-123",
                "peer-456",
                CallEndReason::FailedIpv4Random,
            ).await;
            // Cancel the spawned task immediately to avoid timing issues
            scheduler.cancel();
            assert!(result.is_ok());
        }

        // Next attempt should fail
        let result = scheduler.schedule_retry(
            "call-123",
            "peer-456",
            CallEndReason::FailedIpv4Random,
        ).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_retry_scheduler_wrong_reason() {
        let config = Arc::new(VoIPConfig::default());
        let mut scheduler = RetryScheduler::new(config);

        // Normal end reason should not trigger retry
        let result = scheduler.schedule_retry(
            "call-123",
            "peer-456",
            CallEndReason::Normal,
        ).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_retry_scheduler_disabled() {
        let mut config = VoIPConfig::default();
        config.push_retry_enabled = false;
        let config = Arc::new(config);

        let mut scheduler = RetryScheduler::new(config);

        let result = scheduler.schedule_retry(
            "call-123",
            "peer-456",
            CallEndReason::FailedIpv4Random,
        ).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_retry_scheduler_reset() {
        let config = Arc::new(VoIPConfig::default());
        let mut scheduler = RetryScheduler::new(config);

        // Schedule some retries
        scheduler.schedule_retry(
            "call-123",
            "peer-456",
            CallEndReason::FailedIpv4Random,
        ).await.unwrap();
        scheduler.cancel();

        assert_eq!(scheduler.handler().retry_count(), 1);

        // Reset
        scheduler.reset();
        assert_eq!(scheduler.handler().retry_count(), 0);
        assert!(scheduler.handler().can_retry());
    }

    #[tokio::test]
    async fn test_retry_scheduler_cancel() {
        let config = Arc::new(VoIPConfig::default());
        let mut scheduler = RetryScheduler::new(config);

        scheduler.schedule_retry(
            "call-123",
            "peer-456",
            CallEndReason::FailedIpv4Random,
        ).await.unwrap();

        // Cancel should not panic
        scheduler.cancel();

        // Can schedule again after cancel
        let result = scheduler.schedule_retry(
            "call-123",
            "peer-456",
            CallEndReason::FailedIpv4Random,
        ).await;
        scheduler.cancel();
        assert!(result.is_ok());
    }
}
