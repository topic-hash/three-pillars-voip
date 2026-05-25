//! Push notification relay via Firebase Cloud Messaging (spec/06 §6.7 Step 9c, spec/08 §8.5.1).
//!
//! When a call fails with a retryable reason (END_FAILED_IPV4_RANDOM,
//! END_FAILED_MASQUE_UNREACHABLE), the signaling server sends a PushRetry
//! message to the peer via FCM to wake the peer's app and trigger auto-retry.
//!
//! Current implementation: stub that logs push notifications.
//! Actual FCM integration requires a Google service account JSON key.

use prost::Message;
use tracing::info;

use crate::state::{type_id, AppState, FramedMessage};

/// Reasons that are retryable — the peer should be notified to re-attempt.
/// See spec/08 §8.5.2 and `CallEndReason::should_retry()`.
///
/// - 3: END_FAILED_IPV4_RANDOM
/// - 4: END_FAILED_UDP_BLOCKED
/// - 7: END_FAILED_MASQUE_UNREACHABLE
const RETRYABLE_REASONS: [i32; 3] = [
    3, // END_FAILED_IPV4_RANDOM
    4, // END_FAILED_UDP_BLOCKED
    7, // END_FAILED_MASQUE_UNREACHABLE
];

/// Check whether a CallEndReason value is retryable.
pub fn is_retryable_reason(reason: i32) -> bool {
    RETRYABLE_REASONS.contains(&reason)
}

/// Push notification data for an FCM message.
#[derive(Debug, Clone)]
pub struct PushNotification {
    /// The FCM token of the target device.
    pub fcm_token: String,
    /// The call ID this notification relates to.
    pub call_id: String,
    /// The caller's peer ID.
    pub caller_id: String,
    /// The callee's peer ID.
    pub callee_id: String,
    /// The failure reason (CallEndReason enum value).
    pub reason: i32,
    /// Which retry attempt this is (1, 2, or 3).
    pub retry_attempt: u32,
    /// Delay in ms before the peer should retry.
    pub retry_after_ms: u64,
}

/// A push notifier that sends FCM push notifications.
///
/// In production, this would hold a Firebase credential and use the
/// FCM HTTP v1 API. For now, it logs the notification as a stub.
#[derive(Debug, Clone)]
pub struct PushNotifier {
    /// Whether push notifications are enabled.
    enabled: bool,
}

impl PushNotifier {
    /// Create a new PushNotifier.
    #[allow(dead_code)]
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Create a disabled PushNotifier (stub mode).
    pub fn new_stub() -> Self {
        Self { enabled: false }
    }

    /// Send a push notification via FCM (stub implementation).
    ///
    /// In production this would POST to `https://fcm.googleapis.com/v1/projects/{project}/messages:send`.
    /// For now it logs the notification.
    pub async fn send(&self, notification: &PushNotification) -> Result<(), PushError> {
        if !self.enabled {
            info!(
                fcm_token = %notification.fcm_token,
                call_id = %notification.call_id,
                caller_id = %notification.caller_id,
                callee_id = %notification.callee_id,
                reason = notification.reason,
                retry_attempt = notification.retry_attempt,
                retry_after_ms = notification.retry_after_ms,
                "Push notification (stub): would send FCM push"
            );
            return Ok(());
        }

        // In production:
        //   let client = reqwest::Client::new();
        //   let access_token = self.get_access_token().await?;
        //   let response = client
        //       .post("https://fcm.googleapis.com/v1/projects/{project}/messages:send")
        //       .bearer_auth(access_token)
        //       .json(&fcm_payload)
        //       .send()
        //       .await?;
        //
        // For now, just log.
        info!(
            fcm_token = %notification.fcm_token,
            call_id = %notification.call_id,
            reason = notification.reason,
            retry_attempt = notification.retry_attempt,
            "FCM push notification sent (stub)"
        );

        Ok(())
    }
}

/// Errors that can occur when sending push notifications.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum PushError {
    #[error("FCM token not found for peer {0}")]
    NoFcmToken(String),

    #[error("FCM send failed: {0}")]
    SendFailed(String),

    #[error("push notifications disabled")]
    Disabled,
}

/// Generate a PushRetry framed message for a call failure.
///
/// Per spec/08 §8.5.1: Sent when a call fails due to NAT incompatibility.
/// Delivered via FCM to wake the peer's app.
pub fn build_push_retry_message(
    call_id: &str,
    caller_id: &str,
    callee_id: &str,
    reason: i32,
    retry_attempt: u32,
    retry_after_ms: u64,
) -> FramedMessage {
    let push_retry = voip_core::proto::signaling::PushRetry {
        call_id: call_id.to_owned(),
        caller_id: caller_id.to_owned(),
        callee_id: callee_id.to_owned(),
        reason,
        retry_attempt,
        retry_after_ms,
    };
    let payload = push_retry.encode_to_vec();
    FramedMessage {
        type_id: type_id::PUSH_RETRY,
        payload,
    }
}

/// Handle a retryable call failure: send PushRetry via WebSocket if peer
/// is connected, and queue an FCM push notification as backup.
///
/// Called from the call-failed handler when the reason is retryable.
pub async fn handle_retryable_failure(
    state: &AppState,
    call_id: &str,
    caller_id: &str,
    callee_id: &str,
    reason: i32,
    other_peer_id: &str,
    retry_count: u32,
) {
    let config = &state.inner.config;
    let max_attempts = config.push_retry_max_attempts;

    if retry_count >= max_attempts {
        info!(
            call_id,
            retry_count,
            max_attempts,
            "not retrying: max attempts reached"
        );
        return;
    }

    let next_attempt = retry_count + 1;
    let retry_after_ms = config.retry_delay_secs(next_attempt) * 1000;

    // Try to send PushRetry via WebSocket first (instant delivery)
    let push_msg = build_push_retry_message(
        call_id,
        caller_id,
        callee_id,
        reason,
        next_attempt,
        retry_after_ms,
    );

    match state.send_to_peer(other_peer_id, push_msg).await {
        Ok(()) => {
            info!(
                call_id,
                other_peer_id,
                next_attempt,
                "PushRetry sent via WebSocket"
            );
        }
        Err(e) => {
            info!(
                call_id,
                other_peer_id,
                error = %e,
                "PushRetry WebSocket send failed, will try FCM"
            );
        }
    }

    // Also queue an FCM push notification as backup / wake-up
    let peer_info = state.get_peer(other_peer_id).await;
    if let Some(info) = peer_info {
        if let Some(fcm_token) = info.fcm_token {
            let notifier = &state.inner.push_notifier;
            let notification = PushNotification {
                fcm_token,
                call_id: call_id.to_owned(),
                caller_id: caller_id.to_owned(),
                callee_id: callee_id.to_owned(),
                reason,
                retry_attempt: next_attempt,
                retry_after_ms,
            };
            if let Err(e) = notifier.send(&notification).await {
                info!(
                    call_id,
                    other_peer_id,
                    error = %e,
                    "FCM push notification failed"
                );
            }
        } else {
            info!(
                call_id,
                other_peer_id,
                "no FCM token for peer, cannot send push notification"
            );
        }
    }
}
