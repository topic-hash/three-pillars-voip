//! MASQUE relay coordination logic (spec/06 §6.7 Step 9, spec/08 §8.6).
//!
//! When both peers have NAT_SYMMETRIC_RANDOM, direct P2P is impossible.
//! The signaling server detects this condition and sends MasqueRelayNeeded
//! (type ID 0x0300) to both peers with the proxy URL.

use ed25519_dalek::Signer;
use prost::Message;
use voip_core::types::NATType;

use crate::error::SignalingError;
use crate::state::AppState;

/// Detect whether MASQUE relay is needed based on both peers' NAT types
/// and whether UDP is blocked.
///
/// Per spec/06 §6.7 Step 9 and spec/12: MASQUE relay is needed when:
/// - Both peers have NAT_SYMMETRIC_RANDOM (direct connection impossible), OR
/// - UDP is blocked on the network path
///
/// # Arguments
///
/// * `caller_nat` - The caller's detected NAT type
/// * `callee_nat` - The callee's detected NAT type
/// * `udp_blocked` - Whether UDP is blocked on the network path
///
/// # Returns
///
/// `true` if MASQUE relay is needed, `false` otherwise.
#[allow(dead_code)]
pub fn detect_masque_need(caller_nat: NATType, callee_nat: NATType, udp_blocked: bool) -> bool {
    // Both peers have symmetric NAT with random port allocation
    matches!(
        (caller_nat, callee_nat),
        (NATType::SymmetricRandom, NATType::SymmetricRandom)
    ) || udp_blocked
}

/// Select the least-loaded MASQUE proxy from the known list.
///
/// Per spec/06 §6.8.2: Choose the proxy with the lowest measured latency.
/// For now, we simply pick the first available proxy.
pub async fn select_proxy(state: &AppState) -> Option<crate::state::ProxyInfo> {
    let proxies = state.get_proxies().await;
    proxies.first().cloned()
}

/// Send MasqueRelayNeeded (type ID 0x0300) to both peers in a call.
///
/// Per spec/06 §6.7 Step 9a: The server sends MasqueRelayNeeded to BOTH
/// peers with proxy URL. Both peers then connect to the MASQUE proxy
/// via HTTP/3 + TLS 1.3 and send CONNECT-UDP with the same call_id.
pub async fn send_relay_needed(
    state: &AppState,
    call_id: &str,
    caller_id: &str,
    callee_id: &str,
) -> crate::error::Result<()> {
    let proxy = select_proxy(state)
        .await
        .ok_or(SignalingError::MasqueNoProxy)?;

    // Issue a ProxyToken for the caller (peer_id=caller, target=callee)
    let caller_token = issue_proxy_token(state, caller_id, callee_id);
    // Issue a ProxyToken for the callee (peer_id=callee, target=caller)
    let callee_token = issue_proxy_token(state, callee_id, caller_id);

    // Build MasqueRelayNeeded for the caller
    let caller_msg = voip_core::proto::signaling::MasqueRelayNeeded {
        call_id: call_id.to_owned(),
        proxy_url: proxy.proxy_url.clone(),
        wait_timeout_ms: 10_000,
        proxy_token: Some(caller_token),
    };
    let caller_payload = caller_msg.encode_to_vec();
    let caller_framed = crate::state::FramedMessage {
        type_id: crate::state::type_id::MASQUE_RELAY_NEEDED,
        payload: caller_payload,
    };

    // Build MasqueRelayNeeded for the callee
    let callee_msg = voip_core::proto::signaling::MasqueRelayNeeded {
        call_id: call_id.to_owned(),
        proxy_url: proxy.proxy_url.clone(),
        wait_timeout_ms: 10_000,
        proxy_token: Some(callee_token),
    };
    let callee_payload = callee_msg.encode_to_vec();
    let callee_framed = crate::state::FramedMessage {
        type_id: crate::state::type_id::MASQUE_RELAY_NEEDED,
        payload: callee_payload,
    };

    // Send to both peers. If either send fails, return an error.
    state.send_to_peer(caller_id, caller_framed).await?;
    state.send_to_peer(callee_id, callee_framed).await?;

    tracing::info!(
        call_id,
        caller_id,
        callee_id,
        proxy_url = %proxy.proxy_url,
        "MasqueRelayNeeded sent to both peers (with ProxyTokens)"
    );
    Ok(())
}

/// Issue a signed ProxyToken for a peer using the server's Ed25519 signing key.
///
/// Creates a protobuf `ProxyToken` with the given peer_id and target_peer_id,
/// signs it with the server's signing key, and returns the signed token.
fn issue_proxy_token(
    state: &AppState,
    peer_id: &str,
    target_peer_id: &str,
) -> voip_core::proto::signaling::ProxyToken {
    let ttl_seconds: u32 = 60;
    let issued_at = crate::state::now_secs();

    // Create the protobuf ProxyToken with an empty signature placeholder
    let proxy_token = voip_core::proto::signaling::ProxyToken {
        peer_id: peer_id.to_owned(),
        target_peer_id: target_peer_id.to_owned(),
        issued_at,
        ttl_seconds,
        signature: Vec::new(),
    };

    // Serialize without signature for signing
    let mut token_for_signing = proxy_token.clone();
    token_for_signing.signature.clear();
    let data_to_sign = token_for_signing.encode_to_vec();

    // Sign with server's Ed25519 signing key
    let signature = state.inner.signing_key.sign(&data_to_sign);
    let signature_bytes = signature.to_bytes().to_vec();

    // Build the final token with signature
    voip_core::proto::signaling::ProxyToken {
        peer_id: peer_id.to_owned(),
        target_peer_id: target_peer_id.to_owned(),
        issued_at,
        ttl_seconds,
        signature: signature_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_masque_need_both_random() {
        assert!(detect_masque_need(
            NATType::SymmetricRandom,
            NATType::SymmetricRandom,
            false
        ));
    }

    #[test]
    fn test_detect_masque_not_needed_cone() {
        assert!(!detect_masque_need(NATType::Cone, NATType::Cone, false));
    }

    #[test]
    fn test_detect_masque_not_needed_ipv6() {
        assert!(!detect_masque_need(NATType::None, NATType::None, false));
    }

    #[test]
    fn test_detect_masque_not_needed_one_random() {
        assert!(!detect_masque_need(
            NATType::SymmetricRandom,
            NATType::Cone,
            false
        ));
    }

    #[test]
    fn test_detect_masque_not_needed_sequential() {
        assert!(!detect_masque_need(
            NATType::SymmetricSequential,
            NATType::SymmetricSequential,
            false
        ));
    }

    #[test]
    fn test_detect_masque_not_needed_mixed() {
        assert!(!detect_masque_need(
            NATType::SymmetricPseudo,
            NATType::SymmetricRandom,
            false
        ));
    }

    #[test]
    fn test_detect_masque_need_udp_blocked() {
        // UDP blocked triggers MASQUE need regardless of NAT types
        assert!(detect_masque_need(NATType::None, NATType::None, true));
        assert!(detect_masque_need(NATType::Cone, NATType::Cone, true));
        assert!(detect_masque_need(
            NATType::SymmetricRandom,
            NATType::Cone,
            true
        ));
    }

    #[test]
    fn test_detect_masque_not_needed_udp_not_blocked() {
        // With UDP not blocked and non-SymmetricRandom pair, no MASQUE needed
        assert!(!detect_masque_need(NATType::Cone, NATType::None, false));
        assert!(!detect_masque_need(
            NATType::SymmetricPseudo,
            NATType::SymmetricPseudo,
            false
        ));
    }
}
