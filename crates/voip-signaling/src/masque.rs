//! MASQUE relay coordination logic (spec/06 §6.7 Step 9, spec/08 §8.6).
//!
//! When both peers have NAT_SYMMETRIC_RANDOM, direct P2P is impossible.
//! The signaling server detects this condition and sends MasqueRelayNeeded
//! (type ID 0x0300) to both peers with the proxy URL.

use voip_core::types::NATType;

use crate::error::SignalingError;
use crate::state::AppState;

/// Detect whether MASQUE relay is needed based on both peers' NAT types.
///
/// Per spec/06 §6.7 Step 9: MASQUE relay is needed when both peers
/// have NAT_SYMMETRIC_RANDOM (direct connection impossible).
/// Also needed when UDP is blocked on both sides.
#[allow(dead_code)]
pub fn detect_masque_need(caller_nat: NATType, callee_nat: NATType) -> bool {
    // Both peers have symmetric NAT with random port allocation
    matches!(
        (caller_nat, callee_nat),
        (NATType::SymmetricRandom, NATType::SymmetricRandom)
    )
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

    use prost::Message;
    let relay_msg = voip_core::proto::signaling::MasqueRelayNeeded {
        call_id: call_id.to_owned(),
        proxy_url: proxy.proxy_url.clone(),
        wait_timeout_ms: 10_000,
    };
    let payload = relay_msg.encode_to_vec();

    let framed = crate::state::FramedMessage {
        type_id: crate::state::type_id::MASQUE_RELAY_NEEDED,
        payload,
    };

    // Send to both peers. If either send fails, return an error.
    state.send_to_peer(caller_id, framed.clone()).await?;
    state.send_to_peer(callee_id, framed).await?;

    tracing::info!(
        call_id,
        caller_id,
        callee_id,
        proxy_url = %proxy.proxy_url,
        "MasqueRelayNeeded sent to both peers"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_masque_need_both_random() {
        assert!(detect_masque_need(
            NATType::SymmetricRandom,
            NATType::SymmetricRandom
        ));
    }

    #[test]
    fn test_detect_masque_not_needed_cone() {
        assert!(!detect_masque_need(NATType::Cone, NATType::Cone));
    }

    #[test]
    fn test_detect_masque_not_needed_ipv6() {
        assert!(!detect_masque_need(NATType::None, NATType::None));
    }

    #[test]
    fn test_detect_masque_not_needed_one_random() {
        assert!(!detect_masque_need(
            NATType::SymmetricRandom,
            NATType::Cone
        ));
    }

    #[test]
    fn test_detect_masque_not_needed_sequential() {
        assert!(!detect_masque_need(
            NATType::SymmetricSequential,
            NATType::SymmetricSequential
        ));
    }

    #[test]
    fn test_detect_masque_not_needed_mixed() {
        assert!(!detect_masque_need(
            NATType::SymmetricPseudo,
            NATType::SymmetricRandom
        ));
    }
}
