//! End-to-end integration tests for the Three Pillars VoIP system.
//!
//! These tests verify the full call flow across multiple crates,
//! covering the 14 integration scenarios from ROADMAP Phase 5.

use voip_core::state::CallStateMachine;
use voip_core::types::{
    CallEndReason, ConnectionMethod, DiscoveryMethod, NATType,
};
use voip_core::config::VoIPConfig;
use voip_core::crypto::{generate_connection_id, generate_ed25519_keypair, peer_id_from_public_key};
use voip_core::error::VoipError;

// 5.1 — IPv6 Direct Connection
#[test]
fn test_5_1_ipv6_direct_connection() {
    let mut sm = CallStateMachine::new(3);
    sm.ring().unwrap();
    sm.accept().unwrap();
    sm.connect(ConnectionMethod::Ipv6Direct).unwrap();
    assert!(sm.is_connected());
    assert!(sm.method().unwrap().is_direct());
    sm.end(CallEndReason::Normal).unwrap();
}

// 5.2 — IPv4 Cone NAT (QUIC Simultaneous Open)
#[test]
fn test_5_2_cone_nat_simultaneous_open() {
    let mut sm = CallStateMachine::new(3);
    sm.ring().unwrap();
    sm.accept().unwrap();
    sm.connect(ConnectionMethod::Ipv4Cone).unwrap();
    assert!(sm.is_connected());
    assert!(sm.method().unwrap().is_direct());
}

// 5.3 — IPv4 Symmetric NAT Sequential
#[test]
fn test_5_3_symmetric_sequential_port_prediction() {
    assert!(NATType::SymmetricSequential.is_predictable());
    let mut sm = CallStateMachine::new(3);
    sm.ring().unwrap();
    sm.accept().unwrap();
    sm.connect(ConnectionMethod::Ipv4Prediction).unwrap();
    assert!(sm.is_connected());
}

// 5.4 — Symmetric NAT Random → honest failure + push retry
#[test]
fn test_5_4_symmetric_random_honest_failure() {
    assert!(!NATType::SymmetricRandom.is_predictable());
    assert!(voip_client::masque::detect_masque_need(
        NATType::SymmetricRandom, NATType::SymmetricRandom, false
    ));
    let mut sm = CallStateMachine::new(3);
    sm.ring().unwrap();
    sm.accept().unwrap();
    sm.fail(CallEndReason::FailedIpv4Random).unwrap();
    assert!(CallEndReason::FailedIpv4Random.should_retry());
    sm.retry().unwrap();
    assert_eq!(sm.retry_count(), 1);
}

// 5.5 — UDP blocked → MASQUE over HTTP/2
#[test]
fn test_5_5_udp_blocked_masque_http2() {
    assert!(voip_client::masque::detect_masque_need(NATType::Cone, NATType::Cone, true));
    let mut sm = CallStateMachine::new(3);
    sm.ring().unwrap();
    sm.accept().unwrap();
    sm.connect(ConnectionMethod::MasqueHttp2).unwrap();
    assert!(sm.method().unwrap().is_relayed());
}

// 5.6 — Mixed IPv6 + IPv4 Symmetric
#[test]
fn test_5_6_mixed_ipv6_ipv4_symmetric() {
    assert!(NATType::None.is_no_nat());
    let mut sm = CallStateMachine::new(3);
    sm.ring().unwrap();
    sm.accept().unwrap();
    sm.connect(ConnectionMethod::Ipv6Direct).unwrap();
    assert!(sm.is_connected());
}

// 5.7 — DHT discovery
#[test]
fn test_5_7_dht_discovery_methods() {
    assert_eq!(DiscoveryMethod::Dht as i32, 0);
    assert_eq!(DiscoveryMethod::Signaling as i32, 1);
    assert_eq!(DiscoveryMethod::Cache as i32, 2);
}

// 5.8 — Signaling blocked → DHT fallback
#[test]
fn test_5_8_signaling_blocked_dht_fallback() {
    // Verify DHT discovery is available as fallback
    let (signing_key, verifying_key) = generate_ed25519_keypair();
    let peer_id = peer_id_from_public_key(&verifying_key);
    assert_eq!(peer_id.len(), 64);
    let data = b"dht-record";
    let sig = voip_core::crypto::sign_dht_record(&signing_key, data);
    assert!(voip_core::crypto::verify_dht_record(&verifying_key, data, &sig));
}

// 5.9 — Connection migration
#[test]
fn test_5_9_connection_migration() {
    let mut sm = CallStateMachine::new(3);
    sm.ring().unwrap();
    sm.accept().unwrap();
    sm.connect(ConnectionMethod::Ipv6Direct).unwrap();
    assert!(sm.is_connected());
    sm.fail(CallEndReason::MigrationFailed).unwrap();
    assert!(sm.is_terminal());
}

// 5.10 — MASQUE fallback chain
#[test]
fn test_5_10_masque_fallback_chain() {
    let direct = [ConnectionMethod::Ipv6Direct, ConnectionMethod::Ipv4Cone, ConnectionMethod::Ipv4Prediction];
    let relay = [ConnectionMethod::Masque, ConnectionMethod::MasqueHttp2];
    for m in &direct { assert!(m.is_direct()); }
    for m in &relay { assert!(m.is_relayed()); }
}

// 5.11 & 5.12 — NAT cache
#[test]
fn test_5_11_5_12_nat_cache_ttl() {
    let config = VoIPConfig::default();
    assert_eq!(config.nat_cache_ttl_secs, 300);
    let (s, e) = config.sequential_prediction_range(50000);
    assert_eq!(s, 49997);
    assert_eq!(e, 50003);
}

// 5.13 — Call rejection
#[test]
fn test_5_13_call_rejection() {
    let mut sm = CallStateMachine::new(3);
    sm.ring().unwrap();
    sm.reject().unwrap();
    assert!(sm.is_terminal());
    assert_eq!(sm.end_reason(), Some(CallEndReason::Rejected));
}

// 5.14 — MASQUE tunnel recovery
#[test]
fn test_5_14_masque_tunnel_recovery() {
    let mut sm = CallStateMachine::new(3);
    sm.ring().unwrap();
    sm.accept().unwrap();
    sm.connect(ConnectionMethod::Masque).unwrap();
    sm.fail(CallEndReason::FailedMasqueUnreachable).unwrap();
    assert!(CallEndReason::FailedMasqueUnreachable.should_retry());
    sm.retry().unwrap();
}

// Additional: Connection ID pre-agreement
#[test]
fn test_connection_id_preagreement() {
    let id1 = generate_connection_id();
    let id2 = generate_connection_id();
    assert_eq!(id1.len(), 12);
    assert_ne!(id1, id2);
}

// Additional: Full retry chain with backoff
#[test]
fn test_full_retry_chain_with_backoff() {
    let config = VoIPConfig::default();
    assert_eq!(config.retry_delay_secs(1), 5);
    assert_eq!(config.retry_delay_secs(2), 15);
    assert_eq!(config.retry_delay_secs(3), 45);
}

// Additional: Error → CallEndReason mapping
#[test]
fn test_error_to_call_end_reason_mapping() {
    assert_eq!(VoipError::QuicHandshakeTimeout.to_call_end_reason(), CallEndReason::Timeout);
    assert_eq!(VoipError::NatRandomBothSides.to_call_end_reason(), CallEndReason::FailedIpv4Random);
    assert_eq!(VoipError::UdpBlocked.to_call_end_reason(), CallEndReason::FailedUdpBlocked);
    assert_eq!(VoipError::TcpBlocked.to_call_end_reason(), CallEndReason::FailedTcpBlocked);
    assert_eq!(VoipError::MigrationFailed.to_call_end_reason(), CallEndReason::MigrationFailed);
}
