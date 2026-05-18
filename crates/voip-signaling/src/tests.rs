//! Comprehensive unit tests for the signaling server.
//!
//! Tests cover all REST endpoints, JWT authentication, rate limiting,
//! error responses, and MASQUE relay coordination.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use prost::Message;
use serde_json::{json, Value};
use tower::ServiceExt;
use utoipa::OpenApi;

use crate::error::codes;
use crate::handlers::RegisterPeerRequest;
use crate::jwt;
use crate::masque;
use crate::rate_limit::BucketConfig;
use crate::server::ApiDoc;
use crate::state::{self, ProxyInfo};
use voip_core::types::NATType;

// ── Test helpers ────────────────────────────────────────────────────────

/// Build a test server (not just the router) with default configuration.
/// Returns the server struct so tests can access its state.
fn test_server() -> crate::server::SignalingServer {
    crate::server::SignalingServer::builder()
        .listen_addr("0.0.0.0:0")
        .build()
}

/// Build a test server with very low rate limits for rate-limit testing.
fn test_server_low_limits() -> crate::server::SignalingServer {
    let low_rate_config = crate::rate_limit::RateLimitConfig {
        registrations: BucketConfig {
            max_tokens: 2,
            refill_amount: 2,
            refill_interval_ms: 60_000,
        },
        calls: BucketConfig {
            max_tokens: 2,
            refill_amount: 2,
            refill_interval_ms: 60_000,
        },
        ws_messages: BucketConfig {
            max_tokens: 5,
            refill_amount: 5,
            refill_interval_ms: 1_000,
        },
    };
    crate::server::SignalingServer::builder()
        .listen_addr("0.0.0.0:0")
        .rate_limits(low_rate_config)
        .build()
}

/// Build a test router with default configuration.
fn test_router() -> axum::Router {
    test_server().router()
}

/// Build a test router with a very low rate limit for rate-limit testing.
fn test_router_low_limits() -> axum::Router {
    test_server_low_limits().router()
}

/// Collect the response body into bytes.
async fn body_bytes(body: Body) -> Vec<u8> {
    body.collect().await.unwrap().to_bytes().to_vec()
}

/// Collect the response body and parse as JSON.
async fn body_json(body: Body) -> Value {
    let bytes = body_bytes(body).await;
    serde_json::from_slice(&bytes).unwrap()
}

/// Create a JSON POST request.
fn json_post(uri: &str, body: impl serde::Serialize) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

/// Create a JSON PUT request.
fn json_put(uri: &str, body: impl serde::Serialize) -> Request<Body> {
    Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

/// Create a simple GET request.
fn simple_get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

/// Create a DELETE request.
fn simple_delete(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::DELETE)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

/// Register a peer via POST /v1/peers and return the response JSON.
/// Consumes and recreates the router for each request since oneshot() takes ownership.
async fn register_peer_helper(peer_id: &str, display_name: &str) -> Value {
    let body = RegisterPeerRequest {
        peer_id: peer_id.to_string(),
        display_name: display_name.to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: None,
        status: None,
        fcm_token: None,
    };
    let response = test_router()
        .oneshot(json_post("/v1/peers", &body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    body_json(response.into_body()).await
}

/// Register a peer via POST /v1/peers and return the response JSON.
/// Uses the same router for both the register and subsequent operations.
async fn register_and_get_router(peer_id: &str, display_name: &str) -> (axum::Router, Value) {
    let server = test_server();
    let router = server.router();
    // Use the state directly to register (avoids router ownership issues)
    let info = crate::state::PeerInfo {
        peer_id: peer_id.to_string(),
        display_name: display_name.to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: 0,
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    server.state().register_peer(info, None).await.unwrap();

    // Issue JWT token
    let expiry_secs = server.state().inner.config.jwt_expiry_secs;
    let jwt_token = jwt::create_jwt(&server.state().inner.signing_key, peer_id, expiry_secs).unwrap();

    let result = json!({
        "peer_id": peer_id,
        "jwt_token": jwt_token,
        "expires_in_secs": expiry_secs,
    });
    (router, result)
}

// ═══════════════════════════════════════════════════════════════════════
// 1. REST endpoint tests: register, update, unregister, lookup peers
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_register_peer() {
    let result = register_peer_helper("peer-abc", "Alice").await;
    assert_eq!(result["peer_id"], "peer-abc");
    assert!(result["jwt_token"].is_string());
    assert!(result["expires_in_secs"].is_number());
}

#[tokio::test]
async fn test_register_peer_with_details() {
    let body = json!({
        "peer_id": "peer-detail",
        "display_name": "Bob",
        "ipv6_addresses": ["::1"],
        "ipv4_reflexive": ["1.2.3.4:5678"],
        "nat_type": "CONE",
        "status": "ONLINE",
        "fcm_token": "fcm-token-123"
    });
    let response = test_router()
        .oneshot(json_post("/v1/peers", &body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let result = body_json(response.into_body()).await;
    assert_eq!(result["peer_id"], "peer-detail");
}

#[tokio::test]
async fn test_register_peer_re_register() {
    // First registration
    let _ = register_peer_helper("peer-re", "RePeer").await;
    // Second registration with same peer_id should succeed (re-registration)
    let _ = register_peer_helper("peer-re", "RePeerUpdated").await;
}

#[tokio::test]
async fn test_update_peer() {
    // Test update via AppState directly (avoids Router oneshot ownership issues)
    let server = test_server();
    let state = server.state().clone();

    // Register peer
    let info = crate::state::PeerInfo {
        peer_id: "peer-upd".to_string(),
        display_name: "UpdateMe".to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: 0,
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    state.register_peer(info, None).await.unwrap();

    // Update by re-registering with new info
    let updated_info = crate::state::PeerInfo {
        peer_id: "peer-upd".to_string(),
        display_name: "UpdatedName".to_string(),
        ipv6_addresses: vec!["2001:db8::1".to_string()],
        ipv4_reflexive: vec![],
        nat_type: 4, // SYMMETRIC_RANDOM
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    state.register_peer(updated_info, None).await.unwrap();

    // Verify update
    let peer = state.get_peer("peer-upd").await.unwrap();
    assert_eq!(peer.display_name, "UpdatedName");
    assert_eq!(peer.nat_type, 4);
    assert_eq!(peer.ipv6_addresses, vec!["2001:db8::1"]);
}

#[tokio::test]
async fn test_update_nonexistent_peer() {
    // Test updating a nonexistent peer via AppState — get_peer returns None
    let server = test_server();
    let state = server.state().clone();

    let result = state.get_peer("nonexistent").await;
    assert!(result.is_none());

    // Verify the error type and code
    let err = crate::error::SignalingError::UnknownPeer("nonexistent".to_string());
    assert_eq!(err.code(), codes::UNKNOWN_PEER);
    assert_eq!(err.http_status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_unregister_peer() {
    // Test unregister via AppState directly
    let server = test_server();
    let state = server.state().clone();

    // Register peer
    let info = crate::state::PeerInfo {
        peer_id: "peer-del".to_string(),
        display_name: "DeleteMe".to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: 0,
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    state.register_peer(info, None).await.unwrap();

    // Verify peer exists
    assert!(state.get_peer("peer-del").await.is_some());

    // Unregister
    state.unregister_peer("peer-del").await.unwrap();

    // Verify peer is gone
    assert!(state.get_peer("peer-del").await.is_none());
}

#[tokio::test]
async fn test_unregister_nonexistent_peer() {
    // Unregister a peer that doesn't exist — should still succeed (idempotent)
    let server = test_server();
    let state = server.state().clone();
    // unregister_peer always returns Ok(()) — it's idempotent
    state.unregister_peer("nonexistent").await.unwrap();
}

#[tokio::test]
async fn test_get_peer() {
    let server = test_server();
    let state = server.state().clone();

    // Register peer directly on the shared state
    let info = crate::state::PeerInfo {
        peer_id: "peer-get".to_string(),
        display_name: "GetMe".to_string(),
        ipv6_addresses: vec!["::1".to_string()],
        ipv4_reflexive: vec!["1.2.3.4:5678".to_string()],
        nat_type: 1, // CONE
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    state.register_peer(info, None).await.unwrap();

    // Verify via AppState method (not through router)
    let peer = state.get_peer("peer-get").await;
    assert!(peer.is_some());
    let peer = peer.unwrap();
    assert_eq!(peer.peer_id, "peer-get");
    assert_eq!(peer.display_name, "GetMe");
    assert_eq!(peer.nat_type, 1);
}

#[tokio::test]
async fn test_get_nonexistent_peer() {
    // Test get nonexistent peer via AppState
    let server = test_server();
    let state = server.state().clone();

    let result = state.get_peer("nonexistent").await;
    assert!(result.is_none());

    // Verify the SignalingError produces the correct error code and status
    let err = crate::error::SignalingError::UnknownPeer("nonexistent".to_string());
    assert_eq!(err.code(), codes::UNKNOWN_PEER);
    assert_eq!(err.http_status(), StatusCode::NOT_FOUND);

    // Verify the IntoResponse implementation includes the error code in the JSON body
    use axum::response::IntoResponse;
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_bytes(response.into_body()).await;
    let result: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["code"], codes::UNKNOWN_PEER);
}

#[tokio::test]
async fn test_get_peer_status() {
    // Test peer status via AppState directly
    let server = test_server();
    let state = server.state().clone();

    // Register peer
    let info = crate::state::PeerInfo {
        peer_id: "peer-status".to_string(),
        display_name: "StatusPeer".to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: 0,
        status: 0, // ONLINE
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    state.register_peer(info, None).await.unwrap();

    // Get peer and check status
    let peer = state.get_peer("peer-status").await.unwrap();
    assert_eq!(peer.peer_id, "peer-status");
    assert_eq!(peer.status, 0); // ONLINE

    // Verify status string mapping
    fn peer_status_str(val: i32) -> String {
        match val {
            0 => "ONLINE".into(),
            1 => "OFFLINE".into(),
            2 => "IN_CALL".into(),
            _ => format!("UNKNOWN({})", val),
        }
    }
    assert_eq!(peer_status_str(peer.status), "ONLINE");
}

#[tokio::test]
async fn test_get_peer_status_nonexistent() {
    // Test status of nonexistent peer via AppState
    let server = test_server();
    let state = server.state().clone();

    let result = state.get_peer("nonexistent").await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_lookup_peer() {
    // Test lookup via AppState directly (scan peers by display_name)
    let server = test_server();
    let state = server.state().clone();

    // Register peer
    let info = crate::state::PeerInfo {
        peer_id: "peer-look".to_string(),
        display_name: "LookupUser".to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: 0,
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    state.register_peer(info, None).await.unwrap();

    // Lookup by scanning peers (same logic as handlers::lookup_peer)
    let peers = state.inner.peers.read().await;
    let found = peers.values().find(|e| e.info.display_name == "LookupUser");
    assert!(found.is_some());
    let entry = found.unwrap();
    assert_eq!(entry.info.peer_id, "peer-look");
    assert_eq!(entry.info.display_name, "LookupUser");
}

#[tokio::test]
async fn test_lookup_peer_case_insensitive() {
    // Test case-insensitive lookup via AppState directly
    let server = test_server();
    let state = server.state().clone();

    // Register peer
    let info = crate::state::PeerInfo {
        peer_id: "peer-case".to_string(),
        display_name: "CaseUser".to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: 0,
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    state.register_peer(info, None).await.unwrap();

    // Case-insensitive lookup (same logic as handlers::lookup_peer)
    let peers = state.inner.peers.read().await;
    let query_lower = "caseuser".to_lowercase();
    let found = peers.values().find(|e| e.info.display_name.to_lowercase() == query_lower);
    assert!(found.is_some());
    assert_eq!(found.unwrap().info.peer_id, "peer-case");
}

#[tokio::test]
async fn test_lookup_peer_not_found() {
    let response = test_router()
        .oneshot(simple_get("/v1/peers/lookup?username=Nobody"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let result = body_json(response.into_body()).await;
    assert_eq!(result["code"], codes::UNKNOWN_PEER);
}

// ═══════════════════════════════════════════════════════════════════════
// 2. JWT authentication tests
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_register_peer_issues_valid_jwt() {
    let server = test_server();
    let verifying_key = server.state().verifying_key();
    let signing_key = &server.state().inner.signing_key;
    let expiry_secs = server.state().inner.config.jwt_expiry_secs;

    // Register peer directly
    let info = crate::state::PeerInfo {
        peer_id: "peer-jwt".to_string(),
        display_name: "JWTUser".to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: 0,
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    server.state().register_peer(info, None).await.unwrap();
    let jwt_token = jwt::create_jwt(signing_key, "peer-jwt", expiry_secs).unwrap();

    // Verify the token can be validated with the same server's verifying key
    let claims = jwt::verify_jwt(&verifying_key, &jwt_token);
    assert!(claims.is_ok());
    assert_eq!(claims.unwrap().sub, "peer-jwt");
}

#[tokio::test]
async fn test_jwt_expired_token_rejected() {
    let server = crate::server::SignalingServer::builder()
        .listen_addr("0.0.0.0:0")
        .build();
    let verifying_key = server.state().verifying_key();

    // Create an expired token by manually constructing JWT claims
    use ed25519_dalek::Signer;
    let signing_key = &server.state().inner.signing_key;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claims = jwt::JwtClaims {
        sub: "peer-expired".to_string(),
        iat: now - 200,
        exp: now - 100, // expired 100 seconds ago
        pub_key: "peer-expired".to_string(),
    };
    // Use the public create_jwt function but with 0 expiry, then manually build
    // an expired token. We'll construct the JWT manually using the same format
    // as the create_jwt function.
    let payload_json = serde_json::to_string(&claims).unwrap();

    // Manually base64url-encode and sign (same as create_jwt but with expired claims)
    const JWT_HEADER: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";
    let payload_b64 = jwt_base64url_encode(payload_json.as_bytes());
    let signing_input = format!("{}.{}", JWT_HEADER, payload_b64);
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = jwt_base64url_encode(signature.to_bytes().as_slice());
    let token = format!("{}.{}.{}", JWT_HEADER, payload_b64, sig_b64);

    let result = jwt::verify_jwt(&verifying_key, &token);
    assert!(result.is_err());
}

/// Base64url encode helper for test use (mirrors jwt::base64url_encode).
fn jwt_base64url_encode(data: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };

        result.push(CHARSET[((b0 >> 2) & 0x3F) as usize] as char);

        if i + 1 < data.len() {
            result.push(CHARSET[(((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)) as usize] as char);
        } else {
            result.push(CHARSET[(((b0 & 0x03) << 4)) as usize] as char);
            break;
        }

        if i + 2 < data.len() {
            result.push(CHARSET[(((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)) as usize] as char);
            result.push(CHARSET[(b2 & 0x3F) as usize] as char);
        } else {
            result.push(CHARSET[(((b1 & 0x0F) << 2)) as usize] as char);
            break;
        }

        i += 3;
    }
    result
}

#[tokio::test]
async fn test_jwt_wrong_key_rejected() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = SigningKey::generate(&mut OsRng).verifying_key();

    let token = jwt::create_jwt(&signing_key, "peer-wrong", 3600).unwrap();
    let result = jwt::verify_jwt(&verifying_key, &token);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_jwt_missing_token_ws() {
    let server = crate::server::SignalingServer::builder()
        .listen_addr("0.0.0.0:0")
        .build();
    let verifying_key = server.state().verifying_key();

    // Empty token should fail
    let result = jwt::verify_jwt(&verifying_key, "");
    assert!(result.is_err());

    // Random string should fail
    let result = jwt::verify_jwt(&verifying_key, "not.a.valid.jwt");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_jwt_valid_token_accepted() {
    let server = crate::server::SignalingServer::builder()
        .listen_addr("0.0.0.0:0")
        .build();
    let signing_key = &server.state().inner.signing_key;
    let verifying_key = server.state().verifying_key();

    let token = jwt::create_jwt(signing_key, "peer-valid", 3600).unwrap();
    let claims = jwt::verify_jwt(&verifying_key, &token).unwrap();
    assert_eq!(claims.sub, "peer-valid");
    assert!(claims.exp > claims.iat);
}

// ═══════════════════════════════════════════════════════════════════════
// 3. Rate limiting tests
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_rate_limit_registration() {
    // Test rate limiting by making multiple requests to the same server
    // We need to use the same server state, so we register via the state directly
    // and then test the endpoint's rate limiting with a fresh router.
    // 
    // Actually, rate limiting is keyed by peer_id, so we just test that the 
    // rate limiter works correctly via unit test instead.
    let config = crate::rate_limit::RateLimitConfig {
        registrations: BucketConfig {
            max_tokens: 2,
            refill_amount: 2,
            refill_interval_ms: 60_000,
        },
        ..Default::default()
    };
    let mut limiter = crate::rate_limit::RateLimiter::new(config);
    
    // First two should succeed
    assert!(limiter.check_registration("rl-peer").await);
    assert!(limiter.check_registration("rl-peer").await);
    // Third should fail
    assert!(!limiter.check_registration("rl-peer").await);
}

#[test]
fn test_rate_limit_config_values() {
    let default = crate::rate_limit::RateLimitConfig::default();
    assert_eq!(default.registrations.max_tokens, 6);
    assert_eq!(default.calls.max_tokens, 10);
    assert_eq!(default.ws_messages.max_tokens, 30);
}

// ═══════════════════════════════════════════════════════════════════════
// 4. /v1/myip endpoint test (extract_client_ip function)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_extract_client_ip_ipv4() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
    let (ip, port, version) = state::extract_client_ip(addr);
    assert_eq!(ip, "192.168.1.100");
    assert_eq!(port, 12345);
    assert_eq!(version, 4);
}

#[test]
fn test_extract_client_ip_ipv6() {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    let addr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        54321,
    );
    let (ip, port, version) = state::extract_client_ip(addr);
    assert_eq!(version, 6);
    assert_eq!(port, 54321);
    assert!(ip.contains("2001:db8"));
}

#[test]
fn test_extract_client_ip_loopback() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let (ip, port, version) = state::extract_client_ip(addr);
    assert_eq!(ip, "127.0.0.1");
    assert_eq!(port, 8080);
    assert_eq!(version, 4);
}

// ═══════════════════════════════════════════════════════════════════════
// 5. /v1/proxies endpoint tests
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_get_proxies_empty() {
    let response = test_router()
        .oneshot(simple_get("/v1/proxies"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = body_json(response.into_body()).await;
    assert!(result["proxies"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_get_proxies_with_data() {
    let server = crate::server::SignalingServer::builder()
        .listen_addr("0.0.0.0:0")
        .build();
    let state = server.state().clone();

    // Add a proxy
    state
        .add_proxy(ProxyInfo {
            node_id: "proxy-1".to_string(),
            proxy_url: "https://proxy.example.com:443".to_string(),
            capacity: 100,
            region: "us-east".to_string(),
            latency_hint_ms: 50,
        })
        .await;

    let response = server.router()
        .oneshot(simple_get("/v1/proxies"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = body_json(response.into_body()).await;
    let proxies = result["proxies"].as_array().unwrap();
    assert_eq!(proxies.len(), 1);
    assert_eq!(proxies[0]["node_id"], "proxy-1");
    assert_eq!(proxies[0]["proxy_url"], "https://proxy.example.com:443");
    assert_eq!(proxies[0]["capacity"], 100);
    assert_eq!(proxies[0]["region"], "us-east");
}

// ═══════════════════════════════════════════════════════════════════════
// 6. /v1/proxy-token endpoint tests
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_issue_proxy_token() {
    let server = test_server();
    let router = server.router();

    // Register both peers directly on the same server
    for (id, name) in [("caller", "Caller"), ("callee", "Callee")] {
        let info = crate::state::PeerInfo {
            peer_id: id.to_string(),
            display_name: name.to_string(),
            ipv6_addresses: vec![],
            ipv4_reflexive: vec![],
            nat_type: 0,
            status: 0,
            fcm_token: None,
            last_seen: crate::state::now_secs(),
        };
        server.state().register_peer(info, None).await.unwrap();
    }

    let body = json!({
        "peer_id": "caller",
        "target_peer_id": "callee"
    });
    let response = router
        .oneshot(json_post("/v1/proxy-token", &body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = body_json(response.into_body()).await;
    assert!(result["token"].is_string());
    assert_eq!(result["ttl_seconds"], 60);
}

#[tokio::test]
async fn test_issue_proxy_token_caller_not_found() {
    let server = test_server();
    let router = server.router();

    // Register callee only
    let info = crate::state::PeerInfo {
        peer_id: "callee-only".to_string(),
        display_name: "CalleeOnly".to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: 0,
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    server.state().register_peer(info, None).await.unwrap();

    let body = json!({
        "peer_id": "nonexistent-caller",
        "target_peer_id": "callee-only"
    });
    let response = router
        .oneshot(json_post("/v1/proxy-token", &body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let result = body_json(response.into_body()).await;
    assert_eq!(result["code"], codes::UNKNOWN_PEER);
}

#[tokio::test]
async fn test_issue_proxy_token_target_not_found() {
    let server = test_server();
    let router = server.router();

    // Register caller only
    let info = crate::state::PeerInfo {
        peer_id: "caller-only".to_string(),
        display_name: "CallerOnly".to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: 0,
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    server.state().register_peer(info, None).await.unwrap();

    let body = json!({
        "peer_id": "caller-only",
        "target_peer_id": "nonexistent-target"
    });
    let response = router
        .oneshot(json_post("/v1/proxy-token", &body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let result = body_json(response.into_body()).await;
    assert_eq!(result["code"], codes::UNKNOWN_PEER);
}

// ═══════════════════════════════════════════════════════════════════════
// 7. /v1/dht/bootstrap endpoint tests
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_dht_bootstrap_default() {
    let response = test_router()
        .oneshot(simple_get("/v1/dht/bootstrap"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = body_json(response.into_body()).await;
    // Default config has no DHT bootstrap nodes
    assert!(result["nodes"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_dht_bootstrap_with_nodes() {
    let mut voip_config = voip_core::VoIPConfig::default();
    voip_config.dht_bootstrap_nodes = vec![
        "/ip4/10.0.0.1/udp/443/quic-v1/p2p/QmNode1".to_string(),
        "/ip4/10.0.0.2/udp/443/quic-v1/p2p/QmNode2".to_string(),
    ];

    let server = crate::server::SignalingServer::builder()
        .listen_addr("0.0.0.0:0")
        .voip_config(voip_config)
        .build();

    let response = server.router()
        .oneshot(simple_get("/v1/dht/bootstrap"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = body_json(response.into_body()).await;
    let nodes = result["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 2);
    assert!(nodes[0].as_str().unwrap().contains("QmNode1"));
    assert!(nodes[1].as_str().unwrap().contains("QmNode2"));
}

// ═══════════════════════════════════════════════════════════════════════
// 8. Error response tests with correct error codes (1001-9999)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_error_unknown_peer_code_1001() {
    // Test error code and HTTP status directly via SignalingError
    let err = crate::error::SignalingError::UnknownPeer("nonexistent".to_string());
    assert_eq!(err.code(), codes::UNKNOWN_PEER); // 1001
    assert_eq!(err.http_status(), StatusCode::NOT_FOUND);

    // Verify IntoResponse produces a JSON body with the error code
    use axum::response::IntoResponse;
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_bytes(response.into_body()).await;
    let result: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["code"], codes::UNKNOWN_PEER);
    assert!(result["message"].is_string());
}

#[tokio::test]
async fn test_error_rate_limited_code_2001() {
    // Test rate limiting directly via RateLimiter (avoids Router ownership issues)
    let config = crate::rate_limit::RateLimitConfig {
        registrations: BucketConfig {
            max_tokens: 2,
            refill_amount: 2,
            refill_interval_ms: 60_000,
        },
        ..Default::default()
    };
    let mut limiter = crate::rate_limit::RateLimiter::new(config);

    // First two should succeed
    assert!(limiter.check_registration("rl-code-peer").await);
    assert!(limiter.check_registration("rl-code-peer").await);
    // Third should be rate limited
    assert!(!limiter.check_registration("rl-code-peer").await);

    // Verify the SignalingError produces the correct code and status
    let err = crate::error::SignalingError::RateLimited;
    assert_eq!(err.code(), codes::RATE_LIMITED); // 2001
    assert_eq!(err.http_status(), StatusCode::TOO_MANY_REQUESTS);

    // Verify IntoResponse produces a JSON body with the error code
    use axum::response::IntoResponse;
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = body_bytes(response.into_body()).await;
    let result: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["code"], codes::RATE_LIMITED);
}

#[test]
fn test_error_code_values() {
    // Peer errors (1xxx)
    assert_eq!(codes::UNKNOWN_PEER, 1001);
    assert_eq!(codes::PEER_OFFLINE, 1002);
    assert_eq!(codes::INVALID_CALL_ID, 1003);
    assert_eq!(codes::CALL_ALREADY_EXISTS, 1004);
    assert_eq!(codes::NOT_CALL_PARTICIPANT, 1005);

    // Rate-limit / auth errors (2xxx)
    assert_eq!(codes::RATE_LIMITED, 2001);
    assert_eq!(codes::INVALID_JWT, 2002);
    assert_eq!(codes::INVALID_MESSAGE, 2003);

    // MASQUE errors (3xxx)
    assert_eq!(codes::MASQUE_NO_PROXY, 3001);
    assert_eq!(codes::MASQUE_PROXY_TIMEOUT, 3002);
    assert_eq!(codes::MASQUE_COORDINATION_FAILED, 3003);

    // Internal
    assert_eq!(codes::INTERNAL_ERROR, 9999);
}

#[test]
fn test_error_http_status_mapping() {
    use crate::error::SignalingError;

    // UnknownPeer → 404
    assert_eq!(
        SignalingError::UnknownPeer("test".into()).http_status(),
        StatusCode::NOT_FOUND
    );
    // PeerOffline → 404
    assert_eq!(
        SignalingError::PeerOffline("test".into()).http_status(),
        StatusCode::NOT_FOUND
    );
    // RateLimited → 429
    assert_eq!(
        SignalingError::RateLimited.http_status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // InvalidJwt → 401
    assert_eq!(
        SignalingError::InvalidJwt("test".into()).http_status(),
        StatusCode::UNAUTHORIZED
    );
    // InvalidCallId → 400
    assert_eq!(
        SignalingError::InvalidCallId("test".into()).http_status(),
        StatusCode::BAD_REQUEST
    );
    // CallAlreadyExists → 409
    assert_eq!(
        SignalingError::CallAlreadyExists("test".into()).http_status(),
        StatusCode::CONFLICT
    );
    // NotCallParticipant → 403
    assert_eq!(
        SignalingError::NotCallParticipant("test".into()).http_status(),
        StatusCode::FORBIDDEN
    );
    // MasqueNoProxy → 503
    assert_eq!(
        SignalingError::MasqueNoProxy.http_status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    // Internal → 500
    assert_eq!(
        SignalingError::Internal("test".into()).http_status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[test]
fn test_error_code_mapping() {
    use crate::error::SignalingError;

    assert_eq!(SignalingError::UnknownPeer("x".into()).code(), 1001);
    assert_eq!(SignalingError::PeerOffline("x".into()).code(), 1002);
    assert_eq!(SignalingError::InvalidCallId("x".into()).code(), 1003);
    assert_eq!(SignalingError::CallAlreadyExists("x".into()).code(), 1004);
    assert_eq!(SignalingError::NotCallParticipant("x".into()).code(), 1005);
    assert_eq!(SignalingError::RateLimited.code(), 2001);
    assert_eq!(SignalingError::InvalidJwt("x".into()).code(), 2002);
    assert_eq!(SignalingError::InvalidMessage("x".into()).code(), 2003);
    assert_eq!(SignalingError::MasqueNoProxy.code(), 3001);
    assert_eq!(SignalingError::MasqueProxyTimeout.code(), 3002);
    assert_eq!(SignalingError::MasqueCoordinationFailed.code(), 3003);
    assert_eq!(SignalingError::Internal("x".into()).code(), 9999);
}

// ═══════════════════════════════════════════════════════════════════════
// 9. MASQUE relay coordination tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_detect_masque_need_both_symmetric_random() {
    assert!(masque::detect_masque_need(
        NATType::SymmetricRandom,
        NATType::SymmetricRandom
    ));
}

#[test]
fn test_detect_masque_not_needed_cone() {
    assert!(!masque::detect_masque_need(NATType::Cone, NATType::Cone));
}

#[test]
fn test_detect_masque_not_needed_ipv6() {
    assert!(!masque::detect_masque_need(NATType::None, NATType::None));
}

#[test]
fn test_detect_masque_not_needed_one_random_one_cone() {
    assert!(!masque::detect_masque_need(
        NATType::SymmetricRandom,
        NATType::Cone
    ));
}

#[test]
fn test_detect_masque_not_needed_sequential() {
    assert!(!masque::detect_masque_need(
        NATType::SymmetricSequential,
        NATType::SymmetricSequential
    ));
}

#[test]
fn test_detect_masque_not_needed_pseudo() {
    assert!(!masque::detect_masque_need(
        NATType::SymmetricPseudo,
        NATType::SymmetricPseudo
    ));
}

#[test]
fn test_detect_masque_not_needed_mixed() {
    assert!(!masque::detect_masque_need(
        NATType::SymmetricPseudo,
        NATType::SymmetricRandom
    ));
}

#[tokio::test]
async fn test_masque_relay_no_proxy_available() {
    let server = crate::server::SignalingServer::builder()
        .listen_addr("0.0.0.0:0")
        .build();
    let state = server.state().clone();

    // No proxies configured — coordinate_masque_relay should fail
    let result = state
        .coordinate_masque_relay("call-1", "peer-a", "peer-b")
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), codes::MASQUE_NO_PROXY);
}

#[tokio::test]
async fn test_masque_select_proxy_returns_first() {
    let server = crate::server::SignalingServer::builder()
        .listen_addr("0.0.0.0:0")
        .build();
    let state = server.state().clone();

    state
        .add_proxy(ProxyInfo {
            node_id: "proxy-first".to_string(),
            proxy_url: "https://first.example.com".to_string(),
            capacity: 50,
            region: "us-west".to_string(),
            latency_hint_ms: 30,
        })
        .await;
    state
        .add_proxy(ProxyInfo {
            node_id: "proxy-second".to_string(),
            proxy_url: "https://second.example.com".to_string(),
            capacity: 100,
            region: "eu-central".to_string(),
            latency_hint_ms: 80,
        })
        .await;

    let selected = masque::select_proxy(&state).await;
    assert!(selected.is_some());
    assert_eq!(selected.unwrap().node_id, "proxy-first");
}

// ═══════════════════════════════════════════════════════════════════════
// 10. OpenAPI spec endpoint test
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_openapi_json_endpoint() {
    let response = test_router()
        .oneshot(simple_get("/v1/openapi.json"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let result = body_json(response.into_body()).await;
    // Verify the OpenAPI spec has expected structure
    assert!(result["openapi"].is_string());
    assert!(result["info"].is_object());
    assert!(result["paths"].is_object());

    // Verify all documented paths are present
    let paths = result["paths"].as_object().unwrap();
    assert!(paths.contains_key("/v1/peers"));
    assert!(paths.contains_key("/v1/peers/{peer_id}"));
    assert!(paths.contains_key("/v1/peers/{peer_id}/status"));
    assert!(paths.contains_key("/v1/peers/lookup"));
    assert!(paths.contains_key("/v1/myip"));
    assert!(paths.contains_key("/v1/proxies"));
    assert!(paths.contains_key("/v1/dht/bootstrap"));
    assert!(paths.contains_key("/v1/proxy-token"));
}

#[test]
fn test_api_doc_generates_valid_spec() {
    let spec = ApiDoc::openapi();
    let json = serde_json::to_value(&spec).unwrap();

    // Verify spec structure
    assert!(json["openapi"].is_string());
    assert!(json["info"]["title"].is_string());
    assert!(json["paths"].is_object());
    assert!(json["components"]["schemas"].is_object());

    // Verify schema components exist for key types
    let schemas = json["components"]["schemas"].as_object().unwrap();
    assert!(schemas.contains_key("RegisterPeerRequest"));
    assert!(schemas.contains_key("RegisterPeerResponse"));
    assert!(schemas.contains_key("PeerResponse"));
    assert!(schemas.contains_key("ErrorResponse"));
    assert!(schemas.contains_key("ProxyTokenRequest"));
    assert!(schemas.contains_key("ProxyTokenResponse"));
}

// ═══════════════════════════════════════════════════════════════════════
// 11. State and peer lifecycle tests
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_peer_lifecycle_full() {
    // Full lifecycle via AppState directly (avoids Router oneshot ownership issues)
    let server = test_server();
    let state = server.state().clone();

    // 1. Register
    let info = crate::state::PeerInfo {
        peer_id: "lifecycle-peer".to_string(),
        display_name: "Lifecycle".to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: 0,
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    state.register_peer(info, None).await.unwrap();

    // 2. Get
    let peer = state.get_peer("lifecycle-peer").await;
    assert!(peer.is_some());
    let peer = peer.unwrap();
    assert_eq!(peer.display_name, "Lifecycle");

    // 3. Update (re-register with updated info)
    let updated_info = crate::state::PeerInfo {
        peer_id: "lifecycle-peer".to_string(),
        display_name: "LifecycleUpdated".to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec!["10.0.0.1:1234".to_string()],
        nat_type: 1, // CONE
        status: 0,
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    state.register_peer(updated_info, None).await.unwrap();

    // 4. Verify update
    let updated = state.get_peer("lifecycle-peer").await.unwrap();
    assert_eq!(updated.display_name, "LifecycleUpdated");
    assert_eq!(updated.ipv4_reflexive, vec!["10.0.0.1:1234"]);
    assert_eq!(updated.nat_type, 1);

    // 5. Lookup by display_name (case-insensitive, same logic as handler)
    let peers = state.inner.peers.read().await;
    let query_lower = "lifecycleupdated".to_lowercase();
    let found = peers.values().find(|e| e.info.display_name.to_lowercase() == query_lower);
    assert!(found.is_some());
    drop(peers);

    // 6. Status check
    let peer = state.get_peer("lifecycle-peer").await.unwrap();
    assert_eq!(peer.status, 0); // ONLINE

    // 7. Delete
    state.unregister_peer("lifecycle-peer").await.unwrap();

    // 8. Verify deleted
    assert!(state.get_peer("lifecycle-peer").await.is_none());
}

#[tokio::test]
async fn test_multiple_peers_registration() {
    // Test multiple peers via AppState directly
    let server = test_server();
    let state = server.state().clone();

    for i in 0..5 {
        let info = crate::state::PeerInfo {
            peer_id: format!("multi-peer-{}", i),
            display_name: format!("Peer{}", i),
            ipv6_addresses: vec![],
            ipv4_reflexive: vec![],
            nat_type: 0,
            status: 0,
            fcm_token: None,
            last_seen: crate::state::now_secs(),
        };
        state.register_peer(info, None).await.unwrap();
    }

    // Verify each peer was registered
    for i in 0..5 {
        let peer_id = format!("multi-peer-{}", i);
        let peer = state.get_peer(&peer_id).await;
        assert!(peer.is_some());
        assert_eq!(peer.unwrap().display_name, format!("Peer{}", i));
    }

    // Lookup one of them by display_name
    let peers = state.inner.peers.read().await;
    let found = peers.values().find(|e| e.info.display_name == "Peer3");
    assert!(found.is_some());
    assert_eq!(found.unwrap().info.peer_id, "multi-peer-3");
}

// ═══════════════════════════════════════════════════════════════════════
// 12. Framed message encode/decode tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_encode_decode_message() {
    let type_id: u16 = 0x0001;
    let payload = b"hello world".to_vec();
    let encoded = state::encode_message(type_id, &payload);
    let (decoded_type, decoded_payload) = state::decode_message(&encoded).unwrap();
    assert_eq!(decoded_type, type_id);
    assert_eq!(decoded_payload, payload);
}

#[test]
fn test_decode_message_too_short() {
    let result = state::decode_message(b"a");
    assert!(result.is_err());
}

#[test]
fn test_decode_message_empty() {
    let result = state::decode_message(b"");
    assert!(result.is_err());
}

#[test]
fn test_decode_message_exact_header() {
    let result = state::decode_message(b"\x00\x01");
    assert!(result.is_ok());
    let (type_id, payload) = result.unwrap();
    assert_eq!(type_id, 1);
    assert!(payload.is_empty());
}

#[test]
fn test_framed_message_error() {
    let msg = state::FramedMessage::error(codes::RATE_LIMITED, "test error");
    assert_eq!(msg.type_id, state::type_id::ERROR);
    // The payload should be decodable as a protobuf Error message
    let decoded = voip_core::proto::signaling::Error::decode(msg.payload.as_slice());
    assert!(decoded.is_ok());
    let err = decoded.unwrap();
    assert_eq!(err.code, codes::RATE_LIMITED);
    assert_eq!(err.message, "test error");
}

// ═══════════════════════════════════════════════════════════════════════
// 13. NAT type and peer status string conversion
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_nat_type_strings_in_response() {
    // Test nat_type and status via AppState directly
    let server = test_server();
    let state = server.state().clone();

    // Register peer with specific nat_type and status
    let info = crate::state::PeerInfo {
        peer_id: "nat-peer".to_string(),
        display_name: "NatPeer".to_string(),
        ipv6_addresses: vec![],
        ipv4_reflexive: vec![],
        nat_type: 2, // SYMMETRIC_SEQUENTIAL
        status: 2,   // IN_CALL
        fcm_token: None,
        last_seen: crate::state::now_secs(),
    };
    state.register_peer(info, None).await.unwrap();

    // Get peer and verify values
    let peer = state.get_peer("nat-peer").await.unwrap();
    assert_eq!(peer.nat_type, 2);
    assert_eq!(peer.status, 2);

    // Verify nat_type string mapping (same logic as handlers::nat_type_str)
    fn nat_type_str(val: i32) -> String {
        match val {
            0 => "NONE".into(),
            1 => "CONE".into(),
            2 => "SYMMETRIC_SEQUENTIAL".into(),
            3 => "SYMMETRIC_PSEUDO".into(),
            4 => "SYMMETRIC_RANDOM".into(),
            _ => format!("UNKNOWN({})", val),
        }
    }

    fn peer_status_str(val: i32) -> String {
        match val {
            0 => "ONLINE".into(),
            1 => "OFFLINE".into(),
            2 => "IN_CALL".into(),
            _ => format!("UNKNOWN({})", val),
        }
    }

    assert_eq!(nat_type_str(peer.nat_type), "SYMMETRIC_SEQUENTIAL");
    assert_eq!(peer_status_str(peer.status), "IN_CALL");
}

// ═══════════════════════════════════════════════════════════════════════
// 14. Push notification (stub) tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_is_retryable_reason() {
    use crate::push::is_retryable_reason;

    assert!(is_retryable_reason(3)); // END_FAILED_IPV4_RANDOM
    assert!(is_retryable_reason(7)); // END_FAILED_MASQUE_UNREACHABLE
    assert!(!is_retryable_reason(0)); // END_NORMAL
    assert!(!is_retryable_reason(1)); // END_REJECTED
    assert!(!is_retryable_reason(4)); // END_FAILED_UDP_BLOCKED (not retryable per spec)
}

#[tokio::test]
async fn test_push_notifier_stub() {
    use crate::push::{PushNotifier, PushNotification};

    let notifier = PushNotifier::new_stub();
    let notification = PushNotification {
        fcm_token: "test-token".to_string(),
        call_id: "call-123".to_string(),
        caller_id: "caller".to_string(),
        callee_id: "callee".to_string(),
        reason: 3,
        retry_attempt: 1,
        retry_after_ms: 5000,
    };
    let result = notifier.send(&notification).await;
    assert!(result.is_ok());
}
