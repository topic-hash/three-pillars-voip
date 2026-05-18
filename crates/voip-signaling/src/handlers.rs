//! REST API handlers from spec/08 §8.1.2.
//!
//! Endpoints:
//!   - POST   /v1/peers                 — register peer
//!   - PUT    /v1/peers/{peer_id}       — update peer registration
//!   - DELETE /v1/peers/{peer_id}       — unregister peer
//!   - GET    /v1/peers/{peer_id}       — peer lookup
//!   - GET    /v1/peers/lookup           — resolve username to peer_id
//!   - GET    /v1/peers/{peer_id}/status — peer online status
//!   - GET    /v1/myip                  — client's observed IP
//!   - GET    /v1/proxies               — MASQUE proxy discovery
//!   - GET    /v1/dht/bootstrap         — DHT bootstrap nodes
//!   - POST   /v1/proxy-token           — issue ProxyToken
//!   - GET    /v1/ws                    — WebSocket upgrade

use axum::extract::{ConnectInfo, Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use ed25519_dalek::Signer;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::{debug, info, warn};

use crate::auth::AuthenticatedPeer;
use crate::error::{ErrorResponse, SignalingError};
use crate::jwt;
use crate::session;
use crate::state::{AppState, PeerInfo};

// ── JSON request / response types ──────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PeerResponse {
    pub peer_id: String,
    pub display_name: String,
    pub ipv6_addresses: Vec<String>,
    pub ipv4_reflexive: Vec<String>,
    pub nat_type: String,
    pub status: String,
    pub last_seen: u64,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RegisterPeerRequest {
    pub peer_id: String,
    pub display_name: String,
    #[serde(default)]
    pub ipv6_addresses: Vec<String>,
    #[serde(default)]
    pub ipv4_reflexive: Vec<String>,
    pub nat_type: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    pub fcm_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MyIpResponse {
    pub ip: String,
    pub ip_version: u8,
    pub port: u16,
    pub observed_at: u64,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProxyResponse {
    pub proxies: Vec<ProxyEntryResponse>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProxyEntryResponse {
    pub node_id: String,
    pub proxy_url: String,
    pub capacity: u32,
    pub region: String,
    pub latency_hint_ms: u32,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProxyTokenRequest {
    pub peer_id: String,
    pub target_peer_id: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProxyTokenResponse {
    pub token: String,
    pub ttl_seconds: u32,
}

#[derive(Debug, Serialize, Deserialize, utoipa::IntoParams)]
pub struct LookupQuery {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LookupResponse {
    pub peer_id: String,
    pub display_name: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PeerStatusResponse {
    pub peer_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DhtBootstrapResponse {
    pub nodes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::IntoParams)]
pub struct JwtTokenQuery {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RegisterPeerResponse {
    pub peer_id: String,
    pub jwt_token: String,
    pub expires_in_secs: u64,
}

// ── Helper: convert numeric enum to human-readable string ──────────────

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

// ── Handlers ───────────────────────────────────────────────────────────

/// `POST /v1/peers` — register a new peer.
///
/// Also issues a JWT token for the peer to use for WebSocket auth.
/// This endpoint does NOT require authentication — it is the entry point
/// that issues JWTs. The `peer_id` field must be a valid 64-char hex string
/// representing an Ed25519 public key.
#[utoipa::path(
    post,
    path = "/v1/peers",
    request_body = RegisterPeerRequest,
    responses(
        (status = 201, description = "Peer registered successfully, JWT token issued", body = RegisterPeerResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    tag = "Peers"
)]
pub async fn register_peer(
    State(state): State<AppState>,
    Json(body): Json<RegisterPeerRequest>,
) -> crate::error::Result<(StatusCode, Json<RegisterPeerResponse>)> {
    // Validate peer_id is a valid Ed25519 public key hex string (64 chars)
    voip_core::crypto::parse_peer_id(&body.peer_id).map_err(|e| {
        debug!(
            peer_id = %body.peer_id,
            error = %e,
            "invalid peer_id: must be 64-char hex Ed25519 public key"
        );
        SignalingError::InvalidMessage(
            "peer_id must be a valid 64-char hex Ed25519 public key".to_owned(),
        )
    })?;

    // Rate limit registrations
    if !state
        .inner
        .rate_limiter
        .check_registration(&body.peer_id)
        .await
    {
        return Err(SignalingError::RateLimited);
    }

    let nat_type = match body.nat_type.as_deref() {
        Some("NONE") => 0,
        Some("CONE") => 1,
        Some("SYMMETRIC_SEQUENTIAL") => 2,
        Some("SYMMETRIC_PSEUDO") => 3,
        Some("SYMMETRIC_RANDOM") => 4,
        _ => 0, // default NONE
    };

    let status = match body.status.as_deref() {
        Some("ONLINE") => 0,
        Some("OFFLINE") => 1,
        Some("IN_CALL") => 2,
        _ => 0, // default ONLINE
    };

    let info = PeerInfo {
        peer_id: body.peer_id.clone(),
        display_name: body.display_name.clone(),
        ipv6_addresses: body.ipv6_addresses.clone(),
        ipv4_reflexive: body.ipv4_reflexive.clone(),
        nat_type,
        status,
        fcm_token: body.fcm_token.clone(),
        last_seen: crate::state::now_secs(),
    };

    // Register without WS sender (REST-only registration)
    state.register_peer(info, None).await?;

    // Issue JWT token
    let expiry_secs = state.inner.config.jwt_expiry_secs;
    let jwt_token = jwt::create_jwt(&state.inner.signing_key, &body.peer_id, expiry_secs)
        .map_err(|e| SignalingError::Internal(e.to_string()))?;

    info!(peer_id = %body.peer_id, "peer registered via REST, JWT issued");

    Ok((
        StatusCode::CREATED,
        Json(RegisterPeerResponse {
            peer_id: body.peer_id,
            jwt_token,
            expires_in_secs: expiry_secs,
        }),
    ))
}

/// `PUT /v1/peers/{peer_id}` — update peer registration.
///
/// Requires JWT authentication. The authenticated peer_id must match
/// the `{peer_id}` path parameter.
#[utoipa::path(
    put,
    path = "/v1/peers/{peer_id}",
    request_body = RegisterPeerRequest,
    responses(
        (status = 200, description = "Peer updated successfully", body = PeerResponse),
        (status = 404, description = "Peer not found", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
    tag = "Peers"
)]
pub async fn update_peer(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedPeer>,
    Path(peer_id): Path<String>,
    Json(body): Json<RegisterPeerRequest>,
) -> crate::error::Result<Json<PeerResponse>> {
    // Authorization: authenticated peer must match the target peer_id
    if auth.peer_id != peer_id {
        return Err(SignalingError::Unauthorized(
            "authenticated peer_id does not match target".to_owned(),
        ));
    }

    // Verify peer exists
    let existing = state
        .get_peer(&peer_id)
        .await
        .ok_or_else(|| SignalingError::UnknownPeer(peer_id.clone()))?;

    let nat_type = match body.nat_type.as_deref() {
        Some("NONE") => 0,
        Some("CONE") => 1,
        Some("SYMMETRIC_SEQUENTIAL") => 2,
        Some("SYMMETRIC_PSEUDO") => 3,
        Some("SYMMETRIC_RANDOM") => 4,
        _ => existing.nat_type,
    };

    let status = match body.status.as_deref() {
        Some("ONLINE") => 0,
        Some("OFFLINE") => 1,
        Some("IN_CALL") => 2,
        _ => existing.status,
    };

    let info = PeerInfo {
        peer_id: peer_id.clone(),
        display_name: if body.display_name.is_empty() {
            existing.display_name
        } else {
            body.display_name
        },
        ipv6_addresses: if body.ipv6_addresses.is_empty() {
            existing.ipv6_addresses
        } else {
            body.ipv6_addresses
        },
        ipv4_reflexive: if body.ipv4_reflexive.is_empty() {
            existing.ipv4_reflexive
        } else {
            body.ipv4_reflexive
        },
        nat_type,
        status,
        fcm_token: body.fcm_token.or(existing.fcm_token),
        last_seen: crate::state::now_secs(),
    };

    let response = PeerResponse {
        peer_id: info.peer_id.clone(),
        display_name: info.display_name.clone(),
        ipv6_addresses: info.ipv6_addresses.clone(),
        ipv4_reflexive: info.ipv4_reflexive.clone(),
        nat_type: nat_type_str(info.nat_type),
        status: peer_status_str(info.status),
        last_seen: info.last_seen,
    };

    // Update peer — do NOT overwrite sender (keep WS session if present)
    state.register_peer(info, None).await?;

    debug!(peer_id = %peer_id, "peer updated via REST");
    Ok(Json(response))
}

/// `DELETE /v1/peers/{peer_id}` — unregister a peer.
///
/// Requires JWT authentication. The authenticated peer_id must match
/// the `{peer_id}` path parameter.
#[utoipa::path(
    delete,
    path = "/v1/peers/{peer_id}",
    responses(
        (status = 204, description = "Peer unregistered successfully"),
        (status = 404, description = "Peer not found", body = ErrorResponse),
    ),
    tag = "Peers"
)]
pub async fn unregister_peer(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedPeer>,
    Path(peer_id): Path<String>,
) -> crate::error::Result<StatusCode> {
    // Authorization: authenticated peer must match the target peer_id
    if auth.peer_id != peer_id {
        return Err(SignalingError::Unauthorized(
            "authenticated peer_id does not match target".to_owned(),
        ));
    }

    state.unregister_peer(&peer_id).await?;
    info!(peer_id = %peer_id, "peer deleted via REST");
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/peers/{peer_id}` — peer lookup.
///
/// Requires JWT authentication.
#[utoipa::path(
    get,
    path = "/v1/peers/{peer_id}",
    responses(
        (status = 200, description = "Peer information", body = PeerResponse),
        (status = 404, description = "Peer not found", body = ErrorResponse),
    ),
    tag = "Peers"
)]
pub async fn get_peer(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedPeer>,
    Path(peer_id): Path<String>,
) -> crate::error::Result<Json<PeerResponse>> {
    let info = state
        .get_peer(&peer_id)
        .await
        .ok_or_else(|| SignalingError::UnknownPeer(peer_id))?;

    Ok(Json(PeerResponse {
        peer_id: info.peer_id,
        display_name: info.display_name,
        ipv6_addresses: info.ipv6_addresses,
        ipv4_reflexive: info.ipv4_reflexive,
        nat_type: nat_type_str(info.nat_type),
        status: peer_status_str(info.status),
        last_seen: info.last_seen,
    }))
}

/// `GET /v1/peers/{peer_id}/status` — peer online status.
///
/// Requires JWT authentication.
#[utoipa::path(
    get,
    path = "/v1/peers/{peer_id}/status",
    responses(
        (status = 200, description = "Peer status", body = PeerStatusResponse),
        (status = 404, description = "Peer not found", body = ErrorResponse),
    ),
    tag = "Peers"
)]
pub async fn get_peer_status(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedPeer>,
    Path(peer_id): Path<String>,
) -> crate::error::Result<Json<PeerStatusResponse>> {
    let info = state
        .get_peer(&peer_id)
        .await
        .ok_or_else(|| SignalingError::UnknownPeer(peer_id))?;

    Ok(Json(PeerStatusResponse {
        peer_id: info.peer_id,
        status: peer_status_str(info.status),
    }))
}

/// `GET /v1/peers/lookup?username={name}` — resolve username to peer_id.
///
/// Requires JWT authentication.
#[utoipa::path(
    get,
    path = "/v1/peers/lookup",
    params(LookupQuery),
    responses(
        (status = 200, description = "Peer found", body = LookupResponse),
        (status = 404, description = "Peer not found", body = ErrorResponse),
    ),
    tag = "Peers"
)]
pub async fn lookup_peer(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedPeer>,
    Query(query): Query<LookupQuery>,
) -> crate::error::Result<Json<LookupResponse>> {
    // Search through peers by display_name (case-insensitive exact match).
    // In a production system this would be indexed; here we scan.
    let peers = state.inner.peers.read().await;
    let query_lower = query.username.to_lowercase();

    let found = peers.values().find(|entry| {
        entry.info.display_name.to_lowercase() == query_lower
    });

    match found {
        Some(entry) => Ok(Json(LookupResponse {
            peer_id: entry.info.peer_id.clone(),
            display_name: entry.info.display_name.clone(),
            status: peer_status_str(entry.info.status),
        })),
        None => Err(SignalingError::UnknownPeer(query.username)),
    }
}

/// `GET /v1/myip` — return the client's observed IP address.
///
/// Per spec/08 §8.1.3: Returns observed IP, port, IP version, and timestamp.
/// If the server sees an IPv6 address, the client skips NAT probing entirely.
#[utoipa::path(
    get,
    path = "/v1/myip",
    responses(
        (status = 200, description = "Client's observed IP address", body = MyIpResponse),
    ),
    tag = "Network"
)]
pub async fn get_my_ip(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Json<MyIpResponse> {
    let (ip, port, version) = crate::state::extract_client_ip(addr);
    let observed_at = crate::state::now_secs();
    Json(MyIpResponse {
        ip,
        ip_version: version,
        port,
        observed_at,
    })
}

/// `GET /v1/proxies` — MASQUE proxy discovery.
///
/// Per spec/06 §6.8.3: Returns list of known MASQUE proxy addresses.
/// Proxies returned by the signaling server are guaranteed reachable.
///
/// Requires JWT authentication.
#[utoipa::path(
    get,
    path = "/v1/proxies",
    responses(
        (status = 200, description = "List of MASQUE proxies", body = ProxyResponse),
    ),
    tag = "MASQUE"
)]
pub async fn get_proxies(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedPeer>,
) -> Json<ProxyResponse> {
    let proxies = state.get_proxies().await;
    Json(ProxyResponse {
        proxies: proxies
            .into_iter()
            .map(|p| ProxyEntryResponse {
                node_id: p.node_id,
                proxy_url: p.proxy_url,
                capacity: p.capacity,
                region: p.region,
                latency_hint_ms: p.latency_hint_ms,
            })
            .collect(),
    })
}

/// `GET /v1/dht/bootstrap` — return list of DHT bootstrap nodes.
///
/// Per spec/06 §6.2.3: Returns active DHT node multiaddresses for bootstrap.
/// Fallback: hardcoded seed nodes from app binary.
///
/// Requires JWT authentication.
#[utoipa::path(
    get,
    path = "/v1/dht/bootstrap",
    responses(
        (status = 200, description = "DHT bootstrap nodes", body = DhtBootstrapResponse),
    ),
    tag = "DHT"
)]
pub async fn dht_bootstrap(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedPeer>,
) -> Json<DhtBootstrapResponse> {
    let nodes = state.get_dht_bootstrap().await;
    Json(DhtBootstrapResponse { nodes })
}

/// `POST /v1/proxy-token` — issue a ProxyToken for anti-abuse verification.
///
/// Per spec/08 §8.1.2 and signaling.proto ProxyToken message:
/// Signs a ProxyToken with the server's Ed25519 private key.
/// The token is presented to the MASQUE proxy for anti-abuse verification.
///
/// Requires JWT authentication.
#[utoipa::path(
    post,
    path = "/v1/proxy-token",
    request_body = ProxyTokenRequest,
    responses(
        (status = 200, description = "ProxyToken issued", body = ProxyTokenResponse),
        (status = 404, description = "Peer not found", body = ErrorResponse),
    ),
    tag = "MASQUE"
)]
pub async fn issue_proxy_token(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthenticatedPeer>,
    Json(body): Json<ProxyTokenRequest>,
) -> crate::error::Result<Json<ProxyTokenResponse>> {
    // Verify both peers exist
    let _caller = state
        .get_peer(&body.peer_id)
        .await
        .ok_or_else(|| SignalingError::UnknownPeer(body.peer_id.clone()))?;
    let _target = state
        .get_peer(&body.target_peer_id)
        .await
        .ok_or_else(|| SignalingError::UnknownPeer(body.target_peer_id.clone()))?;

    let ttl_seconds: u32 = 60;
    let issued_at = crate::state::now_secs();

    // Create the protobuf ProxyToken
    let proxy_token = voip_core::proto::signaling::ProxyToken {
        peer_id: body.peer_id.clone(),
        target_peer_id: body.target_peer_id.clone(),
        issued_at,
        ttl_seconds,
        signature: Vec::new(), // placeholder, we sign below
    };

    // Serialize without signature for signing
    let mut token_for_signing = proxy_token.clone();
    token_for_signing.signature.clear();
    let data_to_sign = token_for_signing.encode_to_vec();

    // Sign with server's Ed25519 signing key
    let signature = state.inner.signing_key.sign(&data_to_sign);
    let signature_bytes = signature.to_bytes().to_vec();

    // Build the final token with signature
    let final_token = voip_core::proto::signaling::ProxyToken {
        peer_id: body.peer_id.clone(),
        target_peer_id: body.target_peer_id.clone(),
        issued_at,
        ttl_seconds,
        signature: signature_bytes,
    };

    // Encode the final token as base64 for the JSON response
    let token_bytes = final_token.encode_to_vec();
    let token_b64 = base64_encode(&token_bytes);

    info!(
        peer_id = %body.peer_id,
        target = %body.target_peer_id,
        "ProxyToken issued"
    );

    Ok(Json(ProxyTokenResponse {
        token: token_b64,
        ttl_seconds,
    }))
}

/// `GET /v1/ws` — WebSocket upgrade endpoint.
///
/// This is the main real-time signaling channel. Each connected client
/// gets a session that handles message routing.
///
/// Authentication: JWT token in query parameter `?token=<jwt>`.
pub async fn ws_upgrade(
    ws: axum::extract::ws::WebSocketUpgrade,
    Query(query): Query<JwtTokenQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> crate::error::Result<impl IntoResponse> {
    // Verify JWT token
    let verifying_key = state.verifying_key();
    let claims = jwt::verify_jwt(&verifying_key, &query.token)
        .map_err(|e| {
            warn!(addr = %addr, error = %e, "WebSocket JWT auth failed");
            e
        })?;

    let peer_id = claims.sub.clone();
    info!(addr = %addr, peer_id = %peer_id, "WebSocket upgrade authenticated");

    Ok(ws.on_upgrade(move |socket| {
        session::handle_ws_connection(socket, addr, state, peer_id)
    }))
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Simple base64 encoding for binary data.
fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };

        result.push(CHARSET[((b0 >> 2) & 0x3F) as usize] as char);
        result.push(CHARSET[(((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)) as usize] as char);

        if i + 1 < data.len() {
            result.push(CHARSET[(((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(CHARSET[(b2 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }
    result
}
