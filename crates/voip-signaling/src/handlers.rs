//! REST API handlers from spec/08 §8.1.2.
//!
//! Endpoints:
//!   - GET    /v1/peers/{peer_id}       — peer lookup
//!   - POST   /v1/peers                 — register peer
//!   - PUT    /v1/peers/{peer_id}       — update peer registration
//!   - DELETE /v1/peers/{peer_id}       — unregister peer
//!   - GET    /v1/peers/lookup           — resolve username to peer_id
//!   - GET    /v1/proxies               — MASQUE proxy discovery
//!   - GET    /v1/myip                  — client's observed IP
//!   - POST   /v1/calls                 — initiate call
//!   - GET    /v1/ws                    — WebSocket upgrade

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use futures::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio_tungstenite::tungstenite;
use tracing::{debug, info, warn};

use crate::error::{codes, SignalingError};
use crate::session;
use crate::state::{type_id, AppState, CallEntry, FramedMessage, PeerInfo};

// ── JSON request / response types ──────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerResponse {
    pub peer_id: String,
    pub display_name: String,
    pub ipv6_addresses: Vec<String>,
    pub ipv4_reflexive: Vec<String>,
    pub nat_type: String,
    pub status: String,
    pub last_seen: u64,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct MyIpResponse {
    pub ip: String,
    pub ip_version: u8,
    pub port: u16,
    pub observed_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub proxies: Vec<ProxyEntryResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyEntryResponse {
    pub node_id: String,
    pub proxy_url: String,
    pub capacity: u32,
    pub region: String,
    pub latency_hint_ms: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitiateCallRequest {
    pub call_id: String,
    pub caller_id: String,
    pub callee_id: String,
    #[serde(default)]
    pub ipv6_addresses: Vec<String>,
    #[serde(default)]
    pub ipv4_reflexive: Vec<String>,
    #[serde(default)]
    pub discovery_method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitiateCallResponse {
    pub call_id: String,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LookupQuery {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LookupResponse {
    pub peer_id: String,
    pub display_name: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerStatusResponse {
    pub peer_id: String,
    pub status: String,
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

fn call_state_str(val: i32) -> String {
    match val {
        0 => "RINGING".into(),
        1 => "ACCEPTED".into(),
        2 => "CONNECTED".into(),
        3 => "FAILED".into(),
        4 => "ENDED".into(),
        _ => format!("UNKNOWN({})", val),
    }
}

// ── Handlers ───────────────────────────────────────────────────────────

/// `GET /v1/peers/{peer_id}` — peer lookup.
pub async fn get_peer(
    State(state): State<AppState>,
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
pub async fn get_peer_status(
    State(state): State<AppState>,
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

/// `POST /v1/peers` — register a new peer.
pub async fn register_peer(
    State(state): State<AppState>,
    Json(body): Json<RegisterPeerRequest>,
) -> crate::error::Result<(StatusCode, Json<PeerResponse>)> {
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

    let response = PeerResponse {
        peer_id: info.peer_id.clone(),
        display_name: info.display_name.clone(),
        ipv6_addresses: info.ipv6_addresses.clone(),
        ipv4_reflexive: info.ipv4_reflexive.clone(),
        nat_type: nat_type_str(info.nat_type),
        status: peer_status_str(info.status),
        last_seen: info.last_seen,
    };

    // Register without WS sender (REST-only registration)
    state.register_peer(info, None).await?;

    info!(peer_id = %body.peer_id, "peer registered via REST");
    Ok((StatusCode::CREATED, Json(response)))
}

/// `PUT /v1/peers/{peer_id}` — update peer registration.
pub async fn update_peer(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
    Json(body): Json<RegisterPeerRequest>,
) -> crate::error::Result<Json<PeerResponse>> {
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
pub async fn delete_peer(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
) -> crate::error::Result<StatusCode> {
    state.unregister_peer(&peer_id).await?;
    info!(peer_id = %peer_id, "peer deleted via REST");
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/peers/lookup?username={name}` — resolve username to peer_id.
pub async fn lookup_peer(
    State(state): State<AppState>,
    Query(query): Query<LookupQuery>,
) -> crate::error::Result<Json<LookupResponse>> {
    // Search through peers by display_name (case-insensitive prefix match).
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
pub async fn get_proxies(
    State(state): State<AppState>,
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

/// `POST /v1/calls` — initiate a call.
pub async fn initiate_call(
    State(state): State<AppState>,
    Json(body): Json<InitiateCallRequest>,
) -> crate::error::Result<(StatusCode, Json<InitiateCallResponse>)> {
    // Rate limit calls
    if !state
        .inner
        .rate_limiter
        .check_call(&body.caller_id)
        .await
    {
        return Err(SignalingError::RateLimited);
    }

    let discovery_method = match body.discovery_method.as_deref() {
        Some("DHT") => 0,
        Some("SIGNALING") => 1,
        Some("CACHE") => 2,
        _ => 1, // default SIGNALING
    };

    // Create call entry
    let call = CallEntry {
        call_id: body.call_id.clone(),
        caller_id: body.caller_id.clone(),
        callee_id: body.callee_id.clone(),
        state: 0, // RINGING
        connection_method: 0, // CONN_NONE
        discovery_method,
        created_at: crate::state::now_secs(),
        connected_at: None,
        ended_at: None,
        failure_reason: None,
        retry_count: 0,
    };

    state.create_call(call).await?;

    // Build a CallRequest protobuf to forward to callee
    let call_request = voip_core::signaling::CallRequest {
        call_id: body.call_id.clone(),
        caller_id: body.caller_id.clone(),
        callee_id: body.callee_id.clone(),
        ipv6_addresses: body.ipv6_addresses.clone(),
        ipv4_reflexive: body.ipv4_reflexive.clone(),
        nat_info: None,
        tracks: Vec::new(),
        discovery_method,
        timestamp: crate::state::now_secs(),
        connection_id: Vec::new(),
    };

    let payload = call_request.encode_to_vec();
    let forward = FramedMessage {
        type_id: type_id::CALL_REQUEST_SC,
        payload,
    };

    // Forward to callee
    if let Err(e) = state.send_to_peer(&body.callee_id, forward).await {
        // Callee offline — clean up
        state.remove_call(&body.call_id).await;
        return Err(e);
    }

    info!(
        call_id = %body.call_id,
        caller = %body.caller_id,
        callee = %body.callee_id,
        "call initiated via REST"
    );

    Ok((
        StatusCode::CREATED,
        Json(InitiateCallResponse {
            call_id: body.call_id,
            state: "RINGING".to_owned(),
        }),
    ))
}

/// `GET /v1/dht/bootstrap` — return list of DHT bootstrap nodes.
pub async fn dht_bootstrap() -> Json<serde_json::Value> {
    // Placeholder: In production, this returns active DHT node multiaddresses.
    Json(serde_json::json!({
        "nodes": []
    }))
}

/// `POST /v1/proxy-token` — issue a ProxyToken for anti-abuse verification.
pub async fn issue_proxy_token() -> crate::error::Result<Json<serde_json::Value>> {
    // Placeholder: In production, this signs a ProxyToken with the server's
    // Ed25519 private key.
    Ok(Json(serde_json::json!({
        "token": "",
        "ttl_seconds": 60
    })))
}

/// `GET /v1/ws` — WebSocket upgrade endpoint.
///
/// This is the main real-time signaling channel. Each connected client
/// gets a session that handles message routing.
pub async fn ws_upgrade(
    ws: axum::extract::Ws,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    info!(addr = %addr, "WebSocket upgrade requested");
    ws.on_upgrade(move |socket| handle_ws_connection(socket, addr, state))
}

async fn handle_ws_connection(
    socket: axum::extract::ws::WebSocket,
    addr: SocketAddr,
    state: AppState,
) {
    // Convert axum WebSocket to tokio-tungstenite-compatible stream.
    // We use the axum WS directly since it's already set up.
    // Split into sink/source and process messages.
    let (mut sender, mut receiver) = socket.split();

    // Create channel for sending messages to this session
    let (tx, mut rx) = tokio::sync::mpsc::channel::<FramedMessage>(256);
    let peer_id: std::sync::Arc<tokio::sync::Mutex<Option<String>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));

    // Forward task: channel → WebSocket sender
    let state_fwd = state.clone();
    let peer_id_fwd = peer_id.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let bytes = msg.to_bytes();
            if sender
                .send(axum::extract::ws::Message::Binary(bytes.into()))
                .await
                .is_err()
            {
                break;
            }
        }
        // Channel closed — clean up
        let pid = peer_id_fwd.lock().await;
        if let Some(ref peer_id) = *pid {
            state_fwd.disconnect_peer(peer_id).await;
        }
    });

    // Receive loop: WebSocket → message dispatch
    let state_recv = state.clone();
    let tx_recv = tx.clone();
    let peer_id_recv = peer_id.clone();

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(axum::extract::ws::Message::Binary(data)) => {
                if data.len() < 2 {
                    warn!(addr = %addr, "WS message too short");
                    continue;
                }

                let framed = match FramedMessage::from_bytes(&data) {
                    Some(f) => f,
                    None => continue,
                };

                // Rate limit WS messages
                let pid = peer_id_recv.lock().await.clone();
                if let Some(ref peer_id) = pid {
                    if !state_recv
                        .inner
                        .rate_limiter
                        .check_ws_message(peer_id)
                        .await
                    {
                        let err = FramedMessage::error(
                            codes::RATE_LIMITED,
                            "WebSocket message rate limit exceeded",
                        );
                        let _ = tx_recv.send(err).await;
                        continue;
                    }
                }

                dispatch_ws_message(
                    framed,
                    &addr,
                    &tx_recv,
                    &peer_id_recv,
                    &state_recv,
                )
                .await;
            }
            Ok(axum::extract::ws::Message::Close(_)) => {
                info!(addr = %addr, "WebSocket closed by client");
                break;
            }
            Ok(axum::extract::ws::Message::Ping(_)) => {
                // axum handles Pong automatically
            }
            Ok(_) => {}
            Err(e) => {
                warn!(addr = %addr, error = %e, "WS receive error");
                break;
            }
        }
    }

    // Session ended — clean up
    let pid = peer_id_recv.lock().await;
    if let Some(ref peer_id) = *pid {
        info!(peer_id, "WS session ended, disconnecting peer");
        state_recv.disconnect_peer(peer_id).await;
    }
}

/// Dispatch a single framed WebSocket message.
/// This is the same logic as `session::handle_framed_message` but adapted
/// for the axum WebSocket type.
async fn dispatch_ws_message(
    framed: FramedMessage,
    client_addr: &SocketAddr,
    tx: &tokio::sync::mpsc::Sender<FramedMessage>,
    peer_id_holder: &std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: &AppState,
) {
    match framed.type_id {
        type_id::PEER_REGISTER => {
            ws_handle_peer_register(&framed.payload, client_addr, tx, peer_id_holder, state).await;
        }
        type_id::PEER_UNREGISTER => {
            ws_handle_peer_unregister(&framed.payload, peer_id_holder, state).await;
        }
        type_id::CALL_REQUEST_CS => {
            ws_handle_call_request(&framed.payload, tx, peer_id_holder, state).await;
        }
        type_id::CALL_ACCEPT_CS => {
            ws_handle_call_accept(&framed.payload, tx, peer_id_holder, state).await;
        }
        type_id::CALL_REJECT_CS => {
            ws_handle_call_reject(&framed.payload, tx, peer_id_holder, state).await;
        }
        type_id::CALL_FAILED => {
            ws_handle_call_failed(&framed.payload, tx, peer_id_holder, state).await;
        }
        type_id::CALL_ENDED => {
            ws_handle_call_ended(&framed.payload, tx, peer_id_holder, state).await;
        }
        _ => {
            warn!(type_id = framed.type_id, "unknown WS message type ID");
            let err =
                FramedMessage::error(codes::INVALID_MESSAGE, "unknown message type ID");
            let _ = tx.send(err).await;
        }
    }
}

// ── WS message handler implementations ─────────────────────────────────
// These are the same handlers as in session.rs but using the axum WS channel.

async fn ws_handle_peer_register(
    payload: &[u8],
    client_addr: &SocketAddr,
    tx: &tokio::sync::mpsc::Sender<FramedMessage>,
    peer_id_holder: &std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: &AppState,
) {
    let msg = match voip_core::signaling::PeerRegister::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode PeerRegister");
            let err =
                FramedMessage::error(codes::INVALID_MESSAGE, "invalid PeerRegister payload");
            let _ = tx.send(err).await;
            return;
        }
    };

    if !state
        .inner
        .rate_limiter
        .check_registration(&msg.peer_id)
        .await
    {
        let err = FramedMessage::error(codes::RATE_LIMITED, "registration rate limit exceeded");
        let _ = tx.send(err).await;
        return;
    }

    let peer_id = msg.peer_id.clone();
    let info = PeerInfo {
        peer_id: msg.peer_id,
        display_name: msg.display_name,
        ipv6_addresses: msg.ipv6_addresses,
        ipv4_reflexive: msg.ipv4_reflexive,
        nat_type: msg.nat_info.map(|n| n.nat_type).unwrap_or(0),
        status: msg.status,
        fcm_token: if msg.fcm_token.is_empty() {
            None
        } else {
            Some(msg.fcm_token)
        },
        last_seen: crate::state::now_secs(),
    };

    {
        let mut pid = peer_id_holder.lock().await;
        *pid = Some(peer_id.clone());
    }

    if let Err(e) = state.register_peer(info, Some(tx.clone())).await {
        let err = FramedMessage::error(e.code(), e.to_string());
        let _ = tx.send(err).await;
        return;
    }

    info!(peer_id = %peer_id, addr = %client_addr, "peer registered via WebSocket");
}

async fn ws_handle_peer_unregister(
    payload: &[u8],
    peer_id_holder: &std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: &AppState,
) {
    let msg = match voip_core::signaling::PeerUnregister::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode PeerUnregister");
            return;
        }
    };

    info!(peer_id = %msg.peer_id, "peer unregistered via WebSocket");
    let _ = state.unregister_peer(&msg.peer_id).await;

    let mut pid = peer_id_holder.lock().await;
    *pid = None;
}

async fn ws_handle_call_request(
    payload: &[u8],
    tx: &tokio::sync::mpsc::Sender<FramedMessage>,
    peer_id_holder: &std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: &AppState,
) {
    let msg = match voip_core::signaling::CallRequest::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode CallRequest");
            let err =
                FramedMessage::error(codes::INVALID_MESSAGE, "invalid CallRequest payload");
            let _ = tx.send(err).await;
            return;
        }
    };

    let caller_id = msg.caller_id.clone();
    let callee_id = msg.callee_id.clone();
    let call_id = msg.call_id.clone();

    if !state.inner.rate_limiter.check_call(&caller_id).await {
        let err = FramedMessage::error(codes::RATE_LIMITED, "call rate limit exceeded");
        let _ = tx.send(err).await;
        return;
    }

    // Validate caller_id matches session
    {
        let pid = peer_id_holder.lock().await;
        if let Some(ref session_peer) = *pid {
            if *session_peer != caller_id {
                let err = FramedMessage::error(
                    codes::NOT_CALL_PARTICIPANT,
                    "caller_id does not match session peer_id",
                );
                let _ = tx.send(err).await;
                return;
            }
        }
    }

    let call = CallEntry {
        call_id: call_id.clone(),
        caller_id: caller_id.clone(),
        callee_id: callee_id.clone(),
        state: 0,
        connection_method: 0,
        discovery_method: msg.discovery_method,
        created_at: crate::state::now_secs(),
        connected_at: None,
        ended_at: None,
        failure_reason: None,
        retry_count: 0,
    };

    if let Err(e) = state.create_call(call).await {
        let err = FramedMessage::error(e.code(), e.to_string());
        let _ = tx.send(err).await;
        return;
    }

    let forward = FramedMessage {
        type_id: type_id::CALL_REQUEST_SC,
        payload: payload.to_vec(),
    };

    match state.send_to_peer(&callee_id, forward).await {
        Ok(()) => {
            info!(call_id = %call_id, caller = %caller_id, callee = %callee_id, "CallRequest forwarded");
        }
        Err(e) => {
            let err = FramedMessage::error(e.code(), e.to_string());
            let _ = tx.send(err).await;
            state.remove_call(&call_id).await;
        }
    }
}

async fn ws_handle_call_accept(
    payload: &[u8],
    tx: &tokio::sync::mpsc::Sender<FramedMessage>,
    peer_id_holder: &std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: &AppState,
) {
    let msg = match voip_core::signaling::CallAccept::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode CallAccept");
            let err =
                FramedMessage::error(codes::INVALID_MESSAGE, "invalid CallAccept payload");
            let _ = tx.send(err).await;
            return;
        }
    };

    let call_id = msg.call_id.clone();

    if let Err(e) = state.update_call_state(&call_id, 1).await {
        let err = FramedMessage::error(e.code(), e.to_string());
        let _ = tx.send(err).await;
        return;
    }

    let caller_id = match state.get_call(&call_id).await {
        Some(call) => call.caller_id,
        None => {
            let err = FramedMessage::error(codes::INVALID_CALL_ID, "call not found");
            let _ = tx.send(err).await;
            return;
        }
    };

    let forward = FramedMessage {
        type_id: type_id::CALL_ACCEPT_SC,
        payload: payload.to_vec(),
    };

    match state.send_to_peer(&caller_id, forward).await {
        Ok(()) => {
            info!(call_id = %call_id, "CallAccept forwarded to caller");
        }
        Err(e) => {
            let err = FramedMessage::error(e.code(), e.to_string());
            let _ = tx.send(err).await;
        }
    }
}

async fn ws_handle_call_reject(
    payload: &[u8],
    tx: &tokio::sync::mpsc::Sender<FramedMessage>,
    peer_id_holder: &std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: &AppState,
) {
    let msg = match voip_core::signaling::CallReject::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode CallReject");
            return;
        }
    };

    let call_id = msg.call_id.clone();
    let caller_id = match state.get_call(&call_id).await {
        Some(call) => call.caller_id,
        None => {
            let err = FramedMessage::error(codes::INVALID_CALL_ID, "call not found");
            let _ = tx.send(err).await;
            return;
        }
    };

    let _ = state
        .end_call(&call_id, Some("rejected".to_owned()))
        .await;

    let forward = FramedMessage {
        type_id: type_id::CALL_REJECT_SC,
        payload: payload.to_vec(),
    };
    let _ = state.send_to_peer(&caller_id, forward).await;
    info!(call_id = %call_id, "CallReject forwarded to caller");
    state.remove_call(&call_id).await;
}

async fn ws_handle_call_failed(
    payload: &[u8],
    tx: &tokio::sync::mpsc::Sender<FramedMessage>,
    peer_id_holder: &std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: &AppState,
) {
    let msg = match voip_core::signaling::CallFailed::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode CallFailed");
            return;
        }
    };

    let call_id = msg.call_id.clone();
    if let Some(call_entry) = state.get_call(&call_id).await {
        let other_peer = {
            let pid = peer_id_holder.lock().await;
            if Some(&call_entry.caller_id) == pid.as_ref() {
                call_entry.callee_id.clone()
            } else {
                call_entry.caller_id.clone()
            }
        };

        let forward = FramedMessage {
            type_id: type_id::CALL_FAILED,
            payload: payload.to_vec(),
        };
        let _ = state.send_to_peer(&other_peer, forward).await;

        // If NAT incompatibility, try MASQUE relay
        if msg.reason == 3 || msg.reason == 4 {
            if let Err(e) = state
                .coordinate_masque_relay(&call_id, &call_entry.caller_id, &call_entry.callee_id)
                .await
            {
                warn!(call_id = %call_id, error = %e, "MASQUE relay coordination failed");
            }
        }

        let _ = state
            .end_call(&call_id, Some(msg.description.clone()))
            .await;
    } else {
        let err = FramedMessage::error(codes::INVALID_CALL_ID, "call not found");
        let _ = tx.send(err).await;
    }
}

async fn ws_handle_call_ended(
    payload: &[u8],
    tx: &tokio::sync::mpsc::Sender<FramedMessage>,
    peer_id_holder: &std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: &AppState,
) {
    let msg = match voip_core::signaling::CallEnded::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode CallEnded");
            return;
        }
    };

    let call_id = msg.call_id.clone();
    if let Some(call_entry) = state.get_call(&call_id).await {
        let other_peer = {
            let pid = peer_id_holder.lock().await;
            if Some(&call_entry.caller_id) == pid.as_ref() {
                call_entry.callee_id.clone()
            } else {
                call_entry.caller_id.clone()
            }
        };

        let forward = FramedMessage {
            type_id: type_id::CALL_ENDED,
            payload: payload.to_vec(),
        };
        let _ = state.send_to_peer(&other_peer, forward).await;
        let _ = state.end_call(&call_id, None).await;
        state.remove_call(&call_id).await;
        info!(call_id = %call_id, "CallEnded processed");
    } else {
        let err = FramedMessage::error(codes::INVALID_CALL_ID, "call not found");
        let _ = tx.send(err).await;
    }
}
