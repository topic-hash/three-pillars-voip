//! WebSocket session handler.
//!
//! Each connected client gets a session task that:
//!   1. Reads framed messages from the WebSocket
//!   2. Dispatches them based on the 2-byte type prefix
//!   3. Forwards call-signaling messages to the target peer
//!   4. Handles registration / unregistration
//!   5. Enforces per-peer rate limits
//!   6. Detects MASQUE relay need and coordinates

use std::net::SocketAddr;

use futures::{SinkExt, StreamExt};
use prost::Message;
use tracing::{info, warn};

use crate::error::codes;
use crate::state::{type_id, AppState, FramedMessage, PeerInfo};
use voip_core::types::NATType;

/// Buffer capacity for the channel that pushes messages into this session.
const SESSION_CHANNEL_CAPACITY: usize = 256;

// ── Session launch ─────────────────────────────────────────────────────

/// Handle an incoming axum WebSocket connection.
///
/// This is called from the `ws_upgrade` handler after the HTTP upgrade.
/// It authenticates the peer via JWT, then enters the message loop.
pub async fn handle_ws_connection(
    socket: axum::extract::ws::WebSocket,
    addr: SocketAddr,
    state: AppState,
    peer_id: String,
) {
    info!(addr = %addr, peer_id = %peer_id, "WebSocket session starting");

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Create channel for sending messages to this session
    let (tx, mut rx) = tokio::sync::mpsc::channel::<FramedMessage>(SESSION_CHANNEL_CAPACITY);
    let peer_id_holder: std::sync::Arc<tokio::sync::Mutex<Option<String>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(Some(peer_id.clone())));

    // Forward task: channel → WebSocket sender
    let state_fwd = state.clone();
    let peer_id_fwd = peer_id_holder.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let bytes = msg.to_bytes();
            if ws_sender
                .send(axum::extract::ws::Message::Binary(bytes))
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
    let peer_id_recv = peer_id_holder.clone();

    while let Some(msg) = ws_receiver.next().await {
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

                // Rate limit WS messages per peer
                let pid = peer_id_recv.lock().await.clone();
                if let Some(ref p_id) = pid
                    && !state_recv.inner.rate_limiter.check_ws_message(p_id).await {
                        let err = FramedMessage::error(
                            codes::RATE_LIMITED,
                            "WebSocket message rate limit exceeded",
                        );
                        let _ = tx_recv.send(err).await;
                        continue;
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

// ── Message dispatch ───────────────────────────────────────────────────

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
            let err = FramedMessage::error(codes::INVALID_MESSAGE, "unknown message type ID");
            let _ = tx.send(err).await;
        }
    }
}

// ── Individual message handlers ────────────────────────────────────────

async fn ws_handle_peer_register(
    payload: &[u8],
    client_addr: &SocketAddr,
    tx: &tokio::sync::mpsc::Sender<FramedMessage>,
    peer_id_holder: &std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: &AppState,
) {
    let msg = match voip_core::proto::signaling::PeerRegister::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode PeerRegister");
            let err = FramedMessage::error(codes::INVALID_MESSAGE, "invalid PeerRegister payload");
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
    let msg = match voip_core::proto::signaling::PeerUnregister::decode(payload) {
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
    let msg = match voip_core::proto::signaling::CallRequest::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode CallRequest");
            let err = FramedMessage::error(codes::INVALID_MESSAGE, "invalid CallRequest payload");
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
        if let Some(ref session_peer) = *pid
            && *session_peer != caller_id {
                let err = FramedMessage::error(
                    codes::NOT_CALL_PARTICIPANT,
                    "caller_id does not match session peer_id",
                );
                let _ = tx.send(err).await;
                return;
            }
    }

    let call = crate::state::CallEntry {
        call_id: call_id.clone(),
        caller_id: caller_id.clone(),
        callee_id: callee_id.clone(),
        state: 0, // CALL_RINGING
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

    // Forward CallRequest to callee (type ID 0x0002)
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
    let msg = match voip_core::proto::signaling::CallAccept::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode CallAccept");
            let err = FramedMessage::error(codes::INVALID_MESSAGE, "invalid CallAccept payload");
            let _ = tx.send(err).await;
            return;
        }
    };

    let call_id = msg.call_id.clone();

    // Validate that the sender is the callee (only callee can accept)
    {
        let call_entry = match state.get_call(&call_id).await {
            Some(c) => c,
            None => {
                let err = FramedMessage::error(codes::INVALID_CALL_ID, "call not found");
                let _ = tx.send(err).await;
                return;
            }
        };
        let pid = peer_id_holder.lock().await;
        if let Some(ref session_peer) = *pid
            && *session_peer != call_entry.callee_id {
                let err = FramedMessage::error(
                    codes::NOT_CALL_PARTICIPANT,
                    "only the callee can accept a call",
                );
                let _ = tx.send(err).await;
                return;
            }
    }

    // Update call state to ACCEPTED
    if let Err(e) = state.update_call_state(&call_id, 1).await {
        let err = FramedMessage::error(e.code(), e.to_string());
        let _ = tx.send(err).await;
        return;
    }

    let caller_id = match state.get_call(&call_id).await {
        Some(call) => call.caller_id,
        None => {
            let err = FramedMessage::error(codes::INVALID_CALL_ID, "call not found after state update");
            let _ = tx.send(err).await;
            return;
        }
    };

    // Forward CallAccept to caller (type ID 0x0004)
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
    let msg = match voip_core::proto::signaling::CallReject::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode CallReject");
            return;
        }
    };

    let call_id = msg.call_id.clone();

    // Validate that the sender is the callee (only callee can reject)
    let caller_id = {
        let call_entry = match state.get_call(&call_id).await {
            Some(c) => c,
            None => {
                let err = FramedMessage::error(codes::INVALID_CALL_ID, "call not found");
                let _ = tx.send(err).await;
                return;
            }
        };
        let pid = peer_id_holder.lock().await;
        if let Some(ref session_peer) = *pid
            && *session_peer != call_entry.callee_id {
                let err = FramedMessage::error(
                    codes::NOT_CALL_PARTICIPANT,
                    "only the callee can reject a call",
                );
                let _ = tx.send(err).await;
                return;
            }
        call_entry.caller_id
    };

    let _ = state
        .end_call(&call_id, Some("rejected".to_owned()))
        .await;

    // Forward CallReject to caller (type ID 0x0006)
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
    let msg = match voip_core::proto::signaling::CallFailed::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode CallFailed");
            return;
        }
    };

    let call_id = msg.call_id.clone();
    if let Some(call_entry) = state.get_call(&call_id).await {
        // Validate that the sender is a call participant
        let sending_peer = {
            let pid = peer_id_holder.lock().await;
            pid.clone()
        };
        if let Some(ref sender) = sending_peer
            && sender != &call_entry.caller_id && sender != &call_entry.callee_id {
                let err = FramedMessage::error(
                    codes::NOT_CALL_PARTICIPANT,
                    "not a participant in this call",
                );
                let _ = tx.send(err).await;
                return;
            }

        let other_peer = {
            if Some(&call_entry.caller_id) == sending_peer.as_ref() {
                call_entry.callee_id.clone()
            } else {
                call_entry.caller_id.clone()
            }
        };

        // Forward CallFailed (same type ID 0x0007 either direction)
        let forward = FramedMessage {
            type_id: type_id::CALL_FAILED,
            payload: payload.to_vec(),
        };
        let _ = state.send_to_peer(&other_peer, forward).await;

        let reason_val = msg.reason;

        // Detect MASQUE need based on the failure reason.
        // END_FAILED_IPV4_RANDOM = 3: both peers SymmetricRandom
        // END_FAILED_UDP_BLOCKED = 4: UDP is blocked on the path
        // Per spec/06 §6.7 Step 9 and spec/12: server detects MASQUE need
        // and sends MasqueRelayNeeded to both peers.
        let _udp_blocked = reason_val == 4;
        if reason_val == 3 || reason_val == 4 {
            if let Err(e) = state
                .coordinate_masque_relay(&call_id, &call_entry.caller_id, &call_entry.callee_id)
                .await
            {
                warn!(call_id = %call_id, error = %e, "MASQUE relay coordination failed");

                // If MASQUE coordination failed and the reason is retryable,
                // send PushRetry to the other peer.
                if crate::push::is_retryable_reason(reason_val) {
                    crate::push::handle_retryable_failure(
                        state,
                        &call_id,
                        &call_entry.caller_id,
                        &call_entry.callee_id,
                        reason_val,
                        &other_peer,
                        call_entry.retry_count,
                    )
                    .await;
                }
            }
        } else if crate::push::is_retryable_reason(reason_val) {
            // For other retryable reasons (e.g., END_FAILED_MASQUE_UNREACHABLE = 7)
            // send PushRetry to the other peer.
            crate::push::handle_retryable_failure(
                state,
                &call_id,
                &call_entry.caller_id,
                &call_entry.callee_id,
                reason_val,
                &other_peer,
                call_entry.retry_count,
            )
            .await;
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
    let msg = match voip_core::proto::signaling::CallEnded::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to decode CallEnded");
            return;
        }
    };

    let call_id = msg.call_id.clone();
    if let Some(call_entry) = state.get_call(&call_id).await {
        // Validate that the sender is a call participant
        let sending_peer = {
            let pid = peer_id_holder.lock().await;
            pid.clone()
        };
        if let Some(ref sender) = sending_peer
            && sender != &call_entry.caller_id && sender != &call_entry.callee_id {
                let err = FramedMessage::error(
                    codes::NOT_CALL_PARTICIPANT,
                    "not a participant in this call",
                );
                let _ = tx.send(err).await;
                return;
            }

        let other_peer = {
            if Some(&call_entry.caller_id) == sending_peer.as_ref() {
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

/// Convert a proto NATType i32 value to our native NATType.
#[allow(dead_code)]
fn i32_to_nat_type(val: i32) -> NATType {
    match val {
        0 => NATType::None,
        1 => NATType::Cone,
        2 => NATType::SymmetricSequential,
        3 => NATType::SymmetricPseudo,
        4 => NATType::SymmetricRandom,
        _ => NATType::None,
    }
}
