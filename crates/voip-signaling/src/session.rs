//! WebSocket session handler.
//!
//! Each connected client gets a session task that:
//!   1. Reads framed messages from the WebSocket
//!   2. Dispatches them based on the 2-byte type prefix
//!   3. Forwards call-signaling messages to the target peer
//!   4. Handles registration / unregistration
//!   5. Enforces per-peer rate limits

use std::net::SocketAddr;

use futures::{SinkExt, StreamExt};
use prost::Message;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{tungstenite, WebSocketStream};
use tracing::{debug, error, info, warn};

use crate::error::{codes, SignalingError};
use crate::state::{type_id, AppState, FramedMessage, PeerInfo, SessionSender};

/// The maximum size for a single WebSocket message (64 KiB).
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Buffer capacity for the channel that pushes messages into this session.
const SESSION_CHANNEL_CAPACITY: usize = 256;

// ── Session launch ─────────────────────────────────────────────────────

/// Spawn a new session task for a WebSocket connection.
///
/// Returns the `SessionSender` that the server state uses to push
/// framed messages into this session, and a `peer_id` once the session
/// authenticates (via the first `PeerRegister` message).
pub fn spawn_session(
    ws_stream: WebSocketStream<TcpStream>,
    client_addr: SocketAddr,
    state: AppState,
) -> SessionSender {
    let (ws_sink, ws_source) = ws_stream.split();
    let (tx, rx) = mpsc::channel::<FramedMessage>(SESSION_CHANNEL_CAPACITY);

    let peer_id_holder = std::sync::Arc::new(tokio::sync::Mutex::new(None::<String>));

    // Forward task: channel → WebSocket sink
    let tx_clone = tx.clone();
    let peer_id_holder_fwd = peer_id_holder.clone();
    tokio::spawn(async move {
        forward_to_ws(rx, ws_sink, peer_id_holder_fwd, state.clone()).await;
    });

    // Receive task: WebSocket source → message dispatch
    let peer_id_holder_recv = peer_id_holder.clone();
    tokio::spawn(async move {
        receive_from_ws(
            ws_source,
            client_addr,
            tx_clone,
            peer_id_holder_recv,
            state,
        )
        .await;
    });

    tx
}

// ── Forward: channel → WebSocket ───────────────────────────────────────

async fn forward_to_ws(
    mut rx: mpsc::Receiver<FramedMessage>,
    mut ws_sink: futures::stream::SplitSink<
        WebSocketStream<TcpStream>,
        tungstenite::Message,
    >,
    peer_id_holder: std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: AppState,
) {
    while let Some(msg) = rx.recv().await {
        let bytes = msg.to_bytes();
        if let Err(e) = ws_sink.send(tungstenite::Message::Binary(bytes.into())).await {
            error!(error = %e, "failed to send WS message to client");
            break;
        }
    }
    // Channel closed — session ended. Clean up peer.
    let pid = peer_id_holder.lock().await;
    if let Some(ref peer_id) = *pid {
        info!(peer_id, "session forward task ending, disconnecting peer");
        state.disconnect_peer(peer_id).await;
    }
}

// ── Receive: WebSocket → message dispatch ──────────────────────────────

async fn receive_from_ws(
    mut ws_source: futures::stream::SplitStream<WebSocketStream<TcpStream>>,
    client_addr: SocketAddr,
    tx: SessionSender,
    peer_id_holder: std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: AppState,
) {
    while let Some(result) = ws_source.next().await {
        match result {
            Ok(tungstenite::Message::Binary(data)) => {
                if data.len() < 2 {
                    warn!(
                        addr = %client_addr,
                        "received WS message too short (< 2 bytes), ignoring"
                    );
                    continue;
                }
                let framed = match FramedMessage::from_bytes(&data) {
                    Some(f) => f,
                    None => continue,
                };

                // Rate limit WS messages per peer
                let pid = peer_id_holder.lock().await.clone();
                if let Some(ref peer_id) = pid {
                    if !state.inner.rate_limiter.check_ws_message(peer_id).await {
                        let err = FramedMessage::error(
                            codes::RATE_LIMITED,
                            "WebSocket message rate limit exceeded",
                        );
                        let _ = tx.send(err).await;
                        continue;
                    }
                }

                handle_framed_message(framed, &client_addr, &tx, &peer_id_holder, &state).await;
            }
            Ok(tungstenite::Message::Close(_)) => {
                info!(addr = %client_addr, "WebSocket closed by client");
                break;
            }
            Ok(tungstenite::Message::Ping(data)) => {
                // tungstenite handles Pong automatically
                debug!(addr = %client_addr, "WS ping received");
                let _ = data; // suppress unused warning
            }
            Ok(_) => {
                // Text, Pong, Frame — ignore
            }
            Err(e) => {
                warn!(addr = %client_addr, error = %e, "WS receive error");
                break;
            }
        }
    }

    // Session ended — clean up.
    let pid = peer_id_holder.lock().await;
    if let Some(ref peer_id) = *pid {
        info!(peer_id, "session receive task ending, disconnecting peer");
        state.disconnect_peer(peer_id).await;
    }
}

// ── Message dispatch ───────────────────────────────────────────────────

async fn handle_framed_message(
    framed: FramedMessage,
    client_addr: &SocketAddr,
    tx: &SessionSender,
    peer_id_holder: &std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    state: &AppState,
) {
    match framed.type_id {
        type_id::PEER_REGISTER => {
            handle_peer_register(&framed.payload, client_addr, tx, peer_id_holder, state).await;
        }
        type_id::PEER_UNREGISTER => {
            handle_peer_unregister(&framed.payload, peer_id_holder, state).await;
        }
        type_id::CALL_REQUEST_CS => {
            handle_call_request(&framed.payload, tx, peer_id_holder, state).await;
        }
        type_id::CALL_ACCEPT_CS => {
            handle_call_accept(&framed.payload, tx, peer_id_holder, state).await;
        }
        type_id::CALL_REJECT_CS => {
            handle_call_reject(&framed.payload, tx, peer_id_holder, state).await;
        }
        type_id::CALL_FAILED => {
            handle_call_failed(&framed.payload, tx, peer_id_holder, state).await;
        }
        type_id::CALL_ENDED => {
            handle_call_ended(&framed.payload, tx, peer_id_holder, state).await;
        }
        _ => {
            warn!(type_id = framed.type_id, "unknown WS message type ID");
            let err =
                FramedMessage::error(codes::INVALID_MESSAGE, "unknown message type ID");
            let _ = tx.send(err).await;
        }
    }
}

// ── Individual message handlers ────────────────────────────────────────

async fn handle_peer_register(
    payload: &[u8],
    client_addr: &SocketAddr,
    tx: &SessionSender,
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

    // Rate limit registrations
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

    // Set the peer_id in the session holder
    {
        let mut pid = peer_id_holder.lock().await;
        *pid = Some(peer_id.clone());
    }

    // Register peer with the sender channel
    if let Err(e) = state.register_peer(info, Some(tx.clone())).await {
        let err = FramedMessage::error(e.code(), e.to_string());
        let _ = tx.send(err).await;
        return;
    }

    info!(peer_id = %peer_id, addr = %client_addr, "peer registered via WebSocket");
}

async fn handle_peer_unregister(
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

    // Clear session holder
    let mut pid = peer_id_holder.lock().await;
    *pid = None;
}

async fn handle_call_request(
    payload: &[u8],
    tx: &SessionSender,
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

    // Rate limit calls
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

    // Create call entry
    let call = crate::state::CallEntry {
        call_id: call_id.clone(),
        caller_id: caller_id.clone(),
        callee_id: callee_id.clone(),
        state: 0, // CALL_RINGING
        connection_method: 0, // CONN_NONE
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
        payload: payload.to_vec(), // forward the exact same payload
    };

    match state.send_to_peer(&callee_id, forward).await {
        Ok(()) => {
            info!(call_id = %call_id, caller = %caller_id, callee = %callee_id, "CallRequest forwarded");
        }
        Err(e) => {
            // Callee is offline or unknown — inform caller
            let err = FramedMessage::error(e.code(), e.to_string());
            let _ = tx.send(err).await;
            // Clean up the call
            state.remove_call(&call_id).await;
        }
    }
}

async fn handle_call_accept(
    payload: &[u8],
    tx: &SessionSender,
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

    // Update call state to ACCEPTED
    if let Err(e) = state.update_call_state(&call_id, 1).await {
        let err = FramedMessage::error(e.code(), e.to_string());
        let _ = tx.send(err).await;
        return;
    }

    // Look up call to find caller_id
    let caller_id = match state.get_call(&call_id).await {
        Some(call) => call.caller_id,
        None => {
            let err = FramedMessage::error(codes::INVALID_CALL_ID, "call not found");
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

async fn handle_call_reject(
    payload: &[u8],
    tx: &SessionSender,
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

    // Look up call to find caller_id
    let caller_id = match state.get_call(&call_id).await {
        Some(call) => call.caller_id,
        None => {
            let err = FramedMessage::error(codes::INVALID_CALL_ID, "call not found");
            let _ = tx.send(err).await;
            return;
        }
    };

    // Update call state to ENDED
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

    // Remove call from registry
    state.remove_call(&call_id).await;
}

async fn handle_call_failed(
    payload: &[u8],
    tx: &SessionSender,
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

    // Look up call
    let call = state.get_call(&call_id).await;
    if let Some(call_entry) = call {
        // Forward to the other peer
        let other_peer = {
            let pid = peer_id_holder.lock().await;
            if Some(&call_entry.caller_id) == pid.as_ref() {
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

        // If both peers are IPv4 Symmetric RANDOM, coordinate MASQUE relay
        let reason_val = msg.reason;
        // END_FAILED_IPV4_RANDOM = 3, END_FAILED_UDP_BLOCKED = 4
        if reason_val == 3 || reason_val == 4 {
            // Try MASQUE relay coordination
            if let Err(e) = state
                .coordinate_masque_relay(&call_id, &call_entry.caller_id, &call_entry.callee_id)
                .await
            {
                warn!(
                    call_id = %call_id,
                    error = %e,
                    "MASQUE relay coordination failed"
                );
            }
        }

        // Update call state to FAILED
        let _ = state
            .end_call(&call_id, Some(msg.description.clone()))
            .await;
    } else {
        let err = FramedMessage::error(codes::INVALID_CALL_ID, "call not found");
        let _ = tx.send(err).await;
    }
}

async fn handle_call_ended(
    payload: &[u8],
    tx: &SessionSender,
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

    // Look up call
    let call = state.get_call(&call_id).await;
    if let Some(call_entry) = call {
        // Forward to the other peer
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

        // End and remove the call
        let _ = state.end_call(&call_id, None).await;
        state.remove_call(&call_id).await;

        info!(call_id = %call_id, "CallEnded processed");
    } else {
        let err = FramedMessage::error(codes::INVALID_CALL_ID, "call not found");
        let _ = tx.send(err).await;
    }
}
