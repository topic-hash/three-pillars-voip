//! voip-signaling: Signaling server binary for Three Pillars VoIP.
//!
//! Starts the signaling server on the configured port with:
//!   - axum HTTP server with WebSocket endpoint at `/v1/ws`
//!   - REST endpoints from spec/08
//!   - JWT authentication (Ed25519) for WebSocket connections
//!   - Rate limiting per peer
//!   - MASQUE relay coordination
//!   - QUIC listener on 5 IPs for path probing (placeholder)
//!   - Graceful shutdown via tokio signal

mod auth;
mod error;
mod handlers;
mod jwt;
mod masque;
mod push;
mod quic_probe;
mod rate_limit;
mod server;
mod session;
mod state;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;

use server::SignalingServer;
use tracing::info;

/// Default server IPs for QUIC path probing.
/// In production, these are 5 elastic IPs on the Oracle Cloud instance.
const DEFAULT_SERVER_IPS: &[&str] = &[
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.3",
    "10.0.0.4",
    "10.0.0.5",
];

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "voip_signaling=info,tower_http=debug".into()),
        )
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!("Three Pillars VoIP Signaling Server starting...");

    // Build VoIP config with server IPs
    let mut voip_config = voip_core::VoIPConfig::default();
    voip_config.signaling_server_ips = DEFAULT_SERVER_IPS
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Build the signaling server
    let server = SignalingServer::builder()
        .listen_addr("0.0.0.0:8443")
        .server_ips(
            DEFAULT_SERVER_IPS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .voip_config(voip_config)
        .build();

    let router = server.router();
    let addr: SocketAddr = server
        .listen_addr()
        .parse()
        .expect("invalid listen address");

    info!(%addr, "HTTP+WS signaling server listening");

    // ── QUIC path probing ────────────────────────────────────────
    let quic_probe_config = quic_probe::QuicProbeConfig {
        server_ips: DEFAULT_SERVER_IPS.iter().map(|s| s.to_string()).collect(),
        port: 443,
        max_connections: 100,
    };
    let quic_server = quic_probe::QuicProbeServer::new(quic_probe_config);
    tokio::spawn(async move {
        if let Err(e) = quic_server.start().await {
            tracing::error!(error = %e, "QUIC probe server failed");
        }
    });

    // ── Start the axum HTTP server with graceful shutdown ──────────
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    info!("Signaling server ready — press Ctrl+C to shut down");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server error");
}

/// Wait for SIGINT (Ctrl+C) or SIGTERM to initiate graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("received Ctrl+C, shutting down gracefully...");
        }
        _ = terminate => {
            info!("received SIGTERM, shutting down gracefully...");
        }
    }
}
