//! Main server state and setup.
//!
//! The `SignalingServer` struct holds shared state and provides a
//! builder pattern for configuring and launching the signaling server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{delete, get, post, put};
use axum::Router;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::handlers;
use crate::rate_limit::RateLimitConfig;
use crate::state::AppState;

/// Default HTTP listen port for the signaling server.
const DEFAULT_PORT: u16 = 8443;

/// Signaling server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// HTTP listen address (e.g., "0.0.0.0:8443").
    pub listen_addr: String,
    /// Rate-limit configuration.
    pub rate_limits: RateLimitConfig,
    /// Signaling server elastic IPs for QUIC path probing.
    pub server_ips: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: format!("0.0.0.0:{}", DEFAULT_PORT),
            rate_limits: RateLimitConfig::default(),
            server_ips: Vec::new(),
        }
    }
}

/// Builder for `SignalingServer`.
pub struct SignalingServerBuilder {
    config: ServerConfig,
}

impl SignalingServerBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: ServerConfig::default(),
        }
    }

    /// Set the listen address.
    pub fn listen_addr(mut self, addr: impl Into<String>) -> Self {
        self.config.listen_addr = addr.into();
        self
    }

    /// Set the rate-limit configuration.
    pub fn rate_limits(mut self, config: RateLimitConfig) -> Self {
        self.config.rate_limits = config;
        self
    }

    /// Add a signaling server IP for QUIC path probing.
    pub fn server_ip(mut self, ip: impl Into<String>) -> Self {
        self.config.server_ips.push(ip.into());
        self
    }

    /// Set all signaling server IPs for QUIC path probing.
    pub fn server_ips(mut self, ips: Vec<String>) -> Self {
        self.config.server_ips = ips;
        self
    }

    /// Build the `SignalingServer`.
    pub fn build(self) -> SignalingServer {
        let state = AppState::new(self.config.rate_limits.clone(), self.config.server_ips.clone());
        SignalingServer {
            config: self.config,
            state,
        }
    }
}

impl Default for SignalingServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// The signaling server.
///
/// Holds the shared `AppState` and the `ServerConfig`. Use the builder
/// pattern (`SignalingServer::builder()`) to construct.
pub struct SignalingServer {
    config: ServerConfig,
    state: AppState,
}

impl SignalingServer {
    /// Create a new builder.
    pub fn builder() -> SignalingServerBuilder {
        SignalingServerBuilder::new()
    }

    /// Build the axum router with all routes registered.
    pub fn router(&self) -> Router {
        Router::new()
            // ── REST API (spec/08 §8.1.2) ────────────────────────
            .route("/v1/peers/lookup", get(handlers::lookup_peer))
            .route("/v1/peers/{peer_id}/status", get(handlers::get_peer_status))
            .route("/v1/peers/{peer_id}", get(handlers::get_peer))
            .route("/v1/peers/{peer_id}", put(handlers::update_peer))
            .route("/v1/peers/{peer_id}", delete(handlers::delete_peer))
            .route("/v1/peers", post(handlers::register_peer))
            .route("/v1/myip", get(handlers::get_my_ip))
            .route("/v1/proxies", get(handlers::get_proxies))
            .route("/v1/calls", post(handlers::initiate_call))
            .route("/v1/dht/bootstrap", get(handlers::dht_bootstrap))
            .route("/v1/proxy-token", post(handlers::issue_proxy_token))
            // ── WebSocket ─────────────────────────────────────────
            .route("/v1/ws", get(handlers::ws_upgrade))
            // ── Shared state & middleware ──────────────────────────
            .with_state(self.state.clone())
            .layer(CorsLayer::permissive())
    }

    /// Return a reference to the shared application state.
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Return the listen address from the config.
    pub fn listen_addr(&self) -> &str {
        &self.config.listen_addr
    }
}
