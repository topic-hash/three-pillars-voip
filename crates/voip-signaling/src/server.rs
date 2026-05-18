//! Main server setup and router configuration.
//!
//! The `SignalingServer` struct holds shared state and provides a
//! builder pattern for configuring and launching the signaling server.

use axum::routing::{get, post};
use axum::Router;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use voip_core::VoIPConfig;

use crate::auth;
use crate::error::ErrorResponse;
use crate::handlers;
use crate::handlers::{
    DhtBootstrapResponse, LookupResponse, MyIpResponse, PeerResponse,
    PeerStatusResponse, ProxyEntryResponse, ProxyResponse, ProxyTokenRequest, ProxyTokenResponse,
    RegisterPeerRequest, RegisterPeerResponse,
};
use crate::rate_limit::RateLimitConfig;
use crate::state::AppState;

/// Default HTTP listen port for the signaling server.
const DEFAULT_PORT: u16 = 8443;

// ── OpenAPI specification ────────────────────────────────────────────────

/// OpenAPI specification for the signaling server REST API.
///
/// Includes all REST endpoints with request/response schemas.
/// The spec is served at `/v1/openapi.json` and the Swagger UI at `/swagger-ui/`.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::register_peer,
        handlers::update_peer,
        handlers::unregister_peer,
        handlers::get_peer,
        handlers::get_peer_status,
        handlers::lookup_peer,
        handlers::get_my_ip,
        handlers::get_proxies,
        handlers::dht_bootstrap,
        handlers::issue_proxy_token,
    ),
    components(
        schemas(
            RegisterPeerRequest,
            RegisterPeerResponse,
            PeerResponse,
            PeerStatusResponse,
            LookupResponse,
            MyIpResponse,
            ProxyResponse,
            ProxyEntryResponse,
            ProxyTokenRequest,
            ProxyTokenResponse,
            DhtBootstrapResponse,
            ErrorResponse,
        )
    ),
    tags(
        (name = "Peers", description = "Peer registration and lookup"),
        (name = "Network", description = "Network information endpoints"),
        (name = "MASQUE", description = "MASQUE proxy and relay endpoints"),
        (name = "DHT", description = "Distributed Hash Table bootstrap"),
    )
)]
pub struct ApiDoc;

/// Signaling server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// HTTP listen address (e.g., "0.0.0.0:8443").
    pub listen_addr: String,
    /// Rate-limit configuration.
    pub rate_limits: RateLimitConfig,
    /// Signaling server elastic IPs for QUIC path probing.
    pub server_ips: Vec<String>,
    /// VoIP configuration.
    pub voip_config: VoIPConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: format!("0.0.0.0:{}", DEFAULT_PORT),
            rate_limits: RateLimitConfig::default(),
            server_ips: Vec::new(),
            voip_config: VoIPConfig::default(),
        }
    }
}

/// Builder for `SignalingServer`.
pub struct SignalingServerBuilder {
    config: ServerConfig,
    signing_key: Option<SigningKey>,
}

impl SignalingServerBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: ServerConfig::default(),
            signing_key: None,
        }
    }

    /// Set the listen address.
    pub fn listen_addr(mut self, addr: impl Into<String>) -> Self {
        self.config.listen_addr = addr.into();
        self
    }

    /// Set the rate-limit configuration.
    #[allow(dead_code)]
    pub fn rate_limits(mut self, config: RateLimitConfig) -> Self {
        self.config.rate_limits = config;
        self
    }

    /// Add a signaling server IP for QUIC path probing.
    #[allow(dead_code)]
    pub fn server_ip(mut self, ip: impl Into<String>) -> Self {
        self.config.server_ips.push(ip.into());
        self
    }

    /// Set all signaling server IPs for QUIC path probing.
    pub fn server_ips(mut self, ips: Vec<String>) -> Self {
        self.config.server_ips = ips;
        self
    }

    /// Set the server Ed25519 signing key (for JWT).
    /// If not set, one will be generated automatically.
    #[allow(dead_code)]
    pub fn signing_key(mut self, key: SigningKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Set the VoIP configuration.
    pub fn voip_config(mut self, config: VoIPConfig) -> Self {
        self.config.voip_config = config;
        self
    }

    /// Build the `SignalingServer`.
    pub fn build(self) -> SignalingServer {
        let signing_key = self
            .signing_key
            .unwrap_or_else(|| SigningKey::generate(&mut OsRng));
        let state = AppState::new(
            self.config.rate_limits.clone(),
            self.config.server_ips.clone(),
            signing_key,
            self.config.voip_config.clone(),
        );
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
    ///
    /// Routes are split into:
    /// - **Public routes** (no auth): `POST /v1/peers`, `GET /v1/openapi.json`,
    ///   `GET /swagger-ui/*`, `GET /v1/ws`, `GET /v1/myip`
    /// - **Authenticated routes** (JWT required): all other REST endpoints
    ///
    /// Per spec/08 §8.6, JWT auth is required on all REST endpoints except
    /// the registration endpoint and documentation endpoints.
    pub fn router(&self) -> Router {
        let auth_middleware = axum::middleware::from_fn_with_state(
            self.state.clone(),
            auth::auth_middleware,
        );

        // All routes on a single router. The auth middleware is applied to
        // the entire router but internally skips public paths (POST /v1/peers,
        // GET /v1/myip, GET /v1/ws, documentation). This avoids axum's
        // state-propagation issues when merging separate sub-routers.
        //
        // Note: SwaggerUi must be merged BEFORE .with_state() to avoid
        // routing conflicts that cause 404s on state-dependent routes.
        Router::new()
            .merge(SwaggerUi::new("/swagger-ui").url("/v1/openapi.json", ApiDoc::openapi()))
            .route("/v1/peers", post(handlers::register_peer))
            .route("/v1/peers/lookup", get(handlers::lookup_peer))
            .route(
                "/v1/peers/{peer_id}",
                get(handlers::get_peer)
                    .put(handlers::update_peer)
                    .delete(handlers::unregister_peer),
            )
            .route("/v1/peers/{peer_id}/status", get(handlers::get_peer_status))
            .route("/v1/myip", get(handlers::get_my_ip))
            .route("/v1/ws", get(handlers::ws_upgrade))
            .route("/v1/proxies", get(handlers::get_proxies))
            .route("/v1/dht/bootstrap", get(handlers::dht_bootstrap))
            .route("/v1/proxy-token", post(handlers::issue_proxy_token))
            .layer(auth_middleware)
            .with_state(self.state.clone())
            // ── CORS ──────────────────────────────────────────────────────
            .layer(CorsLayer::permissive())
    }

    /// Return a reference to the shared application state.
    #[allow(dead_code)]
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Return the listen address from the config.
    pub fn listen_addr(&self) -> &str {
        &self.config.listen_addr
    }
}
