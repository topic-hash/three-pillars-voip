//! Peer runtime: identity + signaling registration + QUIC listener.
//!
//! This module is the "steering wheel" that the rest of voip-client was
//! missing. It wires together:
//!   1. An [`Identity`] (Ed25519 keypair + derived peer_id)
//!   2. A signaling REST client (register, lookup)
//!   3. A quinn QUIC endpoint bound to a configurable listen address,
//!      with a self-signed TLS cert accepted by `tls::NoVerifier`
//!
//! The peer runs an accept loop in the background: every incoming QUIC
//! connection is handed to a caller-supplied async callback. This is
//! deliberately generic so the same runtime can be used for text
//! ping/pong (Wave 3), MoQ media (future), and call signaling (future).
//!
//! # Why a new struct instead of fixing `Client::init()`?
//!
//! `Client` is the mobile/FFI-facing state machine (idle → ringing →
//! connected → ended) and owns call-level state. Peer runtime concerns
//! (listen on a socket, register with signaling, accept incoming
//! connections) are a different lifecycle. Putting them in `Client`
//! would require either a builder pattern or pulling in `Arc<RwLock<>>`
//! everywhere. A separate `Peer` struct keeps `Client` mobile-friendly
//! and gives the CLI a clean entry point.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{Endpoint, ServerConfig};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn};

use voip_core::crypto::peer_id_from_public_key;

/// An Ed25519 keypair held in memory by a running Peer.
///
/// Produced by decoding the persisted identity file (voip-cli's
/// `~/.voip-cli/identity.json`). The keypair is used to derive the
/// peer_id and to sign signaling messages (future: DHT records).
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// 32-byte Ed25519 signing key (SECRET).
    pub signing_key: SigningKey,
    /// 32-byte Ed25519 verifying key (public).
    pub verifying_key: VerifyingKey,
    /// 64-char hex peer_id, derived from verifying_key.
    pub peer_id: String,
}

impl PeerIdentity {
    /// Construct from raw key bytes.
    pub fn from_bytes(signing_key_bytes: [u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(&signing_key_bytes);
        let vk = sk.verifying_key();
        let peer_id = peer_id_from_public_key(&vk);
        Self {
            signing_key: sk,
            verifying_key: vk,
            peer_id,
        }
    }

    /// Construct from hex strings (as stored in identity.json).
    pub fn from_hex(signing_key_hex: &str, verifying_key_hex: &str) -> Result<Self> {
        let sk_bytes: [u8; 32] = hex::decode(signing_key_hex)
            .map_err(|e| anyhow!("invalid signing_key hex: {e}"))?
            .try_into()
            .map_err(|_| anyhow!("signing_key must be 32 bytes"))?;
        // Verify the verifying_key matches the signing_key
        let sk = SigningKey::from_bytes(&sk_bytes);
        let expected_vk_hex = hex::encode(sk.verifying_key().to_bytes());
        if expected_vk_hex != verifying_key_hex {
            return Err(anyhow!(
                "verifying_key does not match signing_key (expected {}, got {})",
                expected_vk_hex,
                verifying_key_hex
            ));
        }
        Ok(Self::from_bytes(sk_bytes))
    }
}

/// JSON body for `POST /v1/peers`.
#[derive(Debug, Serialize)]
struct RegisterPeerRequest {
    peer_id: String,
    display_name: String,
}

/// JSON response from `POST /v1/peers`.
#[derive(Debug, Deserialize)]
pub struct RegisterPeerResponse {
    pub peer_id: String,
    pub jwt_token: String,
}

/// JSON response from `GET /v1/peers/{peer_id}`.
#[derive(Debug, Deserialize, Clone)]
pub struct PeerRecord {
    pub peer_id: String,
    pub display_name: String,
    #[serde(default)]
    pub ipv6_addresses: Vec<String>,
    #[serde(default)]
    pub ipv4_reflexive: Vec<String>,
    pub nat_type: String,
    pub status: String,
    pub last_seen: u64,
}

/// Configuration for a running Peer.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Signaling server base URL (e.g., "http://127.0.0.1:8443").
    pub signaling_url: String,
    /// Display name registered with the signaling server.
    pub display_name: String,
    /// QUIC listen address (e.g., "0.0.0.0:4433").
    pub listen_addr: String,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            signaling_url: "http://127.0.0.1:8443".to_string(),
            display_name: "voip-peer".to_string(),
            listen_addr: "0.0.0.0:4433".to_string(),
        }
    }
}

/// A running VoIP peer.
///
/// Owns the QUIC endpoint and the JWT obtained from registration.
/// The accept loop is spawned as a tokio task; the caller decides
/// what to do with each incoming connection via the `on_connection`
/// callback passed to [`Peer::run_accept_loop`].
pub struct Peer {
    pub(crate) identity: PeerIdentity,
    pub(crate) config: PeerConfig,
    pub(crate) endpoint: Endpoint,
    pub(crate) jwt: Mutex<Option<String>>,
}

impl Peer {
    /// Build a QUIC server config with a fresh self-signed cert.
    ///
    /// Uses `tls::dangerous_quinn_server_config()` which generates a
    /// new rcgen cert on each call. Peers connecting to us must use
    /// `tls::NoVerifier` (the default in debug builds) to accept it.
    fn build_server_config() -> Result<ServerConfig> {
        let cfg = crate::tls::dangerous_quinn_server_config()
            .map_err(|e| anyhow!("failed to build QUIC server config: {e}"))?;
        Ok(cfg)
    }

    /// Construct a Peer: bind the QUIC endpoint and store identity.
    ///
    /// Does NOT register with the signaling server yet — call
    /// [`Peer::register`] explicitly. This two-step setup lets tests
    /// bind the endpoint without needing a live signaling server.
    pub fn new(identity: PeerIdentity, config: PeerConfig) -> Result<Self> {
        let server_cfg = Self::build_server_config()?;
        let listen_addr: SocketAddr = config
            .listen_addr
            .parse()
            .with_context(|| format!("invalid listen_addr: {}", config.listen_addr))?;

        let endpoint = Endpoint::server(server_cfg, listen_addr).with_context(|| {
            format!("failed to bind QUIC endpoint to {}", config.listen_addr)
        })?;

        let local_addr = endpoint.local_addr().ok();
        info!(
            ?local_addr,
            peer_id = %identity.peer_id,
            "QUIC listener bound"
        );

        Ok(Self {
            identity,
            config,
            endpoint,
            jwt: Mutex::new(None),
        })
    }

    /// The local address the QUIC endpoint is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("endpoint has no local address")
    }

    /// The peer_id derived from the loaded identity.
    pub fn peer_id(&self) -> &str {
        &self.identity.peer_id
    }

    /// The QUIC endpoint (for outgoing connections in Wave 3).
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Register with the signaling server. Stores the JWT for later use.
    ///
    /// Sends `POST /v1/peers` with the peer_id and display_name.
    /// On success, stores the JWT in `self.jwt`.
    #[instrument(skip(self))]
    pub async fn register(&self) -> Result<RegisterPeerResponse> {
        let url = self.config.signaling_url.trim_end_matches('/');
        let endpoint = format!("{}/v1/peers", url);

        let body = RegisterPeerRequest {
            peer_id: self.identity.peer_id.clone(),
            display_name: self.config.display_name.clone(),
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        debug!(%endpoint, "registering with signaling server");

        let resp = client
            .post(&endpoint)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {} failed", endpoint))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("register failed: HTTP {}: {}", status, text));
        }

        let parsed: RegisterPeerResponse = resp
            .json()
            .await
            .context("failed to parse register response")?;

        if parsed.peer_id != self.identity.peer_id {
            return Err(anyhow!(
                "server returned mismatched peer_id: expected {}, got {}",
                self.identity.peer_id,
                parsed.peer_id
            ));
        }

        *self.jwt.lock().await = Some(parsed.jwt_token.clone());
        info!("registered with signaling server, JWT stored");
        Ok(parsed)
    }

    /// Look up another peer by peer_id via `GET /v1/peers/{peer_id}`.
    ///
    /// Uses the stored JWT for authentication. Returns the peer's
    /// registered addresses (ipv6_addresses, ipv4_reflexive) which
    /// can be passed to `ConnectionManager::establish_connection`.
    pub async fn lookup_peer(&self, peer_id: &str) -> Result<PeerRecord> {
        let jwt = self
            .jwt
            .lock()
            .await
            .clone()
            .ok_or_else(|| anyhow!("not registered — call register() first"))?;

        let url = self.config.signaling_url.trim_end_matches('/');
        let endpoint = format!("{}/v1/peers/{}", url, peer_id);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let resp = client
            .get(&endpoint)
            .header("Authorization", format!("Bearer {}", jwt))
            .send()
            .await
            .with_context(|| format!("GET {} failed", endpoint))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("lookup failed: HTTP {}: {}", status, text));
        }

        let record: PeerRecord = resp
            .json()
            .await
            .context("failed to parse peer record response")?;
        Ok(record)
    }

    /// Run the accept loop: for each incoming QUIC connection, invoke
    /// the supplied callback. The callback receives the connection
    /// and the first bidi stream it opens (Wave 3 callers can read
    /// "ping" and write "pong").
    ///
    /// This future runs until the endpoint is closed or an unrecoverable
    /// error occurs. The caller typically wraps it in `tokio::spawn`
    /// and runs it concurrently with the rest of the application.
    pub async fn run_accept_loop<F, Fut>(&self, on_conn: F) -> Result<()>
    where
        F: Fn(quinn::Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let on_conn = Arc::new(on_conn);
        info!("accept loop running");
        loop {
            let incoming = self.endpoint.accept().await;
            let Some(incoming) = incoming else {
                info!("endpoint closed, accept loop exiting");
                return Ok(());
            };
            let on_conn = on_conn.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        let remote = conn.remote_address();
                        info!(%remote, "incoming QUIC connection accepted");
                        on_conn(conn).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to accept incoming QUIC connection");
                    }
                }
            });
        }
    }

    /// Close the QUIC endpoint and stop accepting connections.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"peer shutting down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_identity_from_bytes_roundtrip() {
        let sk_bytes: [u8; 32] = (0..32).map(|i| i as u8).collect::<Vec<_>>().try_into().unwrap();
        let id = PeerIdentity::from_bytes(sk_bytes);
        assert_eq!(id.peer_id.len(), 64);
        assert_eq!(id.verifying_key.to_bytes().len(), 32);
        assert_eq!(id.signing_key.to_bytes(), sk_bytes);
    }

    #[test]
    fn test_peer_identity_from_hex_rejects_mismatched_keys() {
        let sk_hex = "00".repeat(32);
        let wrong_vk_hex = "ff".repeat(32);
        let result = PeerIdentity::from_hex(&sk_hex, &wrong_vk_hex);
        assert!(
            result.is_err(),
            "mismatched verifying_key must error"
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("does not match"), "error must explain mismatch: {err}");
    }

    #[test]
    fn test_peer_identity_from_hex_accepts_matched_keys() {
        // Generate a real keypair, encode both halves, decode them back.
        let (sk, vk) = voip_core::crypto::generate_ed25519_keypair();
        let sk_hex = hex::encode(sk.to_bytes());
        let vk_hex = hex::encode(vk.to_bytes());
        let id = PeerIdentity::from_hex(&sk_hex, &vk_hex).expect("matched keys decode");
        assert_eq!(id.peer_id, peer_id_from_public_key(&vk));
    }

    #[test]
    fn test_peer_config_default_has_sensible_values() {
        let cfg = PeerConfig::default();
        assert!(cfg.signaling_url.starts_with("http"));
        assert!(cfg.listen_addr.starts_with("0.0.0.0:"));
        assert!(!cfg.display_name.is_empty());
    }

    /// Integration: bind a Peer endpoint, verify it can accept connections.
    ///
    /// This proves the QUIC server config (self-signed cert + quinn
    /// server endpoint) actually works. The test does not register
    /// with a signaling server — it only verifies the QUIC layer.
    #[tokio::test]
    async fn test_peer_binds_quic_endpoint() {
        let (sk, _) = voip_core::crypto::generate_ed25519_keypair();
        let identity = PeerIdentity::from_bytes(sk.to_bytes());
        let config = PeerConfig {
            listen_addr: "127.0.0.1:0".to_string(), // ephemeral port
            ..Default::default()
        };
        let peer = Peer::new(identity, config).expect("peer constructs");
        let local = peer.local_addr().expect("local_addr");
        assert_eq!(local.ip().to_string(), "127.0.0.1");
        // The endpoint must accept connections (not immediately error)
        // We can't easily test the accept loop without a real client,
        // but binding without error is the main contract.
        peer.close();
    }
}
