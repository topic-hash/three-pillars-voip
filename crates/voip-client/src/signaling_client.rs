//! HTTP client for signaling server REST endpoints.
//!
//! Per ROADMAP 3.18: the signaling server exposes REST endpoints that
//! the client queries for proxy discovery and DHT bootstrapping:
//!
//! - `GET /v1/proxies` — returns a list of MASQUE proxy records
//! - `GET /v1/dht/bootstrap` — returns DHT bootstrap multiaddresses
//!
//! All requests are authenticated with a JWT token obtained during
//! the QUIC/WebSocket signaling handshake.

use tracing::{debug, info, instrument, warn};

use voip_core::proto::signaling::ProxyRecord;

use crate::error::ClientError;

/// HTTP client for signaling server REST endpoints.
///
/// Wraps `reqwest::Client` with JWT authentication and provides typed
/// methods for the signaling server's proxy-discovery and DHT-bootstrap
/// endpoints.
pub struct SignalingHttpClient {
    /// Base URL of the signaling server (e.g., `https://signal.example.com`).
    base_url: String,
    /// The underlying HTTP client.
    client: reqwest::Client,
    /// JWT token obtained during signaling handshake, sent in the
    /// `Authorization: Bearer <token>` header.
    jwt_token: String,
}

impl SignalingHttpClient {
    /// Create a new `SignalingHttpClient`.
    ///
    /// # Arguments
    ///
    /// * `base_url` — The base URL of the signaling server
    ///   (e.g., `https://signal.example.com`). Trailing slashes are stripped.
    /// * `jwt_token` — JWT bearer token obtained during the QUIC/WebSocket
    ///   signaling handshake.
    pub fn new(base_url: &str, jwt_token: &str) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            base_url,
            client,
            jwt_token: jwt_token.to_string(),
        }
    }

    /// Fetch the list of available MASQUE proxies from the signaling server.
    ///
    /// `GET /v1/proxies` — returns a JSON array of `ProxyRecord` objects.
    ///
    /// The client uses this to discover volunteer proxy nodes when a
    /// direct P2P connection fails and MASQUE relay is needed.
    #[instrument(skip(self))]
    pub async fn get_proxies(&self) -> Result<Vec<ProxyRecord>, ClientError> {
        let url = format!("{}/v1/proxies", self.base_url);
        debug!(url = %url, "Fetching proxy list from signaling server");

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.jwt_token))
            .send()
            .await
            .map_err(|e| ClientError::SignalingError(format!("proxy fetch: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            warn!(status = %status, "Proxy fetch returned non-success status");
            return Err(ClientError::SignalingError(format!(
                "proxy fetch returned {}: {}",
                status,
                status.canonical_reason().unwrap_or("unknown")
            )));
        }

        let proxies: Vec<ProxyRecord> = response
            .json()
            .await
            .map_err(|e| ClientError::SignalingError(format!("proxy decode: {}", e)))?;

        info!(count = proxies.len(), "Received proxy records from signaling server");
        Ok(proxies)
    }

    /// Fetch DHT bootstrap multiaddresses from the signaling server.
    ///
    /// `GET /v1/dht/bootstrap` — returns a JSON array of multiaddress strings
    /// (e.g., `/ip4/203.0.113.10/udp/4001/quic/p2p/Qm...`).
    ///
    /// The client uses these to bootstrap its DHT node on startup.
    #[instrument(skip(self))]
    pub async fn get_dht_bootstrap(&self) -> Result<Vec<String>, ClientError> {
        let url = format!("{}/v1/dht/bootstrap", self.base_url);
        debug!(url = %url, "Fetching DHT bootstrap addresses from signaling server");

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.jwt_token))
            .send()
            .await
            .map_err(|e| ClientError::SignalingError(format!("DHT bootstrap fetch: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            warn!(status = %status, "DHT bootstrap fetch returned non-success status");
            return Err(ClientError::SignalingError(format!(
                "DHT bootstrap returned {}: {}",
                status,
                status.canonical_reason().unwrap_or("unknown")
            )));
        }

        let addresses: Vec<String> = response
            .json()
            .await
            .map_err(|e| ClientError::SignalingError(format!("DHT bootstrap decode: {}", e)))?;

        info!(count = addresses.len(), "Received DHT bootstrap addresses from signaling server");
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_construction() {
        let client = SignalingHttpClient::new("https://signal.example.com/", "jwt-token-here");
        assert_eq!(client.base_url, "https://signal.example.com");
        assert_eq!(client.jwt_token, "jwt-token-here");
    }

    #[test]
    fn test_client_trailing_slash_stripped() {
        let client = SignalingHttpClient::new("https://signal.example.com///", "token");
        // Only trailing slashes after the last path segment are stripped
        assert!(!client.base_url.ends_with('/'));
    }
}
