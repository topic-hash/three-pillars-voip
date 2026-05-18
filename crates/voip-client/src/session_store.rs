//! In-memory session ticket store for 0-RTT resumption.
//!
//! Per ROADMAP 3.11: reconnection completes in <100ms by persisting
//! TLS 1.3 session tickets between connections.
//!
//! The store implements [`rustls::client::ClientSessionStore`] so it can
//! be plugged into a `rustls::ClientConfig` via
//! [`rustls::client::Resumption::store()`]. Tickets are held in memory
//! with a configurable TTL (default: 24 hours per spec/11).
//!
//! # TTL
//!
//! Tickets expire after `session_ticket_ttl_secs` (default: 86400 = 24h)
//! as specified in spec/11. Expired tickets are lazily evicted on
//! retrieval.
//!
//! # Thread Safety
//!
//! All access is guarded by a [`std::sync::Mutex`]. The store is
//! `Send + Sync` and can be shared across tasks.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use rustls::client::{ClientSessionStore, Resumption, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::pki_types::ServerName;
use rustls::NamedGroup;

use voip_core::config::VoIPConfig;

/// Maximum number of TLS 1.3 tickets stored per server name.
const MAX_TLS13_TICKETS_PER_SERVER: usize = 4;

/// Per-server session data stored in the cache.
#[derive(Debug, Default)]
struct ServerData {
    /// Key-exchange group hint for faster handshake.
    kx_hint: Option<NamedGroup>,
    /// TLS 1.2 session data (at most one per server).
    tls12: Option<Tls12ClientSessionValue>,
    /// TLS 1.3 session tickets (up to MAX_TLS13_TICKETS_PER_SERVER).
    tls13: VecDeque<Tls13ClientSessionValue>,
    /// Instant when each TLS 1.3 ticket was stored (for TTL eviction).
    tls13_timestamps: VecDeque<std::time::Instant>,
}

/// In-memory session ticket store for 0-RTT resumption.
///
/// Per ROADMAP 3.11: reconnection completes in <100ms.
/// This is a basic implementation — for production, tickets should
/// be persisted to disk. For now, in-memory with TTL is sufficient.
pub struct SessionTicketStore {
    /// Per-server session data.
    servers: Mutex<HashMap<ServerName<'static>, ServerData>>,
    /// Time-to-live for TLS 1.3 tickets.
    ttl: std::time::Duration,
}

impl SessionTicketStore {
    /// Create a new session ticket store with the given TTL.
    ///
    /// The TTL defaults to 24 hours (86400 seconds) per spec/11.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            servers: Mutex::new(HashMap::new()),
            ttl: std::time::Duration::from_secs(ttl_secs),
        }
    }

    /// Create a new session ticket store from a [`VoIPConfig`].
    ///
    /// Uses `session_ticket_ttl_secs` from the config.
    pub fn from_config(config: &VoIPConfig) -> Self {
        Self::new(config.session_ticket_ttl_secs)
    }

    /// Evict expired TLS 1.3 tickets for a given server name.
    fn evict_expired_tickets(data: &mut ServerData, ttl: std::time::Duration) {
        let now = std::time::Instant::now();
        while let Some(stored_at) = data.tls13_timestamps.front() {
            if now.duration_since(*stored_at) >= ttl {
                data.tls13.pop_front();
                data.tls13_timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get the number of stored TLS 1.3 tickets (for diagnostics).
    pub fn ticket_count(&self) -> usize {
        let servers = self.servers.lock().unwrap_or_else(|e| e.into_inner());
        servers.values().map(|d| d.tls13.len()).sum()
    }

    /// Clear all stored session data.
    pub fn clear(&self) {
        let mut servers = self.servers.lock().unwrap_or_else(|e| e.into_inner());
        servers.clear();
    }
}

impl std::fmt::Debug for SessionTicketStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit servers data as it may contain sensitive ticket material.
        f.debug_struct("SessionTicketStore")
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl ClientSessionStore for SessionTicketStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        let mut servers = self.servers.lock().unwrap_or_else(|e| e.into_inner());
        servers
            .entry(server_name)
            .or_default()
            .kx_hint = Some(group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        let servers = self.servers.lock().unwrap_or_else(|e| e.into_inner());
        servers.get(server_name).and_then(|d| d.kx_hint)
    }

    fn set_tls12_session(
        &self,
        server_name: ServerName<'static>,
        value: Tls12ClientSessionValue,
    ) {
        let mut servers = self.servers.lock().unwrap_or_else(|e| e.into_inner());
        servers
            .entry(server_name)
            .or_default()
            .tls12 = Some(value);
    }

    fn tls12_session(
        &self,
        server_name: &ServerName<'_>,
    ) -> Option<Tls12ClientSessionValue> {
        let servers = self.servers.lock().unwrap_or_else(|e| e.into_inner());
        servers.get(server_name).and_then(|d| d.tls12.clone())
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        let mut servers = self.servers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(data) = servers.get_mut(server_name) {
            data.tls12.take();
        }
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        let now = std::time::Instant::now();
        let mut servers = self.servers.lock().unwrap_or_else(|e| e.into_inner());
        let data = servers.entry(server_name).or_default();

        // Evict expired tickets before inserting
        Self::evict_expired_tickets(data, self.ttl);

        // Enforce ticket limit (same as rustls default)
        if data.tls13.len() >= MAX_TLS13_TICKETS_PER_SERVER {
            data.tls13.pop_front();
            data.tls13_timestamps.pop_front();
        }

        data.tls13.push_back(value);
        data.tls13_timestamps.push_back(now);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        let mut servers = self.servers.lock().unwrap_or_else(|e| e.into_inner());
        let data = servers.get_mut(server_name)?;

        // Evict expired tickets first
        Self::evict_expired_tickets(data, self.ttl);

        // Return the most recent ticket
        data.tls13.pop_back()
    }
}

/// Create a `rustls::ClientConfig` with session resumption support.
///
/// This configures TLS 1.3 0-RTT session ticket persistence using
/// a [`SessionTicketStore`], enabling reconnections in <100ms
/// per ROADMAP 3.11.
///
/// Uses the dangerous (no certificate verification) verifier for
/// development and DHT trust-on-first-use.
pub fn client_config_with_resumption(
    config: &VoIPConfig,
) -> Result<rustls::ClientConfig, String> {
    let store = Arc::new(SessionTicketStore::from_config(config));

    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
        .with_no_client_auth();

    client_config.resumption = Resumption::store(store);

    Ok(client_config)
}

/// Create a `quinn::ClientConfig` with session resumption and datagram support.
///
/// Combines the TLS session ticket store with QUIC transport configuration
/// (datagram buffers, idle timeout) for the full client stack.
pub fn quinn_client_config_with_resumption(
    config: &VoIPConfig,
) -> Result<quinn::ClientConfig, String> {
    let rustls_config = client_config_with_resumption(config)?;

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|e| format!("QuicClientConfig: {}", e))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));

    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65536));
    transport.datagram_send_buffer_size(65536);

    let idle_timeout = std::time::Duration::from_millis(config.quic_idle_timeout_ms);
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(idle_timeout).map_err(|_| "invalid idle timeout")?,
    ));

    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_store_new() {
        let store = SessionTicketStore::new(86400);
        assert_eq!(store.ticket_count(), 0);
    }

    #[test]
    fn test_session_store_from_config() {
        let config = VoIPConfig::default();
        let store = SessionTicketStore::from_config(&config);
        assert_eq!(store.ticket_count(), 0);
    }

    #[test]
    fn test_session_store_clear() {
        let store = SessionTicketStore::new(86400);
        store.clear();
        assert_eq!(store.ticket_count(), 0);
    }

    #[test]
    fn test_session_store_kx_hint() {
        let store = SessionTicketStore::new(86400);
        let server_name = ServerName::try_from("example.com").unwrap();

        // No hint initially
        assert!(store.kx_hint(&server_name).is_none());

        // Set and retrieve
        store.set_kx_hint(server_name.clone(), NamedGroup::secp256r1);
        assert_eq!(store.kx_hint(&server_name), Some(NamedGroup::secp256r1));
    }

    #[test]
    fn test_session_store_no_tls13_tickets_initially() {
        let store = SessionTicketStore::new(86400);
        let server_name = ServerName::try_from("example.com").unwrap();
        // No tickets initially
        assert!(store.take_tls13_ticket(&server_name).is_none());
    }

    #[test]
    fn test_client_config_with_resumption() {
        let config = VoIPConfig::default();
        let result = client_config_with_resumption(&config);
        assert!(result.is_ok(), "Should create client config with resumption");
    }

    #[test]
    fn test_quinn_client_config_with_resumption() {
        let config = VoIPConfig::default();
        let result = quinn_client_config_with_resumption(&config);
        assert!(result.is_ok(), "Should create quinn client config with resumption");
    }
}
