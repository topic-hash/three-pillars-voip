//! VoIP configuration constants from spec/11 §11.3.
//!
//! All configurable parameters for the Three Pillars VoIP system with
//! sensible defaults as defined in the specification.

/// Global configuration for the VoIP system.
///
/// See spec/11 §11.3 for the authoritative definition of all fields
/// and their default values.
#[derive(Debug, Clone)]
pub struct VoIPConfig {
    // === QUIC Path Probing (replaces STUN) ===
    /// Number of signaling server IPs to probe for NAT classification
    pub path_probe_count: u32,
    /// Timeout per QUIC path migration probe (milliseconds)
    pub path_probe_timeout_ms: u64,
    /// Time-to-live for NAT probe cache (seconds)
    pub nat_cache_ttl_secs: u64,
    /// Number of path probes for quick refresh (before call)
    pub path_refresh_count: u32,
    /// Maximum variance in delta before reclassifying NAT
    pub nat_delta_variance_threshold: u32,

    // === Port Prediction ===
    /// Margin for sequential NAT prediction (range of 7 ports)
    pub prediction_margin_sequential: u32,
    /// Margin for pseudo-sequential NAT prediction (range of 17 ports)
    pub prediction_margin_pseudo: u32,
    /// Maximum prediction probe packets per side
    pub prediction_max_probes: u32,

    // === QUIC Connection ===
    /// Timeout for initial QUIC handshake (milliseconds)
    pub quic_connect_timeout_ms: u64,
    /// Timeout for port prediction probing phase (milliseconds)
    pub quic_prediction_timeout_ms: u64,
    /// Maximum idle timeout for established QUIC connection (milliseconds)
    pub quic_idle_timeout_ms: u64,
    /// QUIC ALPN protocol identifier
    pub quic_alpn: String,

    // === Discovery ===
    /// Discovery priority: true = DHT first (privacy), false = signaling first (speed)
    pub discovery_privacy_first: bool,
    /// DHT lookup timeout before falling back to signaling (milliseconds)
    pub dht_lookup_timeout_ms: u64,
    /// DHT bootstrap nodes (hardcoded fallback)
    pub dht_bootstrap_nodes: Vec<String>,
    /// DHT record TTL (seconds)
    pub dht_record_ttl_secs: u64,

    // === Push Retry ===
    /// Enable push notification retry for failed connections
    pub push_retry_enabled: bool,
    /// Initial retry delay (seconds)
    pub push_retry_initial_delay_secs: u64,
    /// Maximum retry attempts
    pub push_retry_max_attempts: u32,
    /// Retry backoff multiplier
    pub push_retry_backoff_multiplier: u32,

    // === MASQUE Fallback ===
    /// Enable MASQUE CONNECT-UDP fallback when direct P2P fails
    pub masque_fallback_enabled: bool,
    /// Timeout for MASQUE proxy discovery (milliseconds)
    pub masque_discovery_timeout_ms: u64,
    /// Timeout for HTTP/3 + CONNECT-UDP tunnel setup (milliseconds)
    pub masque_connect_timeout_ms: u64,
    /// Maximum number of proxy candidates to try
    pub masque_max_proxy_attempts: u32,
    /// Whether this node can act as a MASQUE proxy (desktop only)
    pub masque_proxy_enabled: bool,
    /// Maximum concurrent relay sessions when acting as proxy
    pub masque_proxy_max_sessions: u32,

    // === Call Setup ===
    /// Timeout for call ringing phase (milliseconds)
    pub call_ring_timeout_ms: u64,
    /// Timeout for call connection attempt (milliseconds)
    pub call_connect_timeout_ms: u64,

    // === Connection Migration ===
    /// Timeout for QUIC connection migration path validation (milliseconds)
    pub migration_path_timeout_ms: u64,
    /// Maximum number of re-probes during connection migration
    pub migration_max_reprobes: u32,

    // === Signaling Server ===
    /// Rate limit: maximum calls per minute per peer
    pub rate_limit_calls_per_min: u32,
    /// Rate limit: maximum registrations per minute per peer
    pub rate_limit_registrations_per_min: u32,
    /// Rate limit: maximum WebSocket messages per second per connection
    pub rate_limit_ws_messages_per_sec: u32,
    /// JWT token expiry duration (seconds)
    pub jwt_expiry_secs: u64,
    /// Signaling server elastic IPs for QUIC path probing
    pub signaling_server_ips: Vec<String>,

    // === Session Tickets (0-RTT) ===
    /// Time-to-live for QUIC session tickets (seconds)
    pub session_ticket_ttl_secs: u64,

    // === MoQ ===
    /// Interval between MoQ quality feedback reports (milliseconds)
    pub moq_feedback_interval_ms: u64,
}

impl Default for VoIPConfig {
    fn default() -> Self {
        Self {
            // === QUIC Path Probing ===
            path_probe_count: 5,
            path_probe_timeout_ms: 1000,
            nat_cache_ttl_secs: 300,
            path_refresh_count: 2,
            nat_delta_variance_threshold: 3,

            // === Port Prediction ===
            prediction_margin_sequential: 3,
            prediction_margin_pseudo: 8,
            prediction_max_probes: 17,

            // === QUIC Connection ===
            quic_connect_timeout_ms: 5000,
            quic_prediction_timeout_ms: 3000,
            quic_idle_timeout_ms: 30000,
            quic_alpn: "moq-00".to_string(),

            // === Discovery ===
            discovery_privacy_first: true,
            dht_lookup_timeout_ms: 200,
            dht_bootstrap_nodes: vec![
                "/ip4/104.131.131.82/udp/4001/quic-v1/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ".to_string(),
                "/ip4/104.236.76.40/udp/4001/quic-v1/p2p/QmSoLV4Bbm51jM9C4gDYZQ9Cy3U6aXMJDAbzgu2fzaDs64".to_string(),
                "/ip4/178.128.155.54/udp/4001/quic-v1/p2p/QmSoLMeWqB7YGVLJN3pNLQpmmEk35v6wYtsMGLzSr5QBU3".to_string(),
            ],
            dht_record_ttl_secs: 3600,

            // === Push Retry ===
            push_retry_enabled: true,
            push_retry_initial_delay_secs: 5,
            push_retry_max_attempts: 3,
            push_retry_backoff_multiplier: 3,

            // === MASQUE Fallback ===
            masque_fallback_enabled: true,
            masque_discovery_timeout_ms: 2000,
            masque_connect_timeout_ms: 3000,
            masque_max_proxy_attempts: 3,
            masque_proxy_enabled: false,
            masque_proxy_max_sessions: 10,

            // === Call Setup ===
            call_ring_timeout_ms: 30000,
            call_connect_timeout_ms: 10000,

            // === Connection Migration ===
            migration_path_timeout_ms: 5000,
            migration_max_reprobes: 1,

            // === Signaling Server ===
            rate_limit_calls_per_min: 10,
            rate_limit_registrations_per_min: 6,
            rate_limit_ws_messages_per_sec: 30,
            jwt_expiry_secs: 3600,
            signaling_server_ips: vec![
                "203.0.113.1".to_string(),
                "203.0.113.2".to_string(),
                "203.0.113.3".to_string(),
                "203.0.113.4".to_string(),
                "203.0.113.5".to_string(),
            ],

            // === Session Tickets ===
            session_ticket_ttl_secs: 86400,

            // === MoQ ===
            moq_feedback_interval_ms: 1000,
        }
    }
}

impl VoIPConfig {
    /// Creates a new configuration with all defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Computes the retry delay for a given attempt number.
    ///
    /// Uses exponential backoff: `initial_delay * backoff_multiplier^(attempt-1)`
    ///
    /// For default config: 5s, 15s, 45s
    pub fn retry_delay_secs(&self, attempt: u32) -> u64 {
        if attempt == 0 {
            return 0;
        }
        let exponent = (attempt - 1) as u64;
        let multiplier = self.push_retry_backoff_multiplier as u64;
        self.push_retry_initial_delay_secs * multiplier.pow(exponent as u32)
    }

    /// Returns the predicted port range for sequential NAT.
    ///
    /// Range: `[base_port - margin, base_port + margin]`
    pub fn sequential_prediction_range(&self, base_port: u32) -> (u32, u32) {
        let start = base_port.saturating_sub(self.prediction_margin_sequential);
        let end = base_port.saturating_add(self.prediction_margin_sequential);
        (start.max(1024), end.min(65535))
    }

    /// Returns the predicted port range for pseudo-sequential NAT.
    ///
    /// Range: `[base_port - margin, base_port + margin]`
    pub fn pseudo_prediction_range(&self, base_port: u32) -> (u32, u32) {
        let start = base_port.saturating_sub(self.prediction_margin_pseudo);
        let end = base_port.saturating_add(self.prediction_margin_pseudo);
        (start.max(1024), end.min(65535))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = VoIPConfig::default();
        assert_eq!(config.path_probe_count, 5);
        assert_eq!(config.path_probe_timeout_ms, 1000);
        assert_eq!(config.nat_cache_ttl_secs, 300);
        assert_eq!(config.prediction_margin_sequential, 3);
        assert_eq!(config.prediction_margin_pseudo, 8);
        assert_eq!(config.prediction_max_probes, 17);
        assert_eq!(config.quic_connect_timeout_ms, 5000);
        assert_eq!(config.quic_prediction_timeout_ms, 3000);
        assert_eq!(config.quic_idle_timeout_ms, 30000);
        assert_eq!(config.quic_alpn, "moq-00");
        assert!(config.discovery_privacy_first);
        assert_eq!(config.dht_lookup_timeout_ms, 200);
        assert_eq!(config.dht_record_ttl_secs, 3600);
        assert!(config.push_retry_enabled);
        assert_eq!(config.push_retry_initial_delay_secs, 5);
        assert_eq!(config.push_retry_max_attempts, 3);
        assert_eq!(config.push_retry_backoff_multiplier, 3);
        assert!(config.masque_fallback_enabled);
        assert_eq!(config.masque_discovery_timeout_ms, 2000);
        assert_eq!(config.masque_connect_timeout_ms, 3000);
        assert_eq!(config.masque_max_proxy_attempts, 3);
        assert!(!config.masque_proxy_enabled);
        assert_eq!(config.masque_proxy_max_sessions, 10);
        assert_eq!(config.call_ring_timeout_ms, 30000);
        assert_eq!(config.call_connect_timeout_ms, 10000);
        assert_eq!(config.migration_path_timeout_ms, 5000);
        assert_eq!(config.migration_max_reprobes, 1);
        assert_eq!(config.rate_limit_calls_per_min, 10);
        assert_eq!(config.rate_limit_registrations_per_min, 6);
        assert_eq!(config.rate_limit_ws_messages_per_sec, 30);
        assert_eq!(config.jwt_expiry_secs, 3600);
        assert_eq!(config.session_ticket_ttl_secs, 86400);
        assert_eq!(config.moq_feedback_interval_ms, 1000);
    }

    #[test]
    fn test_retry_delay_backoff() {
        let config = VoIPConfig::default();
        // Default: 5s * 3^0 = 5s, 5s * 3^1 = 15s, 5s * 3^2 = 45s
        assert_eq!(config.retry_delay_secs(1), 5);
        assert_eq!(config.retry_delay_secs(2), 15);
        assert_eq!(config.retry_delay_secs(3), 45);
        assert_eq!(config.retry_delay_secs(0), 0);
    }

    #[test]
    fn test_prediction_ranges() {
        let config = VoIPConfig::default();
        // Sequential: base 50000, margin 3 -> [49997, 50003]
        let (start, end) = config.sequential_prediction_range(50000);
        assert_eq!(start, 49997);
        assert_eq!(end, 50003);

        // Pseudo-sequential: base 50000, margin 8 -> [49992, 50008]
        let (start, end) = config.pseudo_prediction_range(50000);
        assert_eq!(start, 49992);
        assert_eq!(end, 50008);
    }
}
