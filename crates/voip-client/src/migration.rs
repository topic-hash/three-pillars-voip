//! QUIC connection migration handler.
//!
//! Handles network changes (WiFi ↔ cellular) by migrating the active
//! QUIC connection to a new path. Per spec/04 §4.4:
//!
//! - **Legacy (ICE):** ICE restart → 2-5 seconds of re-gathering candidates,
//!   re-exchanging SDP, re-testing connectivity. Call often drops.
//!
//! - **QUIC:** Connection migration → 1 RTT (PATH_CHALLENGE/PATH_RESPONSE on
//!   new address). Call continues uninterrupted. The Connection ID identifies
//!   the packets as belonging to the existing connection, regardless of the
//!   new IP address.
//!
//! # IPv4 Re-probing
//!
//! After connection migration to a new network, the client re-probes its NAT
//! via QUIC path probing (spec/03) and signals the new predicted range to the
//! peer through the existing QUIC connection (which is still alive on the old
//! path during migration).
//!
//! # Timeout
//!
//! Per spec/11 §11.5: migration timeout is 5 seconds (configurable).
//! If migration doesn't complete within this time, the call fails with
//! END_MIGRATION_FAILED.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::Connection;
use tracing::{debug, error, info, instrument, warn};

use voip_core::proto::signaling::ConnectionMigration;
use voip_core::{NATInfo, VoIPConfig};

use crate::error::MigrationError;
use crate::nat_probe::NATProber;

/// The result of a connection migration attempt.
#[derive(Debug)]
pub enum MigrationResult {
    /// Migration succeeded on the new path
    Success {
        /// New local address after migration
        new_local_addr: SocketAddr,
        /// Whether NAT was re-probed
        nat_reprobed: bool,
        /// Updated NAT info (if re-probed)
        new_nat_info: Option<NATInfo>,
    },
    /// Migration failed — the connection should be considered lost
    Failed(MigrationError),
}

/// Network change event that triggers connection migration.
#[derive(Debug, Clone)]
pub enum NetworkChangeEvent {
    /// WiFi to cellular switch
    WifiToCellular,
    /// Cellular to WiFi switch
    CellularToWifi,
    /// New WiFi network (different SSID/BSSID)
    NewWifiNetwork,
    /// IPv6 prefix change (same network, new prefix)
    Ipv6PrefixChange,
    /// NAT rebinding detected (same network, new external address)
    NatRebinding,
}

impl NetworkChangeEvent {
    /// Whether this event requires NAT re-probing.
    ///
    /// Per spec/04 §4.4: "After connection migration to a new network,
    /// the client re-probes its NAT via QUIC path probing."
    ///
    /// IPv6 prefix changes don't require NAT probing (no NAT for IPv6).
    /// NAT rebinding on the same network may or may not require re-probing
    /// depending on whether the NAT type changed.
    pub fn requires_nat_reprobe(&self) -> bool {
        match self {
            Self::WifiToCellular => true,
            Self::CellularToWifi => true,
            Self::NewWifiNetwork => true,
            Self::Ipv6PrefixChange => false,
            Self::NatRebinding => true,
        }
    }

    /// Whether this event changes the network interface (vs. same interface).
    pub fn changes_interface(&self) -> bool {
        matches!(
            self,
            Self::WifiToCellular
                | Self::CellularToWifi
                | Self::NewWifiNetwork
        )
    }

    /// Human-readable description of the event.
    pub fn description(&self) -> &str {
        match self {
            Self::WifiToCellular => "WiFi → Cellular",
            Self::CellularToWifi => "Cellular → WiFi",
            Self::NewWifiNetwork => "New WiFi network",
            Self::Ipv6PrefixChange => "IPv6 prefix change",
            Self::NatRebinding => "NAT rebinding",
        }
    }
}

/// QUIC connection migration handler.
///
/// Manages the lifecycle of connection migration:
/// 1. Detects network changes
/// 2. Initiates QUIC path migration
/// 3. Re-probes NAT if needed
/// 4. Signals new address information to the peer
/// 5. Handles timeout
pub struct ConnectionMigrator {
    /// Configuration
    config: Arc<VoIPConfig>,
}

impl ConnectionMigrator {
    /// Create a new ConnectionMigrator.
    pub fn new(config: Arc<VoIPConfig>) -> Self {
        Self { config }
    }

    /// Handle a network change event by migrating the QUIC connection.
    ///
    /// Per spec/04 §4.4 and spec/11 §11.5:
    /// - QUIC connection migration: 1 RTT (PATH_CHALLENGE/PATH_RESPONSE)
    /// - Call continues uninterrupted
    /// - For IPv4, re-probe NAT after migration
    /// - Signal new predicted range to peer through existing connection
    ///
    /// # Timeout
    ///
    /// The migration must complete within `migration_path_timeout_ms` (default: 5000ms).
    /// If it doesn't, the call fails with END_MIGRATION_FAILED.
    #[instrument(skip(self, connection, nat_prober), fields(event = %event.description()))]
    pub async fn handle_network_change(
        &self,
        event: NetworkChangeEvent,
        connection: &Connection,
        nat_prober: Option<&NATProber>,
    ) -> MigrationResult {
        info!(
            event = %event.description(),
            requires_reprobe = event.requires_nat_reprobe(),
            "Handling network change event"
        );

        let timeout = Duration::from_millis(self.config.migration_path_timeout_ms);

        // Step 1: Wait for QUIC path migration to complete
        // QUIC connection migration is handled by the QUIC stack (quinn).
        // The connection's remote address changes when migration completes.
        // We wait for the connection to confirm the new path is validated.
        let migration_result = tokio::time::timeout(timeout, async {
            self.wait_for_path_validation(connection).await
        })
        .await;

        match migration_result {
            Ok(Ok(new_local_addr)) => {
                info!(
                    new_addr = %new_local_addr,
                    "QUIC path migration completed"
                );

                // Step 2: Re-probe NAT if required
                let mut new_nat_info: Option<NATInfo> = None;
                let mut nat_reprobed = false;

                if event.requires_nat_reprobe() {
                    if let Some(prober) = nat_prober {
                        info!("Re-probing NAT after network change");
                        prober.invalidate_cache().await;

                        match prober.probe().await {
                            Ok(info) => {
                                info!(
                                    nat_type = ?info.nat_type,
                                    "NAT re-probe completed"
                                );
                                new_nat_info = Some(info);
                                nat_reprobed = true;
                            }
                            Err(e) => {
                                warn!(error = %e, "NAT re-probe failed after migration");
                                // Non-fatal: migration succeeded, NAT info may be stale
                            }
                        }
                    }
                }

                // Step 3: Signal new address to peer
                // Send a ConnectionMigration message on the QUIC stream
                if let Err(e) = self
                    .send_migration_notification(connection, &new_nat_info)
                    .await
                {
                    warn!(error = %e, "Failed to send migration notification to peer");
                    // Non-fatal: the peer will eventually notice the new path
                }

                MigrationResult::Success {
                    new_local_addr,
                    nat_reprobed,
                    new_nat_info,
                }
            }
            Ok(Err(e)) => {
                error!(error = %e, "QUIC path validation failed");
                MigrationResult::Failed(e)
            }
            Err(_) => {
                error!(
                    timeout_ms = self.config.migration_path_timeout_ms,
                    "Connection migration timed out"
                );
                MigrationResult::Failed(MigrationError::Timeout(
                    self.config.migration_path_timeout_ms,
                ))
            }
        }
    }

    /// Wait for QUIC path validation to complete.
    ///
    /// After a network change, the QUIC stack will attempt to validate
    /// the new path using PATH_CHALLENGE/PATH_RESPONSE. We wait for
    /// the local IP to change, which indicates the migration is in progress.
    async fn wait_for_path_validation(
        &self,
        connection: &Connection,
    ) -> Result<SocketAddr, MigrationError> {
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.config.migration_path_timeout_ms);

        // Poll the connection's local address to detect when the path changes.
        // In practice, quinn handles path validation internally. The application
        // can observe the change via the connection statistics or by monitoring
        // the local IP address.
        //
        // For now, we check if the connection is still alive and return
        // the current local address. A full implementation would monitor
        // quinn's path events.
        let mut check_interval = tokio::time::interval(Duration::from_millis(100));

        loop {
            check_interval.tick().await;

            if tokio::time::Instant::now() > deadline {
                return Err(MigrationError::Timeout(
                    self.config.migration_path_timeout_ms,
                ));
            }

            // Check if the connection is still alive
            if connection.close_reason().is_some() {
                return Err(MigrationError::PathValidationFailed(
                    "connection closed during migration".to_string(),
                ));
            }

            // Check the current local address
            // local_ip() returns Option<IpAddr>, but we need a SocketAddr.
            // Use the connection's local_ip and combine with the local port.
            if let Some(local_ip) = connection.local_ip() {
                // Construct a SocketAddr from the local IP.
                // Use port 0 as a placeholder since we can't determine
                // the actual local port from the QUIC connection directly.
                let local_addr = SocketAddr::new(local_ip, 0);
                return Ok(local_addr);
            }

            // Connection has no local IP yet (unusual but possible during migration)
            debug!("Waiting for local IP address during migration");
        }
    }

    /// Send a ConnectionMigration notification to the peer.
    ///
    /// Per spec/08 §8.8, the ConnectionMigration message is sent on the
    /// reliable QUIC stream after migration completes. It contains:
    /// - new_ipv6_addresses: Updated IPv6 addresses
    /// - new_ipv4_reflexive: Updated IPv4 reflexive addresses
    /// - new_prediction: New port prediction if NAT changed
    async fn send_migration_notification(
        &self,
        connection: &Connection,
        new_nat_info: &Option<NATInfo>,
    ) -> Result<(), MigrationError> {
        // Open a bidirectional stream for the notification
        let (mut send, _recv) = connection
            .open_bi()
            .await
            .map_err(|e| MigrationError::PathValidationFailed(e.to_string()))?;

        // Build the ConnectionMigration message
        // Wire format: 2-byte type ID (0x0001 for connection_migration) + prost payload
        let _migration = build_migration_message(new_nat_info);

        // Encode the message
        let type_id: u16 = 0x0001;
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&type_id.to_be_bytes());

        // Encode the prost message
        // In a full implementation, this would use prost::Message::encode
        // For now, we send the type ID as a minimal notification
        send.write_all(&buf)
            .await
            .map_err(|e| MigrationError::PathValidationFailed(e.to_string()))?;

        send.finish()
            .map_err(|e| MigrationError::PathValidationFailed(e.to_string()))?;

        debug!("Migration notification sent to peer");
        Ok(())
    }

    /// Get the migration timeout in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        self.config.migration_path_timeout_ms
    }

    /// Get the maximum number of re-probes during migration.
    pub fn max_reprobes(&self) -> u32 {
        self.config.migration_max_reprobes
    }
}

/// Build a ConnectionMigration message from the new NAT info.
fn build_migration_message(new_nat_info: &Option<NATInfo>) -> ConnectionMigration {
    let new_ipv6_addresses = Vec::new(); // Would be populated from system interfaces
    let new_ipv4_reflexive = Vec::new(); // Would be populated from NAT probe

    let new_prediction = new_nat_info
        .as_ref()
        .and_then(|info| info.prediction.clone())
        .map(|p| {
            let proto_prediction: voip_core::proto::signaling::PortPrediction = p.into();
            proto_prediction
        });

    ConnectionMigration {
        new_ipv6_addresses,
        new_ipv4_reflexive,
        new_prediction,
    }
}

/// Monitor for network changes.
///
/// This module provides platform-specific network change detection.
/// On mobile platforms, this hooks into the OS network change notifications.
/// On desktop, it periodically checks the network interfaces.
pub struct NetworkMonitor {
    /// Last known local addresses
    last_addresses: Vec<SocketAddr>,
    /// Whether monitoring is active
    active: bool,
}

impl NetworkMonitor {
    /// Create a new network monitor.
    pub fn new() -> Self {
        Self {
            last_addresses: Vec::new(),
            active: false,
        }
    }

    /// Start monitoring for network changes.
    pub fn start(&mut self) {
        self.active = true;
        info!("Network monitor started");
    }

    /// Stop monitoring for network changes.
    pub fn stop(&mut self) {
        self.active = false;
        info!("Network monitor stopped");
    }

    /// Check if the network has changed since the last check.
    ///
    /// Returns a list of network change events detected.
    /// In a full implementation, this would:
    /// 1. Query the system's network interfaces
    /// 2. Compare with the previously known addresses
    /// 3. Detect WiFi ↔ cellular switches, IPv6 prefix changes, etc.
    /// 4. Return appropriate NetworkChangeEvent instances
    pub async fn check_for_changes(&mut self) -> Vec<NetworkChangeEvent> {
        if !self.active {
            return Vec::new();
        }

        // In a full implementation, this would check:
        // - WiFi SSID changes
        // - Cellular ↔ WiFi switches
        // - IPv6 prefix changes
        // - NAT rebinding (via QUIC path probing)

        // For now, return an empty list
        Vec::new()
    }

    /// Update the known addresses after a network change.
    pub fn update_addresses(&mut self, addresses: Vec<SocketAddr>) {
        self.last_addresses = addresses;
    }
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Retry logic for connection migration failures.
///
/// Per spec/03 §3.9 and spec/11 §11.5:
/// - Migration timeout: 5 seconds
/// - If migration fails: call fails with END_MIGRATION_FAILED
/// - Auto-retry on network change: re-probe NAT and retry
/// - Scheduled retry: exponential backoff (5s, 15s, 45s)
pub struct MigrationRetryHandler {
    /// Current retry attempt (0-indexed)
    attempt: u32,
    /// Maximum retry attempts
    max_attempts: u32,
    /// Initial delay in seconds
    initial_delay_secs: u64,
    /// Backoff multiplier
    backoff_multiplier: u32,
}

impl MigrationRetryHandler {
    /// Create a new retry handler with the given configuration.
    pub fn new(config: &VoIPConfig) -> Self {
        Self {
            attempt: 0,
            max_attempts: config.push_retry_max_attempts,
            initial_delay_secs: config.push_retry_initial_delay_secs,
            backoff_multiplier: config.push_retry_backoff_multiplier,
        }
    }

    /// Get the delay before the next retry attempt.
    ///
    /// Uses exponential backoff: initial_delay × multiplier^attempt
    /// E.g., 5s, 15s, 45s for initial_delay=5, multiplier=3
    pub fn next_delay(&self) -> Option<Duration> {
        if self.attempt >= self.max_attempts {
            return None;
        }

        let delay_secs = self.initial_delay_secs
            * (self.backoff_multiplier as u64).pow(self.attempt);
        Some(Duration::from_secs(delay_secs))
    }

    /// Record a retry attempt.
    pub fn record_attempt(&mut self) {
        self.attempt += 1;
    }

    /// Whether retries are exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.attempt >= self.max_attempts
    }

    /// Reset the retry counter.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Get the current attempt number (1-indexed).
    pub fn current_attempt(&self) -> u32 {
        self.attempt
    }
}
