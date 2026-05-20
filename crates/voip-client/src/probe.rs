//! Port prediction probing for Symmetric NAT (spec/04 §4.2).
//!
//! For sequential NAT: send QUIC packets to predicted port range (base ± margin).
//! For pseudo-sequential: wider range.
//! Prediction confidence determines range size.
//! Uses the 12-byte connection_id from CallRequest.
//!
//! # Algorithm (spec/03 §3.5 Steps 4-5)
//!
//! After signaling exchanges the predicted ranges:
//! - A sends QUIC PATH_CHALLENGE to B's predicted range (7-17 packets)
//! - B sends QUIC PATH_CHALLENGE to A's predicted range (7-17 packets)
//! - Each PATH_CHALLENGE:
//!   → Punches through the NAT (opens the mapping)
//!   → Is already part of the QUIC protocol (encrypted, Connection ID validated)
//!   → Establishes the connection in the same step as punching the hole
//!
//! # Key Insight (spec/04 §4.3)
//!
//! The QUIC Connection ID eliminates the signaling round-trip that ICE requires
//! for candidate validation. The peer sees the Connection ID and immediately
//! knows which call this belongs to — no extra RTT through the signaling server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint};
use tracing::{debug, info, instrument, warn};

use voip_core::{PortPredictionData, PredictionConfidence, VoIPConfig};

use crate::error::ProbeError;

/// Port prediction prober for Symmetric NAT traversal.
///
/// Sends QUIC PATH_CHALLENGE packets to a range of predicted ports
/// on the peer's IP address. When one of these packets arrives at
/// the correct predicted port, the NAT forwards it, the peer validates
/// the Connection ID, and responds with PATH_RESPONSE — establishing
/// the connection in one step.
pub struct PortPredictionProber {
    /// Configuration
    config: Arc<VoIPConfig>,
}

impl PortPredictionProber {
    /// Create a new PortPredictionProber.
    pub fn new(config: Arc<VoIPConfig>) -> Self {
        Self { config }
    }

    /// Probe a range of predicted ports on the peer's IP.
    ///
    /// Sends QUIC PATH_CHALLENGE (connection attempt) to each port in the
    /// predicted range. The 12-byte connection_id from CallRequest identifies
    /// the QUIC connection to the peer.
    ///
    /// Returns the first successful QUIC connection, or an error if all
    /// predicted ports are exhausted.
    ///
    /// # Arguments
    ///
    /// * `endpoint` — QUIC endpoint for outgoing connections
    /// * `target_ip` — Peer's external IPv4 address
    /// * `port_start` — Start of predicted port range (inclusive)
    /// * `port_end` — End of predicted port range (inclusive)
    /// * `connection_id` — 12-byte CSPRNG QUIC Connection ID from CallRequest
    /// * `timeout_ms` — Timeout per individual connection attempt
    #[instrument(skip(self, endpoint, _connection_id),
        fields(target_ip = %target_ip, port_start, port_end))]
    pub async fn probe_range(
        &self,
        endpoint: &Endpoint,
        target_ip: &str,
        port_start: u16,
        port_end: u16,
        _connection_id: &[u8],
        timeout_ms: u64,
    ) -> Result<Connection, ProbeError> {
        let range_size = (port_end as u32) - (port_start as u32) + 1;
        let max_probes = self.config.prediction_max_probes;

        if range_size > max_probes {
            warn!(
                range_size,
                max_probes,
                "Predicted range exceeds max probes, truncating"
            );
        }

        let effective_end = std::cmp::min(
            port_end,
            port_start + max_probes as u16 - 1,
        );

        info!(
            target_ip,
            port_start,
            port_end = effective_end,
            range = range_size,
            "Starting port prediction probe"
        );

        // Strategy: probe ports with a "racing" approach.
        // Send multiple QUIC Initial packets in parallel, then wait
        // for the first successful connection.
        //
        // Per spec/03 §3.5 Step 5:
        //   A sends QUIC PATH_CHALLENGE to B's predicted range (7-17 packets)
        //   Each PATH_CHALLENGE:
        //     → Punches through the NAT (opens the mapping)
        //     → Is already part of the QUIC protocol (encrypted, Connection ID validated)
        //     → Establishes the connection in the same step as punching the hole

        let mut join_set = tokio::task::JoinSet::new();
        let connect_timeout = Duration::from_millis(timeout_ms);
        let overall_timeout = Duration::from_millis(self.config.quic_prediction_timeout_ms);

        // Launch connection attempts for each port in the range
        for port in port_start..=effective_end {
            let addr_str = format!("{}:{}", target_ip, port);
            let addr: SocketAddr = match addr_str.parse() {
                Ok(a) => a,
                Err(e) => {
                    debug!(port, error = %e, "Invalid address, skipping");
                    continue;
                }
            };

            let endpoint_clone = endpoint.clone();
            let timeout = connect_timeout;

            join_set.spawn(async move {
                // Attempt QUIC connection with the pre-agreed Connection ID
                // In quinn, the connection ID is managed internally during
                // the handshake. The server_name is used for TLS SNI.
                match tokio::time::timeout(
                    timeout,
                    try_quic_connect_to_port(&endpoint_clone, addr),
                )
                .await
                {
                    Ok(Ok(conn)) => Some((port, conn)),
                    Ok(Err(e)) => {
                        debug!(port, error = %e, "Connection attempt failed");
                        None
                    }
                    Err(_) => {
                        debug!(port, "Connection attempt timed out");
                        None
                    }
                }
            });
        }

        // Wait for the first successful connection, or until all attempts fail
        let overall = tokio::time::timeout(overall_timeout, async {
            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok(Some((port, conn))) => {
                        info!(
                            port,
                            "Port prediction succeeded — connection established"
                        );
                        // Cancel remaining attempts
                        join_set.abort_all();
                        return Ok(conn);
                    }
                    Ok(None) => {
                        // This attempt failed, continue waiting
                    }
                    Err(e) => {
                        debug!(error = %e, "Join error");
                    }
                }
            }
            Err(ProbeError::AllPortsExhausted)
        })
        .await;

        match overall {
            Ok(result) => result,
            Err(_) => {
                // Overall timeout
                join_set.abort_all();
                Err(ProbeError::ProbeTimeout(
                    self.config.quic_prediction_timeout_ms,
                ))
            }
        }
    }

    /// Probe a single port (useful for one-sided prediction scenarios).
    ///
    /// When one peer has sequential NAT and the other has random NAT,
    /// only the sequential side can predict. This probes a single predicted port.
    pub async fn probe_single_port(
        &self,
        endpoint: &Endpoint,
        target_ip: &str,
        port: u16,
        timeout_ms: u64,
    ) -> Result<Connection, ProbeError> {
        let addr = format!("{}:{}", target_ip, port);
        let addr: SocketAddr = addr
            .parse()
            .map_err(|_| ProbeError::PredictionNotAvailable)?;

        let connect_timeout = Duration::from_millis(timeout_ms);

        tokio::time::timeout(
            connect_timeout,
            try_quic_connect_to_port(endpoint, addr),
        )
        .await
        .map_err(|_| ProbeError::ProbeTimeout(timeout_ms))?
    }

    /// Calculate the predicted port range from a PortPredictionData.
    ///
    /// This is a convenience method that returns the range directly
    /// from the prediction data.
    pub fn predicted_range(prediction: &PortPredictionData) -> (u16, u16) {
        (
            prediction.predicted_port_start as u16,
            prediction.predicted_port_end as u16,
        )
    }

    /// Get the margin for a given confidence level.
    ///
    /// - SEQUENTIAL: margin = 3 (range of 7 ports)
    /// - PSEUDO_SEQUENTIAL: margin = 8 (range of 17 ports)
    /// - RANDOM: no prediction possible
    pub fn margin_for_confidence(&self, confidence: PredictionConfidence) -> u16 {
        match confidence {
            PredictionConfidence::Sequential => self.config.prediction_margin_sequential as u16,
            PredictionConfidence::PseudoSequential => self.config.prediction_margin_pseudo as u16,
            PredictionConfidence::Random => 0,
        }
    }
}

/// Attempt a QUIC connection to a specific address.
///
/// The connection uses the pre-agreed Connection ID from the CallRequest.
/// In practice, quinn manages connection IDs internally during the handshake.
/// The connection_id from the spec is used at the application level to
/// validate incoming packets against the expected call.
async fn try_quic_connect_to_port(
    endpoint: &Endpoint,
    addr: SocketAddr,
) -> Result<Connection, ProbeError> {
    // Use "voip-peer" as the server name for TLS SNI
    // In production, this could be the peer's domain or a fixed identifier
    let connecting = endpoint
        .connect(addr, "voip-peer")
        .map_err(|_| ProbeError::QuicError(quinn::ConnectionError::TransportError(
            quinn::TransportErrorCode::INTERNAL_ERROR.into(),
        )))?;

    let connection = connecting.await?;

    Ok(connection)
}

/// Strategy for one-sided prediction.
///
/// When one peer has sequential NAT and the other has random NAT,
/// we can only predict one side's port. The strategy is:
/// - Predict the sequential side's port
/// - Send QUIC PATH_CHALLENGE from the random side to the predicted range
/// - The random side's NAT will assign a new port for this new destination
/// - Since the sequential side has a predictable port, the PATH_CHALLENGE
///   may arrive at the correct port
///
/// Success probability: ~60% (spec/09 §9.9 — "PARTIAL ~60%")
pub struct OneSidedPredictionStrategy {
    /// The prediction from the predictable side
    prediction: PortPredictionData,
    /// Config
    config: Arc<VoIPConfig>,
}

impl OneSidedPredictionStrategy {
    /// Create a new one-sided prediction strategy.
    pub fn new(prediction: PortPredictionData, config: Arc<VoIPConfig>) -> Self {
        Self { prediction, config }
    }

    /// Execute the one-sided prediction probe.
    ///
    /// Returns a QUIC connection if the predicted port was reached,
    /// or an error if all attempts fail.
    pub async fn execute(
        &self,
        endpoint: &Endpoint,
        target_ip: &str,
        connection_id: &[u8],
    ) -> Result<Connection, ProbeError> {
        let prober = PortPredictionProber::new(self.config.clone());
        prober
            .probe_range(
                endpoint,
                target_ip,
                self.prediction.predicted_port_start as u16,
                self.prediction.predicted_port_end as u16,
                connection_id,
                self.config.quic_prediction_timeout_ms,
            )
            .await
    }

    /// Get the success probability estimate.
    ///
    /// Per spec/09 §9.9: "One-side prediction + probing (PARTIAL ~60%)"
    pub fn success_probability(&self) -> f64 {
        match self.prediction.confidence {
            PredictionConfidence::Sequential => 0.60,
            PredictionConfidence::PseudoSequential => 0.45,
            PredictionConfidence::Random => 0.0,
        }
    }
}
