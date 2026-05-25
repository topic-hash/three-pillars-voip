//! QUIC path probing module for NAT classification.
//!
//! Replaces STUN entirely per spec/03. Uses QUIC connection migration
//! to the signaling server's 5 elastic IPs to classify the local NAT.
//!
//! # Algorithm (spec/03 §3.5)
//!
//! 1. Client already has QUIC connection to signaling server.
//! 2. For each of the 5 server IPs, migrate the QUIC connection (PATH_CHALLENGE on new path).
//! 3. Server sees client's source IP:port and reflects it back on the QUIC stream.
//! 4. Compare observed ports across all 5 probes.
//! 5. If all same → Cone NAT. If delta is constant → Sequential. If delta varies
//!    but bounded → PseudoSequential. If random → Random.
//!
//! # Caching
//!
//! Results are cached with a TTL of 5 minutes (default). Before a call,
//! a quick 2-path refresh can verify the pattern is still valid.

use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::Connection;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, instrument};

use voip_core::{
    NATInfo, NATType, PortPredictionData, PredictionConfidence, VoIPConfig,
};

use crate::error::NatProbeError;

/// Result of a single NAT path probe.
#[derive(Debug, Clone)]
pub struct NATProbeResult {
    /// The signaling server IP that was probed
    pub server_ip: String,
    /// Local port used for the probe
    pub local_port: u16,
    /// The external IP observed by the server
    pub external_ip: String,
    /// The external port observed by the server
    pub external_port: u16,
    /// When the probe was performed (unix timestamp, milliseconds)
    pub timestamp_ms: u64,
    /// Round-trip time of the probe in milliseconds
    pub rtt_ms: u32,
}

/// Cached NAT probe results.
#[derive(Debug, Clone)]
pub struct NATProbeCache {
    /// Individual probe results
    pub probes: Vec<NATProbeResult>,
    /// Average port delta between probes
    pub average_delta: i32,
    /// Variance of port deltas
    pub delta_variance: i32,
    /// Prediction confidence level
    pub confidence: PredictionConfidence,
    /// When the cache was created (unix timestamp, milliseconds)
    pub cache_timestamp: u64,
    /// Cache TTL in seconds
    pub cache_ttl_seconds: u32,
}

/// The NAT prober that connects to the signaling server's IPs via QUIC
/// connection migration to classify the local NAT type.
pub struct NATProber {
    /// QUIC connection to the signaling server (primary IP)
    connection: Connection,
    /// Configuration
    config: Arc<VoIPConfig>,
    /// Cached probe results
    cache: Arc<RwLock<Option<NATProbeCache>>>,
    /// Whether UDP appears to be blocked
    udp_blocked: bool,
}

impl NATProber {
    /// Create a new NATProber with an existing QUIC connection to the signaling server.
    pub fn new(connection: Connection, config: Arc<VoIPConfig>) -> Self {
        Self {
            connection,
            config,
            cache: Arc::new(RwLock::new(None)),
            udp_blocked: false,
        }
    }

    /// Check whether UDP appears to be blocked.
    pub fn is_udp_blocked(&self) -> bool {
        self.udp_blocked
    }

    /// Mark UDP as blocked (detected externally, e.g. QUIC handshake failure).
    pub fn set_udp_blocked(&mut self, blocked: bool) {
        self.udp_blocked = blocked;
    }

    /// Get cached NAT info if still valid, or None.
    pub async fn cached_nat_info(&self) -> Option<NATInfo> {
        let cache = self.cache.read().await;
        cache.as_ref().and_then(|c| {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            let age_ms = now_ms.saturating_sub(c.cache_timestamp);
            let ttl_ms = c.cache_ttl_seconds as u64 * 1000;

            if age_ms < ttl_ms {
                Some(cached_to_nat_info(c))
            } else {
                None
            }
        })
    }

    /// Perform full 5-path QUIC probe and classify NAT type.
    ///
    /// This is the main entry point. It:
    /// 1. Migrates QUIC connection to each of the signaling server's IPs
    /// 2. Collects observed IP:port from each migration
    /// 3. Classifies NAT type based on port deltas
    /// 4. Caches results
    ///
    /// Cost: ~50ms (5 QUIC path migrations + 5 application messages)
    #[instrument(skip(self), fields(server_ips = ?self.config.signaling_server_ips))]
    pub async fn probe(&self) -> Result<NATInfo, NatProbeError> {
        let server_ips = &self.config.signaling_server_ips;
        let probe_count = self.config.path_probe_count as usize;
        let ips_to_probe = &server_ips[..probe_count.min(server_ips.len())];

        if ips_to_probe.is_empty() {
            return Err(NatProbeError::NotConnected);
        }

        let mut results: Vec<NATProbeResult> = Vec::with_capacity(ips_to_probe.len());

        // Step 1: PROBE — Migrate to each server IP and collect observed addresses
        for (i, server_ip) in ips_to_probe.iter().enumerate() {
            match self.probe_single_path(server_ip, i).await {
                Ok(result) => {
                    debug!(
                        server_ip = %server_ip,
                        observed_ip = %result.external_ip,
                        observed_port = result.external_port,
                        rtt_ms = result.rtt_ms,
                        "Path probe completed"
                    );
                    results.push(result);
                }
                Err(e) => {
                    warn!(
                        server_ip = %server_ip,
                        error = %e,
                        "Path probe failed, continuing with remaining IPs"
                    );
                    // Continue with remaining IPs; we need at least 3 successful probes
                }
            }
        }

        if results.len() < 3 {
            return Err(NatProbeError::InsufficientProbes {
                got: results.len(),
                need: 3,
            });
        }

        // Step 2: ANALYZE — Classify NAT type based on port deltas
        let nat_info = Self::classify_nat(&results, &self.config);

        // Step 3: CACHE — Store results for future use
        let cache = Self::build_cache(&results, &nat_info, &self.config);
        *self.cache.write().await = Some(cache);

        info!(
            nat_type = ?nat_info.nat_type,
            has_prediction = nat_info.prediction.is_some(),
            "NAT classification complete"
        );

        Ok(nat_info)
    }

    /// Quick refresh: probe 2 paths to verify cached pattern is still valid.
    ///
    /// Per spec/07 §7.3.3, a quick 2-path refresh is done before a call
    /// when the cache exists but is approaching TTL expiry.
    pub async fn quick_refresh(&self) -> Result<NATInfo, NatProbeError> {
        let server_ips = &self.config.signaling_server_ips;
        let refresh_count = self.config.path_refresh_count as usize;
        let ips_to_probe = &server_ips[..refresh_count.min(server_ips.len())];

        if ips_to_probe.is_empty() {
            // Fall back to full probe
            return self.probe().await;
        }

        let mut results: Vec<NATProbeResult> = Vec::with_capacity(ips_to_probe.len());
        for (i, server_ip) in ips_to_probe.iter().enumerate() {
            match self.probe_single_path(server_ip, i).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!(server_ip = %server_ip, error = %e, "Refresh probe failed");
                }
            }
        }

        if results.len() < 2 {
            return self.probe().await;
        }

        // Check if the pattern is consistent with the cached prediction
        let cached = self.cache.read().await;
        if let Some(ref cache) = *cached {
            let ports: Vec<u16> = results.iter().map(|r| r.external_port).collect();
            let deltas: Vec<i32> = ports
                .windows(2)
                .map(|w| w[1] as i32 - w[0] as i32)
                .collect();

            if !deltas.is_empty() {
                let avg_delta = deltas.iter().sum::<i32>() / deltas.len() as i32;
                let delta_diff = (avg_delta - cache.average_delta).abs();

                if delta_diff <= self.config.nat_delta_variance_threshold as i32 {
                    // Pattern still valid — extend cache TTL
                    drop(cached);
                    let mut cache_mut = self.cache.write().await;
                    if let Some(ref mut c) = *cache_mut {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        c.cache_timestamp = now_ms;
                    }
                    return Ok(match self.cached_nat_info().await {
                        Some(info) => info,
                        None => {
                            drop(cache_mut);
                            self.probe().await.unwrap_or_else(|_| NATInfo::no_nat())
                        }
                    });
                }
            }
        }
        drop(cached);

        // Pattern changed or no cache — do full probe
        info!("NAT pattern changed during refresh, performing full re-probe");
        self.probe().await
    }

    /// Probe a single server IP via QUIC connection migration.
    ///
    /// 1. Initiates QUIC path migration to the target server IP
    /// 2. Sends a PathProbeRequest on the QUIC stream
    /// 3. Reads PathProbeResponse with observed IP:port
    async fn probe_single_path(
        &self,
        server_ip: &str,
        _index: usize,
    ) -> Result<NATProbeResult, NatProbeError> {
        let start = Instant::now();
        let timeout = Duration::from_millis(self.config.path_probe_timeout_ms);

        // Open a new bidirectional QUIC stream for the probe
        let (mut send, mut recv) = tokio::time::timeout(timeout, self.connection.open_bi())
            .await
            .map_err(|_| NatProbeError::ProbeTimeout(server_ip.to_string()))?
            .map_err(|e| NatProbeError::MigrationFailed {
                ip: server_ip.to_string(),
                reason: e.to_string(),
            })?;

        // Send probe request: 2-byte type (0x0200) + empty payload
        // The server will see our source address from the path migration
        let type_id: u16 = 0x0200; // PathProbeRequest type ID
        send.write_all(&type_id.to_be_bytes())
            .await
            .map_err(|e| NatProbeError::MigrationFailed {
                ip: server_ip.to_string(),
                reason: e.to_string(),
            })?;

        // Read the PathProbeResponse
        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(timeout, recv.read(&mut buf))
            .await
            .map_err(|_| NatProbeError::ProbeTimeout(server_ip.to_string()))?
            .map_err(|e| NatProbeError::MigrationFailed {
                ip: server_ip.to_string(),
                reason: e.to_string(),
            })?
            .unwrap_or(0);

        if n < 2 {
            return Err(NatProbeError::MigrationFailed {
                ip: server_ip.to_string(),
                reason: "response too short".to_string(),
            });
        }

        let rtt = start.elapsed();
        let rtt_ms = rtt.as_millis() as u32;

        // Parse the response — expect: 2-byte type + prost-encoded PathProbeResponse
        // For now, parse the raw prost payload after the 2-byte type prefix
        let response_type = u16::from_be_bytes([buf[0], buf[1]]);
        if response_type != 0x0200 {
            return Err(NatProbeError::MigrationFailed {
                ip: server_ip.to_string(),
                reason: format!("unexpected response type: 0x{:04x}", response_type),
            });
        }

        // Decode PathProbeResponse from prost
        // Fields: server_ip (1), observed_ip (2), observed_port (3), timestamp_ms (4)
        let probe_response = parse_path_probe_response(&buf[2..n]);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Ok(NATProbeResult {
            server_ip: server_ip.to_string(),
            local_port: self.connection.local_ip()
                .map(|_| 0) // Can't get actual local port from IpAddr
                .unwrap_or(0),
            external_ip: probe_response.observed_ip,
            external_port: probe_response.observed_port,
            timestamp_ms: now_ms,
            rtt_ms,
        })
    }

    /// Classify NAT type based on the probe results.
    ///
    /// Algorithm from spec/03 §3.5 Step 2:
    /// - Compute deltas: external_port[i+1] - external_port[i]
    /// - If all ports are the same → Cone NAT
    /// - If deltas are constant (e.g., all +1) → Sequential
    /// - If deltas are bounded (e.g., +1 to +5) → PseudoSequential
    /// - If deltas are random → Random
    fn classify_nat(results: &[NATProbeResult], config: &VoIPConfig) -> NATInfo {
        if results.is_empty() {
            return NATInfo {
                nat_type: NATType::None,
                prediction: None,
            };
        }

        // Check if IPv6 (external_ip contains ':')
        let is_ipv6 = results[0].external_ip.contains(':');
        if is_ipv6 {
            return NATInfo {
                nat_type: NATType::None,
                prediction: None,
            };
        }

        // Collect all observed ports
        let ports: Vec<u16> = results.iter().map(|r| r.external_port).collect();

        // Check if all ports are the same → Cone NAT
        let all_same = ports.windows(2).all(|w| w[0] == w[1]);
        if all_same {
            return NATInfo {
                nat_type: NATType::Cone,
                prediction: None,
            };
        }

        // Compute deltas between consecutive probes
        let deltas: Vec<i32> = ports
            .windows(2)
            .map(|w| w[1] as i32 - w[0] as i32)
            .collect();

        if deltas.is_empty() {
            return NATInfo {
                nat_type: NATType::SymmetricRandom,
                prediction: None,
            };
        }

        // Compute statistics
        let avg_delta = deltas.iter().sum::<i32>() / deltas.len() as i32;
        let variance = if deltas.len() > 1 {
            let mean = avg_delta as f64;
            let variance: f64 = deltas
                .iter()
                .map(|d| (*d as f64 - mean).powi(2))
                .sum::<f64>()
                / (deltas.len() - 1) as f64;
            variance.sqrt() as i32
        } else {
            0
        };

        let threshold = config.nat_delta_variance_threshold as i32;

        // Classify based on delta variance
        let (nat_type, confidence) = if variance == 0 || variance <= threshold {
            // Constant or near-constant deltas → Sequential
            (NATType::SymmetricSequential, PredictionConfidence::Sequential)
        } else if variance <= (threshold * 3) {
            // Bounded variance → PseudoSequential
            (NATType::SymmetricPseudo, PredictionConfidence::PseudoSequential)
        } else {
            // Random → prediction fails
            (NATType::SymmetricRandom, PredictionConfidence::Random)
        };

        // Build prediction if not random
        let prediction = if confidence != PredictionConfidence::Random {
            Some(Self::compute_prediction(results, avg_delta, &confidence, config))
        } else {
            None
        };

        NATInfo {
            nat_type,
            prediction,
        }
    }

    /// Compute port prediction from probe results.
    ///
    /// Algorithm from spec/03 §3.5 Step 3:
    /// - predicted_port = last_known_port + (delta_pattern × estimated_new_mappings)
    /// - estimated_new_mappings = typically 0-3 for a VoIP app
    /// - Signal a RANGE: predicted_port ± margin
    ///   - margin = 3 for SEQUENTIAL (range of 7 ports)
    ///   - margin = 8 for PSEUDO_SEQUENTIAL (range of 17 ports)
    fn compute_prediction(
        results: &[NATProbeResult],
        avg_delta: i32,
        confidence: &PredictionConfidence,
        config: &VoIPConfig,
    ) -> PortPredictionData {
        let last_result = results.last().expect("at least one probe result");
        let base_port = last_result.external_port as u32;

        // Estimate new mappings between probe and call (typically 0-3)
        // We estimate 1 mapping for the next connection
        let estimated_new_mappings: i32 = 1;
        let predicted_center = (base_port as i32) + (avg_delta * estimated_new_mappings);

        let margin = match confidence {
            PredictionConfidence::Sequential => config.prediction_margin_sequential as i32,
            PredictionConfidence::PseudoSequential => config.prediction_margin_pseudo as i32,
            PredictionConfidence::Random => 0, // Should not be called for Random
        };

        let start = (predicted_center - margin).max(1024) as u32;
        let end = (predicted_center + margin).min(65535) as u32;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        PortPredictionData {
            external_ip: last_result.external_ip.clone(),
            predicted_port_start: start,
            predicted_port_end: end,
            confidence: *confidence,
            base_port,
            delta_pattern: avg_delta,
            probed_at: now_secs,
            probe_method: voip_core::ProbeMethod::QuicPathProbing,
        }
    }

    /// Build the NATProbeCache from results and classification.
    fn build_cache(
        results: &[NATProbeResult],
        nat_info: &NATInfo,
        config: &VoIPConfig,
    ) -> NATProbeCache {
        let ports: Vec<u16> = results.iter().map(|r| r.external_port).collect();
        let deltas: Vec<i32> = ports
            .windows(2)
            .map(|w| w[1] as i32 - w[0] as i32)
            .collect();

        let avg_delta = if deltas.is_empty() {
            0
        } else {
            deltas.iter().sum::<i32>() / deltas.len() as i32
        };

        let variance = if deltas.len() > 1 {
            let mean = avg_delta as f64;
            let v: f64 = deltas
                .iter()
                .map(|d| (*d as f64 - mean).powi(2))
                .sum::<f64>()
                / (deltas.len() - 1) as f64;
            v.sqrt() as i32
        } else {
            0
        };

        let confidence = nat_info
            .prediction
            .as_ref()
            .map(|p| p.confidence)
            .unwrap_or(PredictionConfidence::Random);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        NATProbeCache {
            probes: results.to_vec(),
            average_delta: avg_delta,
            delta_variance: variance,
            confidence,
            cache_timestamp: now_ms,
            cache_ttl_seconds: config.nat_cache_ttl_secs as u32,
        }
    }

    /// Invalidate the cache (e.g., on network change).
    pub async fn invalidate_cache(&self) {
        *self.cache.write().await = None;
        info!("NAT probe cache invalidated");
    }

    /// Check if the cache has valid data.
    pub async fn has_valid_cache(&self) -> bool {
        self.cached_nat_info().await.is_some()
    }
}

/// Minimal parsed path probe response.
struct ParsedProbeResponse {
    observed_ip: String,
    observed_port: u16,
}

/// Parse a prost-encoded PathProbeResponse.
///
/// Wire format: field 1 (server_ip, string), field 2 (observed_ip, string),
/// field 3 (observed_port, uint32), field 4 (timestamp_ms, uint64).
fn parse_path_probe_response(data: &[u8]) -> ParsedProbeResponse {
    let mut observed_ip = String::new();
    let mut observed_port: u32 = 0;

    let mut pos = 0;
    while pos < data.len() {
        // Read varint key (field_number << 3 | wire_type)
        let (key, key_len) = decode_varint(&data[pos..]);
        pos += key_len;

        let field_number = (key >> 3) as u32;
        let wire_type = (key & 0x07) as u8;

        match (field_number, wire_type) {
            (1, 2) => {
                // Length-delimited: server_ip (string) — skip
                let (len, len_size) = decode_varint(&data[pos..]);
                pos += len_size + len as usize;
            }
            (2, 2) => {
                // Length-delimited: observed_ip (string)
                let (len, len_size) = decode_varint(&data[pos..]);
                pos += len_size;
                let end = pos + len as usize;
                if end <= data.len() {
                    observed_ip = String::from_utf8_lossy(&data[pos..end]).to_string();
                }
                pos = end;
            }
            (3, 0) => {
                // Varint: observed_port (uint32)
                let (val, val_len) = decode_varint(&data[pos..]);
                observed_port = val as u32;
                pos += val_len;
            }
            (4, 0) => {
                // Varint: timestamp_ms (uint64) — skip
                let (_, val_len) = decode_varint(&data[pos..]);
                pos += val_len;
            }
            _ => {
                // Skip unknown field
                match wire_type {
                    0 => {
                        let (_, val_len) = decode_varint(&data[pos..]);
                        pos += val_len;
                    }
                    2 => {
                        let (len, len_size) = decode_varint(&data[pos..]);
                        pos += len_size + len as usize;
                    }
                    1 => pos += 8,
                    5 => pos += 4,
                    _ => break, // Unknown wire type, stop parsing
                }
            }
        }
    }

    ParsedProbeResponse {
        observed_ip,
        observed_port: observed_port as u16,
    }
}

/// Decode a protobuf varint from the start of a byte slice.
/// Returns (value, bytes_consumed).
fn decode_varint(data: &[u8]) -> (u64, usize) {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;

    for &byte in data.iter() {
        value |= ((byte & 0x7F) as u64) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            break;
        }
    }

    (value, i)
}

/// Convert a NATProbeCache into a NATInfo for external consumption.
fn cached_to_nat_info(cache: &NATProbeCache) -> NATInfo {
    let nat_type = match cache.confidence {
        PredictionConfidence::Sequential => NATType::SymmetricSequential,
        PredictionConfidence::PseudoSequential => NATType::SymmetricPseudo,
        PredictionConfidence::Random => NATType::SymmetricRandom,
    };

    // Check if all ports are the same (Cone NAT)
    let ports: Vec<u16> = cache.probes.iter().map(|p| p.external_port).collect();
    let all_same = ports.windows(2).all(|w| w[0] == w[1]);

    let (nat_type, prediction) = if all_same {
        (NATType::Cone, None)
    } else if cache.confidence == PredictionConfidence::Random {
        (NATType::SymmetricRandom, None)
    } else {
        let last = cache.probes.last();
        let prediction = last.map(|l| {
            let margin = match cache.confidence {
                PredictionConfidence::Sequential => 3u32,
                PredictionConfidence::PseudoSequential => 8u32,
                PredictionConfidence::Random => 0,
            };
            let predicted_center = l.external_port as i32 + cache.average_delta;
            let start = (predicted_center - margin as i32).max(1024) as u32;
            let end = (predicted_center + margin as i32).min(65535) as u32;

            PortPredictionData {
                external_ip: l.external_ip.clone(),
                predicted_port_start: start,
                predicted_port_end: end,
                confidence: cache.confidence,
                base_port: l.external_port as u32,
                delta_pattern: cache.average_delta,
                probed_at: l.timestamp_ms / 1000,
                probe_method: voip_core::ProbeMethod::QuicPathProbing,
            }
        });
        (nat_type, prediction)
    };

    NATInfo {
        nat_type,
        prediction,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_varint() {
        assert_eq!(decode_varint(&[0x00]), (0, 1));
        assert_eq!(decode_varint(&[0x01]), (1, 1));
        assert_eq!(decode_varint(&[0x7F]), (127, 1));
        assert_eq!(decode_varint(&[0x80, 0x01]), (128, 2));
    }

    #[test]
    fn test_classify_nat_cone() {
        let results = vec![
            make_probe_result("1.2.3.4", 42000),
            make_probe_result("1.2.3.5", 42000),
            make_probe_result("1.2.3.6", 42000),
            make_probe_result("1.2.3.7", 42000),
            make_probe_result("1.2.3.8", 42000),
        ];
        let config = VoIPConfig::default();
        let nat_info = NATProber::classify_nat(&results, &config);
        assert_eq!(nat_info.nat_type, NATType::Cone);
        assert!(nat_info.prediction.is_none());
    }

    #[test]
    fn test_classify_nat_sequential() {
        let results = vec![
            make_probe_result("1.2.3.4", 42000),
            make_probe_result("1.2.3.5", 42001),
            make_probe_result("1.2.3.6", 42002),
            make_probe_result("1.2.3.7", 42003),
            make_probe_result("1.2.3.8", 42004),
        ];
        let config = VoIPConfig::default();
        let nat_info = NATProber::classify_nat(&results, &config);
        assert_eq!(nat_info.nat_type, NATType::SymmetricSequential);
        assert!(nat_info.prediction.is_some());
        let pred = nat_info.prediction.unwrap();
        assert_eq!(pred.confidence, PredictionConfidence::Sequential);
        assert_eq!(pred.delta_pattern, 1);
    }

    #[test]
    fn test_classify_nat_random() {
        let results = vec![
            make_probe_result("1.2.3.4", 42000),
            make_probe_result("1.2.3.5", 42347),
            make_probe_result("1.2.3.6", 38956),
            make_probe_result("1.2.3.7", 51234),
            make_probe_result("1.2.3.8", 40001),
        ];
        let config = VoIPConfig::default();
        let nat_info = NATProber::classify_nat(&results, &config);
        assert_eq!(nat_info.nat_type, NATType::SymmetricRandom);
        assert!(nat_info.prediction.is_none());
    }

    #[test]
    fn test_port_prediction_range_sequential() {
        let pred = PortPredictionData {
            external_ip: "203.0.113.5".to_string(),
            predicted_port_start: 42002,
            predicted_port_end: 42008,
            confidence: PredictionConfidence::Sequential,
            base_port: 42004,
            delta_pattern: 1,
            probed_at: 0,
            probe_method: voip_core::ProbeMethod::QuicPathProbing,
        };
        assert_eq!(pred.range_size(), 7); // ±3 = 7 ports
    }

    #[test]
    fn test_port_prediction_range_pseudo() {
        let pred = PortPredictionData {
            external_ip: "203.0.113.5".to_string(),
            predicted_port_start: 41997,
            predicted_port_end: 42013,
            confidence: PredictionConfidence::PseudoSequential,
            base_port: 42005,
            delta_pattern: 2,
            probed_at: 0,
            probe_method: voip_core::ProbeMethod::QuicPathProbing,
        };
        assert_eq!(pred.range_size(), 17); // ±8 = 17 ports
    }

    fn make_probe_result(server_ip: &str, external_port: u16) -> NATProbeResult {
        NATProbeResult {
            server_ip: server_ip.to_string(),
            local_port: 5000,
            external_ip: "203.0.113.5".to_string(),
            external_port,
            timestamp_ms: 0,
            rtt_ms: 10,
        }
    }
}
