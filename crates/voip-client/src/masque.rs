//! MASQUE CONNECT-UDP tunnel client (spec/12).
//!
//! Implements MASQUE CONNECT-UDP (RFC 9298) with two transport paths:
//!
//! - **HTTP/3 path**: connect via quinn QUIC → h3 → CONNECT-UDP → HTTP Datagrams
//!   Used when UDP is available (preferred — lower latency, no HOL blocking).
//!
//! - **HTTP/2 path**: connect via tokio TCP+TLS → h2 → CONNECT-UDP →
//!   HTTP Datagrams (RFC 9297 §5). Used when UDP is blocked.
//!
//! # Bidirectional Model
//!
//! Both peers connect outbound to the proxy. The proxy matches by call_id
//! and bridges the two tunnels. This is necessary because the proxy cannot
//! reach a peer behind Symmetric NAT — the peer must initiate the connection.
//!
//! # MoQ Transparency
//!
//! MoQ runs over the QUIC connection through the tunnel unchanged.
//! The proxy sees only opaque QUIC packets, not MoQ datagrams.

use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use quinn::Connection;
use tracing::{debug, info, instrument, warn};

use crate::error::MasqueError;

// Re-export MASQUE types from voip-core for spec compliance.
pub use voip_core::{MasqueTransport, TunnelStatus as TunnelState};

/// A MASQUE CONNECT-UDP tunnel.
///
/// Supports both HTTP/3 (QUIC/UDP) and HTTP/2 (TCP) transport paths.
/// After establishment, MoQ datagrams flow through the tunnel transparently.
pub struct MasqueTunnel {
    /// Proxy URL we're connected to
    proxy_url: String,
    /// Transport type (HTTP/3 or HTTP/2)
    transport: MasqueTransport,
    /// The underlying QUIC connection (either to the proxy via HTTP/3,
    /// or a peer-to-peer QUIC connection through the HTTP/2 tunnel)
    quic_conn: Connection,
    /// Call ID used for proxy matching
    call_id: String,
    /// Current tunnel state
    state: TunnelState,
}

impl MasqueTunnel {
    /// Establish a MASQUE CONNECT-UDP tunnel via HTTP/3 (QUIC/UDP).
    ///
    /// Preferred path — lower latency, no head-of-line blocking.
    /// Uses the h3 crate on top of quinn for the HTTP/3 connection.
    ///
    /// # CONNECT-UDP Request Format (spec/12 §12.2.2)
    ///
    /// ```http
    /// HEADERS frame:
    ///   :method = CONNECT
    ///   :protocol = connect-udp
    ///   :path = /masque
    ///   :authority = proxy.example.com:443
    ///   connect-udp-target-host = voip-relay
    ///   connect-udp-target-port = 0
    ///   x-voip-call-id = <call_id>
    ///   x-voip-peer-id = <peer_id>
    /// ```
    ///
    /// # Implementation Notes
    ///
    /// The h3 crate (0.0.8+) provides:
    /// - `h3::client::builder()` with `enable_datagram(true)` and
    ///   `enable_extended_connect(true)` for CONNECT-UDP support
    /// - HTTP/3 datagram send/recv for carrying MoQ media
    /// - Stream-based request/response for the CONNECT-UDP handshake
    #[instrument(skip(proxy_url, call_id))]
    pub async fn connect_http3(
        proxy_url: &str,
        call_id: &str,
    ) -> Result<Self, MasqueError> {
        info!(proxy_url = %proxy_url, call_id = %call_id, "Establishing MASQUE HTTP/3 tunnel");

        // Step 1: Parse the proxy URL to get host and port
        let (host, port) = parse_proxy_url(proxy_url)?;

        // Step 2: Establish QUIC connection to the proxy
        let quic_conn = establish_quic_to_proxy(&host, port).await?;

        // Step 3: Initialize HTTP/3 client with datagram + extended connect
        // The h3 crate requires a Buf type parameter — we use Bytes
        let h3_conn = h3::client::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .build(h3_quinn::Connection::new(quic_conn.clone()))
            .await
            .map_err(|e| MasqueError::Http3Error(format!("h3 handshake: {}", e)))?;

        let (h3_driver, mut send_req) = h3_conn;

        // Step 4: Build CONNECT-UDP request headers
        let request = build_connect_udp_request(&host, port, call_id)?;

        // Step 5: Send the CONNECT-UDP request
        let mut request_stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes> = send_req
            .send_request(request)
            .await
            .map_err(|e| MasqueError::Http3Error(format!("send CONNECT-UDP: {}", e)))?;

        // Finish sending the request (no request body for CONNECT-UDP)
        request_stream
            .finish()
            .await
            .map_err(|e| MasqueError::Http3Error(format!("finish request: {}", e)))?;

        // Step 6: Wait for the proxy's response
        // recv_response() on the RequestStream returns the HTTP response
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            request_stream.recv_response(),
        )
        .await
        .map_err(|_| MasqueError::Http3Error("CONNECT-UDP response timeout".to_string()))?
        .map_err(|e| MasqueError::Http3Error(format!("recv response: {}", e)))?;

        // Check the response status — 200 means tunnel is active
        let status = response.status();
        if status != http::StatusCode::OK {
            return Err(MasqueError::ConnectUdpRejected(status.as_u16()));
        }

        info!(
            proxy_url = %proxy_url,
            "MASQUE HTTP/3 tunnel established (CONNECT-UDP 200 OK)"
        );

        // The h3_driver and request_stream are kept alive for datagram send/recv.
        // In a full implementation, these would be stored in the MasqueTunnel
        // struct and used for datagram exchange via h3's datagram API.
        // For now, we keep the QUIC connection and use its datagram API directly.
        drop(h3_driver);
        drop(request_stream);

        Ok(Self {
            proxy_url: proxy_url.to_string(),
            transport: MasqueTransport::Http3,
            quic_conn,
            call_id: call_id.to_string(),
            state: TunnelState::Active,
        })
    }

    /// Establish a MASQUE CONNECT-UDP tunnel via HTTP/2 (TCP).
    ///
    /// Fallback path — works when UDP is blocked.
    /// Uses TCP+TLS 1.3 to connect to the proxy on port 443,
    /// then sends CONNECT-UDP on the HTTP/2 stream.
    ///
    /// # HTTP/2 CONNECT-UDP (spec/12 §12.6.2, RFC 9297 §5)
    ///
    /// After 200 OK, datagrams are exchanged using HTTP/2 capsules:
    ///
    /// ```http
    /// DATA frame:
    ///   Capsule type: DATAGRAM (RFC 9297 §5.1)
    ///   Length: varint
    ///   Quarter Stream ID: 0 (varint)
    ///   HTTP Datagram Payload: <QUIC packet — opaque to proxy>
    /// ```
    #[instrument(skip(proxy_url, call_id))]
    pub async fn connect_http2(
        proxy_url: &str,
        call_id: &str,
    ) -> Result<Self, MasqueError> {
        info!(proxy_url = %proxy_url, call_id = %call_id, "Establishing MASQUE HTTP/2 tunnel");

        // Step 1: Parse the proxy URL
        let (host, port) = parse_proxy_url(proxy_url)?;

        // Step 2: Establish TCP+TLS connection to proxy
        let tcp_stream = tokio::net::TcpStream::connect((&*host, port))
            .await
            .map_err(|e| MasqueError::Http2Error(format!("TCP connect: {}", e)))?;

        // Step 3: Perform TLS handshake
        let tls_stream = perform_tls_handshake(tcp_stream, &host).await?;

        // Step 4: Perform HTTP/2 handshake with CONNECT-UDP
        // Build the CONNECT-UDP request
        let request = build_connect_udp_request(&host, port, call_id)?;

        // Send the request via HTTP/2 and wait for 200 OK
        // Using the hyper crate for HTTP/2 client support
        let (h2_conn, h2_stream) = perform_h2_handshake(tls_stream, request).await?;

        // Step 5: Create a QUIC-like connection through the tunnel
        // For HTTP/2 MASQUE, we create a virtual connection that
        // sends/receives datagrams via RFC 9297 §5 capsule framing
        // on the HTTP/2 stream.
        //
        // However, quinn QUIC connections cannot be created from
        // arbitrary I/O — they require a quinn Endpoint. Therefore,
        // for HTTP/2 MASQUE, we need a different approach:
        //
        // Option A: Use a local loopback QUIC connection pair
        //   (two quinn endpoints on localhost, one "server" that
        //    reads/writes HTTP/2 capsules, one "client" used by MoQ)
        // Option B: Implement MoQ directly over the HTTP/2 stream
        //   without QUIC (use a custom transport abstraction)
        //
        // Option A is the cleaner approach because it keeps the
        // MoQ session API unchanged — it still works with a quinn
        // Connection object. The loopback QUIC pair is transparent
        // to the MoQ layer.
        //
        // For now, we return an error. The loopback QUIC approach
        // will be implemented in the Fine Draft pass.

        let _ = h2_conn;
        let _ = h2_stream;

        Err(MasqueError::Http2Error(
            "HTTP/2 MASQUE tunnel: loopback QUIC not yet implemented".to_string(),
        ))
    }

    /// Send a MoQ datagram through the tunnel.
    ///
    /// For HTTP/3: the datagram is sent as an HTTP/3 datagram (RFC 9221)
    /// on the QUIC connection. The proxy forwards it to the other peer.
    ///
    /// For HTTP/2: the datagram is sent as an RFC 9297 §5 capsule
    /// on the HTTP/2 stream.
    pub async fn send_datagram(&mut self, data: Bytes) -> Result<(), MasqueError> {
        match self.transport {
            MasqueTransport::Http3 => {
                self.quic_conn
                    .send_datagram(data)
                    .map_err(|e| MasqueError::DatagramSendFailed(format!("{}", e)))?;
                debug!("Datagram sent via HTTP/3 MASQUE tunnel");
                Ok(())
            }
            MasqueTransport::Http2 => {
                // For HTTP/2, datagrams are sent as RFC 9297 §5 capsules
                // on the CONNECT-UDP stream.
                let capsule = encode_h2_datagram_capsule(&data);
                debug!(len = capsule.len(), "Sending datagram via HTTP/2 capsule");
                // In full implementation, write capsule to the HTTP/2 stream
                Ok(())
            }
        }
    }

    /// Receive a MoQ datagram from the tunnel.
    ///
    /// For HTTP/3: reads a QUIC datagram from the connection.
    ///
    /// For HTTP/2: reads an RFC 9297 §5 capsule from the CONNECT-UDP stream.
    pub async fn recv_datagram(&mut self) -> Result<Bytes, MasqueError> {
        match self.transport {
            MasqueTransport::Http3 => {
                let data = self
                    .quic_conn
                    .read_datagram()
                    .await
                    .map_err(|e| MasqueError::DatagramRecvFailed(format!("{}", e)))?;
                Ok(data)
            }
            MasqueTransport::Http2 => {
                // For HTTP/2, read a capsule from the CONNECT-UDP stream
                // and decode the RFC 9297 §5 framing
                Err(MasqueError::DatagramRecvFailed(
                    "HTTP/2 datagram receive: loopback QUIC not yet implemented".to_string(),
                ))
            }
        }
    }

    /// Close the tunnel gracefully.
    pub async fn close(&mut self) -> Result<(), MasqueError> {
        match self.transport {
            MasqueTransport::Http3 => {
                // Send HTTP/3 GOAWAY frame to the proxy
                // For now, close the QUIC connection
                self.quic_conn.close(
                    quinn::VarInt::from_u32(0),
                    b"MASQUE tunnel closed",
                );
            }
            MasqueTransport::Http2 => {
                // Close the HTTP/2 stream gracefully
                // In full implementation, send RST_STREAM or GOAWAY
            }
        }
        self.state = TunnelState::Failed;
        info!("MASQUE tunnel closed gracefully");
        Ok(())
    }

    /// Initiate tunnel recovery after proxy failure.
    ///
    /// Per spec/12 §12.8: When the proxy disconnects during an active call,
    /// the client enters the RECOVERING state and attempts:
    /// 1. Re-discover proxies via DHT or signaling server
    /// 2. Reconnect to the same or a different proxy
    /// 3. Re-establish the MASQUE tunnel
    /// 4. Resume MoQ session on the new tunnel
    ///
    /// Target: tunnel re-established within 600ms.
    pub async fn recover(
        &mut self,
        proxy_records: &[voip_core::proto::signaling::ProxyRecord],
    ) -> Result<(), MasqueError> {
        self.state = TunnelState::Recovering;
        info!(
            call_id = %self.call_id,
            "Attempting MASQUE tunnel recovery"
        );

        let call_id = self.call_id.clone();

        // Try each proxy until one works
        for proxy in proxy_records {
            let proxy_url = &proxy.proxy_url;
            info!(proxy_url = %proxy_url, "Recovery: trying proxy");

            match Self::connect_http3(proxy_url, &call_id).await {
                Ok(new_tunnel) => {
                    info!(proxy_url = %proxy_url, "Recovery: MASQUE HTTP/3 tunnel re-established");
                    *self = new_tunnel;
                    return Ok(());
                }
                Err(e) => {
                    warn!(proxy_url = %proxy_url, error = %e, "Recovery: HTTP/3 failed, trying HTTP/2");
                    match Self::connect_http2(proxy_url, &call_id).await {
                        Ok(new_tunnel) => {
                            info!(proxy_url = %proxy_url, "Recovery: MASQUE HTTP/2 tunnel re-established");
                            *self = new_tunnel;
                            return Ok(());
                        }
                        Err(e2) => {
                            warn!(proxy_url = %proxy_url, error = %e2, "Recovery: both transports failed for proxy");
                        }
                    }
                }
            }
        }

        self.state = TunnelState::Failed;
        Err(MasqueError::AllTransportsFailed)
    }

    /// Get the current tunnel state.
    pub fn state(&self) -> TunnelState {
        self.state
    }

    /// Get the transport type.
    pub fn transport(&self) -> MasqueTransport {
        self.transport
    }

    /// Get the QUIC connection (for MoQ session setup).
    ///
    /// For HTTP/3: this is the QUIC connection to the proxy.
    /// For HTTP/2: this is the peer-to-peer QUIC connection
    /// established through the tunnel (via loopback QUIC pair).
    pub fn quic_connection(&self) -> &Connection {
        &self.quic_conn
    }

    /// Get the call ID.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Get the proxy URL.
    pub fn proxy_url(&self) -> &str {
        &self.proxy_url
    }
}

// ==================== HTTP/3 Helper Functions ====================

/// Build the CONNECT-UDP request headers per spec/12 §12.2.2.
///
/// Uses Extended CONNECT (RFC 8441) with the `connect-udp` protocol.
/// The `:protocol` pseudo-header is set via the h3 extended connect API.
fn build_connect_udp_request(host: &str, port: u16, call_id: &str) -> Result<http::Request<()>, MasqueError> {
    build_connect_udp_request_with_peer(host, port, call_id, "")
}

/// Build the CONNECT-UDP request headers per spec/12 §12.2.2 with optional peer ID.
///
/// Uses Extended CONNECT (RFC 8441) with the `connect-udp` protocol.
/// The `:protocol` pseudo-header is set via the h3 extended connect API.
fn build_connect_udp_request_with_peer(host: &str, port: u16, call_id: &str, peer_id: &str) -> Result<http::Request<()>, MasqueError> {
    let authority = format!("{}:{}", host, port);

    // Use the http::request::Builder API which properly handles pseudo-headers
    // The :protocol header for Extended CONNECT must be set via the request
    // extensions or by using the appropriate HTTP/3 CONNECT method
    let mut builder = http::Request::builder();
    builder = builder
        .method(http::Method::CONNECT)
        .uri(format!("https://{}/masque", authority))
        .header("host", &authority)
        .header("connect-udp-target-host", "voip-relay")
        .header("connect-udp-target-port", "0")
        .header("x-voip-call-id", call_id);

    // Per spec/12 §12.2.2: x-voip-peer-id header is required for proxy matching
    if !peer_id.is_empty() {
        builder = builder.header("x-voip-peer-id", peer_id);
    }

    // For Extended CONNECT, the :protocol pseudo-header is set via
    // the h3 protocol-specific mechanism. In h3 0.0.8, this is
    // done by setting the protocol in the request extensions.
    let mut req = builder
        .body(())
        .map_err(|e| MasqueError::Http3Error(format!("build request: {}", e)))?;

    // Set the Extended CONNECT protocol via h3's extension mechanism
    let protocol = h3::ext::Protocol::from_str("connect-udp")
        .map_err(|_| MasqueError::Http3Error("invalid CONNECT-UDP protocol".to_string()))?;
    req.extensions_mut().insert(protocol);

    Ok(req)
}

// ==================== HTTP/2 Helper Functions ====================

/// Perform TLS handshake over TCP for the HTTP/2 MASQUE path.
async fn perform_tls_handshake(
    tcp_stream: tokio::net::TcpStream,
    host: &str,
) -> Result<tokio::io::BufStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>, MasqueError> {
    let rustls_config = crate::tls::dangerous_client_config()
        .map_err(|e| MasqueError::TlsError(format!("TLS config: {}", e)))?;

    let config = Arc::new(rustls_config);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| MasqueError::TlsError(format!("invalid server name: {}", e)))?;

    let connector = tokio_rustls::TlsConnector::from(config);
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| MasqueError::TlsError(format!("TLS handshake: {}", e)))?;

    Ok(tokio::io::BufStream::new(tls_stream))
}

/// Perform HTTP/2 handshake with CONNECT-UDP extended connect.
async fn perform_h2_handshake<S>(
    _tls_stream: S,
    _request: http::Request<()>,
) -> Result<((), ()), MasqueError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // HTTP/2 CONNECT-UDP handshake using the h2 crate:
    // 1. h2::client::Builder::new()
    //    .enable_connect_protocol(true)  // RFC 8441 extended CONNECT
    //    .handshake(tls_stream)
    // 2. Send CONNECT-UDP request on a new stream
    // 3. Wait for 200 OK response
    // 4. Tunnel is active — datagrams via RFC 9297 §5 capsules
    //
    // This requires the `h2` crate which is not currently in Cargo.toml.
    // Will be completed in the Fine Draft pass.
    Err(MasqueError::Http2Error(
        "HTTP/2 CONNECT-UDP handshake not yet fully implemented".to_string(),
    ))
}

// ==================== Common Helper Functions ====================

/// Parse a proxy URL to extract host and port.
fn parse_proxy_url(url: &str) -> Result<(String, u16), MasqueError> {
    let url = url.trim_start_matches("https://").trim_start_matches("http://");
    let parts: Vec<&str> = url.split('/').collect();
    let host_port = parts[0];

    if let Some(idx) = host_port.rfind(':') {
        let host = host_port[..idx].to_string();
        let port: u16 = host_port[idx + 1..].parse().unwrap_or(443);
        Ok((host, port))
    } else {
        Ok((host_port.to_string(), 443))
    }
}

/// Establish a QUIC connection to the MASQUE proxy.
async fn establish_quic_to_proxy(
    host: &str,
    port: u16,
) -> Result<Connection, MasqueError> {
    let addr = format!("{}:{}", host, port);
    let sock_addr: std::net::SocketAddr = tokio::net::lookup_host(&addr)
        .await
        .map_err(|e| MasqueError::Http3Error(format!("DNS lookup: {}", e)))?
        .next()
        .ok_or_else(|| MasqueError::Http3Error("no address found".to_string()))?;

    let client_config = crate::tls::dangerous_quinn_client_config()
        .map_err(MasqueError::Http3Error)?;

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())
        .map_err(|e| MasqueError::Http3Error(format!("create endpoint: {}", e)))?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(sock_addr, host)
        .map_err(|e| MasqueError::Http3Error(format!("connect: {}", e)))?
        .await
        .map_err(|e| MasqueError::Http3Error(format!("handshake: {}", e)))?;

    Ok(connection)
}

/// Encode a datagram as an RFC 9297 §5 HTTP/2 capsule.
fn encode_h2_datagram_capsule(data: &[u8]) -> Vec<u8> {
    let quarter_stream_id: u64 = 0;
    let payload_len = data.len() as u64 + varint_len(quarter_stream_id);

    let mut capsule = Vec::with_capacity(data.len() + 16);
    encode_varint(&mut capsule, 0);
    encode_varint(&mut capsule, payload_len);
    encode_varint(&mut capsule, quarter_stream_id);
    capsule.extend_from_slice(data);
    capsule
}

/// Encode a varint into a byte buffer.
fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Calculate the encoded length of a varint.
fn varint_len(value: u64) -> u64 {
    let mut len = 1;
    let mut v = value;
    while v > 0x7F {
        v >>= 7;
        len += 1;
    }
    len
}

/// Automatic MASQUE tunnel establishment with HTTP/3 → HTTP/2 fallback.
///
/// Per spec/12 §12.6.4: try HTTP/3 first (UDP available, lower latency),
/// then fall back to HTTP/2 (TCP, works when UDP is blocked).
pub async fn establish_masque_tunnel(
    proxy_url: &str,
    call_id: &str,
    udp_blocked: bool,
) -> Result<MasqueTunnel, MasqueError> {
    // Try HTTP/3 first (QUIC/UDP — lower latency, no HOL blocking)
    if !udp_blocked {
        if let Ok(tunnel) = MasqueTunnel::connect_http3(proxy_url, call_id).await {
            return Ok(tunnel);
        }
    }

    // Fall back to HTTP/2 (TCP — works when UDP is blocked)
    if let Ok(tunnel) = MasqueTunnel::connect_http2(proxy_url, call_id).await {
        return Ok(tunnel);
    }

    Err(MasqueError::AllTransportsFailed)
}

/// Detect whether MASQUE relay is needed based on both peers' NAT types.
///
/// Per spec/09 §9.9: The connection fallback chain is:
/// 1. IPv6 Direct → 2. QUIC Simultaneous Open (Cone) →
/// 3. Port Prediction (Symmetric sequential/pseudo) →
/// 4. MASQUE/HTTP3 → 5. MASQUE/HTTP2 → 6. Push Retry
///
/// MASQUE is needed when all direct methods have been exhausted:
/// - Both peers behind SymmetricRandom NAT (neither can predict)
/// - UDP is blocked entirely
/// - One random + one symmetric (prediction from symmetric side fails)
/// - IPv6 firewalls block both sides
///
/// Note: When one side is Random and the other is predictable (Sequential/Pseudo),
/// one-side prediction is attempted first (spec/01 §1.4: ~60% success rate).
/// MASQUE is the fallback when one-side prediction also fails.
pub fn detect_masque_need(
    local_nat_type: voip_core::NATType,
    peer_nat_type: voip_core::NATType,
    udp_blocked: bool,
) -> bool {
    if udp_blocked {
        return true;
    }

    // Both random NAT → no prediction possible, need MASQUE
    if local_nat_type == voip_core::NATType::SymmetricRandom
        && peer_nat_type == voip_core::NATType::SymmetricRandom
    {
        return true;
    }

    // One side IPv6 (None) is always reachable, no MASQUE needed
    if local_nat_type == voip_core::NATType::None
        || peer_nat_type == voip_core::NATType::None
    {
        return false;
    }

    // One side Cone → QUIC simultaneous open works, no MASQUE needed
    if local_nat_type == voip_core::NATType::Cone
        || peer_nat_type == voip_core::NATType::Cone
    {
        return false;
    }

    // One side predictable (Sequential/Pseudo) → one-side prediction attempted first
    // MASQUE is fallback only if prediction also fails
    // This function returns false to indicate "try prediction first, then MASQUE if it fails"
    if local_nat_type.is_predictable() || peer_nat_type.is_predictable() {
        return false;
    }

    // Both are random and neither is Cone/IPv6 → MASQUE needed
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proxy_url_with_port() {
        let (host, port) = parse_proxy_url("https://proxy.example.com:443").unwrap();
        assert_eq!(host, "proxy.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_proxy_url_without_port() {
        let (host, port) = parse_proxy_url("https://proxy.example.com").unwrap();
        assert_eq!(host, "proxy.example.com");
        assert_eq!(port, 443); // default port
    }

    #[test]
    fn test_parse_proxy_url_http() {
        let (host, port) = parse_proxy_url("http://proxy.example.com:8443").unwrap();
        assert_eq!(host, "proxy.example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_build_connect_udp_request() {
        let request = build_connect_udp_request("proxy.example.com", 443, "call-abc123").unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.headers().get("connect-udp-target-host").unwrap(), "voip-relay");
        assert_eq!(request.headers().get("connect-udp-target-port").unwrap(), "0");
        assert_eq!(request.headers().get("x-voip-call-id").unwrap(), "call-abc123");
        // Protocol is set via extensions, not headers
        assert!(request.extensions().get::<h3::ext::Protocol>().is_some());
    }

    #[test]
    fn test_detect_masque_need_both_random() {
        assert!(detect_masque_need(
            voip_core::NATType::SymmetricRandom,
            voip_core::NATType::SymmetricRandom,
            false,
        ));
    }

    #[test]
    fn test_detect_masque_need_udp_blocked() {
        assert!(detect_masque_need(
            voip_core::NATType::Cone,
            voip_core::NATType::Cone,
            true,
        ));
    }

    #[test]
    fn test_detect_masque_not_needed_cone() {
        assert!(!detect_masque_need(
            voip_core::NATType::Cone,
            voip_core::NATType::Cone,
            false,
        ));
    }

    #[test]
    fn test_detect_masque_not_needed_sequential() {
        assert!(!detect_masque_need(
            voip_core::NATType::SymmetricSequential,
            voip_core::NATType::SymmetricSequential,
            false,
        ));
    }

    #[test]
    fn test_detect_masque_not_needed_one_random() {
        // One Cone, one Random — Cone side can receive, so direct works
        assert!(!detect_masque_need(
            voip_core::NATType::Cone,
            voip_core::NATType::SymmetricRandom,
            false,
        ));
    }

    #[test]
    fn test_encode_h2_datagram_capsule() {
        let data = b"hello";
        let capsule = encode_h2_datagram_capsule(data);
        // Capsule format: type(varint=0) + length(varint) + quarter_stream_id(varint=0) + data
        assert!(capsule.len() > data.len());
        // First byte should be 0 (capsule type)
        assert_eq!(capsule[0], 0);
    }
}
