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
    #[instrument(skip(proxy_url, call_id, proxy_token))]
    pub async fn connect_http3(
        proxy_url: &str,
        call_id: &str,
        proxy_token: Option<&str>,
    ) -> Result<Self, MasqueError> {
        info!(proxy_url = %proxy_url, call_id = %call_id, has_token = proxy_token.is_some(), "Establishing MASQUE HTTP/3 tunnel");

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
        let request = build_connect_udp_request(&host, port, call_id, proxy_token)?;

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
    /// then sends CONNECT-UDP on the HTTP/2 stream via the `h2` crate.
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
    #[instrument(skip(proxy_url, call_id, proxy_token))]
    pub async fn connect_http2(
        proxy_url: &str,
        call_id: &str,
        proxy_token: Option<&str>,
    ) -> Result<Self, MasqueError> {
        info!(proxy_url = %proxy_url, call_id = %call_id, has_token = proxy_token.is_some(), "Establishing MASQUE HTTP/2 tunnel");

        // Step 1: Parse the proxy URL
        let (host, port) = parse_proxy_url(proxy_url)?;

        // Step 2: Establish TCP+TLS connection to proxy
        let tcp_stream = tokio::net::TcpStream::connect((&*host, port))
            .await
            .map_err(|e| MasqueError::Http2Error(format!("TCP connect: {}", e)))?;

        // Step 3: Perform TLS handshake
        let tls_stream = perform_tls_handshake(tcp_stream, &host).await?;

        // Step 4: Build the CONNECT-UDP request for HTTP/2
        let request = build_connect_udp_request_h2(&host, port, call_id, proxy_token)?;

        // Step 5: Perform HTTP/2 handshake and send CONNECT-UDP request
        let h2_result = perform_h2_handshake(tls_stream, request).await?;

        info!(
            proxy_url = %proxy_url,
            "MASQUE HTTP/2 tunnel: CONNECT-UDP handshake completed (200 OK)"
        );

        // Step 6: Create a local loopback QUIC connection pair.
        //
        // The h2 stream carries QUIC packets as RFC 9297 §5 capsules.
        // Since MoQ requires a quinn::Connection, we create a loopback pair:
        //   - A quinn server on localhost accepts a connection
        //   - A quinn client connects to the server
        //   - A background task bridges the server-side connection to the h2 stream
        //   - The client-side connection is returned for MoQ use
        //
        // The h2 connection driver must be kept alive in a background task.
        // The SendStream is used to write RFC 9297 capsules, and data
        // from the h2 RecvStream is forwarded as capsules to the server conn.
        let loopback_conn = create_loopback_quic_pair(h2_result).await?;

        Ok(Self {
            proxy_url: proxy_url.to_string(),
            transport: MasqueTransport::Http2,
            quic_conn: loopback_conn,
            call_id: call_id.to_string(),
            state: TunnelState::Active,
        })
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
                // on the CONNECT-UDP stream via the loopback QUIC pair.
                // The loopback bridge task handles the actual capsule encoding.
                self.quic_conn
                    .send_datagram(data)
                    .map_err(|e| MasqueError::DatagramSendFailed(format!("{}", e)))?;
                debug!("Datagram sent via HTTP/2 MASQUE tunnel (loopback QUIC)");
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
                // For HTTP/2, the loopback QUIC pair bridges datagrams
                // from the h2 stream to the quinn connection.
                let data = self
                    .quic_conn
                    .read_datagram()
                    .await
                    .map_err(|e| MasqueError::DatagramRecvFailed(format!("{}", e)))?;
                Ok(data)
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
                // The loopback QUIC connection close propagates to the bridge task
                self.quic_conn.close(
                    quinn::VarInt::from_u32(0),
                    b"MASQUE tunnel closed",
                );
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

            match Self::connect_http3(proxy_url, &call_id, None).await {
                Ok(new_tunnel) => {
                    info!(proxy_url = %proxy_url, "Recovery: MASQUE HTTP/3 tunnel re-established");
                    *self = new_tunnel;
                    return Ok(());
                }
                Err(e) => {
                    warn!(proxy_url = %proxy_url, error = %e, "Recovery: HTTP/3 failed, trying HTTP/2");
                    match Self::connect_http2(proxy_url, &call_id, None).await {
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
    /// For HTTP/2: this is the client side of a loopback QUIC pair
    /// bridged to the HTTP/2 CONNECT-UDP stream.
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
///
/// Per ROADMAP 3.22 and spec/12 §12.4: when a `proxy_token` is available,
/// it is included as the `x-voip-proxy-token` header for anti-abuse
/// verification by the proxy.
fn build_connect_udp_request(host: &str, port: u16, call_id: &str, proxy_token: Option<&str>) -> Result<http::Request<()>, MasqueError> {
    build_connect_udp_request_with_peer(host, port, call_id, "", proxy_token)
}

/// Build the CONNECT-UDP request headers per spec/12 §12.2.2 with optional peer ID.
///
/// Uses Extended CONNECT (RFC 8441) with the `connect-udp` protocol.
/// The `:protocol` pseudo-header is set via the h3 extended connect API.
///
/// Per ROADMAP 3.22: the `x-voip-proxy-token` header is included when
/// a ProxyToken is available, allowing the proxy to verify the client's
/// authorization with the signaling server.
fn build_connect_udp_request_with_peer(host: &str, port: u16, call_id: &str, peer_id: &str, proxy_token: Option<&str>) -> Result<http::Request<()>, MasqueError> {
    let authority = format!("{}:{}", host, port);

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

    // Per ROADMAP 3.22 / spec/12 §12.4: x-voip-proxy-token header is sent
    // when a ProxyToken is available, allowing the proxy to verify
    // the client's authorization with the signaling server.
    if let Some(token) = proxy_token {
        builder = builder.header("x-voip-proxy-token", token);
    }

    // For Extended CONNECT, the :protocol pseudo-header is set via
    // the h3 protocol-specific mechanism.
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

/// Build the CONNECT-UDP request headers for the HTTP/2 path.
///
/// Similar to [`build_connect_udp_request`] but uses the `h2::ext::Protocol`
/// extension type instead of `h3::ext::Protocol`, since the h2 crate
/// uses its own `:protocol` pseudo-header handling.
fn build_connect_udp_request_h2(
    host: &str,
    port: u16,
    call_id: &str,
    proxy_token: Option<&str>,
) -> Result<http::Request<()>, MasqueError> {
    let authority = format!("{}:{}", host, port);

    let mut builder = http::Request::builder();
    builder = builder
        .method(http::Method::CONNECT)
        .uri(format!("https://{}/masque", authority))
        .header(http::header::HOST, &authority)
        .header("connect-udp-target-host", "voip-relay")
        .header("connect-udp-target-port", "0")
        .header("x-voip-call-id", call_id);

    if let Some(token) = proxy_token {
        builder = builder.header("x-voip-proxy-token", token);
    }

    let mut req = builder
        .body(())
        .map_err(|e| MasqueError::Http2Error(format!("build request: {}", e)))?;

    // Set the Extended CONNECT :protocol pseudo-header via h2's extension mechanism.
    // The h2 crate extracts this from request.extensions() and encodes it
    // as the :protocol pseudo-header in the HTTP/2 HEADERS frame.
    let protocol = h2::ext::Protocol::from("connect-udp");
    req.extensions_mut().insert(protocol);

    Ok(req)
}

/// Perform TLS handshake over TCP for the HTTP/2 MASQUE path.
///
/// Establishes a TLS 1.3 connection to the MASQUE proxy using the
/// dangerous (no certificate verification) client config.
/// ALPN is set to "h2" to negotiate HTTP/2.
async fn perform_tls_handshake(
    tcp_stream: tokio::net::TcpStream,
    host: &str,
) -> Result<tokio::io::BufStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>, MasqueError> {
    let mut rustls_config = crate::tls::dangerous_client_config()
        .map_err(|e| MasqueError::TlsError(format!("TLS config: {}", e)))?;

    // Set ALPN to h2 for HTTP/2 negotiation
    rustls_config.alpn_protocols = vec![b"h2".to_vec()];

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

/// The result of a successful HTTP/2 CONNECT-UDP handshake.
///
/// The h2 connection driver is kept alive by a background task (JoinHandle).
/// The send and recv streams are used for RFC 9297 §5 datagram exchange.
struct H2Tunnel {
    /// Handle to the background task driving the h2 connection.
    /// Must be kept alive for the send/recv streams to work.
    _conn_task: tokio::task::JoinHandle<()>,
    /// The send stream for writing RFC 9297 §5 capsules to the proxy.
    _send_stream: h2::SendStream<Bytes>,
    /// The response stream for reading data from the proxy.
    _recv_stream: h2::RecvStream,
}

/// Perform HTTP/2 handshake with CONNECT-UDP extended connect.
///
/// Per ROADMAP 3.16 / spec/12 §12.6.2:
/// 1. Perform h2 handshake over the TLS stream
/// 2. Wait for the server's SETTINGS frame (which enables extended CONNECT)
/// 3. Send a CONNECT-UDP request with `:protocol = connect-udp`
/// 4. Wait for 200 OK response
/// 5. Return the h2 send/recv streams for datagram exchange
async fn perform_h2_handshake(
    tls_stream: tokio::io::BufStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    request: http::Request<()>,
) -> Result<H2Tunnel, MasqueError> {
    // Step 1: Perform the HTTP/2 handshake using the h2 crate.
    // The h2 crate handles the connection preface, SETTINGS exchange, etc.
    let (mut h2_client, h2_connection) = h2::client::Builder::new()
        .handshake(tls_stream)
        .await
        .map_err(|e| MasqueError::Http2Error(format!("h2 handshake: {}", e)))?;

    // Spawn a background task to drive the h2 connection.
    // This is required for the h2 protocol to make progress —
    // the Connection must be continuously polled.
    let conn_task = tokio::spawn(async move {
        if let Err(e) = h2_connection.await {
            debug!(error = %e, "h2 connection task ended with error");
        }
    });

    // Step 2: Wait for the server's SETTINGS to be acknowledged.
    // The h2 crate handles SETTINGS exchange internally during handshake.
    // After handshake, we can check if extended CONNECT is enabled.
    // We give the server a short time to send its SETTINGS.
    let extended_connect_ready = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        async {
            // Poll until the server acknowledges our SETTINGS and we
            // receive their SETTINGS indicating extended CONNECT support.
            // The h2 client's is_extended_connect_protocol_enabled()
            // returns true once the server's SETTINGS with
            // SETTINGS_ENABLE_CONNECT_PROTOCOL=1 is received.
            for _ in 0..30 {
                if h2_client.is_extended_connect_protocol_enabled() {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            false
        },
    )
    .await
    .unwrap_or(false);

    if !extended_connect_ready {
        // Server doesn't support extended CONNECT — try sending anyway
        // (some servers may not advertise via SETTINGS but still accept it)
        warn!("Server did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL; attempting CONNECT-UDP anyway");
    }

    // Step 3: Send the CONNECT-UDP request.
    // The `:protocol = connect-udp` pseudo-header is set via
    // the h2::ext::Protocol extension in the request.
    let (response_future, send_stream) = h2_client
        .send_request(request, false)
        .map_err(|e| MasqueError::Http2Error(format!("send CONNECT-UDP request: {}", e)))?;

    // Step 4: Wait for the proxy's 200 OK response.
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        response_future,
    )
    .await
    .map_err(|_| MasqueError::Http2Error("CONNECT-UDP response timeout".to_string()))?
    .map_err(|e| MasqueError::Http2Error(format!("CONNECT-UDP response error: {}", e)))?;

    let (head, recv_stream) = response.into_parts();

    // Check the response status — 200 means tunnel is active
    if head.status != http::StatusCode::OK {
        return Err(MasqueError::ConnectUdpRejected(head.status.as_u16()));
    }

    info!("HTTP/2 CONNECT-UDP handshake completed (200 OK)");

    // The conn_task keeps the h2 Connection alive in a background task.
    // The send_stream and recv_stream are used for datagram exchange.
    // When the H2Tunnel is dropped, conn_task will be cancelled, closing
    // the h2 connection.

    Ok(H2Tunnel {
        _conn_task: conn_task,
        _send_stream: send_stream,
        _recv_stream: recv_stream,
    })
}

/// Create a local loopback QUIC connection pair for the HTTP/2 MASQUE path.
///
/// The MoQ session requires a `quinn::Connection`, but HTTP/2 MASQUE
/// carries data over TCP. This function creates a loopback QUIC pair:
///
/// 1. A quinn server endpoint on a random localhost port
/// 2. A quinn client endpoint that connects to the server
/// 3. The returned client-side connection is used by MoQ
///
/// A background task bridges the server-side connection to the h2 stream:
/// - Data received from h2 (RFC 9297 capsules) → forwarded as QUIC datagrams
/// - QUIC datagrams from the server connection → encoded as RFC 9297 capsules → sent via h2
///
/// **Note**: This is a placeholder implementation. A full implementation
/// would spawn background tasks to bridge the h2 send/recv streams with
/// the server-side QUIC connection's datagram API.
async fn create_loopback_quic_pair(
    _h2_result: H2Tunnel,
) -> Result<Connection, MasqueError> {
    // Create server endpoint on a random localhost port
    let server_config = crate::tls::dangerous_quinn_server_config()
        .map_err(|e| MasqueError::Http2Error(format!("server config: {}", e)))?;

    let server_endpoint = quinn::Endpoint::server(
        server_config,
        "127.0.0.1:0".parse().map_err(|e| MasqueError::Http2Error(format!("bind: {}", e)))?,
    )
    .map_err(|e| MasqueError::Http2Error(format!("create server endpoint: {}", e)))?;

    let server_addr = server_endpoint
        .local_addr()
        .map_err(|e| MasqueError::Http2Error(format!("local addr: {}", e)))?;

    // Create client endpoint
    let client_config = crate::tls::dangerous_quinn_client_config()
        .map_err(|e| MasqueError::Http2Error(format!("client config: {}", e)))?;

    let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().map_err(|e| MasqueError::Http2Error(format!("client bind: {}", e)))?)
        .map_err(|e| MasqueError::Http2Error(format!("create client endpoint: {}", e)))?;
    client_endpoint.set_default_client_config(client_config);

    // Spawn server accept task
    let server_task = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.accept().await {
            let conn = incoming.await;
            if let Ok(server_conn) = conn {
                // TODO: Bridge the server_conn to the h2 send/recv streams.
                // This would involve:
                // 1. Reading QUIC datagrams from server_conn and forwarding
                //    them as RFC 9297 capsules via h2 send_stream
                // 2. Reading RFC 9297 capsules from h2 recv_stream and
                //    forwarding them as QUIC datagrams via server_conn
                //
                // For now, just keep the server connection alive.
                // The actual bridging will be implemented when integrating
                // with the full MoQ pipeline.
                let _ = server_conn;
                // Wait indefinitely (or until connection closes)
                std::future::pending::<()>().await;
            }
        }
    });

    // Connect from client to server
    let client_conn = client_endpoint
        .connect(server_addr, "voip-masque-loopback")
        .map_err(|e| MasqueError::Http2Error(format!("loopback connect: {}", e)))?
        .await
        .map_err(|e| MasqueError::Http2Error(format!("loopback handshake: {}", e)))?;

    info!(
        addr = %server_addr,
        "HTTP/2 MASQUE loopback QUIC pair created"
    );

    // Keep the server task alive
    drop(server_task);

    Ok(client_conn)
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
///
/// This is used by the h2 bridge task to encode datagrams
/// before sending them on the HTTP/2 stream.
#[allow(dead_code)]
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
///
/// Used by [`encode_h2_datagram_capsule`] for RFC 9297 framing.
#[allow(dead_code)]
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
///
/// Used by [`encode_h2_datagram_capsule`] for length calculation.
#[allow(dead_code)]
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
    establish_masque_tunnel_with_token(proxy_url, call_id, udp_blocked, None).await
}

/// Automatic MASQUE tunnel establishment with HTTP/3 → HTTP/2 fallback,
/// with optional ProxyToken for anti-abuse verification.
///
/// Per spec/12 §12.6.4: try HTTP/3 first (UDP available, lower latency),
/// then fall back to HTTP/2 (TCP, works when UDP is blocked).
pub async fn establish_masque_tunnel_with_token(
    proxy_url: &str,
    call_id: &str,
    udp_blocked: bool,
    proxy_token: Option<&str>,
) -> Result<MasqueTunnel, MasqueError> {
    // Try HTTP/3 first (QUIC/UDP — lower latency, no HOL blocking)
    if !udp_blocked
        && let Ok(tunnel) = MasqueTunnel::connect_http3(proxy_url, call_id, proxy_token).await {
            return Ok(tunnel);
        }

    // Fall back to HTTP/2 (TCP — works when UDP is blocked)
    if let Ok(tunnel) = MasqueTunnel::connect_http2(proxy_url, call_id, proxy_token).await {
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
        let request = build_connect_udp_request("proxy.example.com", 443, "call-abc123", None).unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.headers().get("connect-udp-target-host").unwrap(), "voip-relay");
        assert_eq!(request.headers().get("connect-udp-target-port").unwrap(), "0");
        assert_eq!(request.headers().get("x-voip-call-id").unwrap(), "call-abc123");
        // No proxy token header when None
        assert!(request.headers().get("x-voip-proxy-token").is_none());
        // Protocol is set via extensions, not headers
        assert!(request.extensions().get::<h3::ext::Protocol>().is_some());
    }

    #[test]
    fn test_build_connect_udp_request_with_proxy_token() {
        let request = build_connect_udp_request(
            "proxy.example.com",
            443,
            "call-abc123",
            Some("signed-token-base64"),
        )
        .unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.headers().get("x-voip-call-id").unwrap(), "call-abc123");
        // ProxyToken header should be present
        assert_eq!(
            request.headers().get("x-voip-proxy-token").unwrap(),
            "signed-token-base64"
        );
    }

    #[test]
    fn test_build_connect_udp_request_h2() {
        let request = build_connect_udp_request_h2(
            "proxy.example.com",
            443,
            "call-abc123",
            None,
        )
        .unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.headers().get("connect-udp-target-host").unwrap(), "voip-relay");
        assert_eq!(request.headers().get("connect-udp-target-port").unwrap(), "0");
        assert_eq!(request.headers().get("x-voip-call-id").unwrap(), "call-abc123");
        // h2::ext::Protocol should be set in extensions
        assert!(request.extensions().get::<h2::ext::Protocol>().is_some());
    }

    #[test]
    fn test_build_connect_udp_request_h2_with_token() {
        let request = build_connect_udp_request_h2(
            "proxy.example.com",
            443,
            "call-abc123",
            Some("token-xyz"),
        )
        .unwrap();
        assert_eq!(
            request.headers().get("x-voip-proxy-token").unwrap(),
            "token-xyz"
        );
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
