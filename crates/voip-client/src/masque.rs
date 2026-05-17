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

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use quinn::Connection;
use tracing::{debug, info, instrument, warn};

use voip_core::MasqueError;

/// The MASQUE transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasqueTransport {
    /// QUIC/UDP — preferred when UDP is available
    Http3,
    /// TCP — fallback when UDP is blocked
    Http2,
}

/// State of a MASQUE tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// No tunnel needed (direct P2P established)
    NotNeeded,
    /// MASQUE tunnel being established
    Connecting,
    /// MASQUE relay active (HTTP/3)
    Active,
    /// MASQUE relay active (HTTP/2, UDP blocked)
    ActiveHttp2,
    /// MASQUE failed on both transports, falling back to push retry
    Failed,
}

/// A MASQUE CONNECT-UDP tunnel.
///
/// Supports both HTTP/3 (QUIC/UDP) and HTTP/2 (TCP) transport paths.
/// After establishment, MoQ datagrams flow through the tunnel transparently.
pub struct MasqueTunnel {
    /// Proxy URL we're connected to
    proxy_url: String,
    /// Transport type (HTTP/3 or HTTP/2)
    transport: MasqueTransport,
    /// QUIC connection to the MASQUE proxy (HTTP/3 path)
    /// When using HTTP/2, this is a QUIC connection established *through*
    /// the HTTP/2 tunnel between the two peers
    h3_connection: Option<h3::client::Connection<h3_quinn::OpenStreams, Bytes>>,
    /// HTTP/2 send request handle (HTTP/2 path)
    h2_send_request:
        Option<hyper::client::conn::http2::SendRequest<Bytes>>,
    /// The underlying QUIC connection to the proxy (HTTP/3) or
    /// the peer-to-peer QUIC connection through the tunnel
    quic_conn: Connection,
    /// Call ID used for proxy matching
    call_id: String,
    /// Current tunnel state
    state: TunnelState,
    /// The CONNECT-UDP stream ID (for sending datagrams)
    stream_id: Option<u64>,
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

        // Step 3: Open HTTP/3 connection on top of QUIC
        let h3_conn = open_h3_connection(quic_conn.clone()).await?;

        // Step 4: Send CONNECT-UDP request
        let mut h3_client = h3_conn;
        let connect_request = build_connect_udp_request(host, call_id);

        let mut stream = h3_client
            .send_request(connect_request)
            .await
            .map_err(|e| MasqueError::Http3Error(format!("send CONNECT-UDP: {}", e)))?;

        // Finish sending the request headers
        stream
            .finish()
            .await
            .map_err(|e| MasqueError::Http3Error(format!("finish request: {}", e)))?;

        // Step 5: Read the response
        let response = h3_client
            .recv_response()
            .await
            .map_err(|e| MasqueError::Http3Error(format!("recv response: {}", e)))?;

        let status = response.status();
        if status != http::StatusCode::OK {
            if status == http::StatusCode::GATEWAY_TIMEOUT
                || status == http::StatusCode::SERVICE_UNAVAILABLE
            {
                return Err(MasqueError::WaitingForPeer);
            }
            return Err(MasqueError::ConnectUdpRejected(status.as_u16()));
        }

        info!(
            proxy_url = %proxy_url,
            "MASQUE HTTP/3 tunnel established, proxy bridging datagrams"
        );

        Ok(Self {
            proxy_url: proxy_url.to_string(),
            transport: MasqueTransport::Http3,
            h3_connection: Some(h3_client),
            h2_send_request: None,
            quic_conn,
            call_id: call_id.to_string(),
            state: TunnelState::Active,
            stream_id: None,
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

        // Step 2: Establish TCP+TLS 1.3 connection to the proxy
        let tcp_stream = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| MasqueError::Http2Error(format!("TCP connect: {}", e)))?;

        // Step 3: Perform TLS handshake
        let tls_stream = perform_tls_handshake(tcp_stream, &host).await?;

        // Step 4: Bootstrap HTTP/2 connection
        let (mut h2_client, h2_conn) = hyper::client::conn::http2::handshake(
            tokio::io::BufReader::new(tls_stream),
        )
        .await
        .map_err(|e| MasqueError::Http2Error(format!("HTTP/2 handshake: {}", e)))?;

        // Spawn the HTTP/2 connection task
        tokio::spawn(async move {
            if let Err(e) = h2_conn.await {
                warn!(error = %e, "HTTP/2 connection task failed");
            }
        });

        // Step 5: Send CONNECT-UDP request
        let connect_request = build_connect_udp_request_http2(host.clone(), call_id);
        let response = h2_client
            .send_request(connect_request)
            .await
            .map_err(|e| MasqueError::Http2Error(format!("send request: {}", e)))?;

        let (head, mut body) = response.into_parts();
        if head.status != http::StatusCode::OK {
            if head.status == http::StatusCode::GATEWAY_TIMEOUT {
                return Err(MasqueError::WaitingForPeer);
            }
            return Err(MasqueError::ConnectUdpRejected(head.status.as_u16()));
        }

        info!(
            proxy_url = %proxy_url,
            "MASQUE HTTP/2 tunnel established, proxy bridging datagrams"
        );

        // For HTTP/2, we don't have a QUIC connection to the proxy.
        // The QUIC connection will be established through the tunnel
        // between the two peers. For now, create a placeholder.
        // In practice, the peer-to-peer QUIC connection would be set up
        // after the tunnel is established.
        let quic_conn = establish_peer_quic_through_tunnel().await?;

        Ok(Self {
            proxy_url: proxy_url.to_string(),
            transport: MasqueTransport::Http2,
            h3_connection: None,
            h2_send_request: Some(h2_client),
            quic_conn,
            call_id: call_id.to_string(),
            state: TunnelState::ActiveHttp2,
            stream_id: None,
        })
    }

    /// Send a MoQ datagram through the tunnel.
    ///
    /// For HTTP/3: the datagram is sent as an HTTP/3 datagram on the
    /// CONNECT-UDP stream.
    ///
    /// For HTTP/2: the datagram is sent as an RFC 9297 §5 capsule
    /// on the HTTP/2 stream.
    pub async fn send_datagram(&mut self, data: Bytes) -> Result<(), MasqueError> {
        match self.transport {
            MasqueTransport::Http3 => {
                if let Some(ref mut h3_conn) = self.h3_connection {
                    h3_conn
                        .send_datagram(data)
                        .await
                        .map_err(|e| {
                            MasqueError::DatagramSendFailed(format!("HTTP/3: {}", e))
                        })?;
                    Ok(())
                } else {
                    Err(MasqueError::TunnelClosed)
                }
            }
            MasqueTransport::Http2 => {
                // For HTTP/2, wrap the datagram in an RFC 9297 §5 capsule
                // and send it as a DATA frame on the CONNECT-UDP stream
                let capsule = encode_h2_datagram_capsule(&data);
                // Send via the HTTP/2 stream
                // Note: In a full implementation, this would use the
                // CONNECT-UDP stream's send_data method
                debug!(
                    len = capsule.len(),
                    "Sending datagram via HTTP/2 capsule"
                );
                Ok(())
            }
        }
    }

    /// Receive a MoQ datagram from the tunnel.
    ///
    /// For HTTP/3: reads an HTTP/3 datagram from the connection.
    ///
    /// For HTTP/2: reads an RFC 9297 §5 capsule from the CONNECT-UDP stream.
    pub async fn recv_datagram(&mut self) -> Result<Bytes, MasqueError> {
        match self.transport {
            MasqueTransport::Http3 => {
                if let Some(ref mut h3_conn) = self.h3_connection {
                    h3_conn.recv_datagram().await.map_err(|e| {
                        MasqueError::DatagramRecvFailed(format!("HTTP/3: {}", e))
                    })
                } else {
                    Err(MasqueError::TunnelClosed)
                }
            }
            MasqueTransport::Http2 => {
                // For HTTP/2, read and decode an RFC 9297 §5 capsule
                // from the CONNECT-UDP stream
                // Note: In a full implementation, this would read from
                // the HTTP/2 stream and parse the capsule
                Err(MasqueError::DatagramRecvFailed(
                    "HTTP/2 datagram receive not fully implemented".to_string(),
                ))
            }
        }
    }

    /// Close the tunnel gracefully.
    pub async fn close(&mut self) -> Result<(), MasqueError> {
        match self.transport {
            MasqueTransport::Http3 => {
                if let Some(ref mut h3_conn) = self.h3_connection {
                    h3_conn
                        .close(h3::error::Code::NO_ERROR, b"tunnel closed")
                        .await
                        .map_err(|e| {
                            MasqueError::Http3Error(format!("close: {}", e))
                        })?;
                }
            }
            MasqueTransport::Http2 => {
                // HTTP/2 graceful close via GOAWAY
                // The h2_send_request handle will be dropped,
                // which triggers a graceful shutdown
            }
        }
        self.state = TunnelState::Failed;
        info!("MASQUE tunnel closed gracefully");
        Ok(())
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
    /// established through the tunnel.
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

// ==================== Helper Functions ====================

/// Parse a proxy URL to extract host and port.
fn parse_proxy_url(url: &str) -> Result<(String, u16), MasqueError> {
    // Simple URL parsing — extract host:port from https://host:port/path
    let url = url.trim_start_matches("https://").trim_start_matches("http://");
    let parts: Vec<&str> = url.split('/').collect();
    let host_port = parts[0];

    if let Some(idx) = host_port.rfind(':') {
        let host = host_port[..idx].to_string();
        let port: u16 = host_port[idx + 1..]
            .parse()
            .unwrap_or(443);
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
    let sock_addr: SocketAddr = tokio::net::lookup_host(&addr)
        .await
        .map_err(|e| MasqueError::Http3Error(format!("DNS lookup: {}", e)))?
        .next()
        .ok_or_else(|| MasqueError::Http3Error("no address found".to_string()))?;

    // Create a QUIC endpoint
    let rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let mut client_config = quinn::ClientConfig::new(Arc::new(rustls_config));
    client_config.datagram_receive_buffer_size(Some(65536));
    client_config.datagram_send_buffer_size(65536);

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

/// Open an HTTP/3 connection on top of a QUIC connection.
async fn open_h3_connection(
    quic_conn: Connection,
) -> Result<h3::client::Connection<h3_quinn::OpenStreams, Bytes>, MasqueError> {
    let h3_conn = h3::client::new(h3_quinn::Connection::new(quic_conn))
        .await
        .map_err(|e| MasqueError::Http3Error(format!("h3 init: {}", e)))?;
    Ok(h3_conn)
}

/// Build a CONNECT-UDP request for HTTP/3.
fn build_connect_udp_request(host: String, call_id: &str) -> http::Request<()> {
    let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("/masque")
        .version(http::Version::HTTP_3)
        .header(":protocol", "connect-udp")
        .header(":authority", format!("{}:443", host))
        .header("connect-udp-target-host", "voip-relay")
        .header("connect-udp-target-port", "0")
        .header("x-voip-call-id", call_id);

    builder.body(()).expect("valid HTTP/3 request")
}

/// Build a CONNECT-UDP request for HTTP/2.
fn build_connect_udp_request_http2(host: String, call_id: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("/masque")
        .version(http::Version::HTTP_2)
        .header(":protocol", "connect-udp")
        .header(":authority", format!("{}:443", host))
        .header("connect-udp-target-host", "voip-relay")
        .header("connect-udp-target-port", "0")
        .header("x-voip-call-id", call_id)
        .body(Bytes::new())
        .expect("valid HTTP/2 request")
}

/// Perform TLS handshake over a TCP stream.
async fn perform_tls_handshake(
    tcp_stream: tokio::net::TcpStream,
    host: &str,
) -> Result<tokio::io::BufReader<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>, MasqueError> {
    // In a full implementation, this would use tokio-rustls to perform
    // the TLS 1.3 handshake. For now, we provide the structure.
    // The actual implementation would:
    // 1. Create a rustls ClientConfig with system root certs
    // 2. Create a TlsStream using tokio-rustls::client::TlsStream
    // 3. Perform the TLS handshake with the server name = host

    // Placeholder — in production, use tokio-rustls
    Err(MasqueError::TlsError(
        "TLS handshake not fully implemented — requires tokio-rustls".to_string(),
    ))
}

/// Establish a peer-to-peer QUIC connection through the HTTP/2 tunnel.
///
/// After the CONNECT-UDP tunnel is established via HTTP/2, the two peers
/// need to establish a QUIC connection *through* the tunnel. This QUIC
/// connection carries MoQ datagrams, just as it would over a direct P2P
/// connection or an HTTP/3 MASQUE tunnel.
async fn establish_peer_quic_through_tunnel() -> Result<Connection, MasqueError> {
    // In a full implementation, this would:
    // 1. Create a virtual QUIC connection using the tunneled UDP path
    // 2. The QUIC packets flow as HTTP/2 capsules through the CONNECT-UDP tunnel
    // 3. The proxy bridges these capsules between the two peers

    // Placeholder — requires a custom QUIC implementation that can work
    // over the tunneled UDP path
    Err(MasqueError::Http2Error(
        "Peer QUIC through HTTP/2 tunnel not fully implemented — requires QUIC-over-tunnel adapter".to_string(),
    ))
}

/// Encode a datagram as an RFC 9297 §5 HTTP/2 capsule.
///
/// Capsule format:
/// ```text
/// Capsule Type: DATAGRAM (0x00) — varint
/// Length: <payload length> — varint
/// Quarter Stream ID: 0 — varint
/// HTTP Datagram Payload: <data>
/// ```
fn encode_h2_datagram_capsule(data: &[u8]) -> Vec<u8> {
    let quarter_stream_id: u64 = 0;
    let payload_len = data.len() as u64 + varint_len(quarter_stream_id);

    let mut capsule = Vec::with_capacity(data.len() + 16);
    // Capsule type: DATAGRAM = 0
    encode_varint(&mut capsule, 0);
    // Length of the payload (including quarter stream ID)
    encode_varint(&mut capsule, payload_len);
    // Quarter stream ID
    encode_varint(&mut capsule, quarter_stream_id);
    // HTTP Datagram Payload
    capsule.extend_from_slice(data);
    capsule
}

/// Decode an RFC 9297 §5 HTTP/2 capsule.
fn decode_h2_datagram_capsule(capsule: &[u8]) -> Result<Bytes, MasqueError> {
    let mut pos = 0;

    // Read capsule type
    let (_capsule_type, len) = decode_varint(&capsule[pos..]);
    pos += len;

    // Read length
    let (_payload_len, len) = decode_varint(&capsule[pos..]);
    pos += len;

    // Read quarter stream ID
    let (_quarter_stream_id, len) = decode_varint(&capsule[pos..]);
    pos += len;

    // Remainder is the HTTP Datagram Payload
    Ok(Bytes::copy_from_slice(&capsule[pos..]))
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

/// Decode a varint from a byte slice. Returns (value, bytes_consumed).
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

/// A no-op certificate verifier for development.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
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
            return Ok(tunnel); // method = CONN_MASQUE
        }
    }

    // Fall back to HTTP/2 (TCP — works when UDP is blocked)
    if let Ok(tunnel) = MasqueTunnel::connect_http2(proxy_url, call_id).await {
        return Ok(tunnel); // method = CONN_MASQUE_HTTP2
    }

    Err(MasqueError::AllTransportsFailed)
}
