//! Shared TLS utilities for development and testing.
//!
//! Provides a no-op certificate verifier used during development
//! and for self-signed DHT-verified certificates. In production,
//! the signaling server and MASQUE proxies present valid TLS
//! certificates verified against the system trust store.

/// A no-op certificate verifier for development.
///
/// In production, the signaling server and MASQUE proxies present valid
/// TLS certificates verified against the system trust store. This verifier
/// is used during development and for self-signed DHT-verified certificates
/// (trust-on-first-use model via DHT).
///
/// # Safety
///
/// This verifier accepts ANY certificate without validation.
/// It MUST NOT be used in production without additional
/// application-level verification (e.g., DHT trust-on-first-use,
/// or pinned certificate hashes).
#[derive(Debug)]
pub struct NoVerifier;

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
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Create a rustls ClientConfig that skips certificate verification.
///
/// Used for development and DHT trust-on-first-use certificate validation.
/// The `dangerous()` API is required because we need to accept self-signed
/// certificates from volunteer MASQUE proxies.
pub fn dangerous_client_config() -> Result<rustls::ClientConfig, rustls::Error> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerifier))
        .with_no_client_auth();
    Ok(config)
}

/// Create a quinn ClientConfig with dangerous TLS and datagram support.
///
/// Configures QUIC datagrams (RFC 9221) for MoQ media and sets
/// idle timeout and datagram buffer sizes.
pub fn dangerous_quinn_client_config() -> Result<quinn::ClientConfig, String> {
    let rustls_config = dangerous_client_config()
        .map_err(|e| format!("TLS config: {}", e))?;

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|e| format!("QuicClientConfig: {}", e))?;

    let mut client_config = quinn::ClientConfig::new(std::sync::Arc::new(quic_config));

    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65536));
    transport.datagram_send_buffer_size(65536);

    let idle_timeout = std::time::Duration::from_secs(30);
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(idle_timeout).unwrap(),
    ));

    client_config.transport_config(std::sync::Arc::new(transport));

    Ok(client_config)
}

/// Create a quinn ServerConfig with a self-signed certificate for loopback use.
///
/// Used by the HTTP/2 MASQUE loopback QUIC pair to create a local
/// server endpoint. The self-signed certificate is generated with rcgen
/// and accepted by the dangerous client verifier.
///
/// # Panics
///
/// Will not panic — returns errors as `String`.
pub fn dangerous_quinn_server_config() -> Result<quinn::ServerConfig, String> {
    // Generate a self-signed certificate for the loopback endpoint
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| format!("rcgen key pair: {}", e))?;

    let cert = rcgen::CertificateParams::new(vec!["voip-masque-loopback".to_string()])
        .and_then(|params| params.self_signed(&key_pair))
        .map_err(|e| format!("rcgen cert: {}", e))?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    let rustls_cert = rustls::pki_types::CertificateDer::from(cert_der);
    let private_key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| format!("private key: {}", e))?;

    let server_config = quinn::ServerConfig::with_single_cert(
        vec![rustls_cert],
        private_key,
    )
    .map_err(|e| format!("server config: {}", e))?;

    Ok(server_config)
}
