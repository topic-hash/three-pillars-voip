//! Cryptographic utilities for the VoIP system.
//!
//! Provides Ed25519 key generation, signing, verification, and
//! Connection ID generation as specified in spec/08 §8.7.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// The size of a QUIC Connection ID in bytes (spec/08 §8.7.1).
pub const CONNECTION_ID_SIZE: usize = 12;

/// Generate a 12-byte CSPRNG Connection ID for QUIC hole punching.
///
/// Per spec/08 §8.7.1: The caller generates a 12-byte Connection ID
/// using a CSPRNG. The probability of collision is < 10^-20 for any
/// reasonable number of concurrent calls.
///
/// # Security
///
/// - Uses `OsRng` which is a CSPRNG provided by the operating system.
/// - The Connection ID is sent over TLS 1.3, so it is not visible to
///   network observers.
/// - The Connection ID is single-use — it identifies one call.
pub fn generate_connection_id() -> [u8; CONNECTION_ID_SIZE] {
    let mut id = [0u8; CONNECTION_ID_SIZE];
    // Use fill_bytes from OsRng for CSPRNG
    use rand::RngCore;
    OsRng.fill_bytes(&mut id);
    id
}

/// Generate a new Ed25519 signing key pair.
///
/// Returns the signing key (private) and verifying key (public).
/// The verifying key is used as the basis for the peer ID.
///
/// # Security
///
/// - Uses `OsRng` which is a CSPRNG provided by the operating system.
/// - The signing key must be stored securely and never transmitted.
/// - The verifying key can be shared publicly.
pub fn generate_ed25519_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Derive a peer ID from an Ed25519 public key.
///
/// The peer ID is the hex-encoded representation of the verifying key
/// (public key). Per spec/08 §8.6.1, the `sub` claim in the JWT is
/// the peer ID, and the `pub_key` claim is also the hex-encoded public key.
///
/// # Example
///
/// ```
/// use voip_core::crypto::{generate_ed25519_keypair, peer_id_from_public_key};
///
/// let (signing_key, verifying_key) = generate_ed25519_keypair();
/// let peer_id = peer_id_from_public_key(&verifying_key);
/// assert_eq!(peer_id.len(), 64); // 32 bytes hex-encoded = 64 chars
/// ```
pub fn peer_id_from_public_key(pk: &VerifyingKey) -> String {
    hex::encode(pk.to_bytes())
}

/// Sign DHT record data with an Ed25519 signing key.
///
/// Per spec/11 §11.9: All DHT records are signed by the peer's Ed25519
/// private key. Consumers verify before trusting.
///
/// # Arguments
///
/// * `key` - The signing key (private key) to sign with
/// * `data` - The data to sign (typically the serialized proto message
///   without the signature field)
///
/// # Returns
///
/// The Ed25519 signature over the data.
pub fn sign_dht_record(key: &SigningKey, data: &[u8]) -> Signature {
    key.sign(data)
}

/// Verify a DHT record signature.
///
/// Per spec/11 §11.9: Consumers verify before trusting DHT records.
///
/// # Arguments
///
/// * `pk` - The verifying key (public key) to verify against
/// * `data` - The data that was signed
/// * `sig` - The signature to verify
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise.
pub fn verify_dht_record(pk: &VerifyingKey, data: &[u8], sig: &Signature) -> bool {
    pk.verify(data, sig).is_ok()
}

/// Hex encoding/decoding utilities.
///
/// Simple implementation to avoid an external dependency.
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    /// Encode a byte slice as a lowercase hex string.
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }

    /// Decode a hex string to bytes.
    ///
    /// Returns `None` if the string contains invalid hex characters
    /// or has an odd length.
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 {
            return None;
        }

        let mut bytes = Vec::with_capacity(s.len() / 2);
        for chunk in s.as_bytes().chunks(2) {
            let high = char_from_hex(chunk[0])?;
            let low = char_from_hex(chunk[1])?;
            bytes.push((high << 4) | low);
        }
        Some(bytes)
    }

    fn char_from_hex(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_length() {
        let id = generate_connection_id();
        assert_eq!(id.len(), CONNECTION_ID_SIZE);
    }

    #[test]
    fn test_connection_id_uniqueness() {
        let id1 = generate_connection_id();
        let id2 = generate_connection_id();
        // Extremely unlikely to collide with CSPRNG
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_ed25519_keypair() {
        let (sk, pk) = generate_ed25519_keypair();

        // Sign and verify
        let data = b"hello world";
        let sig = sign_dht_record(&sk, data);
        assert!(verify_dht_record(&pk, data, &sig));
    }

    #[test]
    fn test_ed25519_wrong_key_fails() {
        let (sk1, _pk1) = generate_ed25519_keypair();
        let (_sk2, pk2) = generate_ed25519_keypair();

        let data = b"hello world";
        let sig = sign_dht_record(&sk1, data);
        // Verify with wrong key should fail
        assert!(!verify_dht_record(&pk2, data, &sig));
    }

    #[test]
    fn test_ed25519_wrong_data_fails() {
        let (sk, pk) = generate_ed25519_keypair();

        let data = b"hello world";
        let sig = sign_dht_record(&sk, data);
        // Verify with wrong data should fail
        assert!(!verify_dht_record(&pk, b"wrong data", &sig));
    }

    #[test]
    fn test_peer_id_from_public_key() {
        let (_sk, pk) = generate_ed25519_keypair();
        let peer_id = peer_id_from_public_key(&pk);
        // Ed25519 public key is 32 bytes = 64 hex chars
        assert_eq!(peer_id.len(), 64);
        // Should be valid lowercase hex
        assert!(peer_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_peer_id_deterministic() {
        let (_sk, pk) = generate_ed25519_keypair();
        let id1 = peer_id_from_public_key(&pk);
        let id2 = peer_id_from_public_key(&pk);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let original = vec![0x00, 0x01, 0xab, 0xcd, 0xef, 0xff];
        let encoded = hex::encode(&original);
        assert_eq!(encoded, "0001abcdef ff".replace(" ", ""));
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
