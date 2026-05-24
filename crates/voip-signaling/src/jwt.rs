//! JWT creation and verification using Ed25519 (spec/08 §8.6).
//!
//! The signaling server signs JWTs with its Ed25519 private key.
//! Clients connect via WebSocket with `?token=<jwt>`.
//! Claims: sub (peer_id), iat, exp, pub_key.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::SignalingError;

/// JWT claims structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Peer ID (hex-encoded Ed25519 public key)
    pub sub: String,
    /// Issued at (unix seconds)
    pub iat: u64,
    /// Expiration time (unix seconds)
    pub exp: u64,
    /// Not-before time (unix seconds)
    pub nbf: u64,
    /// Ed25519 public key (hex-encoded)
    pub pub_key: String,
}

/// Custom JWT format using Ed25519 signatures.
///
/// Format: `header.payload.signature` where:
/// - header = base64url({"alg":"EdDSA","typ":"JWT"})
/// - payload = base64url(json(claims))
/// - signature = Ed25519 signature over `header.payload`
///
/// We implement this manually instead of using a JWT crate because
/// most JWT crates only support HMAC/ECDSA/RSA, not Ed25519 directly.
const JWT_HEADER: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";

/// Create a JWT token signed with the server's Ed25519 signing key.
///
/// # Arguments
/// * `signing_key` - The server's Ed25519 signing key
/// * `peer_id` - The peer ID (hex-encoded public key) to issue the token for
/// * `expiry_secs` - How many seconds until the token expires
pub fn create_jwt(
    signing_key: &SigningKey,
    peer_id: &str,
    expiry_secs: u64,
) -> std::result::Result<String, SignalingError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let claims = JwtClaims {
        sub: peer_id.to_owned(),
        iat: now,
        exp: now + expiry_secs,
        nbf: now,
        pub_key: peer_id.to_owned(),
    };

    let payload_json = serde_json::to_string(&claims)
        .map_err(|e| SignalingError::Internal(format!("failed to serialize claims: {}", e)))?;

    let payload_b64 = base64url_encode(payload_json.as_bytes());
    let signing_input = format!("{}.{}", JWT_HEADER, payload_b64);

    use ed25519_dalek::Signer;
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = base64url_encode(signature.to_bytes().as_slice());

    Ok(format!("{}.{}.{}", JWT_HEADER, payload_b64, sig_b64))
}

/// Verify a JWT token using the server's Ed25519 verifying key.
///
/// Returns the decoded claims if the signature is valid and the token
/// has not expired.
pub fn verify_jwt(
    verifying_key: &VerifyingKey,
    token: &str,
) -> std::result::Result<JwtClaims, SignalingError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(SignalingError::InvalidJwt("invalid JWT format".to_owned()));
    }

    let header = parts[0];
    let payload_b64 = parts[1];
    let sig_b64 = parts[2];

    // Verify header
    if header != JWT_HEADER {
        return Err(SignalingError::InvalidJwt("invalid JWT header".to_owned()));
    }

    // Decode signature
    let sig_bytes = base64url_decode(sig_b64)
        .map_err(|e| SignalingError::InvalidJwt(format!("invalid signature encoding: {}", e)))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| SignalingError::InvalidJwt("invalid signature length".to_owned()))?;
    let signature = Signature::from_bytes(&sig_array);

    // Verify signature
    let signing_input = format!("{}.{}", header, payload_b64);
    use ed25519_dalek::Verifier;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| SignalingError::InvalidJwt("invalid JWT signature".to_owned()))?;

    // Decode payload
    let payload_bytes = base64url_decode(payload_b64)
        .map_err(|e| SignalingError::InvalidJwt(format!("invalid payload encoding: {}", e)))?;
    let claims: JwtClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| SignalingError::InvalidJwt(format!("invalid claims JSON: {}", e)))?;

    // Check expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if claims.exp < now {
        return Err(SignalingError::InvalidJwt("token expired".to_owned()));
    }

    // Verify sub == pub_key: the peer ID IS the hex-encoded public key
    if claims.sub != claims.pub_key {
        return Err(SignalingError::InvalidJwt("sub claim does not match pub_key claim".to_owned()));
    }

    // Verify not-before time
    if claims.nbf > now {
        return Err(SignalingError::InvalidJwt("token not yet valid".to_owned()));
    }

    Ok(claims)
}

/// Base64url encode without padding.
fn base64url_encode(data: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };

        result.push(CHARSET[((b0 >> 2) & 0x3F) as usize] as char);

        if i + 1 < data.len() {
            result.push(CHARSET[(((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)) as usize] as char);
        } else {
            result.push(CHARSET[((b0 & 0x03) << 4) as usize] as char);
            break;
        }

        if i + 2 < data.len() {
            result.push(CHARSET[(((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)) as usize] as char);
            result.push(CHARSET[(b2 & 0x3F) as usize] as char);
        } else {
            result.push(CHARSET[((b1 & 0x0F) << 2) as usize] as char);
            break;
        }

        i += 3;
    }
    result
}

/// Base64url decode without padding.
fn base64url_decode(input: &str) -> std::result::Result<Vec<u8>, String> {
    const DECODE_TABLE: [i8; 256] = {
        let mut table = [-1i8; 256];
        let mut i = 0u8;
        loop {
            if i >= 65 && i <= 90 {
                table[i as usize] = (i - 65) as i8;
            } else if i >= 97 && i <= 122 {
                table[i as usize] = (i - 97 + 26) as i8;
            } else if i >= 48 && i <= 57 {
                table[i as usize] = (i - 48 + 52) as i8;
            } else if i == 45 {
                table[i as usize] = 62;
            } else if i == 95 {
                table[i as usize] = 63;
            }
            if i == 255 {
                break;
            }
            i += 1;
        }
        table
    };

    let input = input.trim_end_matches('=');
    let input_bytes = input.as_bytes();
    let mut result = Vec::with_capacity(input.len() * 3 / 4);

    let mut buffer: u32 = 0;
    let mut bits = 0u32;

    for &byte in input_bytes {
        let val = DECODE_TABLE[byte as usize];
        if val < 0 {
            return Err(format!("invalid base64url character: {:?}", byte as char));
        }
        buffer = (buffer << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_jwt_create_and_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let peer_id = voip_core::crypto::peer_id_from_public_key(&verifying_key);

        let token = create_jwt(&signing_key, &peer_id, 3600).unwrap();
        let claims = verify_jwt(&verifying_key, &token).unwrap();

        assert_eq!(claims.sub, peer_id);
        assert_eq!(claims.pub_key, peer_id);
    }

    #[test]
    fn test_jwt_expired() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let peer_id = voip_core::crypto::peer_id_from_public_key(&verifying_key);

        // Create a token that expired 10 seconds ago
        // We manually construct the claims with an expired timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let claims = JwtClaims {
            sub: peer_id.clone(),
            iat: now - 100,
            exp: now - 10, // expired 10 seconds ago
            nbf: now - 100,
            pub_key: peer_id.clone(),
        };

        let payload_json = serde_json::to_string(&claims).unwrap();
        let payload_b64 = crate::jwt::base64url_encode(payload_json.as_bytes());
        let signing_input = format!("{}.{}", JWT_HEADER, payload_b64);

        use ed25519_dalek::Signer;
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = crate::jwt::base64url_encode(signature.to_bytes().as_slice());

        let token = format!("{}.{}.{}", JWT_HEADER, payload_b64, sig_b64);

        let result = verify_jwt(&verifying_key, &token);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_wrong_key() {
        let signing_key1 = SigningKey::generate(&mut OsRng);
        let verifying_key2 = SigningKey::generate(&mut OsRng).verifying_key();
        let peer_id = voip_core::crypto::peer_id_from_public_key(&signing_key1.verifying_key());

        let token = create_jwt(&signing_key1, &peer_id, 3600).unwrap();
        let result = verify_jwt(&verifying_key2, &token);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_invalid_format() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let result = verify_jwt(&verifying_key, "not.a.valid.jwt.token");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"hello world 12345";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_base64url_empty() {
        let data = b"";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_jwt_not_yet_valid() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let peer_id = voip_core::crypto::peer_id_from_public_key(&verifying_key);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create a token with nbf in the future
        let claims = JwtClaims {
            sub: peer_id.clone(),
            iat: now - 100,
            exp: now + 3600,
            nbf: now + 3600, // not valid for another hour
            pub_key: peer_id.clone(),
        };

        let payload_json = serde_json::to_string(&claims).unwrap();
        let payload_b64 = crate::jwt::base64url_encode(payload_json.as_bytes());
        let signing_input = format!("{}.{}", JWT_HEADER, payload_b64);

        use ed25519_dalek::Signer;
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = crate::jwt::base64url_encode(signature.to_bytes().as_slice());

        let token = format!("{}.{}.{}", JWT_HEADER, payload_b64, sig_b64);

        let result = verify_jwt(&verifying_key, &token);
        assert!(result.is_err());
        match result {
            Err(SignalingError::InvalidJwt(msg)) => {
                assert!(msg.contains("not yet valid"), "Expected 'not yet valid' error, got: {}", msg);
            }
            _ => panic!("Expected InvalidJwt error"),
        }
    }

    #[test]
    fn test_jwt_sub_pubkey_mismatch() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let peer_id = voip_core::crypto::peer_id_from_public_key(&verifying_key);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create a token where sub != pub_key
        let claims = JwtClaims {
            sub: "different_peer_id".to_string(),
            iat: now,
            exp: now + 3600,
            nbf: now,
            pub_key: peer_id.clone(),
        };

        let payload_json = serde_json::to_string(&claims).unwrap();
        let payload_b64 = crate::jwt::base64url_encode(payload_json.as_bytes());
        let signing_input = format!("{}.{}", JWT_HEADER, payload_b64);

        use ed25519_dalek::Signer;
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = crate::jwt::base64url_encode(signature.to_bytes().as_slice());

        let token = format!("{}.{}.{}", JWT_HEADER, payload_b64, sig_b64);

        let result = verify_jwt(&verifying_key, &token);
        assert!(result.is_err());
    }

    #[test]
    fn test_base64url_single_byte() {
        let data = b"a";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_jwt_not_yet_valid() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let peer_id = voip_core::crypto::peer_id_from_public_key(&verifying_key);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create a token with nbf in the future
        let claims = JwtClaims {
            sub: peer_id.clone(),
            iat: now - 100,
            exp: now + 3600,
            nbf: now + 3600, // not valid for another hour
            pub_key: peer_id.clone(),
        };

        let payload_json = serde_json::to_string(&claims).unwrap();
        let payload_b64 = crate::jwt::base64url_encode(payload_json.as_bytes());
        let signing_input = format!("{}.{}", JWT_HEADER, payload_b64);

        use ed25519_dalek::Signer;
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = crate::jwt::base64url_encode(signature.to_bytes().as_slice());

        let token = format!("{}.{}.{}", JWT_HEADER, payload_b64, sig_b64);

        let result = verify_jwt(&verifying_key, &token);
        assert!(result.is_err());
        match result {
            Err(SignalingError::InvalidJwt(msg)) => {
                assert!(msg.contains("not yet valid"), "expected 'not yet valid' error, got: {}", msg);
            }
            _ => panic!("expected InvalidJwt error"),
        }
    }
}
