//! Identity management for voip-cli.
//!
//! An `Identity` is an Ed25519 keypair persisted as JSON at
//! `$HOME/.voip-cli/identity.json`. The file contains:
//!   - `peer_id`:    64-char hex string (32-byte verifying key)
//!   - `signing_key`: 64-char hex string (32-byte signing key — SECRET)
//!   - `verifying_key`: 64-char hex string (32-byte public key)
//!
//! File permissions are 0600 to protect the signing key. The directory
//! `$HOME/.voip-cli/` is created with 0700 permissions.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use voip_core::crypto::{generate_ed25519_keypair, peer_id_from_public_key};

/// The persisted identity file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    /// The 64-char hex peer ID (derived from verifying_key).
    pub peer_id: String,
    /// The 64-char hex signing key (32 bytes). SECRET — never transmit.
    pub signing_key: String,
    /// The 64-char hex verifying key (32 bytes). Public.
    pub verifying_key: String,
}

impl Identity {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        let (sk, vk) = generate_ed25519_keypair();
        let peer_id = peer_id_from_public_key(&vk);
        Self {
            peer_id,
            signing_key: hex::encode(sk.to_bytes()),
            verifying_key: hex::encode(vk.to_bytes()),
        }
    }

    /// Decode the signing key into the ed25519-dalek type.
    pub fn signing_key(&self) -> Result<SigningKey> {
        let bytes: [u8; 32] = hex::decode(&self.signing_key)
            .map_err(|e| anyhow!("invalid signing_key hex: {e}"))?
            .try_into()
            .map_err(|_| anyhow!("signing_key must be 32 bytes"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    /// Decode the verifying key into the ed25519-dalek type.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let bytes: [u8; 32] = hex::decode(&self.verifying_key)
            .map_err(|e| anyhow!("invalid verifying_key hex: {e}"))?
            .try_into()
            .map_err(|_| anyhow!("verifying_key must be 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes).map_err(|e| anyhow!("invalid verifying key: {e}"))
    }
}

/// Return the path to the identity file: `$HOME/.voip-cli/identity.json`.
///
/// Errors if `$HOME` is not set.
pub fn identity_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("$HOME not set"))?;
    Ok(home.join(".voip-cli").join("identity.json"))
}

/// Load the identity from disk. Errors if the file does not exist.
pub fn load() -> Result<Identity> {
    let path = identity_path()?;
    load_from(&path)
}

/// Load the identity from a specific path. Errors if the file does not exist.
pub fn load_from(path: &Path) -> Result<Identity> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read identity at {}", path.display()))?;
    let id: Identity = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse identity at {}", path.display()))?;
    Ok(id)
}

/// Save the identity to disk, creating the parent directory if needed.
///
/// File permissions are 0600 (read/write by owner only) to protect the
/// signing key. The parent directory is created with 0700 permissions.
pub fn save(identity: &Identity) -> Result<()> {
    save_to(identity, &identity_path()?)
}

/// Save the identity to a specific path.
pub fn save_to(identity: &Identity, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create directory {}", parent.display())
        })?;
        // Set directory permissions to 0700 on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }

    let json = serde_json::to_string_pretty(identity)
        .context("failed to serialize identity")?;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open {} for writing", path.display()))?;
    file.write_all(json.as_bytes())
        .with_context(|| format!("failed to write identity to {}", path.display()))?;

    Ok(())
}

/// Check whether an identity file exists at the default path.
pub fn exists() -> bool {
    identity_path().map(|p| p.exists()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_identity_generate_produces_valid_keys() {
        let id = Identity::generate();
        assert_eq!(id.peer_id.len(), 64, "peer_id must be 64 hex chars");
        assert_eq!(id.signing_key.len(), 64, "signing_key must be 64 hex chars");
        assert_eq!(id.verifying_key.len(), 64, "verifying_key must be 64 hex chars");

        // Decoding must work
        let sk = id.signing_key().expect("signing_key decodes");
        let vk = id.verifying_key().expect("verifying_key decodes");

        // The peer_id must match the hex of the verifying key
        assert_eq!(id.peer_id, hex::encode(vk.to_bytes()));

        // The signing key's verifying key must match
        assert_eq!(sk.verifying_key().to_bytes(), vk.to_bytes());
    }

    #[test]
    fn test_identity_generate_is_random() {
        // Two consecutive generations must produce different keys.
        let a = Identity::generate();
        let b = Identity::generate();
        assert_ne!(a.signing_key, b.signing_key, "signing keys must differ");
        assert_ne!(a.peer_id, b.peer_id, "peer IDs must differ");
    }

    #[test]
    fn test_identity_save_and_load_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");

        let original = Identity::generate();
        save_to(&original, &path).expect("save");

        // File must exist
        assert!(path.exists(), "identity file must exist after save");

        // File must have a valid JSON structure
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"peer_id\""));
        assert!(contents.contains("\"signing_key\""));
        assert!(contents.contains("\"verifying_key\""));

        // Loading must return the same identity
        let loaded = load_from(&path).expect("load");
        assert_eq!(loaded, original, "loaded identity must match saved");
    }

    #[test]
    fn test_identity_load_missing_file_errors() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist.json");
        let result = load_from(&path);
        assert!(result.is_err(), "loading a missing file must error");
    }

    #[test]
    fn test_identity_load_corrupt_json_errors() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");
        std::fs::write(&path, b"not json").unwrap();
        let result = load_from(&path);
        assert!(result.is_err(), "loading corrupt JSON must error");
    }

    #[test]
    fn test_identity_signing_key_decodes() {
        let id = Identity::generate();
        let sk = id.signing_key().expect("signing key decodes");
        // Signing a message and verifying with the public key must work.
        use ed25519_dalek::{Signer, Verifier};
        let msg = b"hello world";
        let sig = sk.sign(msg);
        let vk = id.verifying_key().expect("verifying key decodes");
        assert!(vk.verify(msg, &sig).is_ok(), "signature must verify");
    }
}
