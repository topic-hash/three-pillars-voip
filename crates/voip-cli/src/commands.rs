//! Command handlers for voip-cli.
//!
//! Each function corresponds to a clap subcommand and returns `anyhow::Result<()>`.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::identity;

/// `voip-cli init [--force]` — generate a new keypair and persist to disk.
pub async fn init(force: bool) -> Result<()> {
    let path = identity::identity_path()?;

    if path.exists() && !force {
        bail!(
            "identity already exists at {}. Use --force to overwrite (DESTRUCTIVE).",
            path.display()
        );
    }

    let id = identity::Identity::generate();
    identity::save(&id)?;

    println!("Generated new identity:");
    println!("  peer_id:      {}", id.peer_id);
    println!("  verifying_key: {}", id.verifying_key);
    println!("  saved to:     {}", path.display());
    println!();
    println!("Keep {} secret. Anyone with this file can impersonate you.",
        path.display());

    Ok(())
}

/// `voip-cli whoami` — print the current peer ID.
pub async fn whoami() -> Result<()> {
    let id = identity::load().context(
        "no identity found. Run `voip-cli init` first."
    )?;
    println!("{}", id.peer_id);
    Ok(())
}

/// Request body for POST /v1/peers.
#[derive(Debug, Serialize)]
struct RegisterPeerRequest {
    peer_id: String,
    display_name: String,
}

/// Response body from POST /v1/peers.
#[derive(Debug, Deserialize)]
struct RegisterPeerResponse {
    peer_id: String,
    jwt_token: String,
}

/// `voip-cli register <url>` — register self with a signaling server.
///
/// Sends `POST /v1/peers` with the local peer_id and display_name.
/// On success, stores the returned JWT in `~/.voip-cli/jwt.txt` and
/// prints the JWT.
pub async fn register(url: &str, display_name: &str) -> Result<()> {
    let id = identity::load().context(
        "no identity found. Run `voip-cli init` first."
    )?;

    let url = url.trim_end_matches('/');
    let endpoint = format!("{}/v1/peers", url);

    tracing::info!(%endpoint, peer_id = %id.peer_id, %display_name, "registering");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let body = RegisterPeerRequest {
        peer_id: id.peer_id.clone(),
        display_name: display_name.to_string(),
    };

    let resp = client
        .post(&endpoint)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {} failed", endpoint))?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!("register failed: HTTP {}: {}", status, text);
    }

    let parsed: RegisterPeerResponse = resp
        .json()
        .await
        .context("failed to parse register response")?;

    if parsed.peer_id != id.peer_id {
        bail!(
            "server returned mismatched peer_id: expected {}, got {}",
            id.peer_id,
            parsed.peer_id
        );
    }

    // Persist the JWT for use by future commands (listen, call).
    let jwt_path = identity::identity_path()?
        .parent()
        .ok_or_else(|| anyhow!("identity path has no parent"))?
        .join("jwt.txt");
    std::fs::write(&jwt_path, &parsed.jwt_token)
        .with_context(|| format!("failed to write JWT to {}", jwt_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&jwt_path, std::fs::Permissions::from_mode(0o600));
    }

    println!("Registered with signaling server: {}", url);
    println!("  peer_id: {}", parsed.peer_id);
    println!("  jwt:     {}", &parsed.jwt_token[..40.min(parsed.jwt_token.len())]);
    println!("    ...");
    println!("  jwt saved to: {}", jwt_path.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_request_serializes_correctly() {
        let req = RegisterPeerRequest {
            peer_id: "ab".repeat(32),
            display_name: "alice".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["peer_id"], "ab".repeat(32));
        assert_eq!(json["display_name"], "alice");
    }

    #[test]
    fn test_register_response_deserializes_correctly() {
        let json = serde_json::json!({
            "peer_id": "cd".repeat(32),
            "jwt_token": "eyJ.example.jwt",
        });
        let parsed: RegisterPeerResponse = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.peer_id, "cd".repeat(32));
        assert_eq!(parsed.jwt_token, "eyJ.example.jwt");
    }

    #[test]
    fn test_register_response_requires_jwt_token_field() {
        // Missing jwt_token must fail.
        let json = serde_json::json!({
            "peer_id": "cd".repeat(32),
        });
        let result: Result<RegisterPeerResponse, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_register_response_requires_peer_id_field() {
        let json = serde_json::json!({
            "jwt_token": "eyJ.example.jwt",
        });
        let result: Result<RegisterPeerResponse, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }
}
