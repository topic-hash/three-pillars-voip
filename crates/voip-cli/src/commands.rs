//! Command handlers for voip-cli.
//!
//! Each function corresponds to a clap subcommand and returns `anyhow::Result<()>`.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use voip_client::peer::{Peer, PeerConfig, PeerIdentity};

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

/// `voip-cli listen <url> [--listen ADDR]` — register with signaling
/// and accept incoming P2P QUIC connections.
///
/// Wave 2 behavior: for each incoming connection, accepts a bidi
/// stream, reads bytes until the stream ends, prints them as UTF-8
/// (lossy), and replies with a single line "ack: <n>".
/// Wave 3 will replace this with a proper ping/pong protocol.
pub async fn listen(url: &str, display_name: &str, listen_addr: &str) -> Result<()> {
    let id = identity::load().context("no identity found. Run `voip-cli init` first.")?;
    let peer_identity = PeerIdentity::from_hex(&id.signing_key, &id.verifying_key)
        .context("failed to decode identity keypair")?;

    let cfg = PeerConfig {
        signaling_url: url.to_string(),
        display_name: display_name.to_string(),
        listen_addr: listen_addr.to_string(),
    };

    let peer = Peer::new(peer_identity, cfg)?;
    let local = peer.local_addr()?;
    println!("Listening for P2P QUIC on {}", local);
    println!("Peer ID: {}", peer.peer_id());

    // Register with signaling server
    match peer.register().await {
        Ok(resp) => {
            println!("Registered with {} as '{}'", url, resp.peer_id);
        }
        Err(e) => {
            tracing::warn!(error = %e, "registration failed (continuing in listen-only mode)");
            eprintln!("warning: registration failed: {}", e);
            eprintln!("(continuing in listen-only mode — calls from peers cannot find us without registration)");
        }
    }

    println!("Waiting for incoming connections. Press Ctrl+C to stop.");

    // Spawn a counter for ack replies
    use std::sync::atomic::{AtomicU64, Ordering};
    let counter = std::sync::Arc::new(AtomicU64::new(0));

    peer.run_accept_loop(move |conn| {
        let counter = counter.clone();
        async move {
            // Accept a single bidi stream from the connecting peer
            match conn.accept_bi().await {
                Ok((mut send, mut recv)) => {
                    use tokio::io::AsyncWriteExt;
                    let mut buf = vec![0u8; 4096];
                    let n = match recv.read(&mut buf).await {
                        Ok(Some(n)) => n,
                        Ok(None) => {
                            // Stream ended with no data
                            let remote = conn.remote_address();
                            println!("[{}] connected but sent no data", remote);
                            return;
                        }
                        Err(e) => {
                            eprintln!("read error: {}", e);
                            return;
                        }
                    };
                    let text = String::from_utf8_lossy(&buf[..n]);
                    let remote = conn.remote_address();
                    println!("[{}] said: {}", remote, text.trim_end());

                    // Reply with "ack: <n>"
                    let n = counter.fetch_add(1, Ordering::SeqCst);
                    let reply = format!("ack: {}\n", n);
                    if let Err(e) = send.write_all(reply.as_bytes()).await {
                        eprintln!("reply write error: {}", e);
                    }
                    // Flush the reply to the wire before finishing the stream.
                    let _ = send.flush().await;
                    let _ = send.finish();
                    // Give the QUIC layer a moment to actually transmit
                    // the reply before the spawned task drops the
                    // connection (which would close it abruptly).
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(e) => {
                    eprintln!("accept_bi error: {}", e);
                }
            }
        }
    })
    .await?;

    println!("Shutting down.");
    Ok(())
}

/// `voip-cli call <url> <peer_id>` — place a P2P call to another peer.
///
/// Wave 3 implementation:
///   1. Load identity, build PeerIdentity + PeerConfig (caller binds an
///      ephemeral QUIC endpoint on 0.0.0.0:0 by default)
///   2. Register with the signaling server (so the callee can see us)
///   3. Look up the target peer via GET /v1/peers/{peer_id}
///   4. Resolve the target's QUIC address:
///      - If --direct-addr is given, use it verbatim
///      - Else use the first ipv4_reflexive or ipv6_addresses from the
///        signaling record. If none, error out (target registered
///        without addresses).
///   5. Open a QUIC connection to the target via peer.endpoint().connect()
///   6. Open a bidi stream, send the message, read the reply, print it
///   7. Close the connection
pub async fn call(
    url: &str,
    peer_id: &str,
    message: &str,
    direct_addr: Option<String>,
    listen_addr: &str,
) -> Result<()> {
    let id = identity::load().context("no identity found. Run `voip-cli init` first.")?;
    let peer_identity = PeerIdentity::from_hex(&id.signing_key, &id.verifying_key)
        .context("failed to decode identity keypair")?;

    let cfg = PeerConfig {
        signaling_url: url.to_string(),
        display_name: format!("caller-{}", &id.peer_id[..8]),
        listen_addr: listen_addr.to_string(),
    };

    let peer = Peer::new(peer_identity, cfg)?;
    let local = peer.local_addr()?;
    println!("Caller bound on {}", local);
    println!("Our peer_id: {}", peer.peer_id());

    // Register with signaling
    peer.register().await.context("failed to register with signaling server")?;
    println!("Registered with {}", url);

    // Resolve target address
    let target_addr: String = if let Some(addr) = direct_addr {
        println!("Using --direct-addr {} (bypassing signaling lookup)", addr);
        addr
    } else {
        println!("Looking up peer {} via signaling...", peer_id);
        let record = peer.lookup_peer(peer_id).await
            .context("failed to look up peer via signaling")?;
        println!("Found peer: {} ({})", record.display_name, record.peer_id);

        let candidate = record
            .ipv6_addresses
            .first()
            .or_else(|| record.ipv4_reflexive.first())
            .cloned();
        match candidate {
            Some(addr) => {
                println!("Target address from signaling: {}", addr);
                addr
            }
            None => {
                bail!(
                    "peer {} registered with no addresses. Use --direct-addr <ip:port> to specify the target's QUIC address manually",
                    peer_id
                );
            }
        }
    };

    let target: std::net::SocketAddr = target_addr
        .parse()
        .with_context(|| format!("invalid target address: {}", target_addr))?;

    println!("Connecting to {} via QUIC...", target);

    // Set up the QUIC client config (dangerous / no cert verification,
    // matches the self-signed cert the listener generated via
    // tls::dangerous_quinn_server_config)
    let client_cfg = voip_client::tls::dangerous_quinn_client_config()
        .map_err(|e| anyhow!("failed to build QUIC client config: {}", e))?;

    // Endpoint::connect uses the endpoint's default client config, so
    // we need to set it on the peer's endpoint. Peer exposes endpoint()
    // — but endpoint.set_default_client_config takes ownership of
    // Endpoint. We need a different approach: clone the endpoint
    // (quinn::Endpoint is Clone) and set the default client config
    // on the clone.
    //
    // Actually, quinn::Endpoint::connect accepts a ClientConfig
    // directly via Endpoint::connect_with. We use that.
    use quinn::Endpoint;
    let mut endpoint_clone: Endpoint = peer.endpoint().clone();
    // We must set the default client config on the clone for connect()
    // to use our dangerous TLS config. set_default_client_config
    // returns the old config; we ignore it.
    endpoint_clone.set_default_client_config(client_cfg);

    let connect = endpoint_clone
        .connect(target, "voip-peer")
        .map_err(|e| anyhow!("failed to initiate QUIC connect to {}: {}", target, e))?;

    let conn = tokio::time::timeout(std::time::Duration::from_secs(10), connect)
        .await
        .map_err(|_| anyhow!("QUIC connect timeout (10s) to {}", target))?
        .map_err(|e| anyhow!("QUIC connect to {} failed: {}", target, e))?;

    println!("Connected to {} (remote: {})", target, conn.remote_address());

    // Open a bidi stream and send the message
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open bidi stream: {}", e))?;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let payload = format!("{}\n", message);
    send.write_all(payload.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to write message: {}", e))?;
    // Flush to make sure the data is on the wire before we read.
    send.flush()
        .await
        .map_err(|e| anyhow!("failed to flush send stream: {}", e))?;
    // Do NOT call send.finish() yet — closing the send side prematurely
    // can race with the callee's reply. Keep the stream bidirectionally
    // open until we have the reply.

    println!("Sent:     {:?}", message);

    // Read the reply
    let mut buf = vec![0u8; 4096];
    let n = match recv.read(&mut buf).await {
        Ok(Some(n)) => n,
        Ok(None) => {
            println!("(peer closed the stream without replying)");
            0
        }
        Err(e) => {
            bail!("failed to read reply: {}", e);
        }
    };
    if n > 0 {
        let reply = String::from_utf8_lossy(&buf[..n]);
        println!("Received: {:?}", reply.trim_end());
    }

    // Now close the send side cleanly.
    let _ = send.finish();
    // Close the connection
    conn.close(0u32.into(), b"call done");
    println!("Call complete.");
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
