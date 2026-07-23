//! voip-cli: command-line interface for the Three Pillars VoIP client.
//!
//! Wave 1 deliverables:
//!   - `voip-cli init`         Generate a new Ed25519 keypair and persist to disk
//!   - `voip-cli whoami`       Print the current peer ID (derived from persisted keypair)
//!   - `voip-cli register <url>`  Register self with a signaling server, receive JWT
//!
//! The keypair is stored at `$HOME/.voip-cli/identity.json` containing the
//! hex-encoded 32-byte signing key + 32-byte verifying key + derived peer_id.
//! File permissions are 0600 to protect the private key.

mod identity;
mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "voip-cli",
    version,
    about = "Three Pillars VoIP — P2P client",
    long_about = "Command-line client for the Three Pillars VoIP system.\n\
                  Wave 1: identity management + signaling registration."
)]
struct Cli {
    /// Increase verbosity (can be repeated: -v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new Ed25519 keypair and persist to disk.
    Init {
        /// Overwrite existing identity if present (DESTRUCTIVE).
        #[arg(long)]
        force: bool,
    },
    /// Print the current peer ID, derived from the persisted keypair.
    Whoami,
    /// Register self with a signaling server and store the issued JWT.
    Register {
        /// Signaling server base URL (e.g., http://127.0.0.1:8443).
        url: String,
        /// Display name to register under.
        #[arg(short, long, default_value = "voip-cli-peer")]
        display_name: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = match cli.verbose {
        0 => "voip_cli=info,voip_client=warn",
        1 => "voip_cli=debug,voip_client=info",
        _ => "voip_cli=trace,voip_client=debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| filter.into()),
        )
        .with_target(true)
        .init();

    match cli.command {
        Commands::Init { force } => commands::init(force).await,
        Commands::Whoami => commands::whoami().await,
        Commands::Register { url, display_name } => {
            commands::register(&url, &display_name).await
        }
    }
}
