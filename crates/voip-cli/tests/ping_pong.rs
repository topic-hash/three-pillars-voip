//! Wave 3 integration test: P2P ping/pong over QUIC between two voip-cli peers.
//!
//! This test exercises the full Wave 3 stack:
//!   1. Spawn a voip-signaling-server on an ephemeral port
//!   2. Spawn a voip-cli listen (callee) on an ephemeral port
//!   3. Spawn a voip-cli call (caller) targeting the callee via --direct-addr
//!   4. Assert the caller received "ack: 0" from the callee
//!
//! Skips automatically if the voip-cli or voip-signaling-server binaries
//! are not present in target/debug/.
//!
//! Run with: cargo test --test ping_pong -- --nocapture --test-threads=1

use std::process::{Command, Stdio};
use std::time::Duration;

fn find_bin(name: &str) -> Option<std::path::PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    // crates/voip-cli -> ../.. -> workspace root -> target/debug
    let candidates = [
        std::path::PathBuf::from(&manifest_dir).join("..").join("..").join("target").join("debug").join(name),
        std::path::PathBuf::from(&manifest_dir).join("..").join("target").join("debug").join(name),
        std::path::PathBuf::from(&manifest_dir).join("target").join("debug").join(name),
    ];
    for c in &candidates {
        if c.exists() {
            return Some(c.clone());
        }
    }
    None
}

fn wait_for_port(addr: &str, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn pick_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("failed to bind ephemeral port")
        .local_addr()
        .expect("failed to read local_addr")
        .port()
}

#[test]
fn test_p2p_ping_pong_loopback() {
    let signaling_bin = find_bin("voip-signaling-server")
        .expect("voip-signaling-server binary not found; run `cargo build` first");
    let cli_bin = find_bin("voip-cli")
        .expect("voip-cli binary not found; run `cargo build -p voip-cli` first");

    // Signaling server uses the hardcoded default port 8443 in main.
    // (The LISTEN_ADDR env-var override is on an unmerged branch.)
    // The test therefore can't run in parallel with another instance
    // using 8443 — guarded by --test-threads=1.
    let signaling_addr = "127.0.0.1:8443".to_string();
    let signaling_url = format!("http://{}", signaling_addr);

    let callee_port = pick_port();
    let callee_addr = format!("127.0.0.1:{}", callee_port);

    let temp = tempfile::tempdir().expect("tempdir");
    let caller_home = temp.path().join("caller");
    let callee_home = temp.path().join("callee");
    std::fs::create_dir_all(&caller_home).unwrap();
    std::fs::create_dir_all(&callee_home).unwrap();

    // Make sure no stale server is on 8443
    {
        let _guard = std::net::TcpListener::bind(&signaling_addr)
            .expect("port 8443 is already in use; kill any stale voip-signaling-server");
        // Rebind succeeds above means port is free; _guard is dropped here
    }

    // Spawn signaling server
    let mut srv = Command::new(&signaling_bin)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn voip-signaling-server");

    assert!(
        wait_for_port(&signaling_addr, Duration::from_secs(10)),
        "signaling server failed to start on {}",
        signaling_addr
    );

    // Callee: init identity
    let status = Command::new(&cli_bin)
        .env("HOME", &callee_home)
        .args(["init"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("callee init failed");
    assert!(status.success(), "callee init failed");

    // Callee: get peer_id
    let callee_id_output = Command::new(&cli_bin)
        .env("HOME", &callee_home)
        .args(["whoami"])
        .output()
        .expect("callee whoami failed");
    let callee_peer_id = String::from_utf8_lossy(&callee_id_output.stdout)
        .trim()
        .to_string();
    assert_eq!(callee_peer_id.len(), 64, "callee peer_id must be 64 chars");

    // Spawn callee listen
    let callee_log = temp.path().join("callee.log");
    let callee_log_clone = callee_log.clone();
    let callee_home_clone = callee_home.clone();
    let signaling_url_clone = signaling_url.clone();
    let callee_addr_clone = callee_addr.clone();
    let cli_bin_clone = cli_bin.clone();
    let callee_thread = std::thread::spawn(move || {
        let _callee = Command::new(&cli_bin_clone)
            .env("HOME", &callee_home_clone)
            .env("RUST_LOG", "warn")
            .args(["listen", &signaling_url_clone, "--listen", &callee_addr_clone])
            .stdout(std::fs::File::create(&callee_log_clone).unwrap())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn voip-cli listen");
        std::mem::forget(_callee);
    });
    callee_thread.join().unwrap();

    // Wait for the listener to bind UDP
    std::thread::sleep(Duration::from_secs(2));

    // Caller: init identity
    let status = Command::new(&cli_bin)
        .env("HOME", &caller_home)
        .args(["init"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("caller init failed");
    assert!(status.success(), "caller init failed");

    // Caller places call
    let caller_output = Command::new(&cli_bin)
        .env("HOME", &caller_home)
        .env("RUST_LOG", "warn")
        .args([
            "call",
            &signaling_url,
            &callee_peer_id,
            "--direct-addr",
            &callee_addr,
            "--message",
            "ping",
        ])
        .output()
        .expect("caller call command failed to spawn");

    let caller_stdout = String::from_utf8_lossy(&caller_output.stdout).to_string();
    let caller_stderr = String::from_utf8_lossy(&caller_output.stderr).to_string();
    eprintln!("=== CALLER STDOUT ===\n{}", caller_stdout);
    eprintln!("=== CALLER STDERR ===\n{}", caller_stderr);

    assert!(caller_output.status.success(), "caller call did not exit cleanly");
    assert!(
        caller_stdout.contains("Sent:     \"ping\""),
        "caller must report sending ping. Got: {}",
        caller_stdout
    );
    assert!(
        caller_stdout.contains("Received: \"ack: 0\""),
        "caller must receive 'ack: 0' from callee. Got: {}",
        caller_stdout
    );

    let callee_log_contents = std::fs::read_to_string(&callee_log).unwrap_or_default();
    eprintln!("=== CALLEE LOG ===\n{}", callee_log_contents);
    assert!(
        callee_log_contents.contains("said: ping"),
        "callee log must show it received 'ping'. Got: {}",
        callee_log_contents
    );

    let _ = srv.kill();
    let _ = srv.wait();
}
