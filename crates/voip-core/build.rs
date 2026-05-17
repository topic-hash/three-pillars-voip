//! Build script: compile both proto files with prost-build.
//!
//! - `proto/signaling.proto` → module `signaling` (voip.signaling.rs)
//! - `proto/internal.proto`  → module `internal`  (voip.internal.rs)
//!
//! The internal proto imports signaling types; we use `extern_path` so
//! that generated internal code references `crate::proto::signaling::*`
//! instead of re-generating those types.

use std::io::Result;

fn main() -> Result<()> {
    let signaling_proto = "../../proto/signaling.proto";
    let internal_proto = "../../proto/internal.proto";

    println!("cargo:rerun-if-changed={}", signaling_proto);
    println!("cargo:rerun-if-changed={}", internal_proto);

    // Compile signaling.proto → OUT_DIR/voip.signaling.rs
    prost_build::Config::new()
        .type_attribute(
            ".voip.signaling",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .compile_protos(&[signaling_proto], &["../../proto/"])
        .expect("Failed to compile signaling.proto");

    // Compile internal.proto → OUT_DIR/voip.internal.rs
    // External signaling types are referenced via crate::proto::signaling
    prost_build::Config::new()
        .type_attribute(
            ".voip.internal",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .extern_path(".voip.signaling", "crate::proto::signaling")
        .compile_protos(&[internal_proto], &["../../proto/"])
        .expect("Failed to compile internal.proto");

    Ok(())
}
