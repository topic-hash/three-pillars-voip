//! Build script: compile proto/signaling.proto with prost-build.

use std::io::Result;

fn main() -> Result<()> {
    let proto_path = "../../proto/signaling.proto";
    println!("cargo:rerun-if-changed={}", proto_path);

    prost_build::Config::new()
        .compile_protos(&[proto_path], &["../../proto/"])
        .expect("Failed to compile protobuf");

    Ok(())
}
