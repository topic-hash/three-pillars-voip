//! Build script for voip-ffi.
//!
//! This is a minimal build script. With the proc-macro approach in uniffi 0.28,
//! no special build steps are needed — the proc-macros handle everything at
//! compile time. The UDL file (`voip.udl`) is provided as a reference
//! specification and is not processed during the build.
//!
//! If you prefer the UDL-based workflow, uncomment the `uniffi::uniffi_bindgen`
//! call below and add `uniffi` to `[build-dependencies]`.

fn main() {
    // No special build steps needed for the proc-macro approach.
    // The UDL file is provided as documentation only.

    // For UDL-based approach, uncomment:
    // uniffi::uniffi_bindgen::generate_scaffolding("./voip.udl")
    //     .expect("Failed to generate UniFFI scaffolding from voip.udl");
}
