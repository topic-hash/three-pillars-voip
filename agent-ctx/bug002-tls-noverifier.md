# BUG-002: TLS NoVerifier in Production

## Summary
Fixed security vulnerability where `NoVerifier` (no-op TLS certificate verifier) was unconditionally available in production builds, allowing MITM attacks.

## Changes
1. `tls.rs`: Added `#[cfg(debug_assertions)]` to `dangerous_client_config()`
2. `tls.rs`: Added `production_client_config()` behind `#[cfg(not(debug_assertions))]` using `rustls_native_certs`
3. `tls.rs`: Updated `dangerous_quinn_client_config()` with conditional compilation
4. `masque.rs`: Updated `perform_tls_handshake()` call site with conditional compilation
5. `Cargo.toml`: Added `rustls-native-certs = "7"` dependency
