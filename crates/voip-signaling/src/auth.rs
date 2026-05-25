//! REST API authentication middleware (spec/08 §8.6).
//!
//! Per spec/08 §8.6, JWT auth must be required on all REST endpoints
//! except:
//!   - `GET /v1/openapi.json`
//!   - `GET /swagger-ui/*`
//!   - `POST /v1/peers` (registration endpoint — no auth yet, it issues the JWT)
//!
//! This middleware extracts the `Authorization: Bearer <jwt>` header,
//! validates the JWT using the server's Ed25519 verifying key, and
//! makes the authenticated `peer_id` available to handlers via a
//! request extension.

use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use tracing::warn;

use crate::error::SignalingError;
use crate::jwt;
use crate::state::AppState;

// ── Authenticated peer extension ────────────────────────────────────────

/// The authenticated peer identity, extracted from a validated JWT.
///
/// Inserted into request extensions by [`auth_middleware`] so that
/// downstream handlers can access the caller's peer_id.
#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    /// The `sub` claim from the validated JWT — the caller's peer_id.
    pub peer_id: String,
}

// ── Auth middleware ─────────────────────────────────────────────────────

/// JWT authentication middleware for REST endpoints.
///
/// Extracts the `Authorization: Bearer <jwt>` header, validates the
/// JWT using the server's Ed25519 verifying key, extracts the `sub`
/// (peer_id) claim, and inserts an [`AuthenticatedPeer`] extension
/// into the request.
///
/// # Path-based bypass
///
/// The following paths are exempt from authentication:
/// - `POST /v1/peers` (registration endpoint — issues the JWT)
/// - `GET /v1/myip` (IP discovery — no auth needed)
/// - `GET /v1/ws` (WebSocket upgrade — uses query-param JWT)
/// - `GET /v1/openapi.json` and `GET /swagger-ui/*` (documentation)
///
/// # Errors
///
/// Returns [`SignalingError::Unauthorized`] if:
/// - The `Authorization` header is missing
/// - The header doesn't start with `Bearer `
/// - The JWT is invalid or expired
///
/// # Usage
///
/// Apply via `axum::middleware::from_fn_with_state` as a layer on the
/// entire router (the middleware skips auth for public paths internally):
/// ```ignore
/// let auth_layer = axum::middleware::from_fn_with_state(
///     state.clone(),
///     auth_middleware,
/// );
/// router.layer(auth_layer);
/// ```
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, SignalingError> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();

    // Skip auth for public endpoints
    if is_public_path(&path, &method) {
        // Insert a default (empty) authenticated peer for handlers that
        // still extract the extension, so they don't fail with a missing extractor.
        req.extensions_mut().insert(AuthenticatedPeer {
            peer_id: String::new(),
        });
        return Ok(next.run(req).await);
    }

    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| {
            warn!(path = %path, "missing Authorization header");
            SignalingError::Unauthorized("missing Authorization header".to_owned())
        })?
        .to_str()
        .map_err(|e| {
            warn!(path = %path, error = %e, "invalid Authorization header encoding");
            SignalingError::Unauthorized("invalid Authorization header".to_owned())
        })?;

    // Expect "Bearer <jwt>"
    let jwt_token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        warn!(path = %path, "Authorization header missing Bearer prefix");
        SignalingError::Unauthorized(
            "Authorization header must use Bearer scheme".to_owned(),
        )
    })?;

    // Validate the JWT using the server's verifying key
    let verifying_key = state.verifying_key();
    let claims = jwt::verify_jwt(&verifying_key, jwt_token).map_err(|e| {
        warn!(path = %path, error = %e, "JWT validation failed");
        SignalingError::Unauthorized(format!("invalid JWT: {}", e))
    })?;

    // Insert the authenticated peer_id as a request extension
    req.extensions_mut().insert(AuthenticatedPeer {
        peer_id: claims.sub,
    });

    Ok(next.run(req).await)
}

/// Check whether the given path and method should bypass JWT authentication.
///
/// Public endpoints per spec/08 §8.6:
/// - `POST /v1/peers` — registration (issues JWT)
/// - `GET /v1/myip` — IP discovery
/// - `GET /v1/ws` — WebSocket upgrade (uses query-param JWT)
/// - `GET /v1/openapi.json` — OpenAPI spec
/// - `GET /swagger-ui/*` — Swagger UI
fn is_public_path(path: &str, method: &axum::http::Method) -> bool {
    // Registration endpoint
    if path == "/v1/peers" && method == axum::http::Method::POST {
        return true;
    }
    // IP discovery
    if path == "/v1/myip" && method == axum::http::Method::GET {
        return true;
    }
    // WebSocket upgrade (uses query-param JWT, not Bearer)
    if path == "/v1/ws" && method == axum::http::Method::GET {
        return true;
    }
    // OpenAPI spec
    if path == "/v1/openapi.json" && method == axum::http::Method::GET {
        return true;
    }
    // Swagger UI
    if path.starts_with("/swagger-ui") && method == axum::http::Method::GET {
        return true;
    }
    false
}
