// SPDX-License-Identifier: AGPL-3.0-only
//! HTTP server for health checks and Prometheus metrics.

use crate::metrics::metrics;
use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

/// Server readiness state shared between HTTP server and main application.
#[derive(Clone)]
pub struct ServerState {
    /// Whether the server is ready to accept TACACS+ connections.
    ready: Arc<AtomicBool>,
    /// Whether the server is alive (not deadlocked).
    alive: Arc<AtomicBool>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            alive: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Set the ready state.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
    }

    /// Check if server is ready.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Set the alive state (used during graceful shutdown).
    #[allow(dead_code)]
    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::SeqCst);
    }

    /// Check if server is alive.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check response.
#[derive(serde::Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// Liveness probe - returns 200 if the process is alive.
async fn health_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(HealthResponse { status: "healthy" }),
    )
}

/// Readiness probe - returns 200 if ready to accept connections, 503 otherwise.
async fn ready_handler(
    axum::extract::State(state): axum::extract::State<ServerState>,
) -> Response {
    if state.is_ready() {
        (
            StatusCode::OK,
            axum::Json(HealthResponse { status: "ready" }),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(HealthResponse { status: "not_ready" }),
        )
            .into_response()
    }
}

/// Liveness probe - returns 200 if not deadlocked, 503 otherwise.
async fn live_handler(
    axum::extract::State(state): axum::extract::State<ServerState>,
) -> Response {
    if state.is_alive() {
        (
            StatusCode::OK,
            axum::Json(HealthResponse { status: "alive" }),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(HealthResponse { status: "dead" }),
        )
            .into_response()
    }
}

/// Prometheus metrics endpoint.
async fn metrics_handler() -> impl IntoResponse {
    let body = metrics().encode();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

/// Build the HTTP router with all endpoints.
fn build_router(state: ServerState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/live", get(live_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

/// Start the HTTP server for health checks and metrics.
pub async fn serve_http(addr: SocketAddr, state: ServerState) -> anyhow::Result<()> {
    let app = build_router(state);

    let listener = TcpListener::bind(addr).await?;
    info!(addr = %addr, "HTTP server listening for health checks and metrics");

    if let Err(e) = axum::serve(listener, app).await {
        error!(error = %e, "HTTP server error");
        return Err(e.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = ServerState::new();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_ready_endpoint_not_ready() {
        let state = ServerState::new();
        // Default is not ready
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_ready_endpoint_ready() {
        let state = ServerState::new();
        state.set_ready(true);
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_live_endpoint() {
        let state = ServerState::new();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/live").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let state = ServerState::new();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_server_state() {
        let state = ServerState::new();

        assert!(!state.is_ready());
        assert!(state.is_alive());

        state.set_ready(true);
        assert!(state.is_ready());

        state.set_alive(false);
        assert!(!state.is_alive());
    }
}
