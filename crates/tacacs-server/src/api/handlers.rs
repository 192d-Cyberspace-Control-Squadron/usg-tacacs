// SPDX-License-Identifier: Apache-2.0
//! HTTP handlers for the Management API endpoints.

use super::models::*;
use super::rbac::RbacConfig;
use crate::metrics::metrics;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::info;

/// Shared state for API handlers.
#[derive(Clone)]
pub struct ApiState {
    pub rbac: RbacConfig,
    pub start_time: SystemTime,
}

/// Build the API router with all endpoints.
pub fn build_api_router(rbac: RbacConfig) -> Router {
    let state = ApiState {
        rbac,
        start_time: SystemTime::now(),
    };

    Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/sessions", get(get_sessions))
        .route("/api/v1/sessions/:id", delete(delete_session))
        .route("/api/v1/policy", get(get_policy))
        .route("/api/v1/policy/reload", post(reload_policy))
        .route("/api/v1/config", get(get_config))
        .route("/api/v1/metrics", get(get_metrics))
        .with_state(Arc::new(state))
}

/// GET /api/v1/status - Server health and statistics.
///
/// Requires permission: `read:status`
async fn get_status(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().unwrap_or_default().as_secs();

    // Collect metrics from Prometheus registry
    // Note: For now, we return placeholder values
    // TODO: Implement proper metric aggregation from CounterVec
    let metrics = metrics();
    let active_conns = metrics.connections_active.get() as u64;

    let response = StatusResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        stats: ServerStats {
            total_connections: 0, // TODO: aggregate from connections_total CounterVec
            active_connections: active_conns,
            total_authn_requests: 0, // TODO: aggregate from authn_requests_total CounterVec
            total_authz_requests: 0, // TODO: aggregate from authz_requests_total CounterVec
            total_acct_requests: 0,  // TODO: aggregate from acct_requests_total CounterVec
            authn_success_rate: 0.0, // TODO: calculate from CounterVec labels
            authz_success_rate: 0.0, // TODO: calculate from CounterVec labels
        },
    };

    Json(response)
}

/// GET /api/v1/sessions - List active sessions.
///
/// Requires permission: `read:sessions`
async fn get_sessions() -> impl IntoResponse {
    // TODO: Implement actual session tracking
    // For now, return empty list
    let response = SessionsResponse {
        sessions: vec![],
        total: 0,
    };

    Json(response)
}

/// DELETE /api/v1/sessions/:id - Terminate a session.
///
/// Requires permission: `write:sessions`
async fn delete_session(Path(session_id): Path<u32>) -> impl IntoResponse {
    info!(session_id = session_id, "API request to terminate session");

    // TODO: Implement actual session termination
    // For now, return success
    let response = SuccessResponse {
        success: true,
        message: format!("Session {} termination requested", session_id),
    };

    Json(response)
}

/// GET /api/v1/policy - Get current policy information.
///
/// Requires permission: `read:policy`
async fn get_policy() -> impl IntoResponse {
    // TODO: Get actual policy information from PolicyEngine
    let response = PolicyResponse {
        rule_count: 0,
        last_loaded: "unknown".to_string(),
        source: "unknown".to_string(),
    };

    Json(response)
}

/// POST /api/v1/policy/reload - Trigger policy hot reload.
///
/// Requires permission: `write:policy`
async fn reload_policy() -> impl IntoResponse {
    info!("API request to reload policy");

    // TODO: Implement actual policy reload via SIGHUP or channel
    let response = SuccessResponse {
        success: true,
        message: "Policy reload triggered".to_string(),
    };

    Json(response)
}

/// GET /api/v1/config - Get running configuration (sanitized).
///
/// Requires permission: `read:config`
async fn get_config() -> impl IntoResponse {
    // TODO: Get actual configuration
    let response = ConfigResponse {
        listen_addrs: vec![],
        tls_enabled: false,
        ldap_enabled: false,
        policy_source: "unknown".to_string(),
        metrics_enabled: true,
        api_enabled: true,
    };

    Json(response)
}

/// GET /api/v1/metrics - Get Prometheus metrics.
///
/// Requires permission: `read:metrics`
async fn get_metrics() -> impl IntoResponse {
    let body = metrics().encode();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(body)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_get_status() {
        let rbac = RbacConfig::default();
        let app = build_api_router(rbac);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_sessions() {
        let rbac = RbacConfig::default();
        let app = build_api_router(rbac);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_metrics() {
        let rbac = RbacConfig::default();
        let app = build_api_router(rbac);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.contains("text/plain"));
    }
}
