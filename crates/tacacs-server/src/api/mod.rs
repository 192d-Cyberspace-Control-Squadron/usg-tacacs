// SPDX-License-Identifier: Apache-2.0
//! Management API server with RBAC.
//!
//! Provides REST API endpoints for runtime management of the TACACS+ server,
//! including session management, policy reload, and monitoring.

mod handlers;
mod models;
mod rbac;

pub use handlers::build_api_router;
pub use models::*;
pub use rbac::{RbacConfig, RbacMiddleware};

use axum::Router;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

/// Start the management API server.
///
/// For now, only plaintext mode is supported. TLS will be added in a future update.
pub async fn serve_api(
    addr: SocketAddr,
    _acceptor: Option<TlsAcceptor>,
    rbac: RbacConfig,
) -> anyhow::Result<()> {
    let app = build_api_router(rbac);

    info!(addr = %addr, "Management API server listening");
    let listener = TcpListener::bind(addr).await?;
    if let Err(e) = axum::serve(listener, app).await {
        error!(error = %e, "API server error");
        return Err(e.into());
    }
    Ok(())
}
