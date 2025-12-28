// SPDX-License-Identifier: AGPL-3.0-only
use crate::ascii::{field_for_policy, username_for_policy};
use std::sync::Arc;
use tokio::sync::RwLock;
use usg_tacacs_policy::PolicyEngine;
use usg_tacacs_proto::{AuthSessionState, AuthenReply, AUTHEN_STATUS_FAIL};

/// Enforce server_msg_raw policy; clears/denies reply if blocked.
pub async fn enforce_server_msg(
    policy: &Arc<RwLock<PolicyEngine>>,
    state: &AuthSessionState,
    reply: &mut AuthenReply,
) {
    if reply.server_msg_raw.is_empty() {
        return;
    }
    let policy = policy.read().await;
    let policy_user = username_for_policy(state.username.as_deref(), state.username_raw.as_ref());
    let policy_port = field_for_policy(state.port.as_deref(), state.port_raw.as_ref());
    let policy_rem = field_for_policy(state.rem_addr.as_deref(), state.rem_addr_raw.as_ref());
    if !policy.observe_server_msg(
        policy_user.as_deref(),
        policy_port.as_deref(),
        policy_rem.as_deref(),
        state.service,
        state.action,
        &reply.server_msg_raw,
    ) {
        reply.status = AUTHEN_STATUS_FAIL;
        reply.flags = 0;
        reply.server_msg = "server message blocked by policy".into();
        reply.server_msg_raw.clear();
        reply.data.clear();
    }
}
