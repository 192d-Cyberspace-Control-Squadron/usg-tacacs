// SPDX-License-Identifier: AGPL-3.0-only
use crate::ascii::{
    calc_ascii_backoff_capped, field_for_policy, handle_ascii_continue, username_for_policy,
    AsciiConfig,
};
use crate::auth::{
    handle_chap_continue, verify_pap, verify_pap_bytes, verify_pap_bytes_username,
};
use crate::policy::enforce_server_msg;
use crate::session::SingleConnectState;
use crate::tls::build_tls_config;
use anyhow::{Context, Result};
use openssl::rand::rand_bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use usg_tacacs_policy::{PolicyEngine, validate_policy_file};
use usg_tacacs_proto::{
    ACCT_STATUS_ERROR, ACCT_STATUS_SUCCESS, AUTHEN_FLAG_NOECHO, AUTHEN_STATUS_ERROR,
    AUTHEN_STATUS_FAIL, AUTHEN_STATUS_FOLLOW, AUTHEN_STATUS_GETDATA, AUTHEN_STATUS_GETPASS,
    AUTHEN_STATUS_GETUSER, AUTHEN_STATUS_PASS, AUTHEN_STATUS_RESTART, AUTHEN_TYPE_ASCII,
    AUTHEN_TYPE_CHAP, AUTHEN_TYPE_PAP, AUTHOR_STATUS_ERROR, AUTHOR_STATUS_FAIL,
    AUTHOR_STATUS_PASS_ADD, ACCT_FLAG_START, ACCT_FLAG_STOP, ACCT_FLAG_WATCHDOG, AccountingResponse, AccountingRequest, AuthorizationRequest, AuthSessionState, AuthenData, AuthenPacket,
    AuthenReply, AuthorizationResponse, Packet, read_packet, validate_accounting_response_header,
    validate_author_response_header, write_accounting_response, write_authen_reply,
    write_author_response,
};

fn validate_accounting_semantics(req: &AccountingRequest) -> Result<(), &'static str> {
    let is_start = req.flags & ACCT_FLAG_START != 0;
    let is_stop = req.flags & ACCT_FLAG_STOP != 0;
    let is_watchdog = req.flags & ACCT_FLAG_WATCHDOG != 0;
    // RFC expects one of the flags; parse already enforced exclusivity.
    if (is_start || is_stop || is_watchdog) && req.args.is_empty() {
        return Err("accounting records require attributes");
    }
    let attrs = req.attributes();
    let has_service_or_cmd = attrs.iter().any(|a| {
        let name = a.name.as_str();
        name.eq_ignore_ascii_case("service")
            || name.eq_ignore_ascii_case("cmd")
            || name.eq_ignore_ascii_case("cmd-arg")
    });
    if !has_service_or_cmd {
        return Err("accounting requires service or command attributes");
    }
    let has_task = attrs
        .iter()
        .any(|a| a.name.eq_ignore_ascii_case("task_id"));
    let has_elapsed = attrs
        .iter()
        .any(|a| a.name.eq_ignore_ascii_case("elapsed_time"));
    let has_status = attrs
        .iter()
        .any(|a| a.name.eq_ignore_ascii_case("status"));
    if is_start && !has_task {
        return Err("start accounting requires task_id attribute");
    }
    if is_stop && (!has_task || !has_elapsed || !has_status) {
        return Err("stop accounting requires task_id, elapsed_time, and status attributes");
    }
    if is_watchdog && !has_task {
        return Err("watchdog accounting requires task_id attribute");
    }
    // Numeric fields should be valid unsigned integers.
    let parse_u32 = |key: &str| -> Result<(), &'static str> {
        if let Some(attr) = attrs.iter().find(|a| a.name.eq_ignore_ascii_case(key)) {
            let val = attr.value.as_deref().unwrap_or("");
            if val.parse::<u32>().is_err() {
                return Err("accounting attributes must be numeric where required");
            }
        }
        Ok(())
    };
    if has_task {
        parse_u32("task_id")?;
    }
    if has_elapsed {
        parse_u32("elapsed_time")?;
    }
    if has_status {
        parse_u32("status")?;
    }
    Ok(())
}

fn validate_authorization_semantics(req: &AuthorizationRequest) -> Result<(), &'static str> {
    if !req.has_service_attr() {
        return Err("authorization missing service attribute");
    }
    if req.is_shell_start() {
        return Ok(());
    }
    if !req.has_cmd_attrs() {
        return Err("authorization missing command attributes");
    }
    Ok(())
}

pub async fn serve_tls(
    addr: SocketAddr,
    acceptor: TlsAcceptor,
    policy: Arc<RwLock<PolicyEngine>>,
    secret: Option<Arc<Vec<u8>>>,
    credentials: Arc<HashMap<String, String>>,
    ascii_attempt_limit: u8,
    ascii_user_attempt_limit: u8,
    ascii_pass_attempt_limit: u8,
    ascii_backoff_ms: u64,
    ascii_backoff_max_ms: u64,
    ascii_lockout_limit: u8,
    single_connect_idle_secs: u64,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding TLS listener {}", addr))?;
    info!("listening for TLS TACACS+ on {}", addr);
    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let policy = policy.clone();
        let secret = secret.clone();
        let credentials = credentials.clone();
        let ascii_user_attempt_limit = ascii_user_attempt_limit;
        let ascii_pass_attempt_limit = ascii_pass_attempt_limit;
        let ascii_backoff_ms = ascii_backoff_ms;
        let ascii_backoff_max_ms = ascii_backoff_max_ms;
        let ascii_lockout_limit = ascii_lockout_limit;
        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(stream) => {
                    if let Err(err) = handle_connection(
                        stream,
                        policy,
                        format!("{peer_addr}"),
                        secret,
                        credentials,
                        ascii_attempt_limit,
                        ascii_user_attempt_limit,
                        ascii_pass_attempt_limit,
                        ascii_backoff_ms,
                        ascii_backoff_max_ms,
                        ascii_lockout_limit,
                        single_connect_idle_secs,
                    )
                    .await
                    {
                        warn!(error = %err, peer = %peer_addr, "connection closed with error");
                    }
                }
                Err(err) => warn!(error = %err, peer = %peer_addr, "TLS handshake failed"),
            }
        });
    }
}

pub async fn serve_legacy(
    addr: SocketAddr,
    policy: Arc<RwLock<PolicyEngine>>,
    secret: Option<Arc<Vec<u8>>>,
    credentials: Arc<HashMap<String, String>>,
    ascii_attempt_limit: u8,
    ascii_user_attempt_limit: u8,
    ascii_pass_attempt_limit: u8,
    ascii_backoff_ms: u64,
    ascii_backoff_max_ms: u64,
    ascii_lockout_limit: u8,
    single_connect_idle_secs: u64,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding legacy listener {}", addr))?;
    info!("listening for legacy TACACS+ on {}", addr);
    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let policy = policy.clone();
        let secret = secret.clone();
        let credentials = credentials.clone();
        let ascii_attempt_limit = ascii_attempt_limit;
        let ascii_user_attempt_limit = ascii_user_attempt_limit;
        let ascii_pass_attempt_limit = ascii_pass_attempt_limit;
        let ascii_backoff_ms = ascii_backoff_ms;
        let ascii_backoff_max_ms = ascii_backoff_max_ms;
        let ascii_lockout_limit = ascii_lockout_limit;
        tokio::spawn(async move {
            if let Err(err) = handle_connection(
                socket,
                policy,
                format!("{peer_addr}"),
                secret,
                credentials,
                ascii_attempt_limit,
                ascii_user_attempt_limit,
                ascii_pass_attempt_limit,
                ascii_backoff_ms,
                ascii_backoff_max_ms,
                ascii_lockout_limit,
                single_connect_idle_secs,
            )
            .await
            {
                warn!(error = %err, peer = %peer_addr, "connection closed with error");
            }
        });
    }
}

async fn handle_connection<S>(
    mut stream: S,
    policy: Arc<RwLock<PolicyEngine>>,
    peer: String,
    secret: Option<Arc<Vec<u8>>>,
    credentials: Arc<HashMap<String, String>>,
    ascii_attempt_limit: u8,
    ascii_user_attempt_limit: u8,
    ascii_pass_attempt_limit: u8,
    ascii_backoff_ms: u64,
    ascii_backoff_max_ms: u64,
    ascii_lockout_limit: u8,
    single_connect_idle_secs: u64,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use std::collections::HashMap;
    let mut auth_states: HashMap<u32, AuthSessionState> = HashMap::new();
    let mut single_connect = SingleConnectState::default();
    loop {
        let read_future = read_packet(&mut stream, secret.as_deref().map(|s| s.as_slice()));
        let packet_result = if single_connect.active && single_connect_idle_secs > 0 {
            match timeout(Duration::from_secs(single_connect_idle_secs), read_future).await {
                Ok(res) => res,
                Err(_) => {
                    warn!(peer = %peer, "single-connect idle timeout reached; closing");
                    break;
                }
            }
        } else {
            read_future.await
        };
        match packet_result {
            Ok(Some(Packet::Authorization(request))) => {
                let authz_single =
                    request.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0;
                if single_connect.active && !authz_single {
                    warn!(peer = %peer, "single-connect violation: flag missing on authorization");
                    warn!(peer = %peer, user = %request.user, session = request.header.session_id, "single-connect violation: flag missing on authorization");
                    let response = AuthorizationResponse {
                        status: AUTHOR_STATUS_ERROR,
                        server_msg: "single-connection flag required after authentication"
                            .to_string(),
                        data: String::new(),
                        args: Vec::new(),
                    };
                    let _ = write_author_response(
                        &mut stream,
                        &request.header,
                        &response,
                        secret.as_deref().map(|s| s.as_slice()),
                    )
                    .await;
                    break;
                }
                if authz_single {
                    if let Some(bound) = single_connect.session {
                        if bound != request.header.session_id {
                            warn!(peer = %peer, user = %request.user, session = request.header.session_id, bound_session = bound, "single-connect violation: session-id mismatch on authorization");
                            break;
                        }
                    }
                    if let Some(ref bound_user) = single_connect.user {
                        if bound_user != &request.user {
                            warn!(peer = %peer, user = %request.user, bound_user = %bound_user, session = request.header.session_id, "single-connect violation: user mismatch on authorization");
                            let response = AuthorizationResponse {
                                status: AUTHOR_STATUS_ERROR,
                                server_msg: "single-connection user mismatch".to_string(),
                                data: String::new(),
                                args: Vec::new(),
                            };
                            let _ = write_author_response(
                                &mut stream,
                                &request.header,
                                &response,
                                secret.as_deref().map(|s| s.as_slice()),
                            )
                            .await;
                            break;
                        }
                    } else {
                        warn!(peer = %peer, user = %request.user, session = request.header.session_id, "single-connect violation: authorization before authentication");
                        let response = AuthorizationResponse {
                            status: AUTHOR_STATUS_ERROR,
                            server_msg: "single-connection not authenticated".to_string(),
                            data: String::new(),
                            args: Vec::new(),
                        };
                        let _ = write_author_response(
                            &mut stream,
                            &request.header,
                            &response,
                            secret.as_deref().map(|s| s.as_slice()),
                        )
                        .await;
                        break;
                    }
                }
                let decision = match validate_authorization_semantics(&request) {
                    Ok(()) => {
                        let policy = policy.read().await;
                        if request.is_shell_start() {
                            let attrs = policy
                                .shell_attributes_for(&request.user)
                                .unwrap_or_default();
                            AuthorizationResponse {
                                status: AUTHOR_STATUS_PASS_ADD,
                                server_msg: String::new(),
                                data: String::new(),
                                args: attrs,
                            }
                        } else if let Some(cmd) = request.command_string() {
                            let decision = policy.authorize(&request.user, &cmd);
                            if decision.allowed {
                                AuthorizationResponse {
                                    status: AUTHOR_STATUS_PASS_ADD,
                                    server_msg: String::new(),
                                    data: String::new(),
                                    args: Vec::new(),
                                }
                            } else {
                                AuthorizationResponse {
                                    status: AUTHOR_STATUS_FAIL,
                                    server_msg: "command denied".to_string(),
                                    data: String::new(),
                                    args: Vec::new(),
                                }
                            }
                        } else {
                            AuthorizationResponse {
                                status: AUTHOR_STATUS_ERROR,
                                server_msg: "unsupported request".to_string(),
                                data: String::new(),
                                args: Vec::new(),
                            }
                        }
                    }
                    Err(msg) => {
                        warn!(
                            peer = %peer,
                            user = %request.user,
                            session = request.header.session_id,
                            reason = %msg,
                            "authorization request rejected by semantic checks"
                        );
                        AuthorizationResponse {
                            status: AUTHOR_STATUS_ERROR,
                            server_msg: msg.to_string(),
                            data: String::new(),
                            args: Vec::new(),
                        }
                    }
                };

                if let Err(err) = validate_author_response_header(&request.header.response(0)) {
                    warn!(error = %err, peer = %peer, "authorization header invalid");
                }
                write_author_response(
                    &mut stream,
                    &request.header,
                    &decision,
                    secret.as_deref().map(|s| s.as_slice()),
                )
                .await
                .with_context(|| "sending TACACS+ response")?;
            }
            Ok(Some(Packet::Authentication(packet))) => {
                let session_id = match &packet {
                    AuthenPacket::Start(start) => start.header.session_id,
                    AuthenPacket::Continue(cont) => cont.header.session_id,
                };
                let single_connect_flag = match &packet {
                    AuthenPacket::Start(start) => {
                        start.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0
                    }
                    AuthenPacket::Continue(cont) => {
                        cont.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0
                    }
                };
                if single_connect.active && !single_connect_flag {
                    let header = match &packet {
                        AuthenPacket::Start(start) => &start.header,
                        AuthenPacket::Continue(cont) => &cont.header,
                    };
                    warn!(peer = %peer, session = session_id, "single-connect violation: flag missing on authentication");
                    let reply = AuthenReply {
                        status: AUTHEN_STATUS_ERROR,
                        flags: 0,
                        server_msg: "single-connection flag required after authentication".into(),
                        server_msg_raw: Vec::new(),
                        data: Vec::new(),
                    };
                    let _ = write_authen_reply(
                        &mut stream,
                        header,
                        &reply,
                        secret.as_deref().map(|s| s.as_slice()),
                    )
                    .await;
                    break;
                }
                if let AuthenPacket::Start(start) = &packet {
                    if single_connect.active {
                        if let Some(ref bound_user) = single_connect.user {
                            if bound_user != &start.user {
                                warn!(peer = %peer, user = %start.user, bound_user = %bound_user, session = session_id, "single-connect violation: user mismatch on authentication");
                                let reply = AuthenReply {
                                    status: AUTHEN_STATUS_ERROR,
                                    flags: 0,
                                    server_msg: "single-connection user mismatch".into(),
                                    server_msg_raw: Vec::new(),
                                    data: Vec::new(),
                                };
                                let _ = write_authen_reply(
                                    &mut stream,
                                    &start.header,
                                    &reply,
                                    secret.as_deref().map(|s| s.as_slice()),
                                )
                                .await;
                                break;
                            }
                        } else {
                            warn!(peer = %peer, user = %start.user, session = session_id, "single-connect violation: authentication with missing bound user");
                            let reply = AuthenReply {
                                status: AUTHEN_STATUS_ERROR,
                                flags: 0,
                                server_msg: "single-connection not authenticated".into(),
                                server_msg_raw: Vec::new(),
                                data: Vec::new(),
                            };
                            let _ = write_authen_reply(
                                &mut stream,
                                &start.header,
                                &reply,
                                secret.as_deref().map(|s| s.as_slice()),
                            )
                            .await;
                            break;
                        }
                        if single_connect.locked {
                            warn!(peer = %peer, user = %start.user, session = session_id, "single-connect violation: repeated authentication after lock");
                            let reply = AuthenReply {
                                status: AUTHEN_STATUS_ERROR,
                                flags: 0,
                                server_msg: "single-connection already authenticated".into(),
                                server_msg_raw: Vec::new(),
                                data: Vec::new(),
                            };
                            let _ = write_authen_reply(
                                &mut stream,
                                &start.header,
                                &reply,
                                secret.as_deref().map(|s| s.as_slice()),
                            )
                            .await;
                            break;
                        }
                        if let Some(bound) = single_connect.session {
                            if bound != start.header.session_id {
                                warn!(peer = %peer, user = %start.user, session = session_id, bound_session = bound, "single-connect violation: session-id mismatch on authentication");
                                break;
                            }
                        }
                    }
                }
                let state = auth_states
                    .entry(session_id)
                    .or_insert_with(|| match &packet {
                        AuthenPacket::Start(start) => AuthSessionState::new_from_start(
                            &start.header,
                            start.authen_type,
                            start.user.clone(),
                            start.user_raw.clone(),
                            start.port.clone(),
                            start.port_raw.clone(),
                            start.rem_addr.clone(),
                            start.rem_addr_raw.clone(),
                            start.service,
                            start.action,
                        )
                        .unwrap_or(AuthSessionState {
                            last_seq: start.header.seq_no,
                            expect_client: false,
                            authen_type: Some(start.authen_type),
                            challenge: None,
                            username: if start.user_raw.is_empty() || start.user.is_empty() {
                                None
                            } else {
                                Some(start.user.clone())
                            },
                            username_raw: if start.user_raw.is_empty() {
                                None
                            } else {
                                Some(start.user_raw.clone())
                            },
                            port: Some(start.port.clone()),
                            port_raw: if start.port_raw.is_empty() {
                                None
                            } else {
                                Some(start.port_raw.clone())
                            },
                            rem_addr: Some(start.rem_addr.clone()),
                            rem_addr_raw: if start.rem_addr_raw.is_empty() {
                                None
                            } else {
                                Some(start.rem_addr_raw.clone())
                            },
                            service: Some(start.service),
                            action: Some(start.action),
                            ascii_need_user: start.user.is_empty(),
                            ascii_need_pass: start.data.is_empty(),
                            chap_id: None,
                            ascii_attempts: 0,
                            ascii_user_attempts: 0,
                            ascii_pass_attempts: 0,
                        }),
                        AuthenPacket::Continue(cont) => AuthSessionState {
                            last_seq: cont.header.seq_no,
                            expect_client: false,
                            authen_type: None,
                            challenge: None,
                            username: None,
                            username_raw: None,
                            port_raw: None,
                            port: None,
                            rem_addr_raw: None,
                            rem_addr: None,
                            chap_id: None,
                            ascii_need_user: true,
                            ascii_need_pass: false,
                            ascii_attempts: 0,
                            ascii_user_attempts: 0,
                            ascii_pass_attempts: 0,
                            service: None,
                            action: None,
                        },
                    });
                if let AuthenPacket::Continue(ref cont) = packet {
                    if let Err(err) = state.validate_client(&cont.header) {
                        warn!(error = %err, peer = %peer, "auth sequence invalid");
                    }
                }

                let mut reply = match packet {
                    AuthenPacket::Start(ref start) => match start.authen_type {
                        AUTHEN_TYPE_ASCII => {
                            state.authen_type = Some(AUTHEN_TYPE_ASCII);
                            state.service = Some(start.service);
                            state.action = Some(start.action);
                            let decoded_username = if start.user_raw.is_empty() {
                                None
                            } else if start.user.is_empty() {
                                None
                            } else {
                                Some(start.user.clone())
                            };
                            state.username = decoded_username;
                            state.username_raw = if start.user_raw.is_empty() {
                                None
                            } else {
                                Some(start.user_raw.clone())
                            };
                            let (policy_user_prompt, policy_pass_prompt) = {
                                let policy = policy.read().await;
                                let policy_user = username_for_policy(
                                    state.username.as_deref(),
                                    state.username_raw.as_ref(),
                                );
                                let policy_port =
                                    field_for_policy(state.port.as_deref(), state.port_raw.as_ref());
                                let policy_rem =
                                    field_for_policy(state.rem_addr.as_deref(), state.rem_addr_raw.as_ref());
                                (
                                    policy
                                        .prompt_username(
                                            policy_user.as_deref(),
                                            policy_port.as_deref(),
                                            policy_rem.as_deref(),
                                        )
                                        .map(|s| s.as_bytes().to_vec()),
                                    policy
                                        .prompt_password(policy_user.as_deref())
                                        .map(|s| s.as_bytes().to_vec()),
                                )
                            };
                            let username_prompt =
                                |client_msg: Option<&[u8]>, service: Option<u8>| -> Vec<u8> {
                                    if let Some(msg) = client_msg {
                                        if !msg.is_empty() {
                                            return msg.to_vec();
                                        }
                                    }
                                    if let Some(custom) = policy_user_prompt.as_ref() {
                                        return custom.clone();
                                    }
                                    match service {
                                        Some(svc) => format!("Username (service {svc}):").into_bytes(),
                                        None => b"Username:".to_vec(),
                                    }
                                };
                            let password_prompt =
                                |client_msg: Option<&[u8]>, service: Option<u8>| -> Vec<u8> {
                                    if let Some(msg) = client_msg {
                                        if !msg.is_empty() {
                                            return msg.to_vec();
                                        }
                                    }
                                    if let Some(custom) = policy_pass_prompt.as_ref() {
                                        return custom.clone();
                                    }
                                    match service {
                                        Some(svc) => format!("Password (service {svc}):").into_bytes(),
                                        None => b"Password:".to_vec(),
                                    }
                                };
                            state.ascii_need_user = state.username.is_none();
                            if state.ascii_need_user {
                                AuthenReply {
                                    status: AUTHEN_STATUS_GETUSER,
                                    flags: 0,
                                    server_msg: String::new(),
                                    server_msg_raw: Vec::new(),
                                    data: username_prompt(None, state.service),
                                }
                            } else if !start.data.is_empty() {
                                let ok = if let Some(raw) = state.username_raw.as_ref() {
                                    verify_pap_bytes_username(raw, &start.data, &credentials)
                                } else {
                                    verify_pap_bytes(
                                        state.username.as_deref().unwrap_or_default(),
                                        &start.data,
                                        &credentials,
                                    )
                                };
                                if !ok {
                                    if let Some(delay) =
                                        calc_ascii_backoff_capped(
                                            ascii_backoff_ms,
                                            state.ascii_attempts,
                                            ascii_backoff_max_ms,
                                        )
                                    {
                                        sleep(delay).await;
                                    }
                                }
                                let svc_str = state
                                    .service
                                    .map(|svc| format!(" (service {svc})"))
                                    .unwrap_or_default();
                                let act_str = state
                                    .action
                                    .map(|act| format!(" action {act}"))
                                    .unwrap_or_default();
                                let policy = policy.read().await;
                                AuthenReply {
                                    status: if ok {
                                        AUTHEN_STATUS_PASS
                                    } else {
                                        AUTHEN_STATUS_FAIL
                                    },
                                    flags: 0,
                                    server_msg: if ok {
                                        policy
                                            .message_success()
                                            .map(|m| m.to_string())
                                            .unwrap_or_else(|| {
                                                format!("authentication succeeded{svc_str}{act_str}")
                                            })
                                    } else {
                                        policy
                                            .message_failure()
                                            .map(|m| m.to_string())
                                            .unwrap_or_else(|| {
                                                format!("invalid credentials{svc_str}{act_str}")
                                            })
                                    },
                                    server_msg_raw: Vec::new(),
                                    data: Vec::new(),
                                }
                            } else {
                                state.ascii_need_pass = true;
                                AuthenReply {
                                    status: AUTHEN_STATUS_GETPASS,
                                    flags: AUTHEN_FLAG_NOECHO,
                                    server_msg: String::new(),
                                    server_msg_raw: Vec::new(),
                                    data: password_prompt(None, state.service),
                                }
                            }
                        }
                        AUTHEN_TYPE_PAP => {
                            state.authen_type = Some(AUTHEN_TYPE_PAP);
                            let password = match start.parsed_data() {
                                AuthenData::Pap { password } => password,
                                _ => {
                                    warn!(peer = %peer, user = %start.user, "invalid PAP authentication payload");
                                    return Ok(());
                                }
                            };
                            let ok = verify_pap(&start.user, &password, &credentials);
                            let policy = policy.read().await;
                            let svc_str = start
                                .service
                                .to_string();
                            let act_str = start.action.to_string();
                            AuthenReply {
                                status: if ok {
                                    AUTHEN_STATUS_PASS
                                } else {
                                    AUTHEN_STATUS_FAIL
                                },
                                flags: 0,
                                server_msg: if ok {
                                    policy
                                        .message_success()
                                        .map(|m| m.to_string())
                                        .unwrap_or_else(|| {
                                            format!("authentication succeeded (service {svc_str} action {act_str})")
                                        })
                                } else {
                                    policy
                                        .message_failure()
                                        .map(|m| m.to_string())
                                        .unwrap_or_else(|| {
                                            format!("invalid credentials (service {svc_str} action {act_str})")
                                        })
                                },
                                server_msg_raw: Vec::new(),
                                data: Vec::new(),
                            }
                        }
                        AUTHEN_TYPE_CHAP => {
                            if start.data.len() != 1 {
                                warn!(peer = %peer, user = %start.user, "invalid CHAP start length");
                                return Ok(());
                            }
                            let chap_id = &start.data;
                            let mut chal = [0u8; 16];
                            let mut chap_id_bytes = [0u8; 1];
                            chap_id_bytes.copy_from_slice(chap_id);
                            if rand_bytes(&mut chal).is_err() || rand_bytes(&mut chap_id_bytes).is_err() {
                                AuthenReply {
                                    status: AUTHEN_STATUS_ERROR,
                                    flags: 0,
                                    server_msg: "failed to generate challenge".into(),
                                    server_msg_raw: Vec::new(),
                                    data: Vec::new(),
                                }
                            } else {
                                state.challenge = Some(chal.clone().to_vec());
                                state.chap_id = Some(chap_id_bytes[0]);
                                AuthenReply {
                                    status: AUTHEN_STATUS_GETDATA,
                                    flags: 0,
                                    server_msg: String::new(),
                                    server_msg_raw: Vec::new(),
                                    data: {
                                        let mut payload = Vec::with_capacity(1 + chal.len());
                                        payload.extend_from_slice(&chap_id_bytes);
                                        payload.extend_from_slice(&chal);
                                        payload
                                    },
                                }
                            }
                        }
                        _ => AuthenReply {
                            status: AUTHEN_STATUS_FOLLOW,
                            flags: 0,
                            server_msg: "unsupported auth type - fallback".into(),
                            server_msg_raw: Vec::new(),
                            data: Vec::new(),
                        },
                    },
                    AuthenPacket::Continue(ref cont) => match state.authen_type {
                        Some(AUTHEN_TYPE_ASCII) => {
                            let ascii_cfg = AsciiConfig {
                                attempt_limit: ascii_attempt_limit,
                                user_attempt_limit: ascii_user_attempt_limit,
                                pass_attempt_limit: ascii_pass_attempt_limit,
                                backoff_ms: ascii_backoff_ms,
                                backoff_max_ms: ascii_backoff_max_ms,
                                lockout_limit: ascii_lockout_limit,
                            };
                            handle_ascii_continue(
                                cont.user_msg.as_slice(),
                                cont.data.as_slice(),
                                cont.flags,
                                state,
                                &policy,
                                &credentials,
                                &ascii_cfg,
                            )
                            .await
                        }
                        _ if state.challenge.is_some() => {
                            let user = state.username.clone().unwrap_or_default();
                            match state.authen_type {
                                Some(AUTHEN_TYPE_CHAP) => {
                                    handle_chap_continue(&user, cont.data.as_slice(), state, &credentials)
                                }
                                _ => AuthenReply {
                                    status: AUTHEN_STATUS_FAIL,
                                    flags: 0,
                                    server_msg: "unexpected continue".into(),
                                    server_msg_raw: Vec::new(),
                                    data: Vec::new(),
                                },
                            }
                        }
                        _ => AuthenReply {
                            status: AUTHEN_STATUS_FAIL,
                            flags: 0,
                            server_msg: format!(
                                "unexpected authentication continue (flags {:02x})",
                                cont.flags
                            ),
                            server_msg_raw: Vec::new(),
                            data: Vec::new(),
                        },
                    },
                };

                let header = match &packet {
                    AuthenPacket::Start(start) => &start.header,
                    AuthenPacket::Continue(cont) => &cont.header,
                };
                let terminal = matches!(
                    reply.status,
                    AUTHEN_STATUS_PASS
                        | AUTHEN_STATUS_FAIL
                        | AUTHEN_STATUS_ERROR
                        | AUTHEN_STATUS_FOLLOW
                        | AUTHEN_STATUS_RESTART
                );
                let single_user = state.username.clone();

                write_authen_reply(
                    &mut stream,
                    header,
                    &reply,
                    secret.as_deref().map(|s| s.as_slice()),
                )
                .await
                .with_context(|| "sending TACACS+ auth reply")?;
                if !reply.server_msg_raw.is_empty() {
                    enforce_server_msg(&policy, state, &mut reply).await;
                    debug!(
                        peer = %peer,
                        session = session_id,
                        raw_len = reply.server_msg_raw.len(),
                        server_msg_raw_hex = %hex::encode(&reply.server_msg_raw),
                        "auth reply carried raw server_msg bytes"
                    );
                }
                if terminal {
                    auth_states.remove(&session_id);
                    if reply.status != AUTHEN_STATUS_PASS {
                        single_connect.reset();
                    }
                }
                if matches!(reply.status, AUTHEN_STATUS_PASS) && single_connect_flag {
                    if let Some(user) = single_user {
                        single_connect.activate(user.clone(), session_id);
                        info!(peer = %peer, user = %user, session = session_id, "single-connect established");
                    }
                }
            }
            Ok(Some(Packet::Accounting(request))) => {
                let acct_single = request.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0;
                if single_connect.active && !acct_single {
                    warn!(peer = %peer, user = %request.user, session = request.header.session_id, "single-connect violation: flag missing on accounting");
                    let response = AccountingResponse {
                        status: ACCT_STATUS_ERROR,
                        server_msg: "single-connection flag required after authentication"
                            .to_string(),
                        data: String::new(),
                        args: Vec::new(),
                    };
                    let _ = write_accounting_response(
                        &mut stream,
                        &request.header,
                        &response,
                        secret.as_deref().map(|s| s.as_slice()),
                    )
                    .await;
                    break;
                }
                if acct_single {
                    if let Some(bound) = single_connect.session {
                        if bound != request.header.session_id {
                            warn!(peer = %peer, user = %request.user, session = request.header.session_id, bound_session = bound, "single-connect violation: session-id mismatch on accounting");
                            break;
                        }
                    }
                    if let Some(ref bound_user) = single_connect.user {
                        if bound_user != &request.user {
                            warn!(peer = %peer, user = %request.user, bound_user = %bound_user, session = request.header.session_id, "single-connect violation: user mismatch on accounting");
                            let response = AccountingResponse {
                                status: ACCT_STATUS_ERROR,
                                server_msg: "single-connection user mismatch".to_string(),
                                data: String::new(),
                                args: Vec::new(),
                            };
                            let _ = write_accounting_response(
                                &mut stream,
                                &request.header,
                                &response,
                                secret.as_deref().map(|s| s.as_slice()),
                            )
                            .await;
                            break;
                        }
                    } else {
                        warn!(peer = %peer, user = %request.user, session = request.header.session_id, "single-connect violation: accounting before authentication");
                        let response = AccountingResponse {
                            status: ACCT_STATUS_ERROR,
                            server_msg: "single-connection not authenticated".to_string(),
                            data: String::new(),
                            args: Vec::new(),
                        };
                        let _ = write_accounting_response(
                            &mut stream,
                            &request.header,
                            &response,
                            secret.as_deref().map(|s| s.as_slice()),
                        )
                        .await;
                        break;
                    }
                }
                if let Err(err) = validate_accounting_response_header(&request.header.response(0)) {
                    warn!(error = %err, peer = %peer, "accounting header invalid");
                }
                let response = match validate_accounting_semantics(&request) {
                    Ok(()) => AccountingResponse {
                        status: ACCT_STATUS_SUCCESS,
                        server_msg: String::new(),
                        data: String::new(),
                        args: Vec::new(),
                    },
                    Err(msg) => {
                        warn!(
                            peer = %peer,
                            user = %request.user,
                            session = request.header.session_id,
                            reason = %msg,
                            "accounting request rejected by semantic checks"
                        );
                        AccountingResponse {
                        status: ACCT_STATUS_ERROR,
                        server_msg: msg.to_string(),
                        data: String::new(),
                        args: Vec::new(),
                        }
                    }
                };
                write_accounting_response(
                    &mut stream,
                    &request.header,
                    &response,
                    secret.as_deref().map(|s| s.as_slice()),
                )
                .await
                .with_context(|| "sending TACACS+ accounting response")?;
            }
            Ok(None) => {
                debug!(peer = %peer, "client closed connection");
                break;
            }
            Err(err) => {
                warn!(error = %err, peer = %peer, "failed to read TACACS+ packet");
                break;
            }
        }
    }
    Ok(())
}

pub async fn watch_sighup(
    policy_path: PathBuf,
    schema: Option<PathBuf>,
    policy: Arc<RwLock<PolicyEngine>>,
) {
    match signal(SignalKind::hangup()) {
        Ok(mut stream) => {
            while stream.recv().await.is_some() {
                match PolicyEngine::from_path(&policy_path, schema.as_ref()) {
                    Ok(new_policy) => {
                        *policy.write().await = new_policy;
                        info!("reloaded policy after SIGHUP");
                    }
                    Err(err) => warn!(error = %err, "failed to reload policy on SIGHUP"),
                }
            }
        }
        Err(err) => warn!(error = %err, "failed to install SIGHUP handler"),
    }
}

pub fn validate_policy(path: &PathBuf, schema: Option<&PathBuf>) -> Result<()> {
    let schema_path = schema.context("schema is required to validate policy")?;
    let document = validate_policy_file(path, schema_path)?;
    PolicyEngine::from_document(document)?;
    Ok(())
}

pub fn tls_acceptor(cert: &PathBuf, key: &PathBuf, ca: &PathBuf) -> Result<TlsAcceptor> {
    let tls_config = build_tls_config(cert, key, ca)?;
    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}
