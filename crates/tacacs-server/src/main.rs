use crate::auth::{compute_chap_response, verify_pap, verify_pap_bytes, verify_pap_bytes_username};
use crate::config::{Args, credentials_map};
use crate::tls::build_tls_config;
use anyhow::{Context, Result, bail};
use clap::Parser;
use openssl::rand::rand_bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};
use usg_tacacs_policy::{PolicyEngine, validate_policy_file};
use usg_tacacs_proto::{
    ACCT_STATUS_ERROR, ACCT_STATUS_SUCCESS, AUTHEN_FLAG_NOECHO, AUTHEN_STATUS_ERROR,
    AUTHEN_STATUS_FAIL, AUTHEN_STATUS_FOLLOW, AUTHEN_STATUS_GETDATA, AUTHEN_STATUS_GETPASS,
    AUTHEN_STATUS_GETUSER, AUTHEN_STATUS_PASS, AUTHEN_STATUS_RESTART, AUTHEN_TYPE_ASCII,
    AUTHEN_TYPE_CHAP, AUTHEN_TYPE_PAP, AUTHOR_STATUS_ERROR, AUTHOR_STATUS_FAIL,
    AUTHOR_STATUS_PASS_ADD, AccountingResponse, AuthSessionState, AuthenData, AuthenPacket,
    AuthenReply, AuthorizationResponse, Packet, read_packet, validate_accounting_response_header,
    validate_author_response_header, write_accounting_response, write_authen_reply,
    write_author_response,
};
const AUTHEN_CONT_ABORT: u8 = 0x01;

fn calc_ascii_backoff(base_ms: u64, attempt: u8) -> Option<Duration> {
    if base_ms == 0 {
        return None;
    }
    let linear = base_ms.saturating_mul(attempt.max(1) as u64);
    let mut jitter = 0;
    let mut buf = [0u8; 2];
    if rand_bytes(&mut buf).is_ok() {
        let max_jitter = base_ms.min(5_000);
        jitter = (u16::from_be_bytes(buf) as u64) % (max_jitter + 1);
    }
    Some(Duration::from_millis(linear.saturating_add(jitter)))
}

fn username_for_policy<'a>(
    decoded: Option<&'a str>,
    raw: Option<&'a Vec<u8>>,
) -> Option<String> {
    if let Some(u) = decoded {
        return Some(u.to_string());
    }
    raw.map(|bytes| hex::encode(bytes))
}

fn field_for_policy<'a>(decoded: Option<&'a str>, raw: Option<&'a Vec<u8>>) -> Option<String> {
    if let Some(v) = decoded {
        return Some(v.to_string());
    }
    raw.map(|bytes| hex::encode(bytes))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if let Some(policy_path) = args.check_policy.as_ref() {
        let schema = args
            .schema
            .as_ref()
            .context("--schema is required with --check-policy")?;
        let document = validate_policy_file(policy_path, schema)?;
        PolicyEngine::from_document(document)?;
        println!("policy validated");
        return Ok(());
    }

    let policy_path = args
        .policy
        .as_ref()
        .context("a --policy path is required to start the server")?;
    let engine = PolicyEngine::from_path(policy_path, args.schema.as_ref())?;
    let shared_policy = Arc::new(RwLock::new(engine));
    let shared_secret: Option<Arc<Vec<u8>>> = args
        .secret
        .as_ref()
        .map(|s| Arc::new(s.clone().into_bytes()));
    if let (Some(secret), Some(psk)) = (args.secret.as_ref(), args.tls_psk.as_ref()) {
        if secret == psk {
            bail!("TACACS+ shared secret must not match TLS PSK");
        }
    }
    let credentials: Arc<HashMap<String, String>> = Arc::new(credentials_map(&args));

    let mut handles = Vec::new();

    if let Some(addr) = args.listen_tls {
        let allow_unencrypted = !(args.forbid_unencrypted
            && shared_secret
                .as_ref()
                .map(|s| s.len() >= usg_tacacs_proto::MIN_SECRET_LEN)
                .unwrap_or(false));
        if allow_unencrypted
            && shared_secret.as_ref().map(|s| s.len()).unwrap_or(0)
                < usg_tacacs_proto::MIN_SECRET_LEN
        {
            warn!("TLS mode: shared secret missing/short; UNENCRYPTED packets will be accepted");
        }
        let cert = args
            .tls_cert
            .as_ref()
            .context("--tls-cert is required when --listen-tls is set")?;
        let key = args
            .tls_key
            .as_ref()
            .context("--tls-key is required when --listen-tls is set")?;
        let ca = args
            .client_ca
            .as_ref()
            .context("--client-ca is required when --listen-tls is set")?;
        let tls_config = build_tls_config(cert, key, ca)?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let policy = shared_policy.clone();
        let secret = shared_secret.clone();
        let credentials = credentials.clone();
        let ascii_attempt_limit = args.ascii_attempt_limit;
        let ascii_user_attempt_limit = args.ascii_user_attempt_limit;
        let ascii_pass_attempt_limit = args.ascii_pass_attempt_limit;
        let ascii_backoff_ms = args.ascii_backoff_ms;
        handles.push(tokio::spawn(async move {
            if let Err(err) = serve_tls(
                addr,
                acceptor,
                policy,
                secret,
                credentials,
                ascii_attempt_limit,
                ascii_user_attempt_limit,
                ascii_pass_attempt_limit,
                ascii_backoff_ms,
            )
            .await
            {
                error!(error = %err, "TLS listener stopped");
            }
        }));
    }

    if let Some(addr) = args.listen_legacy {
        if shared_secret.is_none() {
            bail!("--secret is required for legacy TACACS+");
        }
        if shared_secret.as_ref().unwrap().len() < usg_tacacs_proto::MIN_SECRET_LEN {
            bail!(
                "shared secret must be at least {} bytes for legacy TACACS+",
                usg_tacacs_proto::MIN_SECRET_LEN
            );
        }
        let policy = shared_policy.clone();
        let secret = shared_secret.clone();
        let credentials = credentials.clone();
        let ascii_attempt_limit = args.ascii_attempt_limit;
        let ascii_user_attempt_limit = args.ascii_user_attempt_limit;
        let ascii_pass_attempt_limit = args.ascii_pass_attempt_limit;
        let ascii_backoff_ms = args.ascii_backoff_ms;
        handles.push(tokio::spawn(async move {
            if let Err(err) =
                serve_legacy(
                    addr,
                    policy,
                    secret,
                    credentials,
                    ascii_attempt_limit,
                    ascii_user_attempt_limit,
                    ascii_pass_attempt_limit,
                    ascii_backoff_ms,
                )
                .await
            {
                error!(error = %err, "legacy listener stopped");
            }
        }));
    }

    if handles.is_empty() {
        bail!("no listeners configured; set --listen-tls and/or --listen-legacy");
    }

    let policy = shared_policy.clone();
    let schema_path = args.schema.clone();
    let policy_path = policy_path.clone();
    handles.push(tokio::spawn(async move {
        watch_sighup(policy_path, schema_path, policy).await;
    }));

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

async fn serve_tls(
    addr: SocketAddr,
    acceptor: TlsAcceptor,
    policy: Arc<RwLock<PolicyEngine>>,
    secret: Option<Arc<Vec<u8>>>,
    credentials: Arc<HashMap<String, String>>,
    ascii_attempt_limit: u8,
    ascii_user_attempt_limit: u8,
    ascii_pass_attempt_limit: u8,
    ascii_backoff_ms: u64,
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

async fn serve_legacy(
    addr: SocketAddr,
    policy: Arc<RwLock<PolicyEngine>>,
    secret: Option<Arc<Vec<u8>>>,
    credentials: Arc<HashMap<String, String>>,
    ascii_attempt_limit: u8,
    ascii_user_attempt_limit: u8,
    ascii_pass_attempt_limit: u8,
    ascii_backoff_ms: u64,
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
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use std::collections::HashMap;
    let mut auth_states: HashMap<u32, AuthSessionState> = HashMap::new();
    let mut single_connect_user: Option<String> = None;
    let mut single_connect_active = false;
    let mut single_connect_locked = false;
    let mut single_connect_session: Option<u32> = None;
    loop {
        match read_packet(&mut stream, secret.as_deref().map(|s| s.as_slice())).await {
            Ok(Some(Packet::Authorization(request))) => {
                let authz_single =
                    request.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0;
                if single_connect_active && !authz_single {
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
                    if let Some(bound) = single_connect_session {
                        if bound != request.header.session_id {
                            warn!(peer = %peer, user = %request.user, session = request.header.session_id, bound_session = bound, "single-connect violation: session-id mismatch on authorization");
                            break;
                        }
                    }
                    if let Some(ref bound_user) = single_connect_user {
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
                let decision = {
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
                    } else if !request.has_cmd_attrs() || !request.has_service_attr() {
                        AuthorizationResponse {
                            status: AUTHOR_STATUS_ERROR,
                            server_msg: "missing required command/service attributes".to_string(),
                            data: String::new(),
                            args: Vec::new(),
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
                let single_connect = match &packet {
                    AuthenPacket::Start(start) => {
                        start.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0
                    }
                    AuthenPacket::Continue(cont) => {
                        cont.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0
                    }
                };
                if single_connect_active && !single_connect {
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
                    if single_connect_active {
                        if let Some(ref bound_user) = single_connect_user {
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
                        if single_connect_locked {
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
                        if let Some(bound) = single_connect_session {
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
                            port_raw: Some(start.port_raw.clone()),
                            port: if start.port_raw.is_empty() || start.port.is_empty() {
                                None
                            } else {
                                Some(start.port.clone())
                            },
                            rem_addr_raw: Some(start.rem_addr_raw.clone()),
                            rem_addr: if start.rem_addr_raw.is_empty() || start.rem_addr.is_empty() {
                                None
                            } else {
                                Some(start.rem_addr.clone())
                            },
                            ascii_need_user: false,
                            ascii_need_pass: false,
                            chap_id: None,
                            ascii_attempts: 0,
                            ascii_user_attempts: 0,
                            ascii_pass_attempts: 0,
                            service: Some(start.service),
                            action: Some(start.action),
                        }),
                        AuthenPacket::Continue(_) => AuthSessionState {
                            last_seq: 0,
                            expect_client: true,
                            authen_type: None,
                            challenge: None,
                            username: None,
                            username_raw: None,
                            port_raw: None,
                            port: None,
                            rem_addr_raw: None,
                            rem_addr: None,
                            ascii_need_user: false,
                            ascii_need_pass: false,
                            chap_id: None,
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

                let reply = match packet {
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
                                        calc_ascii_backoff(ascii_backoff_ms, state.ascii_attempts)
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
                            let data = start.parsed_data();
                            let password = match data {
                                AuthenData::Pap { ref password } => password.as_str(),
                                _ => "",
                            };
                            AuthenReply {
                                status: if verify_pap(&start.user, password, &credentials) {
                                    AUTHEN_STATUS_PASS
                                } else {
                                    AUTHEN_STATUS_FAIL
                                },
                                flags: 0,
                                server_msg: String::new(),
                                server_msg_raw: Vec::new(),
                                data: Vec::new(),
                            }
                        }
                        AUTHEN_TYPE_CHAP => {
                            let chal_len = if start.authen_type == AUTHEN_TYPE_CHAP {
                                16
                            } else {
                                8
                            };
                            let mut chal = vec![0u8; chal_len];
                            let mut chap_id = [0u8; 1];
                            if rand_bytes(&mut chal).is_err() || rand_bytes(&mut chap_id).is_err() {
                                AuthenReply {
                                    status: AUTHEN_STATUS_ERROR,
                                    flags: 0,
                                    server_msg: "failed to generate challenge".into(),
                                    server_msg_raw: Vec::new(),
                                    data: Vec::new(),
                                }
                            } else {
                                state.challenge = Some(chal.clone());
                                state.chap_id = Some(chap_id[0]);
                                AuthenReply {
                                    status: AUTHEN_STATUS_GETDATA,
                                    flags: 0,
                                    server_msg: String::new(),
                                    server_msg_raw: Vec::new(),
                                    data: {
                                        let mut payload = Vec::with_capacity(1 + chal_len);
                                        payload.extend_from_slice(&chap_id);
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
                            let (policy_user_prompt, policy_pass_prompt) = {
                                let policy = policy.read().await;
                                let policy_user = username_for_policy(
                                    state.username.as_deref(),
                                    state.username_raw.as_ref(),
                                );
                                let policy_port =
                                    field_for_policy(state.port.as_deref(), state.port_raw.as_ref());
                                let policy_rem = field_for_policy(
                                    state.rem_addr.as_deref(),
                                    state.rem_addr_raw.as_ref(),
                                );
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
                            let uname_prompt = if !cont.user_msg.is_empty() {
                                cont.user_msg.clone()
                            } else if let Some(custom) = policy_user_prompt {
                                custom
                            } else {
                                match (state.service, state.action) {
                                    (Some(svc), Some(act)) => {
                                        format!("Username (service {svc}, action {act}):").into_bytes()
                                    }
                                    (Some(svc), None) => format!("Username (service {svc}):").into_bytes(),
                                    _ => b"Username:".to_vec(),
                                }
                            };
                            let pwd_prompt = if !cont.user_msg.is_empty() {
                                cont.user_msg.clone()
                            } else if let Some(custom) = policy_pass_prompt {
                                custom
                            } else {
                                match (state.service, state.action) {
                                    (Some(svc), Some(act)) => {
                                        format!("Password (service {svc}, action {act}):").into_bytes()
                                    }
                                    (Some(svc), None) => format!("Password (service {svc}):").into_bytes(),
                                    _ => b"Password:".to_vec(),
                                }
                            };

                            if cont.flags & AUTHEN_CONT_ABORT != 0 {
                                state.ascii_need_user = true;
                                state.ascii_need_pass = false;
                                state.username = None;
                                state.username_raw = None;
                                state.ascii_attempts = 0;
                                state.ascii_user_attempts = 0;
                                state.ascii_pass_attempts = 0;
                                let policy_abort = {
                                    let policy = policy.read().await;
                                    policy.message_abort().map(|m| m.to_string())
                                };
                                AuthenReply {
                                    status: AUTHEN_STATUS_FAIL,
                                    flags: 0,
                                    server_msg: policy_abort
                                        .unwrap_or_else(|| "authentication aborted".into()),
                                    server_msg_raw: Vec::new(),
                                    data: Vec::new(),
                                }
                            } else if ascii_attempt_limit > 0
                                && state.ascii_attempts >= ascii_attempt_limit
                            {
                                AuthenReply {
                                    status: AUTHEN_STATUS_FAIL,
                                    flags: 0,
                                    server_msg: "too many authentication attempts".into(),
                                    server_msg_raw: Vec::new(),
                                    data: Vec::new(),
                                }
                            } else if state.ascii_need_user
                                && ascii_user_attempt_limit > 0
                                && state.ascii_user_attempts >= ascii_user_attempt_limit
                            {
                                AuthenReply {
                                    status: AUTHEN_STATUS_FAIL,
                                    flags: 0,
                                    server_msg: "too many username attempts".into(),
                                    server_msg_raw: Vec::new(),
                                    data: Vec::new(),
                                }
                            } else if state.ascii_need_pass
                                && ascii_pass_attempt_limit > 0
                                && state.ascii_pass_attempts >= ascii_pass_attempt_limit
                            {
                                AuthenReply {
                                    status: AUTHEN_STATUS_FAIL,
                                    flags: 0,
                                    server_msg: "too many password attempts".into(),
                                    server_msg_raw: Vec::new(),
                                    data: Vec::new(),
                                }
                            } else {
                                if ascii_attempt_limit > 0 {
                                    state.ascii_attempts = state.ascii_attempts.saturating_add(1);
                                }

                                if state.ascii_need_user {
                                    state.ascii_user_attempts =
                                        state.ascii_user_attempts.saturating_add(1);
                                    let username_raw = cont.data.clone();
                                    if !username_raw.is_empty() {
                                        state.username_raw = Some(username_raw.clone());
                                        state.username =
                                            String::from_utf8(username_raw).ok();
                                        state.ascii_need_user = false;
                                        state.ascii_need_pass = true;
                                        AuthenReply {
                                            status: AUTHEN_STATUS_GETPASS,
                                            flags: AUTHEN_FLAG_NOECHO,
                                            server_msg: String::new(),
                                            server_msg_raw: Vec::new(),
                                            data: pwd_prompt.clone(),
                                        }
                                    } else {
                                        if let Some(delay) =
                                            calc_ascii_backoff(ascii_backoff_ms, state.ascii_attempts)
                                        {
                                            sleep(delay).await;
                                        }
                                        AuthenReply {
                                            status: AUTHEN_STATUS_GETUSER,
                                            flags: 0,
                                            server_msg: String::new(),
                                            server_msg_raw: Vec::new(),
                                            data: uname_prompt.clone(),
                                        }
                                    }
                                } else if state.ascii_need_pass {
                                    state.ascii_pass_attempts =
                                        state.ascii_pass_attempts.saturating_add(1);
                                    if cont.data.is_empty() {
                                        if let Some(delay) =
                                            calc_ascii_backoff(ascii_backoff_ms, state.ascii_attempts)
                                        {
                                            sleep(delay).await;
                                        }
                                        AuthenReply {
                                            status: AUTHEN_STATUS_GETPASS,
                                            flags: AUTHEN_FLAG_NOECHO,
                                            server_msg: String::new(),
                                            server_msg_raw: Vec::new(),
                                            data: pwd_prompt.clone(),
                                        }
                                    } else {
                                        state.ascii_need_pass = false;
                                        let ok = if let Some(raw_user) = state.username_raw.as_ref()
                                        {
                                            verify_pap_bytes_username(
                                                raw_user,
                                                &cont.data,
                                                &credentials,
                                            )
                                        } else {
                                            let user = state.username.clone().unwrap_or_default();
                                            verify_pap_bytes(&user, &cont.data, &credentials)
                                        };
                                        let svc_str = state
                                            .service
                                            .map(|svc| format!(" (service {svc})"))
                                            .unwrap_or_default();
                                            let act_str = state
                                                .action
                                                .map(|act| format!(" action {act}"))
                                                .unwrap_or_default();
                                        let policy = policy.read().await;
                                        if !ok {
                                            if let Some(delay) = calc_ascii_backoff(
                                                ascii_backoff_ms,
                                                state.ascii_attempts,
                                            ) {
                                                sleep(delay).await;
                                            }
                                        }
                                        AuthenReply {
                                            status: if ok {
                                                AUTHEN_STATUS_PASS
                                            } else {
                                                AUTHEN_STATUS_FAIL
                                            },
                                            flags: 0, // clear NOECHO after decision
                                            server_msg: if ok {
                                                policy
                                                    .message_success()
                                                    .map(|m| m.to_string())
                                                    .unwrap_or_else(|| {
                                                        format!(
                                                            "authentication succeeded{svc_str}{act_str}"
                                                        )
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
                                    }
                                } else {
                                    state.ascii_need_user = true;
                                    state.ascii_need_pass = false;
                                    state.username = None;
                                    state.username_raw = None;
                                    state.ascii_attempts = 0;
                                    state.ascii_user_attempts = 0;
                                    state.ascii_pass_attempts = 0;
                                    AuthenReply {
                                        status: AUTHEN_STATUS_RESTART,
                                        flags: 0,
                                        server_msg: "restart authentication".into(),
                                        server_msg_raw: Vec::new(),
                                        data: Vec::new(),
                                    }
                                }
                            }
                        }
                        _ if state.challenge.is_some() => {
                            let user = state.username.clone().unwrap_or_default();
                            match state.authen_type {
                                Some(AUTHEN_TYPE_CHAP) => {
                                    if cont.data.len() != 1 + 16 {
                                        AuthenReply {
                                            status: AUTHEN_STATUS_ERROR,
                                            flags: 0,
                                            server_msg: "invalid CHAP continue length".into(),
                                            server_msg_raw: Vec::new(),
                                            data: Vec::new(),
                                        }
                                    } else if state.chap_id.is_some()
                                        && cont.data[0] != state.chap_id.unwrap()
                                    {
                                        AuthenReply {
                                            status: AUTHEN_STATUS_FAIL,
                                            flags: 0,
                                            server_msg: "CHAP identifier mismatch".into(),
                                            server_msg_raw: Vec::new(),
                                            data: Vec::new(),
                                        }
                                    } else if let Some(expected) = compute_chap_response(
                                        &user,
                                        &credentials,
                                        cont.data.as_slice(),
                                        state.challenge.as_ref().unwrap(),
                                    ) {
                                        state.challenge = None;
                                        state.chap_id = None;
                                        if expected {
                                            AuthenReply {
                                                status: AUTHEN_STATUS_PASS,
                                                flags: 0,
                                                server_msg: String::new(),
                                                server_msg_raw: Vec::new(),
                                                data: Vec::new(),
                                            }
                                        } else {
                                            AuthenReply {
                                                status: AUTHEN_STATUS_FAIL,
                                                flags: 0,
                                                server_msg: "invalid CHAP response".into(),
                                                server_msg_raw: Vec::new(),
                                                data: Vec::new(),
                                            }
                                        }
                                    } else {
                                        AuthenReply {
                                            status: AUTHEN_STATUS_ERROR,
                                            flags: 0,
                                            server_msg: "missing credentials".into(),
                                            server_msg_raw: Vec::new(),
                                            data: Vec::new(),
                                        }
                                    }
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
                let header = match packet {
                    AuthenPacket::Start(ref start) => &start.header,
                    AuthenPacket::Continue(ref cont) => &cont.header,
                };

                if let Err(err) = state.prepare_server_reply(&header.response(0)) {
                    warn!(error = %err, peer = %peer, "auth reply sequence invalid");
                }

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
                    {
                        let policy = policy.read().await;
                        let policy_user = username_for_policy(
                            state.username.as_deref(),
                            state.username_raw.as_ref(),
                        );
                        let policy_port =
                            field_for_policy(state.port.as_deref(), state.port_raw.as_ref());
                        let policy_rem =
                            field_for_policy(state.rem_addr.as_deref(), state.rem_addr_raw.as_ref());
                        policy.observe_server_msg(
                            policy_user.as_deref(),
                            policy_port.as_deref(),
                            policy_rem.as_deref(),
                            &reply.server_msg_raw,
                        );
                    }
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
                        single_connect_active = false;
                        single_connect_user = None;
                        single_connect_locked = false;
                    }
                }
                if matches!(reply.status, AUTHEN_STATUS_PASS) && single_connect {
                    if let Some(user) = single_user {
                        single_connect_user = Some(user.clone());
                        single_connect_active = true;
                        single_connect_locked = true;
                        single_connect_session = Some(session_id);
                        info!(peer = %peer, user = %user, session = session_id, "single-connect established");
                    }
                }
            }
            Ok(Some(Packet::Accounting(request))) => {
                let acct_single = request.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0;
                if single_connect_active && !acct_single {
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
                    if let Some(bound) = single_connect_session {
                        if bound != request.header.session_id {
                            warn!(peer = %peer, user = %request.user, session = request.header.session_id, bound_session = bound, "single-connect violation: session-id mismatch on accounting");
                            break;
                        }
                    }
                    if let Some(ref bound_user) = single_connect_user {
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
                let response = AccountingResponse {
                    status: ACCT_STATUS_SUCCESS,
                    server_msg: String::new(),
                    data: String::new(),
                    args: Vec::new(),
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
            Ok(None) => break,
            Err(err) => {
                warn!(error = %err, peer = %peer, "failed reading request");
                break;
            }
        }
    }

    Ok(())
}

async fn watch_sighup(
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
mod auth;
mod config;
mod tls;
