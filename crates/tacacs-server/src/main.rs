use crate::auth::{compute_chap_response, verify_pap};
use crate::config::{Args, credentials_map};
use crate::tls::build_tls_config;
use anyhow::{Context, Result, bail};
use clap::Parser;
use openssl::rand::rand_bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
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
        handles.push(tokio::spawn(async move {
            if let Err(err) = serve_tls(addr, acceptor, policy, secret, credentials).await {
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
        handles.push(tokio::spawn(async move {
            if let Err(err) = serve_legacy(addr, policy, secret, credentials).await {
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
        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(stream) => {
                    if let Err(err) = handle_connection(
                        stream,
                        policy,
                        format!("{peer_addr}"),
                        secret,
                        credentials,
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
        tokio::spawn(async move {
            if let Err(err) =
                handle_connection(socket, policy, format!("{peer_addr}"), secret, credentials).await
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
                            warn!(peer = %peer, "single-connect violation: session-id mismatch on authorization");
                            break;
                        }
                    }
                    if let Some(ref bound_user) = single_connect_user {
                        if bound_user != &request.user {
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
                        warn!(peer = %peer, "single-connect violation: authorization before authentication");
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
                    warn!(peer = %peer, "single-connect violation: flag missing on authentication");
                    let reply = AuthenReply {
                        status: AUTHEN_STATUS_ERROR,
                        flags: 0,
                        server_msg: "single-connection flag required after authentication".into(),
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
                                warn!(peer = %peer, "single-connect violation: user mismatch on authentication");
                                let reply = AuthenReply {
                                    status: AUTHEN_STATUS_ERROR,
                                    flags: 0,
                                    server_msg: "single-connection user mismatch".into(),
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
                            warn!(peer = %peer, "single-connect violation: authentication with missing bound user");
                            let reply = AuthenReply {
                                status: AUTHEN_STATUS_ERROR,
                                flags: 0,
                                server_msg: "single-connection not authenticated".into(),
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
                            warn!(peer = %peer, "single-connect violation: repeated authentication after lock");
                            let reply = AuthenReply {
                                status: AUTHEN_STATUS_ERROR,
                                flags: 0,
                                server_msg: "single-connection already authenticated".into(),
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
                                warn!(peer = %peer, "single-connect violation: session-id mismatch on authentication");
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
                        )
                        .unwrap_or(AuthSessionState {
                            last_seq: start.header.seq_no,
                            expect_client: false,
                            authen_type: Some(start.authen_type),
                            challenge: None,
                            username: Some(start.user.clone()),
                            ascii_need_user: false,
                            ascii_need_pass: false,
                            chap_id: None,
                        }),
                        AuthenPacket::Continue(_) => AuthSessionState {
                            last_seq: 0,
                            expect_client: true,
                            authen_type: None,
                            challenge: None,
                            username: None,
                            ascii_need_user: false,
                            ascii_need_pass: false,
                            chap_id: None,
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
                            state.username = if start.user.is_empty() {
                                None
                            } else {
                                Some(start.user.clone())
                            };
                            state.ascii_need_user = state.username.is_none();
                            if state.ascii_need_user {
                                AuthenReply {
                                    status: AUTHEN_STATUS_GETUSER,
                                    flags: 0,
                                    server_msg: "Username:".into(),
                                    data: Vec::new(),
                                }
                            } else if !start.data.is_empty() {
                                match String::from_utf8(start.data.clone()) {
                                    Ok(password) => AuthenReply {
                                        status: if verify_pap(
                                            state.username.as_deref().unwrap_or_default(),
                                            &password,
                                            &credentials,
                                        ) {
                                            AUTHEN_STATUS_PASS
                                        } else {
                                            AUTHEN_STATUS_FAIL
                                        },
                                        flags: 0,
                                        server_msg: String::new(),
                                        data: Vec::new(),
                                    },
                                    Err(_) => AuthenReply {
                                        status: AUTHEN_STATUS_ERROR,
                                        flags: 0,
                                        server_msg: "invalid ASCII password encoding".into(),
                                        data: Vec::new(),
                                    },
                                }
                            } else {
                                state.ascii_need_pass = true;
                                AuthenReply {
                                    status: AUTHEN_STATUS_GETPASS,
                                    flags: AUTHEN_FLAG_NOECHO,
                                    server_msg: "Password:".into(),
                                    data: Vec::new(),
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
                                    data: Vec::new(),
                                }
                            } else {
                                state.challenge = Some(chal.clone());
                                state.chap_id = Some(chap_id[0]);
                                AuthenReply {
                                    status: AUTHEN_STATUS_GETDATA,
                                    flags: 0,
                                    server_msg: String::new(),
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
                            data: Vec::new(),
                        },
                    },
                    AuthenPacket::Continue(ref cont) => match state.authen_type {
                        Some(AUTHEN_TYPE_ASCII) => {
                            if state.ascii_need_user {
                                match String::from_utf8(cont.data.clone()) {
                                    Ok(username) if !username.is_empty() => {
                                        state.username = Some(username);
                                        state.ascii_need_user = false;
                                        state.ascii_need_pass = true;
                                        AuthenReply {
                                            status: AUTHEN_STATUS_GETPASS,
                                            flags: AUTHEN_FLAG_NOECHO,
                                            server_msg: "Password:".into(),
                                            data: Vec::new(),
                                        }
                                    }
                                    _ => AuthenReply {
                                        status: AUTHEN_STATUS_ERROR,
                                        flags: 0,
                                        server_msg: "username required".into(),
                                        data: Vec::new(),
                                    },
                                }
                            } else if state.ascii_need_pass {
                                match String::from_utf8(cont.data.clone()) {
                                    Ok(password) => {
                                        state.ascii_need_pass = false;
                                        let user = state.username.clone().unwrap_or_default();
                                        AuthenReply {
                                            status: if verify_pap(&user, &password, &credentials) {
                                                AUTHEN_STATUS_PASS
                                            } else {
                                                AUTHEN_STATUS_FAIL
                                            },
                                            flags: 0,
                                            server_msg: String::new(),
                                            data: Vec::new(),
                                        }
                                    }
                                    Err(_) => AuthenReply {
                                        status: AUTHEN_STATUS_ERROR,
                                        flags: 0,
                                        server_msg: "invalid ASCII input".into(),
                                        data: Vec::new(),
                                    },
                                }
                            } else {
                                AuthenReply {
                                    status: AUTHEN_STATUS_FAIL,
                                    flags: 0,
                                    server_msg: "unexpected continue".into(),
                                    data: Vec::new(),
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
                                            data: Vec::new(),
                                        }
                                    } else if state.chap_id.is_some()
                                        && cont.data[0] != state.chap_id.unwrap()
                                    {
                                        AuthenReply {
                                            status: AUTHEN_STATUS_FAIL,
                                            flags: 0,
                                            server_msg: "CHAP identifier mismatch".into(),
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
                                                data: Vec::new(),
                                            }
                                        } else {
                                            AuthenReply {
                                                status: AUTHEN_STATUS_FAIL,
                                                flags: 0,
                                                server_msg: "invalid CHAP response".into(),
                                                data: Vec::new(),
                                            }
                                        }
                                    } else {
                                        AuthenReply {
                                            status: AUTHEN_STATUS_ERROR,
                                            flags: 0,
                                            server_msg: "missing credentials".into(),
                                            data: Vec::new(),
                                        }
                                    }
                                }
                                _ => AuthenReply {
                                    status: AUTHEN_STATUS_FAIL,
                                    flags: 0,
                                    server_msg: "unexpected continue".into(),
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
                        single_connect_user = Some(user);
                        single_connect_active = true;
                        single_connect_locked = true;
                        single_connect_session = Some(session_id);
                    }
                }
            }
            Ok(Some(Packet::Accounting(request))) => {
                let acct_single = request.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0;
                if single_connect_active && !acct_single {
                    warn!(peer = %peer, "single-connect violation: flag missing on accounting");
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
                            warn!(peer = %peer, "single-connect violation: session-id mismatch on accounting");
                            break;
                        }
                    }
                    if let Some(ref bound_user) = single_connect_user {
                        if bound_user != &request.user {
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
                        warn!(peer = %peer, "single-connect violation: accounting before authentication");
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
