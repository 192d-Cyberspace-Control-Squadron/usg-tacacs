use anyhow::{bail, Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;
use openssl::rand::rand_bytes;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use std::collections::HashMap;
use crate::auth::{compute_chap_response, verify_arap, verify_pap};
use crate::config::{Args, credentials_map};
use crate::tls::build_tls_config;
use usg_tacacs_policy::{validate_policy_file, PolicyEngine};
use usg_tacacs_proto::{
    read_packet, validate_accounting_response_header, validate_author_response_header, write_accounting_response, write_authen_reply, write_author_response,
    AuthenPacket, AuthenReply, AccountingResponse, AuthorizationResponse, Packet, AuthSessionState,
    AuthenData,
    AUTHEN_STATUS_ERROR, AUTHEN_STATUS_FAIL, AUTHEN_STATUS_FOLLOW, AUTHEN_STATUS_GETDATA, AUTHEN_STATUS_PASS,
    AUTHOR_STATUS_ERROR,
    AUTHOR_STATUS_FAIL, AUTHOR_STATUS_PASS_ADD, ACCT_STATUS_SUCCESS, AUTHEN_TYPE_ASCII,
    AUTHEN_TYPE_PAP, AUTHEN_TYPE_CHAP, AUTHEN_TYPE_ARAP,
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
        if allow_unencrypted && shared_secret.as_ref().map(|s| s.len()).unwrap_or(0) < usg_tacacs_proto::MIN_SECRET_LEN {
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
                    if let Err(err) =
                        handle_connection(stream, policy, format!("{peer_addr}"), secret, credentials).await
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
    loop {
        match read_packet(&mut stream, secret.as_deref().map(|s| s.as_slice())).await {
            Ok(Some(Packet::Authorization(request))) => {
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
                let state = auth_states.entry(session_id).or_insert_with(|| match &packet {
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
                    }),
                    AuthenPacket::Continue(_) => AuthSessionState {
                        last_seq: 0,
                        expect_client: true,
                        authen_type: None,
                        challenge: None,
                        username: None,
                    },
                });
                if let AuthenPacket::Continue(ref cont) = packet {
                    if let Err(err) = state.validate_client(&cont.header) {
                        warn!(error = %err, peer = %peer, "auth sequence invalid");
                    }
                }

                let reply = match packet {
                    AuthenPacket::Start(ref start) => {
                        match start.authen_type {
                            AUTHEN_TYPE_ASCII | AUTHEN_TYPE_PAP => {
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
                                    data: String::new(),
                                }
                            }
                            AUTHEN_TYPE_CHAP | AUTHEN_TYPE_ARAP => {
                                let chal_len = if start.authen_type == AUTHEN_TYPE_CHAP {
                                    16
                                } else {
                                    8
                                };
                                let mut chal = vec![0u8; chal_len];
                                if rand_bytes(&mut chal).is_err() {
                                    AuthenReply {
                                        status: AUTHEN_STATUS_ERROR,
                                        flags: 0,
                                        server_msg: "failed to generate challenge".into(),
                                        data: String::new(),
                                    }
                                } else {
                                    state.challenge = Some(chal.clone());
                                    AuthenReply {
                                        status: AUTHEN_STATUS_GETDATA,
                                        flags: 0,
                                        server_msg: String::new(),
                                        data: hex::encode(chal),
                                    }
                                }
                            }
                            _ => AuthenReply {
                                status: AUTHEN_STATUS_FOLLOW,
                                flags: 0,
                                server_msg: "unsupported auth type - fallback".into(),
                                data: String::new(),
                            },
                        }
                    }
                    AuthenPacket::Continue(ref cont) => {
                        if state.challenge.is_some() {
                            let user = state.username.clone().unwrap_or_default();
                            match state.authen_type {
                        Some(AUTHEN_TYPE_CHAP) => {
                            if let Some(expected) = compute_chap_response(
                                &user,
                                &credentials,
                                cont.data.as_slice(),
                                state.challenge.as_ref().unwrap(),
                            ) {
                                state.challenge = None;
                                if expected {
                                    AuthenReply {
                                        status: AUTHEN_STATUS_PASS,
                                        flags: 0,
                                        server_msg: String::new(),
                                        data: String::new(),
                                    }
                                } else {
                                    AuthenReply {
                                        status: AUTHEN_STATUS_FAIL,
                                        flags: 0,
                                        server_msg: "invalid CHAP response".into(),
                                        data: String::new(),
                                    }
                                }
                            } else {
                                AuthenReply {
                                    status: AUTHEN_STATUS_ERROR,
                                    flags: 0,
                                    server_msg: "missing credentials".into(),
                                    data: String::new(),
                                }
                            }
                        }
                        Some(AUTHEN_TYPE_ARAP) => {
                            let ok = verify_arap(cont.data.as_slice(), state.challenge.as_ref().unwrap());
                            state.challenge = None;
                            AuthenReply {
                                status: if ok { AUTHEN_STATUS_PASS } else { AUTHEN_STATUS_FAIL },
                                flags: 0,
                                server_msg: if ok {
                                    String::new()
                                } else {
                                    "invalid ARAP response".into()
                                },
                                data: String::new(),
                            }
                        }
                        _ => AuthenReply {
                            status: AUTHEN_STATUS_FAIL,
                            flags: 0,
                            server_msg: "unexpected continue".into(),
                            data: String::new(),
                        },
                            }
                        } else {
                            AuthenReply {
                                status: AUTHEN_STATUS_FAIL,
                                flags: 0,
                                server_msg: format!(
                                    "unexpected authentication continue (flags {:02x})",
                                    cont.flags
                                ),
                                data: String::new(),
                            }
                        }
                    }
                };
                let header = match packet {
                    AuthenPacket::Start(ref start) => &start.header,
                    AuthenPacket::Continue(ref cont) => &cont.header,
                };

                if let Err(err) = state.prepare_server_reply(&header.response(0)) {
                    warn!(error = %err, peer = %peer, "auth reply sequence invalid");
                }

                write_authen_reply(&mut stream, header, &reply, secret.as_deref().map(|s| s.as_slice()))
                    .await
                    .with_context(|| "sending TACACS+ auth reply")?;
            }
            Ok(Some(Packet::Accounting(request))) => {
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
