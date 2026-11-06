use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use russh::client::{self, Handler, Msg, Session};
use russh::keys::agent::client::AgentClient;
use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use russh::{Channel, ChannelId, ChannelMsg, Disconnect};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::config::{ResolvedHost, Resolver};
use crate::error::{AppError, sanitize_secret};
use crate::forward::ValidatedForward;
use crate::known_hosts::{self, HostKeyVerdict, TrustEntry, TrustStore};
use crate::model::{
    AuthMode, Direction, ForwardStatus, HistoryEntry, Phase, Profile, Target, TunnelSnapshot,
    now_rfc3339,
};
use crate::secrets::{self, SecretStore};
use crate::store::AppStore;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyPrompt {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
}

#[async_trait]
pub trait HostKeyPrompter: Send + Sync {
    async fn confirm_unknown(&self, prompt: &HostKeyPrompt) -> bool;
}

pub struct FixedPrompter(pub bool);

#[async_trait]
impl HostKeyPrompter for FixedPrompter {
    async fn confirm_unknown(&self, _: &HostKeyPrompt) -> bool {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub identity_files: Vec<String>,
    pub identities_only: bool,
    pub identity_agent: Option<String>,
    pub known_hosts_files: Vec<PathBuf>,
    pub proxy_command: Option<String>,
}

pub struct SessionSpec {
    pub profile_id: String,
    pub name: String,
    pub hops: Vec<Endpoint>,
    pub auth_mode: AuthMode,
    pub preferred: Vec<String>,
    pub forwards: Vec<ValidatedForward>,
    pub password: Option<Zeroizing<String>>,
    pub passphrase: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for SessionSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSpec")
            .field("profile_id", &self.profile_id)
            .field("hops", &self.hops.len())
            .field("auth_mode", &self.auth_mode)
            .field("forwards", &self.forwards.len())
            .finish()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectOutcome {
    pub snapshot: TunnelSnapshot,
    pub warnings: Vec<AppError>,
}

pub struct ActiveSession {
    snapshot: Arc<Mutex<TunnelSnapshot>>,
    cancel: CancellationToken,
    done: Arc<tokio::sync::Notify>,
}

impl ActiveSession {
    pub fn snapshot(&self) -> TunnelSnapshot {
        self.snapshot.lock().expect("snapshot").clone()
    }

    pub async fn shutdown(self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.done.notified()).await;
    }
}

struct Running {
    session: ActiveSession,
    history_id: String,
}

pub struct TunnelManager {
    store: AppStore,
    secrets: Arc<dyn SecretStore>,
    resolver: Resolver,
    running: Mutex<HashMap<String, Running>>,
    watch: watch::Sender<Vec<TunnelSnapshot>>,
}

impl TunnelManager {
    pub fn new(store: AppStore, secrets: Arc<dyn SecretStore>, resolver: Resolver) -> Self {
        let (watch, _) = watch::channel(Vec::new());
        Self {
            store,
            secrets,
            resolver,
            running: Mutex::new(HashMap::new()),
            watch,
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<Vec<TunnelSnapshot>> {
        self.watch.subscribe()
    }

    pub fn snapshots(&self) -> Vec<TunnelSnapshot> {
        self.running
            .lock()
            .expect("running")
            .values()
            .map(|running| running.session.snapshot())
            .collect()
    }

    pub async fn connect(
        &self,
        profile_id: &str,
        password: Option<Zeroizing<String>>,
        passphrase: Option<Zeroizing<String>>,
        remember_password: bool,
        remember_passphrase: bool,
        prompter: Arc<dyn HostKeyPrompter>,
    ) -> Result<ConnectOutcome, AppError> {
        if self
            .running
            .lock()
            .expect("running")
            .get(profile_id)
            .is_some_and(|running| {
                matches!(
                    running.session.snapshot().phase,
                    Phase::Connecting | Phase::Authenticating | Phase::Binding | Phase::Connected
                )
            })
        {
            return Err(AppError::new(
                "already_connected",
                "这条隧道已经在连接或运行",
            ));
        }
        let profile = self
            .store
            .load_profiles()?
            .into_iter()
            .find(|profile| profile.id == profile_id)
            .ok_or_else(|| AppError::new("not_found", "找不到这条隧道"))?;
        let mut warnings = Vec::new();
        let password =
            self.prepare_password(&profile, password, remember_password, &mut warnings)?;
        let passphrase =
            self.prepare_passphrase(&profile, passphrase, remember_passphrase, &mut warnings)?;
        let spec = self.spec_for_profile(&profile, password, passphrase)?;
        let secret_view = secret_view(&spec);
        let trust = Arc::new(Mutex::new(self.store.load_trust()?));
        let result = start_session(spec, prompter, self.store.trust_path(), trust.clone()).await;
        if let Ok(trust) = trust.lock() {
            let _ = self.store.save_trust(&trust);
        }
        match result {
            Ok(session) => {
                let snapshot = session.snapshot();
                let history_id = crate::model::new_id();
                self.store.push_history(HistoryEntry {
                    id: history_id.clone(),
                    profile_id: profile.id.clone(),
                    name: profile.name.clone(),
                    target: snapshot_target(&snapshot, &profile),
                    started_at: snapshot.connected_at.clone().unwrap_or_else(now_rfc3339),
                    ended_at: None,
                    outcome: "connected".into(),
                    message: sanitize_secret(&snapshot.message, secret_view.as_deref()),
                })?;
                self.running.lock().expect("running").insert(
                    profile.id.clone(),
                    Running {
                        session,
                        history_id,
                    },
                );
                self.publish();
                Ok(ConnectOutcome {
                    snapshot: self
                        .running
                        .lock()
                        .expect("running")
                        .get(&profile.id)
                        .unwrap()
                        .session
                        .snapshot(),
                    warnings,
                })
            }
            Err(err) => {
                let message = sanitize_secret(&err.message, secret_view.as_deref());
                let target = profile_target_label(&profile);
                let _ = self.store.push_history(HistoryEntry {
                    id: crate::model::new_id(),
                    profile_id: profile.id,
                    name: profile.name,
                    target,
                    started_at: now_rfc3339(),
                    ended_at: Some(now_rfc3339()),
                    outcome: err.code.clone(),
                    message,
                });
                Err(err)
            }
        }
    }

    pub async fn disconnect(&self, profile_id: &str) -> Result<(), AppError> {
        let running = self.running.lock().expect("running").remove(profile_id);
        if let Some(running) = running {
            let history_id = running.history_id;
            running.session.shutdown().await;
            if let Ok(mut history) = self.store.load_history() {
                if let Some(entry) = history.iter_mut().find(|entry| entry.id == history_id) {
                    entry.ended_at = Some(now_rfc3339());
                    entry.outcome = "disconnected".into();
                    entry.message = "已断开，监听端口已释放".into();
                }
                let _ = self.store.save_history(&history);
            }
        }
        self.publish();
        Ok(())
    }

    pub async fn disconnect_all(&self) -> Result<(), AppError> {
        let ids: Vec<String> = self
            .running
            .lock()
            .expect("running")
            .keys()
            .cloned()
            .collect();
        for id in ids {
            self.disconnect(&id).await?;
        }
        Ok(())
    }

    fn publish(&self) {
        let _ = self.watch.send(self.snapshots());
    }

    pub fn store(&self) -> &AppStore {
        &self.store
    }

    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    pub fn keyring_status(&self) -> crate::secrets::SecretBackendStatus {
        self.secrets.status()
    }

    fn prepare_password(
        &self,
        profile: &Profile,
        typed: Option<Zeroizing<String>>,
        remember: bool,
        warnings: &mut Vec<AppError>,
    ) -> Result<Option<Zeroizing<String>>, AppError> {
        let account = secrets::server_password_account(&profile.id);
        if let Some(password) = typed {
            if remember {
                if let Err(err) = self.secrets.set(&account, &password) {
                    warnings.push(err);
                }
            } else if let Err(err) = self.secrets.delete(&account) {
                warnings.push(err);
            }
            return Ok(Some(password));
        }
        if profile.remember_password || remember {
            {
                let value = self.secrets.get(&account)?;
                return Ok(value);
            }
        }
        Ok(None)
    }

    fn prepare_passphrase(
        &self,
        profile: &Profile,
        typed: Option<Zeroizing<String>>,
        remember: bool,
        warnings: &mut Vec<AppError>,
    ) -> Result<Option<Zeroizing<String>>, AppError> {
        if let Some(passphrase) = typed {
            if remember {
                let identities = self.identity_paths(profile)?;
                if identities.is_empty() {
                    warnings.push(AppError::new(
                        "keyring_unavailable",
                        "没有具体的密钥文件，无法把口令保存到钥匙串",
                    ));
                }
                for path in identities {
                    let account = secrets::key_passphrase_account(&profile.id, &path);
                    if let Err(err) = self.secrets.set(&account, &passphrase) {
                        warnings.push(err);
                        break;
                    }
                }
            }
            return Ok(Some(passphrase));
        }
        Ok(None)
    }

    fn identity_paths(&self, profile: &Profile) -> Result<Vec<String>, AppError> {
        let resolved = self.resolve_profile(profile)?;
        Ok(resolved.identity_files)
    }

    fn resolve_profile(&self, profile: &Profile) -> Result<ResolvedHost, AppError> {
        match &profile.target {
            Target::ConfigAlias { alias } => self.resolver.resolve(alias),
            Target::Manual {
                hostname,
                port,
                user,
                identity_file,
                proxy_jump,
            } => {
                let mut resolved = self.resolver.resolve(hostname)?;
                resolved.hostname = hostname.clone();
                resolved.user = user.clone();
                resolved.port = *port;
                if let Some(path) = identity_file
                    && !path.trim().is_empty()
                {
                    resolved.identity_files = vec![path.clone()];
                }
                if let Some(jump) = proxy_jump {
                    if jump.trim().is_empty() {
                        resolved.proxy_jump = None;
                        resolved.proxy_command = None;
                    } else {
                        resolved.proxy_jump = Some(jump.clone());
                        resolved.proxy_command = None;
                    }
                }
                Ok(resolved)
            }
        }
    }

    fn spec_for_profile(
        &self,
        profile: &Profile,
        password: Option<Zeroizing<String>>,
        passphrase: Option<Zeroizing<String>>,
    ) -> Result<SessionSpec, AppError> {
        crate::model::ensure_profile_shape(profile)?;
        let resolved = self.resolve_profile(profile)?;
        let mut hops = Vec::new();
        let mut stack = Vec::new();
        append_resolved(&self.resolver, resolved, &mut stack, &mut hops)?;
        let forwards = profile
            .forwards
            .iter()
            .map(crate::forward::validate_mapping)
            .collect::<Result<Vec<_>, _>>()?;
        let preferred = hops
            .last()
            .map(|hop| hop.preferred.clone())
            .unwrap_or_default();
        Ok(SessionSpec {
            profile_id: profile.id.clone(),
            name: profile.name.clone(),
            hops: hops.into_iter().map(Endpoint::from).collect(),
            auth_mode: profile.auth_mode,
            preferred,
            forwards,
            password,
            passphrase,
        })
    }

    pub fn secret_meta(&self, profile_id: &str) -> Result<crate::model::SecretMeta, AppError> {
        let status = self.secrets.status();
        let server_password_stored = match self
            .secrets
            .get(&secrets::server_password_account(profile_id))
        {
            Ok(value) => value.is_some(),
            Err(_) => false,
        };
        let mut key_passphrase_stored = false;
        if let Some(profile) = self
            .store
            .load_profiles()?
            .into_iter()
            .find(|profile| profile.id == profile_id)
            && let Ok(paths) = self.identity_paths(&profile)
        {
            key_passphrase_stored = paths.into_iter().any(|path| {
                self.secrets
                    .get(&secrets::key_passphrase_account(profile_id, &path))
                    .ok()
                    .flatten()
                    .is_some()
            });
        }
        Ok(crate::model::SecretMeta {
            server_password_stored,
            key_passphrase_stored,
            keyring_available: status.available,
            keyring_message: status.message,
        })
    }

    pub fn forget_server_password(&self, profile_id: &str) -> Result<(), AppError> {
        self.secrets
            .delete(&secrets::server_password_account(profile_id))
    }

    pub fn forget_passphrases(&self, profile_id: &str) -> Result<(), AppError> {
        if let Some(profile) = self
            .store
            .load_profiles()?
            .into_iter()
            .find(|profile| profile.id == profile_id)
            && let Ok(paths) = self.identity_paths(&profile)
        {
            for path in paths {
                self.secrets
                    .delete(&secrets::key_passphrase_account(profile_id, &path))?;
            }
        }
        Ok(())
    }
}

struct ResolvedHop {
    endpoint: Endpoint,
    preferred: Vec<String>,
}

impl From<ResolvedHop> for Endpoint {
    fn from(value: ResolvedHop) -> Self {
        value.endpoint
    }
}

fn append_resolved(
    resolver: &Resolver,
    resolved: ResolvedHost,
    stack: &mut Vec<String>,
    out: &mut Vec<ResolvedHop>,
) -> Result<(), AppError> {
    let marker = format!("{}:{}", resolved.hostname, resolved.port);
    if stack.iter().any(|item| item == &marker) {
        return Err(AppError::new("proxy_failed", "ProxyJump 出现循环"));
    }
    stack.push(marker);
    if resolved.proxy_command.is_none()
        && let Some(jump) = resolved.proxy_jump.clone()
    {
        for token in jump.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let parsed = parse_jump(token)?;
            let mut hop = resolver.resolve(&parsed.host)?;
            if let Some(user) = parsed.user {
                hop.user = user;
            }
            if let Some(port) = parsed.port {
                hop.port = port;
            }
            append_resolved(resolver, hop, stack, out)?;
        }
    }
    out.push(resolved_hop(resolved));
    stack.pop();
    Ok(())
}

fn resolved_hop(resolved: ResolvedHost) -> ResolvedHop {
    ResolvedHop {
        preferred: resolved.preferred_authentications.clone(),
        endpoint: Endpoint {
            user: resolved.user,
            host: resolved.hostname,
            port: resolved.port,
            identity_files: resolved.identity_files,
            identities_only: resolved.identities_only,
            identity_agent: resolved.identity_agent,
            known_hosts_files: resolved
                .known_hosts_files
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            proxy_command: resolved.proxy_command,
        },
    }
}

struct JumpRef {
    user: Option<String>,
    host: String,
    port: Option<u16>,
}

fn parse_jump(token: &str) -> Result<JumpRef, AppError> {
    let token = token.trim();
    if token.is_empty()
        || token.starts_with('-')
        || token.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(AppError::new("invalid_target", "ProxyJump 无效"));
    }
    if let Some(start) = token.find('[') {
        let end = token
            .find(']')
            .ok_or_else(|| AppError::new("invalid_target", "ProxyJump 的 IPv6 地址无效"))?;
        let host = token[start + 1..end].to_string();
        crate::forward::validate_hostname(&host)?;
        let user = if start > 0 {
            Some(token[..start].trim_end_matches('@').to_string())
        } else {
            None
        };
        let port = if token[end + 1..].starts_with(':') {
            Some(parse_port(&token[end + 2..])?)
        } else {
            None
        };
        return Ok(JumpRef { user, host, port });
    }
    let (user, rest) = if let Some((user, rest)) = token.rsplit_once('@') {
        (Some(user.to_string()), rest)
    } else {
        (None, token)
    };
    let (host, port) = if let Some((host, port)) = rest.rsplit_once(':') {
        if port.chars().all(|ch| ch.is_ascii_digit()) {
            (host.to_string(), Some(parse_port(port)?))
        } else {
            (rest.to_string(), None)
        }
    } else {
        (rest.to_string(), None)
    };
    crate::forward::validate_hostname(&host).or_else(|_| crate::forward::validate_alias(&host))?;
    if let Some(user) = &user {
        crate::forward::validate_user(user)?;
    }
    Ok(JumpRef { user, host, port })
}

fn parse_port(value: &str) -> Result<u16, AppError> {
    let port: u16 = value
        .parse()
        .map_err(|_| AppError::new("invalid_port", "端口必须在 1 到 65535 之间"))?;
    if port == 0 {
        return Err(AppError::new("invalid_port", "端口必须在 1 到 65535 之间"));
    }
    Ok(port)
}

fn secret_view(spec: &SessionSpec) -> Option<String> {
    spec.password
        .as_ref()
        .map(|value| value.as_str().to_string())
        .or_else(|| {
            spec.passphrase
                .as_ref()
                .map(|value| value.as_str().to_string())
        })
}

fn profile_target_label(profile: &Profile) -> String {
    match &profile.target {
        Target::ConfigAlias { alias } => alias.clone(),
        Target::Manual {
            user,
            hostname,
            port,
            ..
        } => format!("{user}@{hostname}:{port}"),
    }
}

fn snapshot_target(snapshot: &TunnelSnapshot, profile: &Profile) -> String {
    let _ = snapshot;
    profile_target_label(profile)
}

pub async fn start_session(
    spec: SessionSpec,
    prompter: Arc<dyn HostKeyPrompter>,
    trust_path: PathBuf,
    trust: Arc<Mutex<TrustStore>>,
) -> Result<ActiveSession, AppError> {
    if spec.hops.is_empty() {
        return Err(AppError::new("invalid_target", "没有可连接的主机"));
    }
    if spec.forwards.is_empty() {
        return Err(AppError::new("no_forwards", "至少需要一条端口映射"));
    }
    let snapshot = Arc::new(Mutex::new(TunnelSnapshot {
        profile_id: spec.profile_id.clone(),
        name: spec.name.clone(),
        phase: Phase::Connecting,
        message: "正在建立 SSH 连接".into(),
        forwards: spec
            .forwards
            .iter()
            .map(|forward| forward_status(forward, "pending", "等待绑定"))
            .collect(),
        connected_at: None,
    }));
    let cancel = CancellationToken::new();
    let done = Arc::new(tokio::sync::Notify::new());
    let (ready_tx, ready_rx) = oneshot::channel();
    let task_snapshot = snapshot.clone();
    let task_cancel = cancel.clone();
    let task_done = done.clone();
    tokio::spawn(async move {
        let outcome = run_session(
            spec,
            prompter,
            trust_path,
            trust,
            task_snapshot.clone(),
            task_cancel.clone(),
        )
        .await;
        match outcome {
            Ok(runtime) => {
                set_phase(
                    &task_snapshot,
                    Phase::Connected,
                    "认证成功，端口映射已绑定",
                    None,
                );
                let _ = ready_tx.send(Ok(()));
                tokio::select! {
                    _ = task_cancel.cancelled() => {
                        cleanup(runtime, false).await;
                        set_phase(&task_snapshot, Phase::Disconnected, "已断开", None);
                    }
                    _ = runtime.lost.notified() => {
                        cleanup(runtime, true).await;
                        set_phase(&task_snapshot, Phase::Failed, "SSH 连接已中断", None);
                    }
                }
            }
            Err(err) => {
                set_phase(&task_snapshot, Phase::Failed, &err.message, None);
                let _ = ready_tx.send(Err(err));
            }
        }
        task_done.notify_one();
    });
    match ready_rx.await {
        Ok(Ok(())) => Ok(ActiveSession {
            snapshot,
            cancel,
            done,
        }),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(AppError::new("ssh", "连接任务意外结束")),
    }
}

struct LiveRuntime {
    handle: Arc<tokio::sync::Mutex<client::Handle<ClientHandler>>>,
    kept: Vec<client::Handle<ClientHandler>>,
    proxies: Vec<tokio::process::Child>,
    remote_started: Vec<(String, u16)>,
    lost: Arc<tokio::sync::Notify>,
    cancel: CancellationToken,
}

async fn run_session(
    spec: SessionSpec,
    prompter: Arc<dyn HostKeyPrompter>,
    trust_path: PathBuf,
    trust: Arc<Mutex<TrustStore>>,
    snapshot: Arc<Mutex<TunnelSnapshot>>,
    cancel: CancellationToken,
) -> Result<LiveRuntime, AppError> {
    let config = Arc::new(client_config());
    let mut kept = Vec::new();
    let mut proxies = Vec::new();
    let mut current: Option<client::Handle<ClientHandler>> = None;
    let hop_count = spec.hops.len();
    for (index, endpoint) in spec.hops.iter().enumerate() {
        if cancel.is_cancelled() {
            return Err(AppError::new("cancelled", "连接已取消"));
        }
        let last = index + 1 == hop_count;
        let handler = ClientHandler {
            host: endpoint.host.clone(),
            port: endpoint.port,
            known_hosts: endpoint.known_hosts_files.clone(),
            trust: trust.clone(),
            trust_path: trust_path.clone(),
            prompter: prompter.clone(),
            remote_rules: if last {
                spec.forwards
                    .iter()
                    .filter(|forward| forward.direction == Direction::Remote)
                    .map(|forward| RemoteRule {
                        listen_port: forward.listen_port,
                        destination_host: forward.destination_host.clone(),
                        destination_port: forward.destination_port,
                    })
                    .collect()
            } else {
                Vec::new()
            },
            accept_forwards: last,
            cancel: cancel.clone(),
        };
        let mut handle = connect_hop(
            config.clone(),
            endpoint,
            current.as_ref(),
            handler,
            &mut proxies,
        )
        .await?;
        if last {
            set_phase(&snapshot, Phase::Authenticating, "正在认证", None);
            authenticate_final(&mut handle, endpoint, &spec).await?;
        } else {
            authenticate_jump(&mut handle, endpoint, spec.passphrase.as_ref()).await?;
        }
        if let Some(previous) = current.take() {
            kept.push(previous);
        }
        current = Some(handle);
    }
    let handle = current.ok_or_else(|| AppError::new("ssh", "没有可用的 SSH 会话"))?;
    set_phase(&snapshot, Phase::Binding, "正在绑定端口映射", None);
    let lost = Arc::new(tokio::sync::Notify::new());
    let mut statuses = Vec::new();
    let mut listeners = Vec::new();
    for forward in spec
        .forwards
        .iter()
        .filter(|forward| forward.direction == Direction::Local)
    {
        match TcpListener::bind((forward.listen_ip, forward.listen_port)).await {
            Ok(listener) => {
                statuses.push(forward_status(forward, "listening", "本地监听已绑定"));
                listeners.push((listener, forward.clone()));
            }
            Err(err) => {
                drop(listeners);
                let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
                if err.kind() == std::io::ErrorKind::AddrInUse {
                    return Err(AppError::new(
                        "port_in_use",
                        format!("本地端口 {} 已被占用", forward.listen_port),
                    ));
                }
                return Err(AppError::new(
                    "bind_failed",
                    format!("无法绑定本地端口 {}: {err}", forward.listen_port),
                ));
            }
        }
    }
    let shared = Arc::new(tokio::sync::Mutex::new(handle));
    let mut remote_started = Vec::new();
    for forward in spec
        .forwards
        .iter()
        .filter(|forward| forward.direction == Direction::Remote)
    {
        let address = forward.listen_ip.to_string();
        let result = {
            let handle = shared.lock().await;
            handle
                .tcpip_forward(address.clone(), u32::from(forward.listen_port))
                .await
        };
        match result {
            Ok(_) => {
                remote_started.push((address, forward.listen_port));
                statuses.push(forward_status(forward, "listening", "服务器已接受远程转发"));
            }
            Err(err) => {
                for (address, port) in &remote_started {
                    let handle = shared.lock().await;
                    let _ = handle
                        .cancel_tcpip_forward(address.clone(), u32::from(*port))
                        .await;
                }
                let handle = shared.lock().await;
                let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
                return Err(AppError::from(err));
            }
        }
    }
    {
        let mut snap = snapshot.lock().expect("snapshot");
        snap.forwards = statuses;
        snap.connected_at = Some(now_rfc3339());
    }
    for (listener, forward) in listeners {
        let shared = shared.clone();
        let lost = lost.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            local_accept_loop(listener, shared, forward, lost, cancel).await;
        });
    }
    Ok(LiveRuntime {
        handle: shared,
        kept,
        proxies,
        remote_started,
        lost,
        cancel,
    })
}

async fn connect_hop(
    config: Arc<client::Config>,
    endpoint: &Endpoint,
    previous: Option<&client::Handle<ClientHandler>>,
    handler: ClientHandler,
    proxies: &mut Vec<tokio::process::Child>,
) -> Result<client::Handle<ClientHandler>, AppError> {
    if let Some(command) = &endpoint.proxy_command {
        let (stream, child) = spawn_proxy(command)?;
        proxies.push(child);
        return tokio::time::timeout(
            Duration::from_secs(20),
            client::connect_stream(config, stream, handler),
        )
        .await
        .map_err(|_| AppError::new("proxy_failed", "ProxyCommand 连接超时"))?;
    }
    if let Some(previous) = previous {
        let channel = previous
            .channel_open_direct_tcpip(&endpoint.host, u32::from(endpoint.port), "127.0.0.1", 0)
            .await?;
        let stream = channel.into_stream();
        return tokio::time::timeout(
            Duration::from_secs(20),
            client::connect_stream(config, stream, handler),
        )
        .await
        .map_err(|_| AppError::new("proxy_failed", "ProxyJump 连接超时"))?;
    }
    tokio::time::timeout(
        Duration::from_secs(20),
        client::connect(config, (endpoint.host.as_str(), endpoint.port), handler),
    )
    .await
    .map_err(|_| {
        AppError::new(
            "ssh",
            format!("连接 {}:{} 超时", endpoint.host, endpoint.port),
        )
    })?
}

async fn local_accept_loop(
    listener: TcpListener,
    handle: Arc<tokio::sync::Mutex<client::Handle<ClientHandler>>>,
    forward: ValidatedForward,
    lost: Arc<tokio::sync::Notify>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((socket, peer)) = accepted else { break };
                let handle = handle.clone();
                let lost = lost.clone();
                let cancel = cancel.clone();
                let destination_host = forward.destination_host.clone();
                let destination_port = forward.destination_port;
                tokio::spawn(async move {
                    let opened = {
                        let session = handle.lock().await;
                        session.channel_open_direct_tcpip(
                            destination_host,
                            u32::from(destination_port),
                            peer.ip().to_string(),
                            u32::from(peer.port()),
                        ).await
                    };
                    match opened {
                        Ok(channel) => bridge_tcp(socket, channel, cancel).await,
                        Err(_) => lost.notify_one(),
                    }
                });
            }
        }
    }
}

async fn cleanup(runtime: LiveRuntime, failed: bool) {
    runtime.cancel.cancel();
    let handle = runtime.handle.lock().await;
    for (address, port) in &runtime.remote_started {
        let _ = handle
            .cancel_tcpip_forward(address.clone(), u32::from(*port))
            .await;
    }
    let _ = handle
        .disconnect(
            if failed {
                Disconnect::ConnectionLost
            } else {
                Disconnect::ByApplication
            },
            "",
            "en",
        )
        .await;
    drop(handle);
    for hop in runtime.kept {
        let _ = hop.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    drop(runtime.proxies);
}

fn client_config() -> client::Config {
    let mut config = client::Config::default();
    config.nodelay = true;
    config.keepalive_interval = Some(Duration::from_secs(20));
    config.keepalive_max = 3;
    config
}

#[derive(Clone)]
struct RemoteRule {
    listen_port: u16,
    destination_host: String,
    destination_port: u16,
}

struct ClientHandler {
    host: String,
    port: u16,
    known_hosts: Vec<PathBuf>,
    trust: Arc<Mutex<TrustStore>>,
    trust_path: PathBuf,
    prompter: Arc<dyn HostKeyPrompter>,
    remote_rules: Vec<RemoteRule>,
    accept_forwards: bool,
    cancel: CancellationToken,
}

impl Handler for ClientHandler {
    type Error = AppError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if server_public_key.certificate().is_some() {
            return Err(AppError::new(
                "host_cert_unsupported",
                "服务器出示的是主机证书。TunnelDesk 目前只接受原始主机密钥，不会跳过校验。",
            ));
        }
        let key = server_public_key.public_key();
        let verdict = match known_hosts::check_known_hosts_files(
            &self.known_hosts,
            &self.host,
            self.port,
            &key,
        )? {
            HostKeyVerdict::Unknown => self
                .trust
                .lock()
                .expect("trust")
                .verdict(&self.host, self.port, &key),
            other => other,
        };
        match verdict {
            HostKeyVerdict::Trusted { .. } => Ok(true),
            HostKeyVerdict::Revoked { source } => Err(AppError::new(
                "host_key_revoked",
                format!("主机密钥已被吊销（{source}），连接已拒绝"),
            )),
            HostKeyVerdict::Changed { source, previous } => Err(AppError::new(
                "host_key_changed",
                format!(
                    "主机密钥与已记录的值不一致（{source}）。已记录 {previous}，本次为 {}。连接已拒绝，不会自动更换信任。",
                    known_hosts::fingerprint(&key)
                ),
            )),
            HostKeyVerdict::Unknown => {
                let prompt = HostKeyPrompt {
                    host: self.host.clone(),
                    port: self.port,
                    algorithm: known_hosts::algorithm_name(&key),
                    fingerprint: known_hosts::fingerprint(&key),
                };
                if !self.prompter.confirm_unknown(&prompt).await {
                    return Err(AppError::new(
                        "host_key_rejected",
                        "未信任该主机密钥，连接已取消",
                    ));
                }
                let entry = TrustEntry {
                    host: self.host.clone(),
                    port: self.port,
                    algorithm: prompt.algorithm,
                    fingerprint: prompt.fingerprint,
                    public_key: key.to_openssh().unwrap_or_default(),
                    trusted_at: now_rfc3339(),
                };
                let snapshot = {
                    let mut trust = self.trust.lock().expect("trust");
                    trust.insert(entry);
                    trust.clone()
                };
                let _ = crate::store::save_trust_file(&self.trust_path, &snapshot);
                Ok(true)
            }
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.accept_forwards {
            drop(reply);
            return Ok(());
        }
        let Some(rule) = self
            .remote_rules
            .iter()
            .find(|rule| u32::from(rule.listen_port) == connected_port)
            .cloned()
        else {
            drop(reply);
            return Ok(());
        };
        reply.accept().await;
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            match TcpStream::connect((rule.destination_host.as_str(), rule.destination_port)).await
            {
                Ok(socket) => bridge_tcp(socket, channel, cancel).await,
                Err(_) => {
                    let _ = channel.close().await;
                }
            }
        });
        Ok(())
    }
}

pub async fn bridge_tcp<S>(
    mut socket: TcpStream,
    mut channel: Channel<S>,
    cancel: CancellationToken,
) where
    S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    let mut buffer = vec![0u8; 16 * 1024];
    let mut socket_open = true;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            read = socket.read(&mut buffer), if socket_open => {
                match read {
                    Ok(0) => {
                        socket_open = false;
                        let _ = channel.eof().await;
                    }
                    Ok(size) => {
                        if channel.data_bytes(Bytes::copy_from_slice(&buffer[..size])).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            message = channel.wait() => {
                match message {
                    Some(ChannelMsg::Data { data }) => {
                        if socket.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        let _ = socket.write_all(&data).await;
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                    Some(_) => {}
                }
            }
        }
    }
    let _ = channel.close().await;
    let _ = socket.shutdown().await;
}

async fn authenticate_final(
    handle: &mut client::Handle<ClientHandler>,
    endpoint: &Endpoint,
    spec: &SessionSpec,
) -> Result<(), AppError> {
    let order = if spec.preferred.is_empty() {
        vec![
            "publickey".into(),
            "password".into(),
            "keyboard-interactive".into(),
        ]
    } else {
        spec.preferred.clone()
    };
    let order = match spec.auth_mode {
        AuthMode::Agent => vec!["publickey-agent".into()],
        AuthMode::PublicKey => vec!["publickey-file".into()],
        AuthMode::Password => vec!["password".into(), "keyboard-interactive".into()],
        AuthMode::Auto => order,
    };
    let mut saw_encrypted_key = false;
    for method in order {
        match method.as_str() {
            "publickey" => {
                if try_agent(handle, endpoint).await? {
                    return Ok(());
                }
                match try_files(handle, endpoint, spec.passphrase.as_ref()).await? {
                    FileAttempt::Success => return Ok(()),
                    FileAttempt::NeedsPassphrase => saw_encrypted_key = true,
                    FileAttempt::Failed => {}
                }
            }
            "publickey-agent" => {
                if try_agent(handle, endpoint).await? {
                    return Ok(());
                }
                return Err(AppError::new(
                    "agent_unavailable",
                    "SSH agent 没有接受此次认证",
                ));
            }
            "publickey-file" => {
                match try_files(handle, endpoint, spec.passphrase.as_ref()).await? {
                    FileAttempt::Success => return Ok(()),
                    FileAttempt::NeedsPassphrase => {
                        return Err(AppError::new("passphrase_required", "私钥已加密，需要口令"));
                    }
                    FileAttempt::Failed => {}
                }
            }
            "password" | "keyboard-interactive" => {
                let Some(password) = spec.password.as_ref() else {
                    continue;
                };
                if method == "password" && try_password(handle, &endpoint.user, password).await? {
                    return Ok(());
                }
                if method == "keyboard-interactive"
                    && try_keyboard(handle, &endpoint.user, password).await?
                {
                    return Ok(());
                }
            }
            "gssapi-with-mic" | "hostbased" | "none" => {}
            _ => {}
        }
    }
    if spec.password.is_none() && matches!(spec.auth_mode, AuthMode::Password | AuthMode::Auto) {
        return Err(AppError::new("password_required", "需要服务器密码"));
    }
    if saw_encrypted_key && spec.passphrase.is_none() {
        return Err(AppError::new("passphrase_required", "私钥已加密，需要口令"));
    }
    Err(AppError::new("auth_failed", "认证失败"))
}

async fn authenticate_jump(
    handle: &mut client::Handle<ClientHandler>,
    endpoint: &Endpoint,
    passphrase: Option<&Zeroizing<String>>,
) -> Result<(), AppError> {
    if try_agent(handle, endpoint).await? {
        return Ok(());
    }
    match try_files(handle, endpoint, passphrase).await? {
        FileAttempt::Success => Ok(()),
        FileAttempt::NeedsPassphrase => Err(AppError::new(
            "jump_auth_failed",
            format!(
                "跳板 {} 的私钥需要口令。当前只支持用 agent 或未加密密钥登录跳板。",
                endpoint.host
            ),
        )),
        FileAttempt::Failed => Err(AppError::new(
            "jump_auth_failed",
            format!(
                "无法认证跳板 {}。跳板需要 agent 或密钥，不使用目标服务器密码。",
                endpoint.host
            ),
        )),
    }
}

async fn try_password(
    handle: &mut client::Handle<ClientHandler>,
    user: &str,
    password: &Zeroizing<String>,
) -> Result<bool, AppError> {
    let result = handle
        .authenticate_password(user, password.as_str())
        .await?;
    Ok(result.success())
}

async fn try_keyboard(
    handle: &mut client::Handle<ClientHandler>,
    user: &str,
    password: &Zeroizing<String>,
) -> Result<bool, AppError> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await?;
    for _ in 0..4 {
        match response {
            client::KeyboardInteractiveAuthResponse::Success => return Ok(true),
            client::KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let answers = prompts
                    .iter()
                    .map(|_| password.as_str().to_string())
                    .collect();
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Ok(false)
}

enum FileAttempt {
    Success,
    NeedsPassphrase,
    Failed,
}

async fn try_files(
    handle: &mut client::Handle<ClientHandler>,
    endpoint: &Endpoint,
    passphrase: Option<&Zeroizing<String>>,
) -> Result<FileAttempt, AppError> {
    let mut needs_passphrase = false;
    for path in &endpoint.identity_files {
        if !std::path::Path::new(path).is_file() {
            continue;
        }
        let loaded = match russh::keys::load_secret_key(path, None) {
            Ok(key) => key,
            Err(russh::keys::Error::KeyIsEncrypted) => {
                let Some(passphrase) = passphrase else {
                    needs_passphrase = true;
                    continue;
                };
                match russh::keys::load_secret_key(path, Some(passphrase.as_str())) {
                    Ok(key) => key,
                    Err(_) => return Err(AppError::new("auth_failed", "密钥口令不正确")),
                }
            }
            Err(_) => continue,
        };
        let hash_alg = if matches!(loaded.algorithm(), russh::keys::Algorithm::Rsa { .. }) {
            supported_rsa_hash(handle).await
        } else {
            None
        };
        let wrapped = PrivateKeyWithHashAlg::new(std::sync::Arc::new(loaded), hash_alg);
        let result = handle
            .authenticate_publickey(&endpoint.user, wrapped)
            .await?;
        if result.success() {
            return Ok(FileAttempt::Success);
        }
    }
    if needs_passphrase {
        Ok(FileAttempt::NeedsPassphrase)
    } else {
        Ok(FileAttempt::Failed)
    }
}

async fn supported_rsa_hash(
    handle: &client::Handle<ClientHandler>,
) -> Option<russh::keys::HashAlg> {
    match handle.best_supported_rsa_hash().await {
        Ok(Some(Some(alg))) => Some(alg),
        _ => Some(russh::keys::HashAlg::Sha256),
    }
}

async fn try_agent(
    handle: &mut client::Handle<ClientHandler>,
    endpoint: &Endpoint,
) -> Result<bool, AppError> {
    #[cfg(not(unix))]
    {
        let _ = (handle, endpoint);
        return Ok(false);
    }
    #[cfg(unix)]
    {
        let Some(mut agent) = connect_agent(endpoint.identity_agent.as_deref()).await? else {
            return Ok(false);
        };
        if let Some(binding) = handle.agent_session_binding() {
            let _ = agent.bind_session(binding, false).await;
        }
        let identities = match agent.request_identities().await {
            Ok(identities) => identities,
            Err(_) => return Ok(false),
        };
        let allowed = if endpoint.identities_only {
            endpoint
                .identity_files
                .iter()
                .filter_map(|path| identity_public(std::path::Path::new(path)))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        for identity in identities {
            let russh::keys::agent::AgentIdentity::PublicKey { key, .. } = &identity else {
                continue;
            };
            if endpoint.identities_only
                && !allowed
                    .iter()
                    .any(|allowed| allowed.key_data() == key.key_data())
            {
                continue;
            }
            let hash_alg = if matches!(key.algorithm(), russh::keys::Algorithm::Rsa { .. }) {
                supported_rsa_hash(handle).await
            } else {
                None
            };
            match handle
                .authenticate_publickey_with(&endpoint.user, key.clone(), hash_alg, &mut agent)
                .await
            {
                Ok(result) if result.success() => return Ok(true),
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
        Ok(false)
    }
}

fn identity_public(path: &std::path::Path) -> Option<PublicKey> {
    if let Ok(key) = russh::keys::load_secret_key(path, None) {
        return Some(key.public_key().clone());
    }
    let text = std::fs::read_to_string(format!("{}.pub", path.display())).ok()?;
    let line = text.lines().next()?.trim();
    russh::keys::PublicKey::from_openssh(line).ok()
}

#[cfg(unix)]
async fn connect_agent(
    explicit: Option<&str>,
) -> Result<Option<AgentClient<tokio::net::UnixStream>>, AppError> {
    let path = match explicit {
        Some("none") | Some("") => return Ok(None),
        Some("SSH_AUTH_SOCK") | None => match std::env::var("SSH_AUTH_SOCK") {
            Ok(path) => path,
            Err(_) => return Ok(None),
        },
        Some(path) => path.to_string(),
    };
    match AgentClient::connect_uds(path).await {
        Ok(agent) => Ok(Some(agent)),
        Err(_) => Ok(None),
    }
}

fn spawn_proxy(
    command: &str,
) -> Result<(tokio::io::DuplexStream, tokio::process::Child), AppError> {
    let (client_side, process_side) = tokio::io::duplex(64 * 1024);
    let mut command_builder = shell_command(command);
    command_builder
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = command_builder
        .spawn()
        .map_err(|_| AppError::new("proxy_failed", "无法启动 ProxyCommand"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| AppError::new("proxy_failed", "ProxyCommand 没有标准输入"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::new("proxy_failed", "ProxyCommand 没有标准输出"))?;
    tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(process_side);
        let outbound = tokio::io::copy(&mut read, &mut stdin);
        let inbound = tokio::io::copy(&mut stdout, &mut write);
        tokio::pin!(outbound);
        tokio::pin!(inbound);
        tokio::select! {
            _ = &mut outbound => {}
            _ = &mut inbound => {}
        }
    });
    Ok((client_side, child))
}

fn shell_command(command: &str) -> tokio::process::Command {
    #[cfg(windows)]
    {
        let mut cmd = tokio::process::Command::new("cmd.exe");
        cmd.arg("/C").arg(command);
        cmd
    }
    #[cfg(not(windows))]
    {
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(command);
        cmd
    }
}

fn forward_status(forward: &ValidatedForward, state: &str, message: &str) -> ForwardStatus {
    ForwardStatus {
        id: forward.id.clone(),
        direction: forward.direction,
        listen: format!("{}:{}", forward.listen_ip, forward.listen_port),
        destination: format!("{}:{}", forward.destination_host, forward.destination_port),
        state: state.into(),
        message: message.into(),
    }
}

fn set_phase(
    snapshot: &Mutex<TunnelSnapshot>,
    phase: Phase,
    message: &str,
    forwards: Option<Vec<ForwardStatus>>,
) {
    let mut snap = snapshot.lock().expect("snapshot");
    snap.phase = phase;
    snap.message = message.to_string();
    if let Some(forwards) = forwards {
        snap.forwards = forwards;
    }
}

pub fn listen_address(forward: &ValidatedForward) -> SocketAddr {
    SocketAddr::new(forward.listen_ip, forward.listen_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_jump_rejects_injection_and_reads_ipv6() {
        let jump = parse_jump("jump.example").unwrap();
        assert_eq!(jump.host, "jump.example");
        let jump = parse_jump("rui@[2001:db8::1]:2222").unwrap();
        assert_eq!(jump.user.as_deref(), Some("rui"));
        assert_eq!(jump.host, "2001:db8::1");
        assert_eq!(jump.port, Some(2222));
        assert!(parse_jump("-oProxyCommand=id").is_err());
        assert!(parse_jump("jump;rm").is_err());
    }

    #[test]
    fn proxy_chain_preserves_order_and_cycle_detection() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config"),
            "Host jump\n  HostName 127.0.0.1\n  User jumper\n  Port 2222\nHost dest\n  HostName example.com\n  User destuser\n  ProxyJump jump\n",
        )
        .unwrap();
        let resolver = Resolver {
            user_config: dir.path().join("config"),
            system_config: None,
            ssh_binary: None,
            home: dir.path().to_path_buf(),
            local_user: "rui".into(),
            local_host: "laptop".into(),
        };
        let resolved = resolver.resolve_builtin("dest").unwrap();
        let mut hops = Vec::new();
        append_resolved(&resolver, resolved, &mut Vec::new(), &mut hops).unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].endpoint.host, "127.0.0.1");
        assert_eq!(hops[0].endpoint.user, "jumper");
        assert_eq!(hops[1].endpoint.host, "example.com");
    }
}
