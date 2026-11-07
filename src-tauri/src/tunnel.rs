use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use russh::client::{self, Handler, Msg, Session};
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg};
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
use crate::identity::{self, AuthOffer, KeySource, ListedAgentKey};
use crate::known_hosts::{self, TrustEntry, TrustStore};
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
    pub certificate_files: Vec<String>,
    pub identities_only: bool,
    pub pubkey_authentication: bool,
    pub identity_agent: Option<String>,
    pub host_key_alias: Option<String>,
    pub known_hosts_files: Vec<PathBuf>,
    pub revoked_host_keys: Vec<PathBuf>,
    pub preferred: Vec<String>,
    pub proxy_command: Option<String>,
}

#[derive(Clone)]
pub struct SessionSpec {
    pub profile_id: String,
    pub name: String,
    pub hops: Vec<Endpoint>,
    pub auth_mode: AuthMode,
    pub forwards: Vec<ValidatedForward>,
    pub password: Option<Zeroizing<String>>,
    pub passphrase: Option<Zeroizing<String>>,
    pub passphrases_by_endpoint: HashMap<String, Zeroizing<String>>,
}

fn endpoint_credential_key(endpoint: &Endpoint) -> String {
    format!("{}@{}:{}", endpoint.user, endpoint.host, endpoint.port)
}

impl SessionSpec {
    fn passphrase_for(&self, endpoint: &Endpoint) -> Option<&Zeroizing<String>> {
        self.passphrases_by_endpoint
            .get(&endpoint_credential_key(endpoint))
            .or(self.passphrase.as_ref())
    }

    fn merge_passphrase_for(&mut self, endpoint: &Endpoint, value: Zeroizing<String>) {
        self.passphrases_by_endpoint
            .insert(endpoint_credential_key(endpoint), value.clone());
        if self
            .hops
            .last()
            .is_some_and(|hop| endpoint_credential_key(hop) == endpoint_credential_key(endpoint))
        {
            self.passphrase = Some(value);
        }
    }
}

struct PendingAuth {
    spec: SessionSpec,
    hops: Vec<Endpoint>,
    hop_index: usize,
    kept: Mutex<Vec<client::Handle<ClientHandler>>>,
    proxies: Mutex<Vec<tokio::process::Child>>,
    pending: Mutex<Option<client::Handle<ClientHandler>>>,
    trust: Arc<Mutex<TrustStore>>,
    trust_path: PathBuf,
    snapshot: Arc<Mutex<TunnelSnapshot>>,
    remote_rules: Arc<Mutex<Vec<RemoteRule>>>,
    cancel: CancellationToken,
    lost: Arc<tokio::sync::Notify>,
    challenge_id: String,
}

fn fresh_challenge_id() -> String {
    crate::model::new_id()
}

fn auth_challenge_resumable(err: &AppError) -> bool {
    matches!(
        err.code.as_str(),
        "passphrase_required"
            | "passphrase_rejected"
            | "password_required"
            | "password_rejected"
            | "auth_failed"
    )
}

fn pending_auth_ticket(
    spec: SessionSpec,
    hops: Vec<Endpoint>,
    hop_index: usize,
    kept: Vec<client::Handle<ClientHandler>>,
    proxies: Vec<tokio::process::Child>,
    handle: client::Handle<ClientHandler>,
    trust: Arc<Mutex<TrustStore>>,
    trust_path: PathBuf,
    snapshot: Arc<Mutex<TunnelSnapshot>>,
    remote_rules: Arc<Mutex<Vec<RemoteRule>>>,
    cancel: CancellationToken,
    lost: Arc<tokio::sync::Notify>,
) -> PendingAuth {
    PendingAuth {
        spec,
        hops,
        hop_index,
        kept: Mutex::new(kept),
        proxies: Mutex::new(proxies),
        pending: Mutex::new(Some(handle)),
        trust,
        trust_path,
        snapshot,
        remote_rules,
        cancel,
        lost,
        challenge_id: fresh_challenge_id(),
    }
}

fn attach_pending_challenge(
    mut pending: PendingAuth,
    err: AppError,
    endpoint: &Endpoint,
) -> SessionFailure {
    pending.challenge_id = fresh_challenge_id();
    let hop = if pending.hop_index + 1 == pending.hops.len() {
        "target"
    } else {
        "jump"
    };
    SessionFailure {
        error: err.with_challenge_ticket(
            &endpoint.host,
            hop,
            endpoint_credential_key(endpoint),
            &pending.challenge_id,
        ),
        resume: Some(pending),
    }
}

struct SessionFailure {
    error: AppError,
    resume: Option<PendingAuth>,
}

impl From<AppError> for SessionFailure {
    fn from(error: AppError) -> Self {
        Self {
            error,
            resume: None,
        }
    }
}

async fn teardown_hops(
    kept: Vec<client::Handle<ClientHandler>>,
    proxies: Vec<tokio::process::Child>,
) {
    for hop in kept {
        let _ = hop.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    drop(proxies);
}

async fn teardown_pending(pending: PendingAuth) {
    let handle = pending.pending.lock().expect("pending").take();
    if let Some(handle) = handle {
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    let kept = std::mem::take(&mut *pending.kept.lock().expect("kept"));
    let proxies = std::mem::take(&mut *pending.proxies.lock().expect("proxies"));
    teardown_hops(kept, proxies).await;
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

    fn completion(&self) -> Arc<tokio::sync::Notify> {
        self.done.clone()
    }
}

struct Running {
    session: ActiveSession,
    live: Arc<LiveRuntime>,
    history_id: String,
}

struct ForwardRuntime {
    cancel: CancellationToken,
    remote: Option<(String, u16)>,
    local_task: Option<tokio::task::JoinHandle<()>>,
}

pub struct TunnelManager {
    store: AppStore,
    secrets: Arc<dyn SecretStore>,
    resolver: Resolver,
    running: Arc<Mutex<HashMap<String, Running>>>,
    inflight: Arc<Mutex<HashMap<String, CancellationToken>>>,
    pending_auth: Arc<Mutex<HashMap<String, PendingAuth>>>,
    watch: watch::Sender<Vec<TunnelSnapshot>>,
}

impl TunnelManager {
    pub fn new(store: AppStore, secrets: Arc<dyn SecretStore>, resolver: Resolver) -> Self {
        let (watch, _) = watch::channel(Vec::new());
        Self {
            store,
            secrets,
            resolver,
            running: Arc::new(Mutex::new(HashMap::new())),
            inflight: Arc::new(Mutex::new(HashMap::new())),
            pending_auth: Arc::new(Mutex::new(HashMap::new())),
            watch,
        }
    }

    fn running_snapshot(&self, profile_id: &str) -> Result<TunnelSnapshot, AppError> {
        self.running
            .lock()
            .expect("running")
            .get(profile_id)
            .map(|running| running.session.snapshot())
            .ok_or_else(|| AppError::new("not_connected", "隧道未连接"))
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

    pub async fn connect_challenge_response(
        &self,
        profile_id: &str,
        ticket: &AppError,
        password: Option<Zeroizing<String>>,
        passphrase: Option<Zeroizing<String>>,
        remember_password: bool,
        remember_passphrase: bool,
        prompter: Arc<dyn HostKeyPrompter>,
    ) -> Result<ConnectOutcome, AppError> {
        self.connect_with_challenge(
            profile_id,
            password,
            passphrase,
            remember_password,
            remember_passphrase,
            ticket.challenge_host.clone(),
            ticket.challenge_id.clone(),
            ticket.challenge_endpoint.clone(),
            prompter,
        )
        .await
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
        self.connect_with_challenge(
            profile_id,
            password,
            passphrase,
            remember_password,
            remember_passphrase,
            None,
            None,
            None,
            prompter,
        )
        .await
    }

    pub async fn connect_with_challenge(
        &self,
        profile_id: &str,
        password: Option<Zeroizing<String>>,
        passphrase: Option<Zeroizing<String>>,
        remember_password: bool,
        remember_passphrase: bool,
        challenge_host: Option<String>,
        challenge_id: Option<String>,
        challenge_endpoint: Option<String>,
        prompter: Arc<dyn HostKeyPrompter>,
    ) -> Result<ConnectOutcome, AppError> {
        if self
            .inflight
            .lock()
            .expect("inflight")
            .contains_key(profile_id)
        {
            return Err(AppError::new(
                "already_connecting",
                "这条隧道正在连接，请先取消或等待完成",
            ));
        }
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
        let typed_password = password.clone();
        let typed_passphrase = passphrase.clone();
        let password = self.load_password(&profile, password, remember_password, &mut warnings)?;
        let passphrase =
            self.load_passphrase(&profile, passphrase, remember_passphrase, &mut warnings)?;
        let mut spec = self.spec_for_profile(&profile, password.clone(), passphrase.clone())?;
        let secret_view = secret_view(&spec);
        let trust = Arc::new(Mutex::new(self.store.load_trust()?));
        let connect_cancel = CancellationToken::new();
        self.inflight
            .lock()
            .expect("inflight")
            .insert(profile_id.to_string(), connect_cancel.clone());
        let pending_resume = self
            .pending_auth
            .lock()
            .expect("pending")
            .remove(profile_id);
        let result = if let Some(mut pending) = pending_resume {
            let hop = pending.hops[pending.hop_index].clone();
            let hop_kind = if pending.hop_index + 1 == pending.hops.len() {
                "target"
            } else {
                "jump"
            };
            let ticket = pending.challenge_id.clone();
            let endpoint_key = endpoint_credential_key(&hop);
            let Some(submitted) = challenge_id else {
                self.pending_auth
                    .lock()
                    .expect("pending")
                    .insert(profile_id.to_string(), pending);
                return Err(AppError::new(
                    "challenge_id_required",
                    "需要最新的认证挑战编号才能继续",
                )
                .with_challenge_ticket(&hop.host, hop_kind, endpoint_key, ticket));
            };
            if submitted != ticket {
                self.pending_auth
                    .lock()
                    .expect("pending")
                    .insert(profile_id.to_string(), pending);
                return Err(AppError::new(
                    "challenge_stale",
                    "该认证挑战已过期，请使用最新提示重试",
                )
                .with_challenge_ticket(&hop.host, hop_kind, endpoint_key, ticket));
            }
            if let Some(submitted_endpoint) = challenge_endpoint.as_deref() {
                if submitted_endpoint != endpoint_key {
                    self.pending_auth
                        .lock()
                        .expect("pending")
                        .insert(profile_id.to_string(), pending);
                    return Err(
                        AppError::new("challenge_mismatch", "凭据与当前认证目标不匹配")
                            .with_challenge_ticket(&hop.host, hop_kind, endpoint_key, ticket),
                    );
                }
            }
            if let Some(value) = spec.password.clone() {
                pending.spec.password = Some(value);
            }
            if let Some(phrase) = typed_passphrase.clone() {
                pending.spec.merge_passphrase_for(&hop, phrase);
            } else if let Some(phrase) = spec.passphrase.clone() {
                pending.spec.merge_passphrase_for(&hop, phrase);
            }
            continue_pending_session(pending, prompter, connect_cancel).await
        } else {
            if challenge_id.is_some() {
                return Err(AppError::new(
                    "challenge_stale",
                    "没有进行中的认证会话可继续",
                ));
            }
            let _ = challenge_host;
            start_session(
                spec,
                prompter,
                self.store.trust_path(),
                trust.clone(),
                connect_cancel,
            )
            .await
        };
        self.inflight.lock().expect("inflight").remove(profile_id);
        if let Ok(trust) = trust.lock() {
            let _ = self.store.save_trust(&trust);
        }
        match result {
            Ok((session, live)) => {
                self.pending_auth
                    .lock()
                    .expect("pending")
                    .remove(profile_id);
                self.persist_secrets(
                    &profile,
                    typed_password,
                    typed_passphrase,
                    remember_password,
                    remember_passphrase,
                    &mut warnings,
                )?;
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
                let watch_history = history_id.clone();
                self.running.lock().expect("running").insert(
                    profile.id.clone(),
                    Running {
                        session,
                        live,
                        history_id,
                    },
                );
                let done = self
                    .running
                    .lock()
                    .expect("running")
                    .get(&profile.id)
                    .expect("inserted")
                    .session
                    .completion();
                let watch_running = Arc::clone(&self.running);
                let watch_store = self.store.clone();
                let watch_sender = self.watch.clone();
                let watch_id = profile.id.clone();
                tokio::spawn(async move {
                    done.notified().await;
                    let (phase, remove) = {
                        let mut running = watch_running.lock().expect("running");
                        let Some(entry) = running.get(&watch_id) else {
                            return;
                        };
                        let phase = entry.session.snapshot().phase;
                        let remove = matches!(phase, Phase::Failed | Phase::Disconnected);
                        if remove {
                            running.remove(&watch_id);
                        }
                        (phase, remove)
                    };
                    if remove && phase == Phase::Failed {
                        if let Ok(mut history) = watch_store.load_history() {
                            if let Some(entry) =
                                history.iter_mut().find(|entry| entry.id == watch_history)
                            {
                                if entry.ended_at.is_none() {
                                    entry.ended_at = Some(now_rfc3339());
                                    entry.outcome = "failed".into();
                                    entry.message = "SSH 连接已中断，监听端口已释放".into();
                                }
                            }
                            let _ = watch_store.save_history(&history);
                        }
                    }
                    let snapshots: Vec<TunnelSnapshot> = watch_running
                        .lock()
                        .expect("running")
                        .values()
                        .map(|running| running.session.snapshot())
                        .collect();
                    let _ = watch_sender.send(snapshots);
                });
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
            Err(failure) => {
                if let Some(pending) = failure.resume {
                    self.pending_auth
                        .lock()
                        .expect("pending")
                        .insert(profile_id.to_string(), pending);
                }
                let err = failure.error;
                if err.code != "cancelled" {
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
                }
                Err(err)
            }
        }
    }

    pub async fn cancel_connect(&self, profile_id: &str) -> Result<(), AppError> {
        if let Some(cancel) = self.inflight.lock().expect("inflight").remove(profile_id) {
            cancel.cancel();
        }
        let pending = self
            .pending_auth
            .lock()
            .expect("pending")
            .remove(profile_id);
        if let Some(pending) = pending {
            teardown_pending(pending).await;
        }
        let running = self.running.lock().expect("running").remove(profile_id);
        if let Some(running) = running {
            running.session.shutdown().await;
            self.publish();
        }
        Ok(())
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

    pub async fn add_runtime_forward(
        &self,
        profile_id: &str,
        mapping: &crate::model::ForwardMapping,
        persist: bool,
    ) -> Result<TunnelSnapshot, AppError> {
        let forward = crate::forward::validate_mapping(mapping)?;
        let live = {
            let running = self.running.lock().expect("running");
            let Some(running) = running.get(profile_id) else {
                return Err(AppError::new("not_connected", "隧道未连接，无法添加映射"));
            };
            if running.session.snapshot().phase != Phase::Connected {
                return Err(AppError::new("not_connected", "隧道未处于已连接状态"));
            }
            Arc::clone(&running.live)
        };
        let forward_id = forward.id.clone();
        let profiles_on_disk = if persist {
            let profiles = self.store.load_profiles()?;
            if !profiles.iter().any(|item| item.id == profile_id) {
                return Err(AppError::new("not_found", "找不到这条隧道"));
            }
            Some(profiles)
        } else {
            None
        };
        live.add_forward(forward).await?;
        if let Some(mut profiles) = profiles_on_disk {
            let Some(profile) = profiles.iter_mut().find(|item| item.id == profile_id) else {
                let _ = live.remove_forward(&forward_id).await;
                return Err(AppError::new("not_found", "找不到这条隧道"));
            };
            if !profile.forwards.iter().any(|item| item.id == mapping.id) {
                profile.forwards.push(mapping.clone());
            }
            if let Err(err) = self.store.save_profiles(&profiles) {
                let rollback = live.remove_forward(&forward_id).await;
                return Err(if rollback.is_err() {
                    AppError::new(
                        "persist_rollback_failed",
                        format!(
                            "配置保存失败且运行时回滚也失败。映射可能仍在运行：{}",
                            rollback.unwrap_err().message
                        ),
                    )
                    .with_persist_state(true, false)
                } else {
                    err.with_persist_state(false, false)
                });
            }
        }
        self.publish();
        self.running_snapshot(profile_id)
    }

    pub async fn remove_runtime_forward(
        &self,
        profile_id: &str,
        forward_id: &str,
        persist: bool,
    ) -> Result<TunnelSnapshot, AppError> {
        let live = {
            let running = self.running.lock().expect("running");
            let Some(running) = running.get(profile_id) else {
                return Err(AppError::new("not_connected", "隧道未连接，无法移除映射"));
            };
            Arc::clone(&running.live)
        };
        let removed_mapping = if persist {
            let profiles = self.store.load_profiles()?;
            let mapping = profiles
                .iter()
                .find(|item| item.id == profile_id)
                .and_then(|profile| profile.forwards.iter().find(|f| f.id == forward_id))
                .cloned();
            Some((profiles, mapping))
        } else {
            None
        };
        live.remove_forward(forward_id).await?;
        if let Some((mut profiles, mapping)) = removed_mapping {
            let Some(profile) = profiles.iter_mut().find(|item| item.id == profile_id) else {
                return Err(AppError::new("not_found", "找不到这条隧道"));
            };
            profile.forwards.retain(|item| item.id != forward_id);
            if let Err(err) = self.store.save_profiles(&profiles) {
                if let Some(mapping) = mapping {
                    if let Ok(validated) = crate::forward::validate_mapping(&mapping) {
                        let restore = live.add_forward(validated).await;
                        return Err(if restore.is_err() {
                            AppError::new(
                                "persist_compensate_failed",
                                format!(
                                    "配置未保存且无法把映射恢复到运行态：{}",
                                    restore.unwrap_err().message
                                ),
                            )
                            .with_persist_state(false, true)
                        } else {
                            AppError::new(
                                "persist_failed",
                                format!("配置保存失败，映射已恢复到运行态：{}", err.message),
                            )
                            .with_persist_state(true, false)
                        });
                    }
                }
                return Err(err.with_persist_state(false, true));
            }
        }
        self.publish();
        self.running_snapshot(profile_id)
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

    fn load_password(
        &self,
        profile: &Profile,
        typed: Option<Zeroizing<String>>,
        _remember: bool,
        warnings: &mut Vec<AppError>,
    ) -> Result<Option<Zeroizing<String>>, AppError> {
        if let Some(password) = typed {
            return Ok(Some(password));
        }
        let account = secrets::server_password_account(&profile.id);
        if profile.remember_password {
            match self.secrets.get(&account) {
                Ok(value) => return Ok(value),
                Err(err) => warnings.push(err),
            }
        }
        Ok(None)
    }

    fn load_passphrase(
        &self,
        profile: &Profile,
        typed: Option<Zeroizing<String>>,
        _remember: bool,
        warnings: &mut Vec<AppError>,
    ) -> Result<Option<Zeroizing<String>>, AppError> {
        let identities = match self.identity_paths(profile) {
            Ok(paths) => paths,
            Err(err) => {
                if typed.is_some() {
                    return Err(err);
                }
                warnings.push(err);
                return Ok(None);
            }
        };
        if let Some(passphrase) = typed {
            return Ok(Some(passphrase));
        }
        for path in identities {
            let account = secrets::key_passphrase_account(&profile.id, &path);
            match self.secrets.get(&account) {
                Ok(Some(value)) => return Ok(Some(value)),
                Ok(None) => {}
                Err(err) => {
                    warnings.push(err);
                    break;
                }
            }
        }
        Ok(None)
    }

    fn persist_secrets(
        &self,
        profile: &Profile,
        typed_password: Option<Zeroizing<String>>,
        typed_passphrase: Option<Zeroizing<String>>,
        remember_password: bool,
        remember_passphrase: bool,
        warnings: &mut Vec<AppError>,
    ) -> Result<(), AppError> {
        if remember_password {
            if let Some(password) = typed_password {
                let account = secrets::server_password_account(&profile.id);
                if let Err(err) = self.secrets.set(&account, &password) {
                    warnings.push(err);
                }
            }
        }
        if remember_passphrase {
            if let Some(passphrase) = typed_passphrase {
                let identities = match self.identity_paths(profile) {
                    Ok(paths) => paths,
                    Err(err) => {
                        warnings.push(err);
                        return Ok(());
                    }
                };
                if identities.is_empty() {
                    warnings.push(AppError::new(
                        "keyring_unavailable",
                        "没有具体的密钥文件，无法把口令保存到钥匙串",
                    ));
                } else {
                    for path in &identities {
                        let account = secrets::key_passphrase_account(&profile.id, path);
                        if let Err(err) = self.secrets.set(&account, &passphrase) {
                            warnings.push(err);
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
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
                    resolved.certificate_files.clear();
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
        Ok(SessionSpec {
            profile_id: profile.id.clone(),
            name: profile.name.clone(),
            hops: hops.into_iter().map(Endpoint::from).collect(),
            auth_mode: profile.auth_mode,
            forwards,
            password,
            passphrase,
            passphrases_by_endpoint: HashMap::new(),
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
        endpoint: Endpoint {
            user: resolved.user,
            host: resolved.hostname,
            port: resolved.port,
            identity_files: resolved.identity_files,
            certificate_files: resolved.certificate_files,
            identities_only: resolved.identities_only,
            pubkey_authentication: resolved.pubkey_authentication,
            identity_agent: resolved.identity_agent,
            host_key_alias: resolved.host_key_alias,
            known_hosts_files: resolved
                .known_hosts_files
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            revoked_host_keys: resolved
                .revoked_host_keys
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            preferred: resolved.preferred_authentications,
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
    cancel: CancellationToken,
) -> Result<StartedSession, SessionFailure> {
    if spec.hops.is_empty() {
        return Err(AppError::new("invalid_target", "没有可连接的主机").into());
    }
    if spec.forwards.is_empty() {
        return Err(AppError::new("no_forwards", "至少需要一条端口映射").into());
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
    let done = Arc::new(tokio::sync::Notify::new());
    let (ready_tx, ready_rx) = oneshot::channel::<Result<(), SessionFailure>>();
    let (live_tx, live_rx) = oneshot::channel::<Arc<LiveRuntime>>();
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
                let runtime = Arc::new(runtime);
                set_phase(
                    &task_snapshot,
                    Phase::Connected,
                    "认证成功，端口映射已绑定",
                    None,
                );
                let _ = live_tx.send(Arc::clone(&runtime));
                let _ = ready_tx.send(Ok(()));
                tokio::select! {
                    _ = task_cancel.cancelled() => {
                        cleanup_shared(runtime, false).await;
                        set_phase(&task_snapshot, Phase::Disconnected, "已断开", None);
                    }
                    _ = runtime.lost.notified() => {
                        cleanup_shared(runtime, true).await;
                        set_phase(&task_snapshot, Phase::Failed, "SSH 连接已中断", None);
                    }
                }
            }
            Err(failure) => {
                set_phase(&task_snapshot, Phase::Failed, &failure.error.message, None);
                let _ = ready_tx.send(Err(failure));
            }
        }
        task_done.notify_one();
    });
    match ready_rx.await {
        Ok(Ok(())) => {
            let live = live_rx.await.map_err(|_| SessionFailure {
                error: AppError::new("ssh", "连接任务未返回会话句柄"),
                resume: None,
            })?;
            Ok((
                ActiveSession {
                    snapshot,
                    cancel,
                    done,
                },
                live,
            ))
        }
        Ok(Err(failure)) => Err(failure),
        Err(_) => Err(AppError::new("ssh", "连接任务意外结束").into()),
    }
}

pub async fn continue_pending_session(
    pending: PendingAuth,
    prompter: Arc<dyn HostKeyPrompter>,
    cancel: CancellationToken,
) -> Result<StartedSession, SessionFailure> {
    if cancel.is_cancelled() {
        teardown_pending(pending).await;
        return Err(AppError::new("cancelled", "连接已取消").into());
    }
    let snapshot = pending.snapshot.clone();
    let done = Arc::new(tokio::sync::Notify::new());
    let (ready_tx, ready_rx) = oneshot::channel::<Result<(), SessionFailure>>();
    let (live_tx, live_rx) = oneshot::channel::<Arc<LiveRuntime>>();
    let task_cancel = cancel.clone();
    let task_done = done.clone();
    let task_snapshot = snapshot.clone();
    tokio::spawn(async move {
        let outcome = continue_from_pending(pending, prompter, task_cancel.clone()).await;
        match outcome {
            Ok(runtime) => {
                let runtime = Arc::new(runtime);
                set_phase(
                    &task_snapshot,
                    Phase::Connected,
                    "认证成功，端口映射已绑定",
                    None,
                );
                let _ = live_tx.send(Arc::clone(&runtime));
                let _ = ready_tx.send(Ok(()));
                tokio::select! {
                    _ = task_cancel.cancelled() => {
                        cleanup_shared(runtime, false).await;
                        set_phase(&task_snapshot, Phase::Disconnected, "已断开", None);
                    }
                    _ = runtime.lost.notified() => {
                        cleanup_shared(runtime, true).await;
                        set_phase(&task_snapshot, Phase::Failed, "SSH 连接已中断", None);
                    }
                }
            }
            Err(failure) => {
                set_phase(&task_snapshot, Phase::Failed, &failure.error.message, None);
                let _ = ready_tx.send(Err(failure));
            }
        }
        task_done.notify_one();
    });
    match ready_rx.await {
        Ok(Ok(())) => {
            let live = live_rx.await.map_err(|_| SessionFailure {
                error: AppError::new("ssh", "恢复连接未返回会话句柄"),
                resume: None,
            })?;
            Ok((
                ActiveSession {
                    snapshot,
                    cancel,
                    done,
                },
                live,
            ))
        }
        Ok(Err(failure)) => Err(failure),
        Err(_) => Err(AppError::new("ssh", "恢复连接意外结束").into()),
    }
}

pub(crate) type StartedSession = (ActiveSession, Arc<LiveRuntime>);

struct LiveRuntime {
    handle: Arc<tokio::sync::Mutex<client::Handle<ClientHandler>>>,
    kept: Mutex<Vec<client::Handle<ClientHandler>>>,
    proxies: Mutex<Vec<tokio::process::Child>>,
    remote_rules: Arc<Mutex<Vec<RemoteRule>>>,
    remote_started: Mutex<Vec<(String, u16)>>,
    forwards: Mutex<HashMap<String, ForwardRuntime>>,
    snapshot: Arc<Mutex<TunnelSnapshot>>,
    lost: Arc<tokio::sync::Notify>,
    cancel: CancellationToken,
    ops: tokio::sync::Mutex<()>,
}

impl LiveRuntime {
    fn snapshot(&self) -> TunnelSnapshot {
        self.snapshot.lock().expect("snapshot").clone()
    }

    async fn add_forward(&self, forward: ValidatedForward) -> Result<(), AppError> {
        let _ops = self.ops.lock().await;
        {
            let snap = self.snapshot.lock().expect("snapshot");
            if snap.forwards.iter().any(|item| item.id == forward.id) {
                return Err(AppError::new(
                    "forward_exists",
                    format!("映射 {} 已在运行", forward.id),
                ));
            }
            let map = self.forwards.lock().expect("forwards");
            if map.contains_key(&forward.id) {
                return Err(AppError::new(
                    "forward_exists",
                    format!("映射 {} 正在绑定", forward.id),
                ));
            }
            drop(map);
            drop(snap);
        }
        self.upsert_forward_status(&forward, "binding", "正在绑定", None)
            .await?;
        let per_forward = CancellationToken::new();
        let mut bound_remote = false;
        let remote_addr = forward.listen_ip.to_string();
        match forward.direction {
            Direction::Local => {
                let listener =
                    match TcpListener::bind((forward.listen_ip, forward.listen_port)).await {
                        Ok(listener) => listener,
                        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
                            self.drop_forward_status(&forward.id).await;
                            return Err(AppError::new(
                                "port_in_use",
                                format!("本地端口 {} 已被占用", forward.listen_port),
                            ));
                        }
                        Err(err) => {
                            self.drop_forward_status(&forward.id).await;
                            return Err(AppError::new(
                                "bind_failed",
                                format!("无法绑定本地端口 {}: {err}", forward.listen_port),
                            ));
                        }
                    };
                let handle = self.handle.clone();
                let loop_cancel = per_forward.clone();
                let validated = forward.clone();
                let local_task = tokio::spawn(async move {
                    local_accept_loop(listener, handle, validated, loop_cancel).await;
                });
                self.forwards.lock().expect("forwards").insert(
                    forward.id.clone(),
                    ForwardRuntime {
                        cancel: per_forward,
                        remote: None,
                        local_task: Some(local_task),
                    },
                );
                self.upsert_forward_status(&forward, "listening", "本地监听已绑定", None)
                    .await?;
            }
            Direction::Remote => {
                {
                    let handle = self.handle.lock().await;
                    match handle
                        .tcpip_forward(remote_addr.clone(), u32::from(forward.listen_port))
                        .await
                    {
                        Ok(_) => bound_remote = true,
                        Err(err) => {
                            self.drop_forward_status(&forward.id).await;
                            return Err(AppError::from(err));
                        }
                    }
                }
                self.remote_rules.lock().expect("rules").push(RemoteRule {
                    listen_port: forward.listen_port,
                    destination_host: forward.destination_host.clone(),
                    destination_port: forward.destination_port,
                });
                self.forwards.lock().expect("forwards").insert(
                    forward.id.clone(),
                    ForwardRuntime {
                        cancel: per_forward,
                        remote: Some((remote_addr.clone(), forward.listen_port)),
                        local_task: None,
                    },
                );
                self.upsert_forward_status(
                    &forward,
                    "listening",
                    "服务器已接受远程转发",
                    Some((remote_addr, forward.listen_port)),
                )
                .await?;
            }
        }
        let _ = bound_remote;
        Ok(())
    }

    async fn drop_forward_status(&self, forward_id: &str) {
        let mut snap = self.snapshot.lock().expect("snapshot");
        snap.forwards.retain(|item| item.id != forward_id);
        self.forwards.lock().expect("forwards").remove(forward_id);
    }

    async fn remove_forward(&self, forward_id: &str) -> Result<(), AppError> {
        let _ops = self.ops.lock().await;
        let mut runtime = self
            .forwards
            .lock()
            .expect("forwards")
            .remove(forward_id)
            .ok_or_else(|| AppError::new("not_found", "找不到这条运行中的映射"))?;
        let status = {
            let snap = self.snapshot.lock().expect("snapshot");
            snap.forwards
                .iter()
                .find(|item| item.id == forward_id)
                .cloned()
        };
        runtime.cancel.cancel();
        if let Some(task) = runtime.local_task.take() {
            task.abort();
        }
        if let Some((address, port)) = runtime.remote.clone() {
            let cancel_result = {
                let handle = self.handle.lock().await;
                handle
                    .cancel_tcpip_forward(address.clone(), u32::from(port))
                    .await
            };
            if let Err(err) = cancel_result {
                self.forwards
                    .lock()
                    .expect("forwards")
                    .insert(forward_id.to_string(), runtime);
                if let Some(status) = status {
                    let mut snap = self.snapshot.lock().expect("snapshot");
                    if !snap.forwards.iter().any(|item| item.id == forward_id) {
                        snap.forwards.push(status);
                    }
                }
                let mapped = AppError::from(err);
                return Err(AppError::new(
                    "forward_cancel_failed",
                    format!("服务器未确认取消远程转发：{}", mapped.message),
                ));
            }
            self.remote_started
                .lock()
                .expect("remote")
                .retain(|item| item.0 != address || item.1 != port);
            self.remote_rules
                .lock()
                .expect("rules")
                .retain(|rule| rule.listen_port != port);
        }
        let mut snap = self.snapshot.lock().expect("snapshot");
        snap.forwards.retain(|item| item.id != forward_id);
        Ok(())
    }

    async fn upsert_forward_status(
        &self,
        forward: &ValidatedForward,
        state: &str,
        message: &str,
        remote: Option<(String, u16)>,
    ) -> Result<(), AppError> {
        let status = forward_status(forward, state, message);
        let mut snap = self.snapshot.lock().expect("snapshot");
        if let Some(existing) = snap.forwards.iter_mut().find(|item| item.id == forward.id) {
            *existing = status;
        } else {
            snap.forwards.push(status);
        }
        if let Some(pair) = remote {
            self.remote_started.lock().expect("remote").push(pair);
        }
        Ok(())
    }
}

async fn continue_from_pending(
    mut pending: PendingAuth,
    prompter: Arc<dyn HostKeyPrompter>,
    cancel: CancellationToken,
) -> Result<LiveRuntime, SessionFailure> {
    let lost = pending.lost.clone();
    let spec = pending.spec.clone();
    let hops = pending.hops.clone();
    let hop_count = hops.len();
    let trust = pending.trust.clone();
    let trust_path = pending.trust_path.clone();
    let snapshot = pending.snapshot.clone();
    let shared_remote_rules = pending.remote_rules.clone();
    let config = Arc::new(client_config());
    let mut kept = std::mem::take(&mut *pending.kept.lock().expect("kept"));
    let mut proxies = std::mem::take(&mut *pending.proxies.lock().expect("proxies"));
    let mut handle = pending
        .pending
        .lock()
        .expect("pending")
        .take()
        .ok_or_else(|| AppError::new("ssh", "没有待恢复的会话"))?;
    let mut index = pending.hop_index;
    if cancel.is_cancelled() {
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
        teardown_hops(kept, proxies).await;
        return Err(AppError::new("cancelled", "连接已取消").into());
    }
    set_phase(&snapshot, Phase::Authenticating, "正在认证", None);
    let endpoint = hops[index].clone();
    let last = index + 1 == hop_count;
    if last {
        if let Err(err) = authenticate_final(&mut handle, &endpoint, &spec, cancel.clone()).await {
            let pending = pending_auth_ticket(
                spec,
                hops,
                index,
                kept,
                proxies,
                handle,
                trust,
                trust_path,
                snapshot,
                shared_remote_rules,
                cancel,
                lost,
            );
            return Err(attach_pending_challenge(pending, err, &endpoint));
        }
    } else if let Err(err) =
        authenticate_jump(&mut handle, &endpoint, spec.passphrase_for(&endpoint)).await
    {
        let pending = pending_auth_ticket(
            spec,
            hops,
            index,
            kept,
            proxies,
            handle,
            trust,
            trust_path,
            snapshot,
            shared_remote_rules,
            cancel,
            lost,
        );
        return Err(attach_pending_challenge(pending, err, &endpoint));
    }
    index += 1;
    while index < hop_count {
        if cancel.is_cancelled() {
            let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
            teardown_hops(kept, proxies).await;
            return Err(AppError::new("cancelled", "连接已取消").into());
        }
        let hop = hops[index].clone();
        let last = index + 1 == hop_count;
        let handler = ClientHandler {
            host: hop.host.clone(),
            port: hop.port,
            host_key_alias: hop.host_key_alias.clone(),
            known_hosts: hop.known_hosts_files.clone(),
            revoked_host_keys: hop.revoked_host_keys.clone(),
            trust: trust.clone(),
            trust_path: trust_path.clone(),
            prompter: prompter.clone(),
            remote_rules: if last {
                Arc::clone(&shared_remote_rules)
            } else {
                Arc::new(Mutex::new(Vec::new()))
            },
            accept_forwards: last,
            cancel: cancel.clone(),
            session_lost: lost.clone(),
            profile_id: spec.profile_id.clone(),
        };
        let mut next =
            connect_hop(config.clone(), &hop, Some(&handle), handler, &mut proxies).await?;
        if last {
            set_phase(&snapshot, Phase::Authenticating, "正在认证", None);
            if let Err(err) = authenticate_final(&mut next, &hop, &spec, cancel.clone()).await {
                kept.push(handle);
                let pending = pending_auth_ticket(
                    spec,
                    hops,
                    index,
                    kept,
                    proxies,
                    next,
                    trust,
                    trust_path,
                    snapshot,
                    shared_remote_rules,
                    cancel,
                    lost,
                );
                return Err(attach_pending_challenge(pending, err, &hop));
            }
        } else if let Err(err) = authenticate_jump(&mut next, &hop, spec.passphrase_for(&hop)).await
        {
            if auth_challenge_resumable(&err) {
                kept.push(handle);
                let pending = pending_auth_ticket(
                    spec,
                    hops,
                    index,
                    kept,
                    proxies,
                    next,
                    trust,
                    trust_path,
                    snapshot,
                    shared_remote_rules,
                    cancel,
                    lost,
                );
                return Err(attach_pending_challenge(pending, err, &hop));
            }
            let _ = next.disconnect(Disconnect::ByApplication, "", "en").await;
            teardown_hops(kept, proxies).await;
            return Err(SessionFailure {
                error: err,
                resume: None,
            });
        }
        kept.push(handle);
        handle = next;
        index += 1;
    }
    assemble_live_runtime(
        handle,
        kept,
        proxies,
        &spec,
        shared_remote_rules,
        snapshot,
        cancel,
        lost,
    )
    .await
}

async fn assemble_live_runtime(
    handle: client::Handle<ClientHandler>,
    kept: Vec<client::Handle<ClientHandler>>,
    proxies: Vec<tokio::process::Child>,
    spec: &SessionSpec,
    shared_remote_rules: Arc<Mutex<Vec<RemoteRule>>>,
    snapshot: Arc<Mutex<TunnelSnapshot>>,
    cancel: CancellationToken,
    lost: Arc<tokio::sync::Notify>,
) -> Result<LiveRuntime, SessionFailure> {
    set_phase(&snapshot, Phase::Binding, "正在绑定端口映射", None);
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
                teardown_hops(kept, proxies).await;
                if err.kind() == std::io::ErrorKind::AddrInUse {
                    return Err(AppError::new(
                        "port_in_use",
                        format!("本地端口 {} 已被占用", forward.listen_port),
                    )
                    .into());
                }
                return Err(AppError::new(
                    "bind_failed",
                    format!("无法绑定本地端口 {}: {err}", forward.listen_port),
                )
                .into());
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
                teardown_hops(kept, proxies).await;
                return Err(AppError::from(err).into());
            }
        }
    }
    {
        let mut snap = snapshot.lock().expect("snapshot");
        snap.forwards = statuses;
        snap.connected_at = Some(now_rfc3339());
    }
    let mut forward_runtimes = HashMap::new();
    for (listener, forward) in listeners {
        let per_forward = CancellationToken::new();
        let shared_handle = shared.clone();
        let loop_cancel = per_forward.clone();
        let validated = forward.clone();
        let local_task = tokio::spawn(async move {
            local_accept_loop(listener, shared_handle, validated, loop_cancel).await;
        });
        forward_runtimes.insert(
            forward.id.clone(),
            ForwardRuntime {
                cancel: per_forward,
                remote: None,
                local_task: Some(local_task),
            },
        );
    }
    for forward in spec
        .forwards
        .iter()
        .filter(|forward| forward.direction == Direction::Remote)
    {
        forward_runtimes.insert(
            forward.id.clone(),
            ForwardRuntime {
                cancel: CancellationToken::new(),
                remote: Some((forward.listen_ip.to_string(), forward.listen_port)),
                local_task: None,
            },
        );
    }
    Ok(LiveRuntime {
        handle: shared,
        kept: Mutex::new(kept),
        proxies: Mutex::new(proxies),
        remote_rules: shared_remote_rules,
        remote_started: Mutex::new(remote_started),
        forwards: Mutex::new(forward_runtimes),
        snapshot: snapshot.clone(),
        lost,
        cancel,
        ops: tokio::sync::Mutex::new(()),
    })
}

async fn run_session(
    spec: SessionSpec,
    prompter: Arc<dyn HostKeyPrompter>,
    trust_path: PathBuf,
    trust: Arc<Mutex<TrustStore>>,
    snapshot: Arc<Mutex<TunnelSnapshot>>,
    cancel: CancellationToken,
) -> Result<LiveRuntime, SessionFailure> {
    let lost = Arc::new(tokio::sync::Notify::new());
    let config = Arc::new(client_config());
    let mut kept = Vec::new();
    let mut proxies = Vec::new();
    let mut current: Option<client::Handle<ClientHandler>> = None;
    let hop_count = spec.hops.len();
    let shared_remote_rules = Arc::new(Mutex::new(
        spec.forwards
            .iter()
            .filter(|forward| forward.direction == Direction::Remote)
            .map(|forward| RemoteRule {
                listen_port: forward.listen_port,
                destination_host: forward.destination_host.clone(),
                destination_port: forward.destination_port,
            })
            .collect::<Vec<_>>(),
    ));
    for (index, endpoint) in spec.hops.iter().enumerate() {
        if cancel.is_cancelled() {
            teardown_hops(kept, proxies).await;
            return Err(AppError::new("cancelled", "连接已取消").into());
        }
        let last = index + 1 == hop_count;
        let handler = ClientHandler {
            host: endpoint.host.clone(),
            port: endpoint.port,
            host_key_alias: endpoint.host_key_alias.clone(),
            known_hosts: endpoint.known_hosts_files.clone(),
            revoked_host_keys: endpoint.revoked_host_keys.clone(),
            trust: trust.clone(),
            trust_path: trust_path.clone(),
            prompter: prompter.clone(),
            remote_rules: if last {
                Arc::clone(&shared_remote_rules)
            } else {
                Arc::new(Mutex::new(Vec::new()))
            },
            accept_forwards: last,
            cancel: cancel.clone(),
            session_lost: lost.clone(),
            profile_id: spec.profile_id.clone(),
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
            if let Err(err) = authenticate_final(&mut handle, endpoint, &spec, cancel.clone()).await
            {
                let pending = pending_auth_ticket(
                    spec.clone(),
                    spec.hops.clone(),
                    index,
                    kept,
                    proxies,
                    handle,
                    trust,
                    trust_path,
                    snapshot,
                    shared_remote_rules,
                    cancel,
                    lost.clone(),
                );
                return Err(attach_pending_challenge(pending, err, endpoint));
            }
        } else if let Err(err) =
            authenticate_jump(&mut handle, endpoint, spec.passphrase_for(endpoint)).await
        {
            if auth_challenge_resumable(&err) {
                let pending = pending_auth_ticket(
                    spec.clone(),
                    spec.hops.clone(),
                    index,
                    kept,
                    proxies,
                    handle,
                    trust,
                    trust_path,
                    snapshot,
                    shared_remote_rules,
                    cancel,
                    lost.clone(),
                );
                return Err(attach_pending_challenge(pending, err, endpoint));
            }
            let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
            teardown_hops(kept, proxies).await;
            return Err(SessionFailure {
                error: err,
                resume: None,
            });
        }
        if let Some(previous) = current.take() {
            kept.push(previous);
        }
        current = Some(handle);
    }
    let handle = current.ok_or_else(|| AppError::new("ssh", "没有可用的 SSH 会话"))?;
    assemble_live_runtime(
        handle,
        kept,
        proxies,
        &spec,
        shared_remote_rules,
        snapshot,
        cancel,
        lost,
    )
    .await
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
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((mut socket, peer)) = accepted else { break };
                let handle = handle.clone();
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
                        // OpenSSH rejects the channel when the destination refuses.
                        // That closes this TCP client only. The session and the
                        // other listeners stay up.
                        Err(_) => {
                            let _ = socket.shutdown().await;
                        }
                    }
                });
            }
        }
    }
}

async fn cleanup_shared(runtime: Arc<LiveRuntime>, failed: bool) {
    runtime.cancel.cancel();
    let forwards: Vec<ForwardRuntime> = runtime
        .forwards
        .lock()
        .expect("forwards")
        .drain()
        .map(|(_, runtime)| runtime)
        .collect();
    for forward_runtime in forwards {
        forward_runtime.cancel.cancel();
        if let Some(task) = forward_runtime.local_task {
            task.abort();
        }
    }
    let handle = runtime.handle.lock().await;
    let remote_started = runtime.remote_started.lock().expect("remote").clone();
    for (address, port) in &remote_started {
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
    let hops: Vec<client::Handle<ClientHandler>> =
        std::mem::take(&mut *runtime.kept.lock().expect("kept"));
    for hop in hops {
        let _ = hop.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    let _ = std::mem::take(&mut *runtime.proxies.lock().expect("proxies"));
}

fn client_config() -> client::Config {
    let mut config = client::Config::default();
    config.nodelay = true;
    config.keepalive_interval = Some(Duration::from_secs(20));
    config.keepalive_max = 3;
    // Advertise certificate host keys ahead of raw keys. ssh-rsa (SHA-1)
    // certificates are intentionally absent.
    config.preferred.host_key_certificates = Cow::Owned(vec![
        Algorithm::Ed25519,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        },
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        },
    ]);
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
    host_key_alias: Option<String>,
    known_hosts: Vec<PathBuf>,
    revoked_host_keys: Vec<PathBuf>,
    trust: Arc<Mutex<TrustStore>>,
    trust_path: PathBuf,
    prompter: Arc<dyn HostKeyPrompter>,
    remote_rules: Arc<Mutex<Vec<RemoteRule>>>,
    accept_forwards: bool,
    cancel: CancellationToken,
    session_lost: Arc<tokio::sync::Notify>,
    profile_id: String,
}

impl Handler for ClientHandler {
    type Error = AppError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let lookup = self
            .host_key_alias
            .clone()
            .unwrap_or_else(|| self.host.clone());
        let trust = self.trust.lock().expect("trust").clone();
        match known_hosts::decide_host_key(
            &self.known_hosts,
            &self.revoked_host_keys,
            &trust,
            &self.host,
            self.port,
            self.host_key_alias.as_deref(),
            server_public_key,
        )? {
            known_hosts::HostDecision::Accept => Ok(true),
            known_hosts::HostDecision::Reject { code, message } => {
                Err(AppError::new(code, message))
            }
            known_hosts::HostDecision::Prompt {
                algorithm,
                fingerprint,
                public_key,
            } => {
                let prompt = HostKeyPrompt {
                    host: lookup,
                    port: self.port,
                    algorithm: algorithm.clone(),
                    fingerprint: fingerprint.clone(),
                };
                let accepted = tokio::select! {
                    biased;
                    _ = self.cancel.cancelled() => {
                        return Err(AppError::new("cancelled", "连接已取消"));
                    }
                    accepted = self.prompter.confirm_unknown(&prompt) => accepted,
                };
                if !accepted {
                    return Err(AppError::new(
                        "host_key_rejected",
                        "未信任该主机密钥，连接已取消",
                    ));
                }
                let entry = TrustEntry {
                    host: prompt.host.clone(),
                    port: self.port,
                    algorithm,
                    fingerprint,
                    public_key,
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

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        if !self.cancel.is_cancelled() {
            self.session_lost.notify_one();
        }
        match reason {
            client::DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            client::DisconnectReason::Error(err) => Err(err),
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
        let rule = {
            let rules = self.remote_rules.lock().expect("rules");
            rules
                .iter()
                .find(|rule| u32::from(rule.listen_port) == connected_port)
                .cloned()
        };
        let Some(rule) = rule else {
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
    cancel: CancellationToken,
) -> Result<(), AppError> {
    let configured = if endpoint.preferred.is_empty() {
        vec![
            "publickey".into(),
            "password".into(),
            "keyboard-interactive".into(),
        ]
    } else {
        endpoint.preferred.clone()
    };
    let order = match spec.auth_mode {
        AuthMode::Agent => vec!["publickey-agent".into()],
        AuthMode::PublicKey => vec!["publickey-file".into()],
        AuthMode::Password => vec!["password".into(), "keyboard-interactive".into()],
        AuthMode::Auto => configured,
    };
    let password_allowed = order
        .iter()
        .any(|method| matches!(method.as_str(), "password" | "keyboard-interactive"));
    let mut saw_encrypted_key = false;
    let mut saw_passphrase_rejected = false;
    let mut password_rejected = false;
    let mut notes = Vec::new();
    for method in &order {
        match method.as_str() {
            "publickey" => {
                match try_publickey(
                    handle,
                    endpoint,
                    spec.passphrase.as_ref(),
                    PublicKeyFilter::Any,
                )
                .await?
                {
                    FileAttempt::Success => return Ok(()),
                    FileAttempt::NeedsPassphrase => saw_encrypted_key = true,
                    FileAttempt::Rejected => {}
                    FileAttempt::Failed { notes: found } => notes.extend(found),
                }
            }
            "publickey-agent" => {
                match try_publickey(
                    handle,
                    endpoint,
                    spec.passphrase.as_ref(),
                    PublicKeyFilter::AgentOnly,
                )
                .await?
                {
                    FileAttempt::Success => return Ok(()),
                    FileAttempt::NeedsPassphrase => saw_encrypted_key = true,
                    FileAttempt::Rejected => {
                        return auth_failure(
                            saw_encrypted_key,
                            spec.passphrase.is_none(),
                            false,
                            &notes,
                            None,
                            password_rejected,
                            saw_passphrase_rejected,
                        );
                    }
                    FileAttempt::Failed { notes: found } => {
                        notes.extend(found);
                        return auth_failure(
                            saw_encrypted_key,
                            spec.passphrase.is_none(),
                            false,
                            &notes,
                            Some("agent_unavailable"),
                            password_rejected,
                            saw_passphrase_rejected,
                        );
                    }
                }
            }
            "publickey-file" => {
                match try_publickey(
                    handle,
                    endpoint,
                    spec.passphrase.as_ref(),
                    PublicKeyFilter::FilesOnly,
                )
                .await?
                {
                    FileAttempt::Success => return Ok(()),
                    FileAttempt::NeedsPassphrase => {
                        return Err(AppError::new("passphrase_required", "私钥已加密，需要口令"));
                    }
                    FileAttempt::Rejected => {}
                    FileAttempt::Failed { notes: found } => notes.extend(found),
                }
            }
            "password" | "keyboard-interactive" => {
                let Some(password) = spec.password.as_ref() else {
                    continue;
                };
                if cancel.is_cancelled() {
                    return Err(AppError::new("cancelled", "连接已取消"));
                }
                password_rejected = true;
                if method == "password"
                    && try_password(handle, &endpoint.user, password, cancel.clone()).await?
                {
                    return Ok(());
                }
                if method == "keyboard-interactive"
                    && try_keyboard(handle, &endpoint.user, password, cancel.clone()).await?
                {
                    return Ok(());
                }
            }
            "gssapi-with-mic" | "hostbased" | "none" => {}
            _ => {}
        }
    }
    auth_failure(
        saw_encrypted_key,
        spec.passphrase.is_none(),
        password_allowed && spec.password.is_none(),
        &notes,
        None,
        password_rejected,
        saw_passphrase_rejected,
    )
}

fn auth_failure(
    saw_encrypted_key: bool,
    passphrase_missing: bool,
    password_missing: bool,
    notes: &[identity::PlanNote],
    forced_code: Option<&str>,
    password_rejected: bool,
    passphrase_rejected: bool,
) -> Result<(), AppError> {
    if saw_encrypted_key && passphrase_missing {
        return Err(AppError::new("passphrase_required", "私钥已加密，需要口令"));
    }
    if let Some(note) = notes.iter().find(|note| {
        matches!(
            note.code,
            "certificate_expired"
                | "certificate_not_yet_valid"
                | "certificate_key_mismatch"
                | "certificate_needs_private_key"
                | "certificate_unreadable"
                | "certificate_missing"
                | "not_user_certificate"
                | "critical_option_unsupported"
                | "verify_required_unsupported"
                | "certificate_signature_unsupported"
                | "security_key_unsupported"
        )
    }) {
        return Err(AppError::new(note.code, note.message.clone()));
    }
    if let Some(code) = forced_code {
        return Err(AppError::new(code, "SSH agent 没有接受此次认证"));
    }
    if password_missing {
        return Err(AppError::new("password_required", "需要服务器密码"));
    }
    if password_rejected {
        return Err(AppError::new(
            "password_rejected",
            "服务器拒绝了该密码，请检查后再试",
        ));
    }
    if passphrase_rejected {
        return Err(AppError::new(
            "passphrase_rejected",
            "私钥口令不正确，请检查后再试",
        ));
    }
    let detail = notes
        .iter()
        .map(|note| note.message.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    Err(AppError::new(
        "auth_failed",
        if detail.is_empty() {
            "认证失败".into()
        } else {
            format!("认证失败。{detail}")
        },
    ))
}

async fn authenticate_jump(
    handle: &mut client::Handle<ClientHandler>,
    endpoint: &Endpoint,
    passphrase: Option<&Zeroizing<String>>,
) -> Result<(), AppError> {
    if !endpoint.pubkey_authentication
        && endpoint
            .preferred
            .iter()
            .all(|method| method != "publickey")
        && !endpoint.preferred.is_empty()
    {
        return Err(AppError::new(
            "jump_auth_failed",
            format!(
                "无法认证跳板 {}。跳板需要 agent 或密钥，不使用目标服务器密码。",
                endpoint.host
            ),
        ));
    }
    match try_publickey(handle, endpoint, passphrase, PublicKeyFilter::Any).await? {
        FileAttempt::Success => Ok(()),
        FileAttempt::Rejected => {
            if passphrase.is_some() {
                Err(AppError::new(
                    "auth_failed",
                    format!("跳板 {} 拒绝了当前密钥", endpoint.host),
                )
                .with_challenge(&endpoint.host, "jump"))
            } else {
                Err(AppError::new(
                    "jump_auth_failed",
                    format!(
                        "无法认证跳板 {}。跳板需要 agent 或密钥，不使用目标服务器密码。",
                        endpoint.host
                    ),
                ))
            }
        }
        FileAttempt::NeedsPassphrase => Err(AppError::new(
            "passphrase_required",
            format!("跳板 {} 的私钥已加密，需要口令", endpoint.host),
        )
        .with_challenge(&endpoint.host, "jump")),
        FileAttempt::Failed { notes } => {
            let detail = notes
                .iter()
                .map(|note| note.message.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            Err(AppError::new(
                "jump_auth_failed",
                if detail.is_empty() {
                    format!(
                        "无法认证跳板 {}。跳板需要 agent 或密钥，不使用目标服务器密码。",
                        endpoint.host
                    )
                } else {
                    format!("无法认证跳板 {}。{detail}", endpoint.host)
                },
            ))
        }
    }
}

async fn try_password(
    handle: &mut client::Handle<ClientHandler>,
    user: &str,
    password: &Zeroizing<String>,
    cancel: CancellationToken,
) -> Result<bool, AppError> {
    let attempt = handle.authenticate_password(user, password.as_str());
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(AppError::new("cancelled", "连接已取消")),
        result = attempt => result?,
    };
    Ok(result.success())
}

async fn try_keyboard(
    handle: &mut client::Handle<ClientHandler>,
    user: &str,
    password: &Zeroizing<String>,
    cancel: CancellationToken,
) -> Result<bool, AppError> {
    let mut response = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(AppError::new("cancelled", "连接已取消")),
        result = handle.authenticate_keyboard_interactive_start(user, None::<String>) => result?,
    };
    for _ in 0..4 {
        if cancel.is_cancelled() {
            return Err(AppError::new("cancelled", "连接已取消"));
        }
        match response {
            client::KeyboardInteractiveAuthResponse::Success => return Ok(true),
            client::KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let answers = prompts
                    .iter()
                    .map(|_| password.as_str().to_string())
                    .collect();
                response = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Err(AppError::new("cancelled", "连接已取消")),
                    result = handle.authenticate_keyboard_interactive_respond(answers) => result?,
                };
            }
        }
    }
    Ok(false)
}

enum PublicKeyFilter {
    Any,
    AgentOnly,
    FilesOnly,
}

enum FileAttempt {
    Success,
    NeedsPassphrase,
    /// A signature was produced and the server rejected it.
    Rejected,
    Failed {
        notes: Vec<identity::PlanNote>,
    },
}

async fn try_publickey(
    handle: &mut client::Handle<ClientHandler>,
    endpoint: &Endpoint,
    passphrase: Option<&Zeroizing<String>>,
    filter: PublicKeyFilter,
) -> Result<FileAttempt, AppError> {
    #[cfg(unix)]
    {
        let mut agent = connect_agent_unix(endpoint.identity_agent.as_deref()).await?;
        if let Some(agent) = agent.as_mut()
            && let Some(binding) = handle.agent_session_binding()
        {
            let _ = agent.bind_session(binding, false).await;
        }
        offer_publickey(handle, endpoint, passphrase, &mut agent, filter).await
    }
    #[cfg(windows)]
    {
        let mut agent = connect_agent_windows(endpoint.identity_agent.as_deref()).await?;
        if let Some(agent) = agent.as_mut()
            && let Some(binding) = handle.agent_session_binding()
        {
            let _ = agent.bind_session(binding, false).await;
        }
        offer_publickey(handle, endpoint, passphrase, &mut agent, filter).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut agent: Option<AgentClient<tokio::net::TcpStream>> = None;
        let _ = filter;
        offer_publickey(
            handle,
            endpoint,
            passphrase,
            &mut agent,
            PublicKeyFilter::FilesOnly,
        )
        .await
    }
}

async fn offer_publickey<S>(
    handle: &mut client::Handle<ClientHandler>,
    endpoint: &Endpoint,
    passphrase: Option<&Zeroizing<String>>,
    agent: &mut Option<AgentClient<S>>,
    filter: PublicKeyFilter,
) -> Result<FileAttempt, AppError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let identities = if let Some(agent) = agent.as_mut() {
        agent.request_identities().await.unwrap_or_default()
    } else {
        Vec::new()
    };
    let listed = identities.iter().map(listed_agent_key).collect::<Vec<_>>();
    let plan = identity::plan_authentication(
        &endpoint.identity_files,
        &endpoint.certificate_files,
        endpoint.identities_only,
        endpoint.pubkey_authentication,
        &listed,
        identity::unix_now(),
    );
    let mut needs_passphrase = false;
    let mut rejected_certs = Vec::new();
    for offer in &plan.offers {
        match filter {
            PublicKeyFilter::AgentOnly if !matches!(offer.source, KeySource::Agent(_)) => continue,
            PublicKeyFilter::FilesOnly if !matches!(offer.source, KeySource::File(_)) => continue,
            _ => {}
        }
        if matches!(offer.source, KeySource::File(_))
            && offer.certificate.as_ref().is_some_and(|cert| {
                cert.to_bytes()
                    .ok()
                    .is_some_and(|bytes| rejected_certs.iter().any(|seen| seen == &bytes))
            })
        {
            continue;
        }
        match execute_offer(handle, endpoint, offer, passphrase, agent, &identities).await? {
            FileAttempt::Success => return Ok(FileAttempt::Success),
            FileAttempt::NeedsPassphrase => needs_passphrase = true,
            FileAttempt::Rejected => {
                if matches!(offer.source, KeySource::Agent(_))
                    && let Some(cert) = &offer.certificate
                    && let Ok(bytes) = cert.to_bytes()
                {
                    rejected_certs.push(bytes);
                }
            }
            FileAttempt::Failed { .. } => {}
        }
    }
    if needs_passphrase {
        Ok(FileAttempt::NeedsPassphrase)
    } else {
        Ok(FileAttempt::Failed { notes: plan.notes })
    }
}

fn listed_agent_key(identity: &AgentIdentity) -> ListedAgentKey {
    match identity {
        AgentIdentity::PublicKey { key, comment } => ListedAgentKey {
            public_key: key.clone(),
            certificate: None,
            comment: comment.clone(),
        },
        AgentIdentity::Certificate {
            certificate,
            comment,
        } => ListedAgentKey {
            public_key: PublicKey::new(certificate.public_key().clone(), comment.as_str()),
            certificate: Some(certificate.clone()),
            comment: comment.clone(),
        },
    }
}

async fn execute_offer<S>(
    handle: &mut client::Handle<ClientHandler>,
    endpoint: &Endpoint,
    offer: &AuthOffer,
    passphrase: Option<&Zeroizing<String>>,
    agent: &mut Option<AgentClient<S>>,
    identities: &[AgentIdentity],
) -> Result<FileAttempt, AppError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    match &offer.source {
        KeySource::File(path) => {
            let loaded = match load_private(path, passphrase)? {
                PrivateLoad::Key(key) => key,
                PrivateLoad::Encrypted => return Ok(FileAttempt::NeedsPassphrase),
                PrivateLoad::Unavailable => {
                    return Ok(FileAttempt::Failed { notes: Vec::new() });
                }
            };
            if let Some(cert) = &offer.certificate
                && loaded.public_key().key_data() != cert.public_key()
            {
                return Err(AppError::new(
                    "certificate_key_mismatch",
                    format!(
                        "证书与私钥 {} 的公钥不一致。证书不能代替签名私钥",
                        path.display()
                    ),
                ));
            }
            let hash_alg = if matches!(loaded.algorithm(), Algorithm::Rsa { .. }) {
                supported_rsa_hash(handle).await
            } else {
                None
            };
            let key = std::sync::Arc::new(loaded);
            let result = if let Some(cert) = &offer.certificate {
                let mut signer = LocalKeySigner { key };
                handle
                    .authenticate_certificate_with(
                        &endpoint.user,
                        cert.clone(),
                        hash_alg,
                        &mut signer,
                    )
                    .await
                    .map_err(|_| AppError::new("auth_failed", "无法用这把私钥完成证书签名"))?
            } else {
                let wrapped = PrivateKeyWithHashAlg::new(key, hash_alg);
                handle
                    .authenticate_publickey(&endpoint.user, wrapped)
                    .await?
            };
            if result.success() {
                Ok(FileAttempt::Success)
            } else {
                Ok(FileAttempt::Rejected)
            }
        }
        KeySource::Agent(index) => {
            let (Some(agent), Some(identity)) = (agent.as_mut(), identities.get(*index)) else {
                return Ok(FileAttempt::Failed { notes: Vec::new() });
            };
            let hash_alg = rsa_hash_for_identity(handle, identity).await;
            let result = if let Some(cert) = &offer.certificate {
                match identity {
                    AgentIdentity::Certificate { .. } => {
                        handle
                            .authenticate_certificate_with(
                                &endpoint.user,
                                cert.clone(),
                                hash_alg,
                                agent,
                            )
                            .await
                    }
                    AgentIdentity::PublicKey { key, .. } => {
                        let mut signer = PlainAgentSigner {
                            agent,
                            key: key.clone(),
                        };
                        handle
                            .authenticate_certificate_with(
                                &endpoint.user,
                                cert.clone(),
                                hash_alg,
                                &mut signer,
                            )
                            .await
                    }
                }
            } else {
                let AgentIdentity::PublicKey { key, .. } = identity else {
                    return Ok(FileAttempt::Failed { notes: Vec::new() });
                };
                handle
                    .authenticate_publickey_with(&endpoint.user, key.clone(), hash_alg, agent)
                    .await
            };
            match result {
                Ok(result) if result.success() => Ok(FileAttempt::Success),
                Ok(_) => Ok(FileAttempt::Rejected),
                Err(_) => Ok(FileAttempt::Failed { notes: Vec::new() }),
            }
        }
    }
}

struct LocalKeySigner {
    key: std::sync::Arc<russh::keys::PrivateKey>,
}

impl russh::Signer for LocalKeySigner {
    type Error = russh::AgentAuthError;

    fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let key = self.key.clone();
        async move {
            use russh::keys::signature::Signer;
            use russh::keys::ssh_encoding::Encode;
            let signature = match key.key_data() {
                russh::keys::ssh_key::private::KeypairData::Rsa(rsa) => {
                    Signer::try_sign(&(rsa, hash_alg), to_sign.as_slice())
                }
                _ => Signer::try_sign(key.as_ref(), to_sign.as_slice()),
            }
            .map_err(|_| russh::keys::Error::CouldNotReadKey)?;
            let mut wire = Vec::new();
            signature
                .encode(&mut wire)
                .map_err(|_| russh::keys::Error::CouldNotReadKey)?;
            let mut signed = to_sign;
            wire.encode(&mut signed)
                .map_err(|_| russh::keys::Error::CouldNotReadKey)?;
            Ok(signed)
        }
    }
}

struct PlainAgentSigner<'a, S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    agent: &'a mut AgentClient<S>,
    key: PublicKey,
}

impl<S> russh::Signer for PlainAgentSigner<'_, S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    type Error = russh::AgentAuthError;

    fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let identity = AgentIdentity::PublicKey {
            key: self.key.clone(),
            comment: String::new(),
        };
        let agent = &mut *self.agent;
        async move {
            agent
                .sign_request(&identity, hash_alg, to_sign)
                .await
                .map_err(Into::into)
        }
    }
}

enum PrivateLoad {
    Key(russh::keys::PrivateKey),
    Encrypted,
    Unavailable,
}

fn load_private(
    path: &std::path::Path,
    passphrase: Option<&Zeroizing<String>>,
) -> Result<PrivateLoad, AppError> {
    if !path.is_file() {
        return Ok(PrivateLoad::Unavailable);
    }
    match russh::keys::load_secret_key(path, None) {
        Ok(key) => Ok(PrivateLoad::Key(key)),
        Err(russh::keys::Error::KeyIsEncrypted) => {
            let Some(passphrase) = passphrase else {
                return Ok(PrivateLoad::Encrypted);
            };
            match russh::keys::load_secret_key(path, Some(passphrase.as_str())) {
                Ok(key) => Ok(PrivateLoad::Key(key)),
                Err(_) => Err(AppError::new("passphrase_rejected", "密钥口令不正确")),
            }
        }
        Err(_) => Ok(PrivateLoad::Unavailable),
    }
}

async fn rsa_hash_for_identity(
    handle: &client::Handle<ClientHandler>,
    identity: &AgentIdentity,
) -> Option<HashAlg> {
    let algorithm = match identity {
        AgentIdentity::PublicKey { key, .. } => key.algorithm(),
        AgentIdentity::Certificate { certificate, .. } => certificate.algorithm(),
    };
    if matches!(algorithm, Algorithm::Rsa { .. }) {
        supported_rsa_hash(handle).await
    } else {
        None
    }
}

async fn supported_rsa_hash(
    handle: &client::Handle<ClientHandler>,
) -> Option<russh::keys::HashAlg> {
    match handle.best_supported_rsa_hash().await {
        Ok(Some(Some(alg))) => Some(alg),
        _ => Some(HashAlg::Sha256),
    }
}

#[cfg(unix)]
async fn connect_agent_unix(
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

#[cfg(windows)]
async fn connect_agent_windows(
    explicit: Option<&str>,
) -> Result<Option<AgentClient<tokio::net::windows::named_pipe::NamedPipeClient>>, AppError> {
    let path = match explicit {
        Some("none") | Some("") => return Ok(None),
        Some(path) => path.to_string(),
        None => std::env::var("SSH_AUTH_SOCK")
            .unwrap_or_else(|_| r"\\.\pipe\openssh-ssh-agent".to_string()),
    };
    if !path.starts_with(r"\\.\pipe\") {
        return Ok(None);
    }
    match AgentClient::connect_named_pipe(path).await {
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
    } else if matches!(phase, Phase::Failed | Phase::Disconnected) {
        for forward in &mut snap.forwards {
            forward.state = "stopped".into();
            forward.message = message.to_string();
        }
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
