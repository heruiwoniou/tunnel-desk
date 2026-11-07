use std::sync::Arc;

use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

use crate::AppState;
use crate::error::AppError;
use crate::model::{BackendInfo, HistoryEntry, Profile, SecretMeta, Settings, TunnelSnapshot};
use crate::tunnel::{ConnectOutcome, HostKeyPrompt, HostKeyPrompter, TunnelManager};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectRequest {
    profile_id: String,
    server_password: Option<String>,
    key_passphrase: Option<String>,
    remember_server_password: bool,
    remember_key_passphrase: bool,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostKeyAnswer {
    request_id: String,
    accept: bool,
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HostKeyEvent {
    request_id: String,
    host: String,
    port: u16,
    algorithm: String,
    fingerprint: String,
}

struct GuiPrompter {
    app: AppHandle,
    hub: Arc<crate::PromptHub>,
}

#[async_trait::async_trait]
impl HostKeyPrompter for GuiPrompter {
    async fn confirm_unknown(&self, prompt: &HostKeyPrompt) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let request_id = crate::model::new_id();
        self.hub.insert(request_id.clone(), tx);
        let _ = self.app.emit(
            "hostkey-required",
            HostKeyEvent {
                request_id,
                host: prompt.host.clone(),
                port: prompt.port,
                algorithm: prompt.algorithm.clone(),
                fingerprint: prompt.fingerprint.clone(),
            },
        );
        match tokio::time::timeout(std::time::Duration::from_secs(120), rx).await {
            Ok(Ok(accepted)) => accepted,
            _ => false,
        }
    }
}

fn seal(value: Option<String>) -> Option<Zeroizing<String>> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(Zeroizing::new(value))
        }
    })
}

fn prompter(app: &AppHandle, state: &AppState) -> Arc<GuiPrompter> {
    Arc::new(GuiPrompter {
        app: app.clone(),
        hub: state.prompts.clone(),
    })
}

#[tauri::command]
fn backend_info(state: State<'_, AppState>) -> BackendInfo {
    let keyring = state.manager.keyring_status();
    BackendInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        engine: "russh".into(),
        tray_available: state
            .tray_available
            .load(std::sync::atomic::Ordering::SeqCst),
        keyring_available: keyring.available,
        keyring_message: keyring.message,
        ssh_binary: state
            .manager
            .resolver()
            .ssh_binary
            .as_ref()
            .map(|path| path.display().to_string()),
    }
}

#[tauri::command]
fn list_profiles(state: State<'_, AppState>) -> Result<Vec<Profile>, AppError> {
    state.manager.store().load_profiles()
}

#[tauri::command]
fn save_profile(state: State<'_, AppState>, profile: Profile) -> Result<Profile, AppError> {
    crate::model::ensure_profile_shape(&profile)?;
    let mut profiles = state.manager.store().load_profiles()?;
    if let Some(existing) = profiles.iter_mut().find(|item| item.id == profile.id) {
        *existing = profile.clone();
    } else {
        profiles.push(profile.clone());
    }
    state.manager.store().save_profiles(&profiles)?;
    crate::tray::refresh(&state);
    Ok(profile)
}

#[tauri::command]
fn delete_profile(state: State<'_, AppState>, id: String) -> Result<(), AppError> {
    let profiles = state
        .manager
        .store()
        .load_profiles()?
        .into_iter()
        .filter(|profile| profile.id != id)
        .collect::<Vec<_>>();
    state.manager.store().save_profiles(&profiles)?;
    let _ = state.manager.forget_server_password(&id);
    let _ = state.manager.forget_passphrases(&id);
    crate::tray::refresh(&state);
    Ok(())
}

#[tauri::command]
fn list_hosts(state: State<'_, AppState>) -> Result<Vec<crate::config::SshAlias>, AppError> {
    state.manager.resolver().list_aliases()
}

#[tauri::command]
fn resolve_host(
    state: State<'_, AppState>,
    query: String,
) -> Result<crate::config::ResolvedHost, AppError> {
    state.manager.resolver().resolve(&query)
}

#[tauri::command]
fn list_history(state: State<'_, AppState>) -> Result<Vec<HistoryEntry>, AppError> {
    state.manager.store().load_history()
}

#[tauri::command]
fn clear_history(state: State<'_, AppState>) -> Result<(), AppError> {
    state.manager.store().save_history(&[])
}

#[tauri::command]
fn get_settings(state: State<'_, AppState>) -> Result<Settings, AppError> {
    state.manager.store().load_settings()
}

#[tauri::command]
fn save_settings(state: State<'_, AppState>, settings: Settings) -> Result<Settings, AppError> {
    state.manager.store().save_settings(&settings)?;
    crate::tray::refresh(&state);
    Ok(settings)
}

#[tauri::command]
fn runtime_snapshots(state: State<'_, AppState>) -> Vec<TunnelSnapshot> {
    state.manager.snapshots()
}

#[tauri::command]
fn secret_meta(state: State<'_, AppState>, profile_id: String) -> Result<SecretMeta, AppError> {
    state.manager.secret_meta(&profile_id)
}

#[tauri::command]
fn forget_server_password(state: State<'_, AppState>, profile_id: String) -> Result<(), AppError> {
    state.manager.forget_server_password(&profile_id)
}

#[tauri::command]
fn forget_passphrases(state: State<'_, AppState>, profile_id: String) -> Result<(), AppError> {
    state.manager.forget_passphrases(&profile_id)
}

#[tauri::command]
fn list_trust(state: State<'_, AppState>) -> Result<crate::known_hosts::TrustStore, AppError> {
    state.manager.store().load_trust()
}

#[tauri::command]
fn forget_trust(state: State<'_, AppState>, host: String, port: u16) -> Result<bool, AppError> {
    let mut trust = state.manager.store().load_trust()?;
    let removed = trust.forget(&host, port);
    state.manager.store().save_trust(&trust)?;
    Ok(removed)
}

#[tauri::command]
fn respond_host_key(state: State<'_, AppState>, answer: HostKeyAnswer) -> Result<(), AppError> {
    if state.prompts.respond(&answer.request_id, answer.accept) {
        Ok(())
    } else {
        Err(AppError::new("not_found", "这个主机密钥确认已经过期"))
    }
}

#[tauri::command]
async fn connect_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    request: ConnectRequest,
) -> Result<ConnectOutcome, AppError> {
    let manager = state.manager.clone();
    let prompter = prompter(&app, &state);
    let outcome = manager
        .connect(
            &request.profile_id,
            seal(request.server_password),
            seal(request.key_passphrase),
            request.remember_server_password,
            request.remember_key_passphrase,
            prompter,
        )
        .await?;
    crate::tray::refresh(&state);
    let _ = app.emit("tunnel-state", manager.snapshots());
    Ok(outcome)
}

#[tauri::command]
async fn disconnect_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<(), AppError> {
    state.manager.disconnect(&profile_id).await?;
    crate::tray::refresh(&state);
    let _ = app.emit("tunnel-state", state.manager.snapshots());
    Ok(())
}

#[tauri::command]
async fn disconnect_all(app: AppHandle, state: State<'_, AppState>) -> Result<(), AppError> {
    state.manager.disconnect_all().await?;
    crate::tray::refresh(&state);
    let _ = app.emit("tunnel-state", state.manager.snapshots());
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeForwardRequest {
    profile_id: String,
    mapping: crate::model::ForwardMapping,
    persist: bool,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeForwardRemove {
    profile_id: String,
    forward_id: String,
    persist: bool,
}

#[tauri::command]
async fn add_runtime_forward(
    app: AppHandle,
    state: State<'_, AppState>,
    request: RuntimeForwardRequest,
) -> Result<TunnelSnapshot, AppError> {
    let snapshot = state
        .manager
        .add_runtime_forward(&request.profile_id, &request.mapping, request.persist)
        .await?;
    crate::tray::refresh(&state);
    let _ = app.emit("tunnel-state", state.manager.snapshots());
    Ok(snapshot)
}

#[tauri::command]
async fn remove_runtime_forward(
    app: AppHandle,
    state: State<'_, AppState>,
    request: RuntimeForwardRemove,
) -> Result<TunnelSnapshot, AppError> {
    let snapshot = state
        .manager
        .remove_runtime_forward(&request.profile_id, &request.forward_id, request.persist)
        .await?;
    crate::tray::refresh(&state);
    let _ = app.emit("tunnel-state", state.manager.snapshots());
    Ok(snapshot)
}

pub fn invoke_handler() -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        backend_info,
        list_profiles,
        save_profile,
        delete_profile,
        list_hosts,
        resolve_host,
        list_history,
        clear_history,
        get_settings,
        save_settings,
        runtime_snapshots,
        secret_meta,
        forget_server_password,
        forget_passphrases,
        list_trust,
        forget_trust,
        respond_host_key,
        connect_profile,
        disconnect_profile,
        disconnect_all,
        add_runtime_forward,
        remove_runtime_forward,
    ]
}

pub async fn connect_from_tray(
    app: &AppHandle,
    manager: &TunnelManager,
    prompts: &Arc<crate::PromptHub>,
    profile_id: &str,
) {
    let prompter = Arc::new(GuiPrompter {
        app: app.clone(),
        hub: prompts.clone(),
    });
    match manager
        .connect(profile_id, None, None, false, false, prompter)
        .await
    {
        Ok(_) => {
            let _ = app.emit("tunnel-state", manager.snapshots());
        }
        Err(err) if err.code == "password_required" || err.code == "passphrase_required" => {
            reveal(app);
            let _ = app.emit(
                "connect-needs-input",
                serde_json::json!({ "profileId": profile_id, "code": err.code, "message": err.message }),
            );
        }
        Err(_) => {
            reveal(app);
            let _ = app.emit("tunnel-state", manager.snapshots());
        }
    }
}

pub fn reveal(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        #[cfg(target_os = "linux")]
        {
            let _ = window.set_always_on_top(true);
            let _ = window.set_always_on_top(false);
        }
        let _ = window.set_focus();
    }
}
