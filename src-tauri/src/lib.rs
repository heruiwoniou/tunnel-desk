pub mod commands;
pub mod config;
pub mod error;
pub mod forward;
pub mod identity;
pub mod known_hosts;
pub mod model;
pub mod secrets;
pub mod store;
pub mod tray;
pub mod tunnel;

#[cfg(test)]
mod ssh_itest;

#[cfg(all(test, unix))]
mod cert_itest;
#[cfg(all(test, unix))]
mod sshd_itest;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tauri::{Emitter, Manager, WindowEvent};
use tokio::sync::oneshot;

use crate::error::AppError;
use crate::secrets::OsSecretStore;
use crate::store::AppStore;
use crate::tunnel::TunnelManager;

pub struct PromptHub {
    pending: Mutex<std::collections::HashMap<String, oneshot::Sender<bool>>>,
    owners: Mutex<std::collections::HashMap<String, String>>,
}

impl PromptHub {
    fn new() -> Self {
        Self {
            pending: Mutex::new(std::collections::HashMap::new()),
            owners: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn insert(&self, profile_id: &str, id: String, sender: oneshot::Sender<bool>) {
        self.pending
            .lock()
            .expect("prompts")
            .insert(id.clone(), sender);
        self.owners
            .lock()
            .expect("owners")
            .insert(id, profile_id.to_string());
    }

    fn respond(&self, id: &str, accept: bool) -> bool {
        if let Some(sender) = self.pending.lock().expect("prompts").remove(id) {
            self.owners.lock().expect("owners").remove(id);
            let _ = sender.send(accept);
            true
        } else {
            false
        }
    }

    pub fn cancel_for(&self, profile_id: &str) {
        let owners = self.owners.lock().expect("owners");
        let ids: Vec<String> = owners
            .iter()
            .filter_map(|(id, owner)| {
                if owner == profile_id {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        drop(owners);
        let mut pending = self.pending.lock().expect("prompts");
        let mut owners = self.owners.lock().expect("owners");
        for id in ids {
            if let Some(sender) = pending.remove(&id) {
                let _ = sender.send(false);
            }
            owners.remove(&id);
        }
    }

    pub fn cancel_all(&self) {
        let mut pending = self.pending.lock().expect("prompts");
        self.owners.lock().expect("owners").clear();
        for (_, sender) in pending.drain() {
            let _ = sender.send(false);
        }
    }
}

pub struct AppState {
    pub app: tauri::AppHandle,
    pub manager: Arc<TunnelManager>,
    pub prompts: Arc<PromptHub>,
    pub tray_available: Arc<AtomicBool>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(commands::invoke_handler())
        .setup(|app| {
            let data_dir = app_data_dir(app.handle())
                .map_err(|err| Box::new(std::io::Error::other(err.message)))?;
            let store = AppStore::open(&data_dir)
                .map_err(|err| Box::new(std::io::Error::other(err.message)))?;
            let manager = Arc::new(TunnelManager::new(
                store,
                Arc::new(OsSecretStore),
                crate::config::Resolver::from_env(),
            ));
            let prompts = Arc::new(PromptHub::new());
            let tray_available = Arc::new(AtomicBool::new(false));
            app.manage(AppState {
                app: app.handle().clone(),
                manager: manager.clone(),
                prompts,
                tray_available: tray_available.clone(),
            });
            let mut installed = tray::install(app.handle());
            // A tray object without a panel host cannot be clicked. Treat that as
            // no tray so closing the window quits instead of hiding it.
            #[cfg(target_os = "linux")]
            if installed && !tray::status_notifier_watcher_present() {
                installed = false;
            }
            tray_available.store(installed, Ordering::SeqCst);
            let settings = manager.store().load_settings().unwrap_or_default();
            if settings.start_minimized && installed {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            } else if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
            }
            let handle = app.handle().clone();
            let mut watch = manager.subscribe();
            tauri::async_runtime::spawn(async move {
                loop {
                    if watch.changed().await.is_err() {
                        break;
                    }
                    let snapshots = watch.borrow().clone();
                    let _ = handle.emit("tunnel-state", snapshots);
                    if let Some(state) = handle.try_state::<AppState>() {
                        tray::refresh(&state);
                    }
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let window = window.clone();
                let app = window.app_handle().clone();
                tauri::async_runtime::spawn(async move {
                    tray::on_close(&app, &window).await;
                });
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running TunnelDesk");
}

#[cfg(test)]
mod version_source {
    #[test]
    fn cargo_package_version_matches_tauri_config() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(conf["version"].as_str(), Some(env!("CARGO_PKG_VERSION")));
    }
}

fn app_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, AppError> {
    if let Some(dir) = std::env::var_os("TUNNELDESK_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    app.path()
        .app_data_dir()
        .map_err(|err| AppError::new("config", err.to_string()))
}
