use std::sync::atomic::Ordering;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

use crate::AppState;
use crate::model::{CloseBehavior, Phase};

/// Ayatana and KDE register this name when a panel is actually hosting icons.
pub fn watcher_reply_owns_name(reply: &str) -> bool {
    reply.lines().any(|line| line.contains("boolean true"))
}

/// Linux tray icons are invisible unless a StatusNotifierWatcher is on the session bus.
/// When the check cannot confirm a host, hiding the window would leave the app stuck.
#[cfg(target_os = "linux")]
pub fn status_notifier_watcher_present() -> bool {
    let Ok(output) = std::process::Command::new("dbus-send")
        .args([
            "--session",
            "--dest=org.freedesktop.DBus",
            "--type=method_call",
            "--print-reply",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            "string:org.kde.StatusNotifierWatcher",
        ])
        .output()
    else {
        return false;
    };
    output.status.success() && watcher_reply_owns_name(&String::from_utf8_lossy(&output.stdout))
}

pub fn install(app: &AppHandle) -> bool {
    let menu = match build_menu(app) {
        Ok(menu) => menu,
        Err(_) => return false,
    };
    let mut builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .tooltip("TunnelDesk")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            let id = event.id().as_ref().to_string();
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                handle_menu(&app, &id).await;
            });
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                crate::commands::reveal(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app).is_ok()
}

pub fn refresh(state: &AppState) {
    let app = state.app.clone();
    if !state.tray_available.load(Ordering::SeqCst) {
        return;
    }
    let Some(tray) = app.tray_by_id("main") else {
        return;
    };
    if let Ok(menu) = build_menu(&app) {
        let _ = tray.set_menu(Some(menu));
    }
}

fn build_menu(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    let state = app.state::<AppState>();
    let settings = state.manager.store().load_settings().unwrap_or_default();
    let zh = matches!(settings.language, crate::model::Language::Zh);
    let show = MenuItem::with_id(
        app,
        "show",
        if zh { "显示窗口" } else { "Show window" },
        true,
        None::<&str>,
    )?;
    let disconnect_all = MenuItem::with_id(
        app,
        "disconnect-all",
        if zh { "断开全部" } else { "Disconnect all" },
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(
        app,
        "quit",
        if zh { "退出" } else { "Quit" },
        true,
        Some("CmdOrCtrl+Q"),
    )?;
    let separator = PredefinedMenuItem::separator(app)?;
    let separator_b = PredefinedMenuItem::separator(app)?;
    let mut items: Vec<&dyn tauri::menu::IsMenuItem<Wry>> = vec![&show, &separator];
    let profiles = state.manager.store().load_profiles().unwrap_or_default();
    let snapshots = state.manager.snapshots();
    let mut owned: Vec<MenuItem<Wry>> = Vec::new();
    for profile in profiles.iter().take(16) {
        let active = snapshots.iter().any(|snapshot| {
            snapshot.profile_id == profile.id
                && matches!(
                    snapshot.phase,
                    Phase::Connected | Phase::Connecting | Phase::Authenticating | Phase::Binding
                )
        });
        let label = if active {
            if zh {
                format!("断开 {}", profile.name)
            } else {
                format!("Disconnect {}", profile.name)
            }
        } else if zh {
            format!("连接 {}", profile.name)
        } else {
            format!("Connect {}", profile.name)
        };
        let id = if active {
            format!("disconnect:{}", profile.id)
        } else {
            format!("connect:{}", profile.id)
        };
        owned.push(MenuItem::with_id(app, id, label, true, None::<&str>)?);
    }
    for item in &owned {
        items.push(item);
    }
    if !owned.is_empty() {
        items.push(&separator_b);
    }
    items.push(&disconnect_all);
    items.push(&quit);
    Menu::with_items(app, &items)
}

async fn handle_menu(app: &AppHandle, id: &str) {
    let state = app.state::<AppState>();
    match id {
        "show" => crate::commands::reveal(app),
        "quit" => {
            let _ = state.manager.disconnect_all().await;
            app.exit(0);
        }
        "disconnect-all" => {
            let _ = state.manager.disconnect_all().await;
            let _ = app.emit("tunnel-state", state.manager.snapshots());
            refresh(&state);
        }
        other if let Some(profile_id) = other.strip_prefix("connect:") => {
            crate::commands::connect_from_tray(app, &state.manager, &state.prompts, profile_id)
                .await;
            refresh(&state);
        }
        other if let Some(profile_id) = other.strip_prefix("disconnect:") => {
            let _ = state.manager.disconnect(profile_id).await;
            let _ = app.emit("tunnel-state", state.manager.snapshots());
            refresh(&state);
        }
        _ => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseDecision {
    Hide,
    Quit,
}

/// Hiding is only safe when a tray exists to bring the window back.
pub fn close_decision(behavior: CloseBehavior, tray_available: bool) -> CloseDecision {
    if behavior == CloseBehavior::MinimizeToTray && tray_available {
        CloseDecision::Hide
    } else {
        CloseDecision::Quit
    }
}

pub async fn on_close(app: &AppHandle, window: &tauri::Window) {
    let state = app.state::<AppState>();
    let settings = state.manager.store().load_settings().unwrap_or_default();
    let tray_ok = state.tray_available.load(Ordering::SeqCst);
    if close_decision(settings.close_behavior, tray_ok) == CloseDecision::Hide {
        if window.hide().is_err() {
            let _ = state.manager.disconnect_all().await;
            app.exit(0);
        }
        return;
    }
    let _ = state.manager.disconnect_all().await;
    app.exit(0);
}

#[cfg(test)]
mod tests {
    use super::{CloseDecision, close_decision, watcher_reply_owns_name};
    use crate::model::CloseBehavior;

    #[test]
    fn missing_tray_never_hides_the_window() {
        assert_eq!(
            close_decision(CloseBehavior::MinimizeToTray, false),
            CloseDecision::Quit
        );
        assert_eq!(
            close_decision(CloseBehavior::Quit, true),
            CloseDecision::Quit
        );
        assert_eq!(
            close_decision(CloseBehavior::MinimizeToTray, true),
            CloseDecision::Hide
        );
    }

    #[test]
    fn watcher_reply_requires_an_owner() {
        assert!(!watcher_reply_owns_name(""));
        assert!(!watcher_reply_owns_name("boolean false"));
        assert!(watcher_reply_owns_name("   boolean true\n"));
    }
}
