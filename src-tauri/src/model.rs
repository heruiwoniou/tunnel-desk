use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    /// Local listener; the destination is reached from the SSH server (`ssh -L`).
    Local,
    /// Server listener; the destination is reached from this client (`ssh -R`).
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthMode {
    Auto,
    Password,
    PublicKey,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Target {
    ConfigAlias {
        alias: String,
    },
    #[serde(rename_all = "camelCase")]
    Manual {
        hostname: String,
        port: u16,
        user: String,
        #[serde(default)]
        identity_file: Option<String>,
        #[serde(default)]
        proxy_jump: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForwardMapping {
    pub id: String,
    pub direction: Direction,
    pub listen_host: String,
    pub listen_port: u16,
    pub destination_host: String,
    pub destination_port: u16,
    /// Required when `listen_host` is not a loopback address.
    #[serde(default)]
    pub allow_external: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub target: Target,
    pub auth_mode: AuthMode,
    /// Preference only. The secret itself lives in the OS keyring.
    #[serde(default)]
    pub remember_password: bool,
    pub forwards: Vec<ForwardMapping>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Theme {
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Language {
    Zh,
    En,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CloseBehavior {
    MinimizeToTray,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub theme: Theme,
    pub language: Language,
    pub close_behavior: CloseBehavior,
    pub start_minimized: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: Theme::System,
            language: Language::Zh,
            close_behavior: CloseBehavior::MinimizeToTray,
            start_minimized: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryEntry {
    pub id: String,
    pub profile_id: String,
    pub name: String,
    pub target: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub outcome: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Disconnected,
    Connecting,
    Authenticating,
    Binding,
    Connected,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardStatus {
    pub id: String,
    pub direction: Direction,
    pub listen: String,
    pub destination: String,
    pub state: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelSnapshot {
    pub profile_id: String,
    pub name: String,
    pub phase: Phase,
    pub message: String,
    pub forwards: Vec<ForwardStatus>,
    pub connected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretMeta {
    pub server_password_stored: bool,
    pub key_passphrase_stored: bool,
    pub keyring_available: bool,
    pub keyring_message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendInfo {
    pub version: String,
    pub engine: String,
    pub tray_available: bool,
    pub keyring_available: bool,
    pub keyring_message: Option<String>,
    pub ssh_binary: Option<String>,
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn ensure_profile_shape(profile: &Profile) -> Result<(), AppError> {
    if profile.name.trim().is_empty() || profile.name.chars().count() > 80 {
        return Err(AppError::new(
            "invalid_name",
            "请填写 1 到 80 个字符的隧道名称",
        ));
    }
    if profile.id.trim().is_empty() || profile.id.len() > 80 {
        return Err(AppError::new("invalid_name", "隧道标识无效"));
    }
    if profile.forwards.is_empty() {
        return Err(AppError::new("no_forwards", "至少需要一条端口映射"));
    }
    match &profile.target {
        Target::ConfigAlias { alias } => {
            crate::forward::validate_alias(alias)?;
        }
        Target::Manual {
            hostname,
            port,
            user,
            identity_file,
            proxy_jump,
        } => {
            crate::forward::validate_hostname(hostname)?;
            crate::forward::validate_user(user)?;
            if *port == 0 {
                return Err(AppError::new("invalid_port", "端口必须在 1 到 65535 之间"));
            }
            if let Some(path) = identity_file {
                crate::forward::validate_path_field(path)?;
            }
            if let Some(jump) = proxy_jump {
                crate::forward::validate_proxy_jump(jump)?;
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for forward in &profile.forwards {
        let validated = crate::forward::validate_mapping(forward)?;
        let key = format!(
            "{}|{}|{}",
            match validated.direction {
                Direction::Local => "L",
                Direction::Remote => "R",
            },
            validated.listen_ip,
            validated.listen_port
        );
        if !seen.insert(key) {
            return Err(AppError::new(
                "duplicate_listen",
                "同一方向上的监听地址和端口不能重复",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Profile {
        Profile {
            id: "p1".into(),
            name: "数据库".into(),
            target: Target::Manual {
                hostname: "db.internal".into(),
                port: 22,
                user: "rui".into(),
                identity_file: None,
                proxy_jump: None,
            },
            auth_mode: AuthMode::Auto,
            remember_password: true,
            forwards: vec![ForwardMapping {
                id: "f1".into(),
                direction: Direction::Local,
                listen_host: "127.0.0.1".into(),
                listen_port: 15432,
                destination_host: "127.0.0.1".into(),
                destination_port: 5432,
                allow_external: false,
            }],
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn assert_no_secret_material(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    let lower = key.to_ascii_lowercase();
                    assert_ne!(lower, "password");
                    assert_ne!(lower, "passphrase");
                    assert_ne!(lower, "secret");
                    assert_ne!(lower, "privatekey");
                    assert_ne!(lower, "private_key");
                    assert_no_secret_material(child);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(assert_no_secret_material),
            serde_json::Value::String(text) => {
                assert!(!text.contains("SENTINEL-SECRET-VALUE"));
            }
            _ => {}
        }
    }

    #[test]
    fn persisted_models_have_no_secret_fields() {
        let profile = serde_json::to_value(sample()).unwrap();
        assert_no_secret_material(&profile);
        let settings = serde_json::to_value(Settings::default()).unwrap();
        assert_no_secret_material(&settings);
        let history = serde_json::to_value(HistoryEntry {
            id: "h".into(),
            profile_id: "p1".into(),
            name: "数据库".into(),
            target: "rui@db.internal:22".into(),
            started_at: "2026-01-01T00:00:00Z".into(),
            ended_at: None,
            outcome: "auth_failed".into(),
            message: "认证失败".into(),
        })
        .unwrap();
        assert_no_secret_material(&history);
    }

    #[test]
    fn password_field_is_rejected() {
        let mut value = serde_json::to_value(sample()).unwrap();
        value.as_object_mut().unwrap().insert(
            "password".into(),
            serde_json::json!("SENTINEL-SECRET-VALUE"),
        );
        let parsed: Result<Profile, _> = serde_json::from_value(value);
        assert!(parsed.is_err());
    }
}
