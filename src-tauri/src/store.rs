use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::AppError;
use crate::known_hosts::TrustStore;
use crate::model::{HistoryEntry, Profile, Settings};

#[derive(Clone)]
pub struct AppStore {
    dir: PathBuf,
}

impl AppStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, AppError> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(AppError::from)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn trust_path(&self) -> PathBuf {
        self.dir.join("trust.json")
    }

    pub fn load_profiles(&self) -> Result<Vec<Profile>, AppError> {
        read_json(&self.dir.join("profiles.json"), Vec::new())
    }

    pub fn save_profiles(&self, profiles: &[Profile]) -> Result<(), AppError> {
        for profile in profiles {
            crate::model::ensure_profile_shape(profile)?;
        }
        write_json(&self.dir.join("profiles.json"), profiles)
    }

    pub fn load_settings(&self) -> Result<Settings, AppError> {
        read_json(&self.dir.join("settings.json"), Settings::default())
    }

    pub fn save_settings(&self, settings: &Settings) -> Result<(), AppError> {
        write_json(&self.dir.join("settings.json"), settings)
    }

    pub fn load_history(&self) -> Result<Vec<HistoryEntry>, AppError> {
        read_json(&self.dir.join("history.json"), Vec::new())
    }

    pub fn save_history(&self, history: &[HistoryEntry]) -> Result<(), AppError> {
        write_json(&self.dir.join("history.json"), history)
    }

    pub fn push_history(&self, entry: HistoryEntry) -> Result<(), AppError> {
        let mut history = self.load_history()?;
        history.insert(0, entry);
        history.truncate(200);
        self.save_history(&history)
    }

    pub fn load_trust(&self) -> Result<TrustStore, AppError> {
        read_json(&self.trust_path(), TrustStore::default())
    }

    pub fn save_trust(&self, trust: &TrustStore) -> Result<(), AppError> {
        save_trust_file(&self.trust_path(), trust)
    }
}

pub fn save_trust_file(path: &Path, trust: &TrustStore) -> Result<(), AppError> {
    write_json(path, trust)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, default: T) -> Result<T, AppError> {
    if !path.exists() {
        return Ok(default);
    }
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|err| AppError::new("config", format!("无法读取 {}: {err}", path.display())))
}

fn write_json<T: serde::Serialize + ?Sized>(path: &Path, value: &T) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|err| AppError::new("config", err.to_string()))?;
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    #[test]
    fn roundtrip_excludes_sentinels_and_rejects_secret_fields() {
        let dir = tempfile::tempdir().unwrap();
        let store = AppStore::open(dir.path()).unwrap();
        let profile = Profile {
            id: "p1".into(),
            name: "示例".into(),
            target: Target::ConfigAlias {
                alias: "dest".into(),
            },
            auth_mode: AuthMode::Password,
            remember_password: true,
            forwards: vec![ForwardMapping {
                id: "f".into(),
                direction: Direction::Remote,
                listen_host: "127.0.0.1".into(),
                listen_port: 9000,
                destination_host: "127.0.0.1".into(),
                destination_port: 3000,
                allow_external: false,
            }],
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
        };
        store.save_profiles(&[profile]).unwrap();
        store
            .push_history(HistoryEntry {
                id: "h".into(),
                profile_id: "p1".into(),
                name: "示例".into(),
                target: "rui@dest:22".into(),
                started_at: now_rfc3339(),
                ended_at: None,
                outcome: "connected".into(),
                message: "已连接".into(),
            })
            .unwrap();
        store.save_settings(&Settings::default()).unwrap();
        let text = fs::read_to_string(dir.path().join("profiles.json")).unwrap()
            + &fs::read_to_string(dir.path().join("history.json")).unwrap()
            + &fs::read_to_string(dir.path().join("settings.json")).unwrap();
        assert!(!text.contains("SENTINEL-SECRET-VALUE"));
        assert!(!text.contains("\"serverPassword\""));
        assert!(!text.contains("\"keyPassphrase\""));
        assert!(!text.contains("\"privateKey\""));
        assert!(!text.contains("\"passphrase\""));
        assert!(text.contains("\"authMode\": \"password\""));
        let loaded = store.load_profiles().unwrap();
        assert_eq!(loaded[0].name, "示例");
        assert!(loaded[0].remember_password);
    }
}
