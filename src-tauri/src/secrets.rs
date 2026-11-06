use zeroize::Zeroizing;

use crate::error::AppError;

pub use zeroize::Zeroizing as SecretString;

/// Must match `identifier` in `tauri.conf.json`. Not a secret.
pub const SERVICE: &str = "dev.tunneldesk.desktop";

#[derive(Debug, Clone)]
pub struct SecretBackendStatus {
    pub available: bool,
    pub message: Option<String>,
}

pub trait SecretStore: Send + Sync {
    fn status(&self) -> SecretBackendStatus;
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError>;
    fn set(&self, account: &str, secret: &str) -> Result<(), AppError>;
    fn delete(&self, account: &str) -> Result<(), AppError>;
}

pub struct OsSecretStore;

impl SecretStore for OsSecretStore {
    fn status(&self) -> SecretBackendStatus {
        let (tx, rx) = std::sync::mpsc::channel();
        let _ = std::thread::Builder::new()
            .name("tunneldesk-keyring".into())
            .spawn(move || {
                let status = match keyring::Entry::store_status() {
                    Ok(()) => SecretBackendStatus {
                        available: true,
                        message: None,
                    },
                    Err(err) => SecretBackendStatus {
                        available: false,
                        message: Some(keyring_message(err)),
                    },
                };
                let _ = tx.send(status);
            });
        rx.recv_timeout(std::time::Duration::from_secs(2))
            .unwrap_or(SecretBackendStatus {
            available: false,
            message: Some(
                "系统钥匙串没有及时响应。它可能已锁定或未运行。TunnelDesk 不会把密码保存为明文。"
                    .into(),
            ),
        })
    }

    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        let account = account.to_string();
        call_keyring(move || {
            let entry = keyring::Entry::new(SERVICE, &account)?;
            match entry.get_password() {
                Ok(password) => Ok(Some(password)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(err) => Err(err),
            }
        })
        .map(|value| value.map(Zeroizing::new))
    }

    fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
        let account = account.to_string();
        let secret = Zeroizing::new(secret.to_string());
        call_keyring(move || {
            let entry = keyring::Entry::new(SERVICE, &account)?;
            entry.set_password(secret.as_str())
        })
    }

    fn delete(&self, account: &str) -> Result<(), AppError> {
        let account = account.to_string();
        call_keyring(move || {
            let entry = keyring::Entry::new(SERVICE, &account)?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(err) => Err(err),
            }
        })
    }
}

fn call_keyring<T: Send + 'static>(
    op: impl FnOnce() -> Result<T, keyring::Error> + Send + 'static,
) -> Result<T, AppError> {
    let (tx, rx) = std::sync::mpsc::channel();
    if let Err(err) = std::thread::Builder::new()
        .name("tunneldesk-keyring".into())
        .spawn(move || {
            let _ = tx.send(op());
        })
    {
        return Err(AppError::new("keyring_unavailable", err.to_string()));
    }
    match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(result) => result.map_err(map_keyring),
        Err(_) => Err(AppError::new(
            "keyring_unavailable",
            "系统钥匙串没有及时响应。它可能已锁定或未运行。TunnelDesk 不会把密码保存为明文。",
        )),
    }
}

pub fn server_password_account(profile_id: &str) -> String {
    format!("server-password:{profile_id}")
}

pub fn key_passphrase_account(profile_id: &str, identity_path: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(identity_path.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("key-passphrase:{profile_id}:{hex}")
}

fn map_keyring(err: keyring::Error) -> AppError {
    let code = match &err {
        keyring::Error::NoStorageAccess(_) => "keyring_locked",
        keyring::Error::NoEntry => "not_found",
        _ => "keyring_unavailable",
    };
    AppError::new(code, keyring_message(&err))
}

fn keyring_message(err: &keyring::Error) -> String {
    match err {
        keyring::Error::NoStorageAccess(_) => {
            "系统钥匙串已锁定或无法访问。密码不会写入普通文件。请解锁钥匙串后重试，或仅本次输入密码。".into()
        }
        keyring::Error::NoDefaultStore | keyring::Error::PlatformFailure(_) => {
            "系统钥匙串不可用。Linux 需要 Secret Service（例如 gnome-keyring）。TunnelDesk 不会把密码保存为明文。".into()
        }
        keyring::Error::NoEntry => "没有已保存的密码".into(),
        other => format!("系统钥匙串错误：{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FailingStore;

    impl SecretStore for FailingStore {
        fn status(&self) -> SecretBackendStatus {
            SecretBackendStatus {
                available: false,
                message: Some("Secret Service is unavailable".into()),
            }
        }
        fn get(&self, _: &str) -> Result<Option<Zeroizing<String>>, AppError> {
            Err(AppError::new(
                "keyring_unavailable",
                "Secret Service is unavailable",
            ))
        }
        fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
            Err(AppError::new(
                "keyring_unavailable",
                "Secret Service is unavailable",
            ))
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            Err(AppError::new(
                "keyring_unavailable",
                "Secret Service is unavailable",
            ))
        }
    }

    struct MemoryStore {
        values: Mutex<std::collections::BTreeMap<String, String>>,
    }

    impl SecretStore for MemoryStore {
        fn status(&self) -> SecretBackendStatus {
            SecretBackendStatus {
                available: true,
                message: None,
            }
        }
        fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(account)
                .cloned()
                .map(Zeroizing::new))
        }
        fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
            self.values
                .lock()
                .unwrap()
                .insert(account.into(), secret.into());
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<(), AppError> {
            self.values.lock().unwrap().remove(account);
            Ok(())
        }
    }

    #[test]
    fn keyring_failure_does_not_create_a_plaintext_file() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("should-stay-empty.txt");
        std::fs::write(&marker, b"ok").unwrap();
        let store = FailingStore;
        let err = store
            .set(&server_password_account("profile"), "SENTINEL-SECRET-VALUE")
            .unwrap_err();
        assert_eq!(err.code, "keyring_unavailable");
        let body = std::fs::read_to_string(&marker).unwrap();
        assert!(!body.contains("SENTINEL-SECRET-VALUE"));
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let bytes = std::fs::read(&path).unwrap_or_default();
                let text = String::from_utf8_lossy(&bytes);
                assert!(!text.contains("SENTINEL-SECRET-VALUE"));
            }
        }
    }

    #[test]
    fn accounts_do_not_contain_the_secret() {
        let account = key_passphrase_account("profile", "/home/rui/.ssh/id_ed25519");
        assert!(!account.contains("SENTINEL"));
        assert!(account.starts_with("key-passphrase:profile:"));
        let memory = MemoryStore {
            values: Mutex::new(std::collections::BTreeMap::new()),
        };
        memory
            .set(&server_password_account("profile"), "SENTINEL-SECRET-VALUE")
            .unwrap();
        let got = memory
            .get(&server_password_account("profile"))
            .unwrap()
            .unwrap();
        assert_eq!(got.as_str(), "SENTINEL-SECRET-VALUE");
        memory.delete(&server_password_account("profile")).unwrap();
        assert!(
            memory
                .get(&server_password_account("profile"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn os_keyring_roundtrip_when_explicitly_enabled() {
        if std::env::var("TUNNELDESK_KEYRING_TEST").ok().as_deref() != Some("1") {
            return;
        }
        let store = OsSecretStore;
        let status = store.status();
        assert!(status.available, "{}", status.message.unwrap_or_default());
        let account = format!("test-{}", uuid::Uuid::new_v4());
        let secret = format!("td-{}", uuid::Uuid::new_v4());
        store.set(&account, &secret).unwrap();
        let got = store.get(&account).unwrap().unwrap();
        assert!(
            got.as_str() == secret.as_str(),
            "keyring round trip mismatch"
        );
        store.delete(&account).unwrap();
        assert!(store.get(&account).unwrap().is_none());
    }

    #[test]
    fn service_name_matches_the_bundle_identifier() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(conf["identifier"], SERVICE);
        assert!(!SERVICE.ends_with(".app"));
        assert!(!SERVICE.contains('/'));
    }
}
