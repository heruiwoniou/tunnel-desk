use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use russh::keys::{HashAlg, PublicKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;

use crate::error::AppError;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyVerdict {
    Trusted { source: String },
    Unknown,
    Changed { source: String, previous: String },
    Revoked { source: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustEntry {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key: String,
    pub trusted_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustStore {
    pub entries: Vec<TrustEntry>,
}

impl TrustStore {
    pub fn verdict(&self, host: &str, port: u16, key: &PublicKey) -> HostKeyVerdict {
        let fingerprint = fingerprint(key);
        let encoded = key.to_openssh().unwrap_or_default();
        let mut saw_host = false;
        for entry in &self.entries {
            if !host_eq(&entry.host, host) || entry.port != port {
                continue;
            }
            saw_host = true;
            if (entry.public_key.trim() == encoded.trim() || entry.fingerprint == fingerprint)
                && (entry.algorithm == algorithm_name(key) || entry.fingerprint == fingerprint)
            {
                return HostKeyVerdict::Trusted {
                    source: "tunneldesk-trust".into(),
                };
            }
            if entry.algorithm == algorithm_name(key) && entry.fingerprint != fingerprint {
                return HostKeyVerdict::Changed {
                    source: "tunneldesk-trust".into(),
                    previous: entry.fingerprint.clone(),
                };
            }
        }
        let _ = saw_host;
        HostKeyVerdict::Unknown
    }

    pub fn insert(&mut self, entry: TrustEntry) {
        self.entries.retain(|item| {
            !(host_eq(&item.host, &entry.host)
                && item.port == entry.port
                && item.algorithm == entry.algorithm)
        });
        self.entries.push(entry);
    }

    pub fn forget(&mut self, host: &str, port: u16) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|item| !(host_eq(&item.host, host) && item.port == port));
        before != self.entries.len()
    }
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub fn algorithm_name(key: &PublicKey) -> String {
    key.algorithm().to_string()
}

/// Read OpenSSH known_hosts files. Hashed hosts, markers, and non-standard ports are honored.
/// This function never writes the files.
pub fn check_known_hosts_files(
    paths: &[PathBuf],
    host: &str,
    port: u16,
    key: &PublicKey,
) -> Result<HostKeyVerdict, AppError> {
    let mut trusted = None;
    for path in paths {
        if !path.exists() {
            continue;
        }
        let text = std::fs::read_to_string(path).map_err(|err| {
            AppError::new(
                "config",
                format!("无法读取 known_hosts {}: {err}", path.display()),
            )
        })?;
        match check_known_hosts_text(&text, host, port, key, &path.display().to_string())? {
            HostKeyVerdict::Unknown => {}
            HostKeyVerdict::Trusted { source } => {
                trusted = Some(HostKeyVerdict::Trusted { source })
            }
            other => return Ok(other),
        }
    }
    Ok(trusted.unwrap_or(HostKeyVerdict::Unknown))
}

pub fn check_known_hosts_text(
    text: &str,
    host: &str,
    port: u16,
    key: &PublicKey,
    source: &str,
) -> Result<HostKeyVerdict, AppError> {
    let candidates = host_candidates(host, port);
    let presented = key.to_openssh().unwrap_or_default();
    let mut trusted = false;
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(parsed) = parse_known_hosts_line(line) else {
            continue;
        };
        if !candidates
            .iter()
            .any(|candidate| pattern_matches(&parsed.hosts, candidate))
        {
            continue;
        }
        let recorded = match russh::keys::PublicKey::from_openssh(&parsed.key_line) {
            Ok(recorded) => recorded,
            Err(_) => continue,
        };
        if parsed.marker == Some(Marker::Revoked) && same_key(&recorded, key) {
            return Ok(HostKeyVerdict::Revoked {
                source: format!("{source}:{line}", line = line_no + 1),
            });
        }
        if parsed.marker == Some(Marker::CertAuthority) {
            continue;
        }
        if recorded.algorithm() == key.algorithm() && !same_key(&recorded, key) {
            return Ok(HostKeyVerdict::Changed {
                source: format!("{source}:{}", line_no + 1),
                previous: fingerprint(&recorded),
            });
        }
        if same_key(&recorded, key) || recorded.to_openssh().unwrap_or_default() == presented {
            trusted = true;
        }
    }
    if trusted {
        Ok(HostKeyVerdict::Trusted {
            source: source.to_string(),
        })
    } else {
        Ok(HostKeyVerdict::Unknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    Revoked,
    CertAuthority,
}

struct ParsedLine {
    marker: Option<Marker>,
    hosts: String,
    key_line: String,
}

fn parse_known_hosts_line(line: &str) -> Option<ParsedLine> {
    let tokens = split_ws(line);
    if tokens.len() < 3 {
        return None;
    }
    let (marker, rest) = if tokens[0] == "@revoked" {
        (Some(Marker::Revoked), &tokens[1..])
    } else if tokens[0] == "@cert-authority" {
        (Some(Marker::CertAuthority), &tokens[1..])
    } else {
        (None, &tokens[..])
    };
    if rest.len() < 3 {
        return None;
    }
    Some(ParsedLine {
        marker,
        hosts: rest[0].clone(),
        key_line: format!("{} {}", rest[1], rest[2]),
    })
}

fn host_candidates(host: &str, port: u16) -> Vec<String> {
    let mut values = vec![format!("[{host}]:{port}"), host.to_string()];
    if port == 22 {
        values.push(format!("[{host}]:22"));
    }
    values
}

fn pattern_matches(pattern_list: &str, host: &str) -> bool {
    let mut positive = false;
    let mut any_positive = false;
    for pattern in pattern_list.split(',') {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }
        let (neg, body) = if let Some(rest) = pattern.strip_prefix('!') {
            (true, rest)
        } else {
            (false, pattern)
        };
        if !neg {
            any_positive = true;
        }
        let matched = single_pattern(body, host);
        if neg && matched {
            return false;
        }
        if !neg && matched {
            positive = true;
        }
    }
    positive && any_positive
}

fn single_pattern(pattern: &str, host: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix("|1|") {
        return hashed_match(rest, host);
    }
    glob_match(pattern, host)
}

fn hashed_match(rest: &str, host: &str) -> bool {
    let mut parts = rest.split('|');
    let (Some(salt_b64), Some(hash_b64)) = (parts.next(), parts.next()) else {
        return false;
    };
    let Ok(salt) = STANDARD.decode(salt_b64.trim()) else {
        return false;
    };
    let Ok(expected) = STANDARD.decode(hash_b64.trim()) else {
        return false;
    };
    let Ok(mut mac) = HmacSha1::new_from_slice(&salt) else {
        return false;
    };
    mac.update(host.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(pattern: &[u8], text: &[u8]) -> bool {
        let mut p = 0;
        let mut t = 0;
        while p < pattern.len() {
            if pattern[p] == b'*' {
                if p + 1 == pattern.len() {
                    return true;
                }
                while t <= text.len() {
                    if rec(&pattern[p + 1..], &text[t..]) {
                        return true;
                    }
                    if t == text.len() {
                        break;
                    }
                    t += 1;
                }
                return false;
            }
            if t >= text.len() {
                return false;
            }
            if pattern[p] != b'?' && pattern[p] != text[t] {
                return false;
            }
            p += 1;
            t += 1;
        }
        t == text.len()
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

fn same_key(left: &PublicKey, right: &PublicKey) -> bool {
    left.key_data() == right.key_data()
}

fn host_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn split_ws(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_string).collect()
}

pub fn default_known_hosts(home: &Path) -> Vec<PathBuf> {
    let ssh = home.join(".ssh");
    vec![
        ssh.join("known_hosts"),
        ssh.join("known_hosts2"),
        PathBuf::from("/etc/ssh/ssh_known_hosts"),
        PathBuf::from("/etc/ssh/ssh_known_hosts2"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rng;
    use russh::keys::{Algorithm, PrivateKey};

    fn key() -> PrivateKey {
        PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn trusts_exact_and_bracketed_port_and_rejects_change() {
        let good = key();
        let other = key();
        let line = format!(
            "[db.internal]:2222 {}",
            good.public_key().to_openssh().unwrap()
        );
        let trusted =
            check_known_hosts_text(&line, "db.internal", 2222, good.public_key(), "file").unwrap();
        assert!(matches!(trusted, HostKeyVerdict::Trusted { .. }));
        let changed =
            check_known_hosts_text(&line, "db.internal", 2222, other.public_key(), "file").unwrap();
        assert!(matches!(changed, HostKeyVerdict::Changed { .. }));
        let unknown =
            check_known_hosts_text(&line, "other.internal", 2222, good.public_key(), "file")
                .unwrap();
        assert!(matches!(unknown, HostKeyVerdict::Unknown));
    }

    #[test]
    fn hashed_hosts_and_revocation() {
        let good = key();
        let salt = b"salt-value-16b!";
        let mut mac = HmacSha1::new_from_slice(salt).unwrap();
        mac.update(b"hashed.example");
        let hash = mac.finalize().into_bytes();
        let line = format!(
            "|1|{}|{} {}",
            STANDARD.encode(salt),
            STANDARD.encode(hash),
            good.public_key().to_openssh().unwrap()
        );
        let verdict =
            check_known_hosts_text(&line, "hashed.example", 22, good.public_key(), "file").unwrap();
        assert!(matches!(verdict, HostKeyVerdict::Trusted { .. }));
        let revoked = format!(
            "@revoked hashed.example {}",
            good.public_key().to_openssh().unwrap()
        );
        let verdict =
            check_known_hosts_text(&revoked, "hashed.example", 22, good.public_key(), "file")
                .unwrap();
        assert!(matches!(verdict, HostKeyVerdict::Revoked { .. }));
    }

    #[test]
    fn does_not_treat_certificate_authority_as_raw_key_trust() {
        let good = key();
        let line = format!(
            "@cert-authority *.example {}",
            good.public_key().to_openssh().unwrap()
        );
        let verdict =
            check_known_hosts_text(&line, "a.example", 22, good.public_key(), "file").unwrap();
        assert!(matches!(verdict, HostKeyVerdict::Unknown));
    }

    #[test]
    fn app_trust_store_roundtrip_without_rewriting_known_hosts() {
        let good = key();
        let mut store = TrustStore::default();
        store.insert(TrustEntry {
            host: "App.Example".into(),
            port: 22,
            algorithm: algorithm_name(good.public_key()),
            fingerprint: fingerprint(good.public_key()),
            public_key: good.public_key().to_openssh().unwrap(),
            trusted_at: "2026-01-01T00:00:00Z".into(),
        });
        assert!(matches!(
            store.verdict("app.example", 22, good.public_key()),
            HostKeyVerdict::Trusted { .. }
        ));
        let other = key();
        assert!(matches!(
            store.verdict("app.example", 22, other.public_key()),
            HostKeyVerdict::Changed { .. }
        ));
        let json = serde_json::to_string(&store).unwrap();
        assert!(!json.contains("SENTINEL-SECRET-VALUE"));
    }
}
