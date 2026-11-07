use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::{Certificate, HashAlg, PublicKey, PublicKeyOrCertificate};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostDecision {
    Accept,
    Prompt {
        algorithm: String,
        fingerprint: String,
        public_key: String,
    },
    Reject {
        code: &'static str,
        message: String,
    },
}

/// Decide whether a server host key or host certificate may be trusted.
///
/// A certificate is accepted only when a matching `@cert-authority` signs it
/// and its time, principal, critical options, and signature algorithm pass.
/// The certified raw key being present is not enough. OpenSSH 9.6 compares
/// host-certificate principals exactly (wildcards do not match) and uses
/// `HostKeyAlias` when it is set. An empty principal list matches any name.
/// Revocation is final. Any other certificate failure falls back to the raw
/// key inside the certificate, which is the OpenSSH downgrade path.
pub fn decide_host_key(
    known_hosts: &[PathBuf],
    revoked_files: &[PathBuf],
    trust: &TrustStore,
    host: &str,
    port: u16,
    alias: Option<&str>,
    presented: &PublicKeyOrCertificate,
) -> Result<HostDecision, AppError> {
    let lookup = alias.unwrap_or(host);
    let mut records = Vec::new();
    for path in known_hosts {
        records.extend(read_host_records(path)?);
    }
    for path in revoked_files {
        records.extend(read_revocation_file(path)?);
    }
    if let Some(cert) = presented.certificate() {
        if let Some(source) =
            revocation_hit(&records, lookup, port, Some(cert), &presented.public_key())
        {
            return Ok(HostDecision::Reject {
                code: "host_cert_revoked",
                message: format!("主机证书或其 CA 已被吊销（{source}），连接已拒绝"),
            });
        }
        if trusted_host_certificate(&records, lookup, port, cert).is_some() {
            return Ok(HostDecision::Accept);
        }
        return Ok(decide_raw_key(
            known_hosts,
            &records,
            trust,
            lookup,
            port,
            &presented.public_key(),
        ));
    }
    Ok(decide_raw_key(
        known_hosts,
        &records,
        trust,
        lookup,
        port,
        &presented.public_key(),
    ))
}

fn trusted_host_certificate(
    records: &[HostRecord],
    host: &str,
    port: u16,
    cert: &Certificate,
) -> Option<String> {
    if cert.cert_type() != CertType::Host || !crate::identity::signature_algorithm_allowed(cert) {
        return None;
    }
    if !cert.critical_options().is_empty() {
        return None;
    }
    let now = crate::identity::unix_now();
    if now < cert.valid_after() || now >= cert.valid_before() {
        return None;
    }
    if !cert.valid_principals().is_empty()
        && !cert
            .valid_principals()
            .iter()
            .any(|principal| principal == host)
    {
        return None;
    }
    let candidates = host_candidates(host, port);
    for record in records {
        if record.marker != Some(Marker::CertAuthority) {
            continue;
        }
        if !candidates
            .iter()
            .any(|candidate| pattern_matches(&record.hosts, candidate))
        {
            continue;
        }
        let Ok(ca) = PublicKey::from_openssh(&record.key_line) else {
            continue;
        };
        if cert.signature_key().fingerprint(HashAlg::Sha256)
            != ca.key_data().fingerprint(HashAlg::Sha256)
        {
            continue;
        }
        if cert.verify_signature().is_ok() {
            return Some(record.source.clone());
        }
    }
    None
}

fn decide_raw_key(
    known_hosts: &[PathBuf],
    records: &[HostRecord],
    trust: &TrustStore,
    host: &str,
    port: u16,
    key: &PublicKey,
) -> HostDecision {
    if let Some(source) = revocation_hit(records, host, port, None, key) {
        return HostDecision::Reject {
            code: "host_key_revoked",
            message: format!("主机密钥已被吊销（{source}），连接已拒绝"),
        };
    }
    let verdict = match check_known_hosts_files(known_hosts, host, port, key) {
        Ok(HostKeyVerdict::Unknown) => trust.verdict(host, port, key),
        Ok(other) => other,
        Err(err) => {
            return HostDecision::Reject {
                code: "config",
                message: err.message,
            };
        }
    };
    match verdict {
        HostKeyVerdict::Trusted { .. } => HostDecision::Accept,
        HostKeyVerdict::Revoked { source } => HostDecision::Reject {
            code: "host_key_revoked",
            message: format!("主机密钥已被吊销（{source}），连接已拒绝"),
        },
        HostKeyVerdict::Changed { source, previous } => HostDecision::Reject {
            code: "host_key_changed",
            message: format!(
                "主机密钥与已记录的值不一致（{source}）。已记录 {previous}，本次为 {}。连接已拒绝，不会自动更换信任。",
                fingerprint(key)
            ),
        },
        HostKeyVerdict::Unknown => HostDecision::Prompt {
            algorithm: algorithm_name(key),
            fingerprint: fingerprint(key),
            public_key: key.to_openssh().unwrap_or_default(),
        },
    }
}

fn revocation_hit(
    records: &[HostRecord],
    host: &str,
    port: u16,
    cert: Option<&Certificate>,
    key: &PublicKey,
) -> Option<String> {
    let candidates = host_candidates(host, port);
    for record in records {
        let revoked = record.marker == Some(Marker::Revoked) || record.revocation_file;
        if !revoked {
            continue;
        }
        if !candidates
            .iter()
            .any(|candidate| pattern_matches(&record.hosts, candidate))
        {
            continue;
        }
        if let Some(cert) = cert {
            if cert_matches_record(cert, &record.key_line)
                || key_matches_record(key, &record.key_line)
            {
                return Some(record.source.clone());
            }
            if let Ok(ca) = PublicKey::from_openssh(&record.key_line)
                && cert.signature_key().fingerprint(HashAlg::Sha256)
                    == ca.key_data().fingerprint(HashAlg::Sha256)
            {
                return Some(record.source.clone());
            }
        } else if key_matches_record(key, &record.key_line) {
            return Some(record.source.clone());
        }
    }
    None
}

fn cert_matches_record(cert: &Certificate, key_line: &str) -> bool {
    Certificate::from_openssh(key_line)
        .ok()
        .and_then(|recorded| recorded.to_bytes().ok())
        .zip(cert.to_bytes().ok())
        .is_some_and(|(recorded, presented)| recorded == presented)
}

fn key_matches_record(key: &PublicKey, key_line: &str) -> bool {
    PublicKey::from_openssh(key_line)
        .ok()
        .is_some_and(|recorded| same_key(&recorded, key))
}

struct HostRecord {
    marker: Option<Marker>,
    hosts: String,
    key_line: String,
    source: String,
    revocation_file: bool,
}

fn read_revocation_file(path: &Path) -> Result<Vec<HostRecord>, AppError> {
    if !path.exists() {
        return Err(AppError::new(
            "revoked_host_keys",
            format!("找不到吊销文件 {}", path.display()),
        ));
    }
    let bytes = std::fs::read(path).map_err(|err| {
        AppError::new(
            "revoked_host_keys",
            format!("无法读取吊销文件 {}: {err}", path.display()),
        )
    })?;
    if bytes.starts_with(b"SSHKRL") {
        return Err(AppError::new(
            "krl_unsupported",
            format!(
                "吊销文件 {} 是 OpenSSH KRL。TunnelDesk 不能解析这种二进制吊销列表，连接已拒绝",
                path.display()
            ),
        ));
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut records = read_host_text(&text, &path.display().to_string())?;
    for record in &mut records {
        record.revocation_file = true;
        if record.marker.is_none() {
            record.marker = Some(Marker::Revoked);
        }
    }
    Ok(records)
}

fn read_host_records(path: &Path) -> Result<Vec<HostRecord>, AppError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path).map_err(|err| {
        AppError::new(
            "config",
            format!("无法读取 known_hosts {}: {err}", path.display()),
        )
    })?;
    read_host_text(&text, &path.display().to_string())
}

fn read_host_text(text: &str, source: &str) -> Result<Vec<HostRecord>, AppError> {
    let mut records = Vec::new();
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(parsed) = parse_known_hosts_line(line) else {
            continue;
        };
        records.push(HostRecord {
            marker: parsed.marker,
            hosts: parsed.hosts,
            key_line: parsed.key_line,
            source: format!("{source}:{}", line_no + 1),
            revocation_file: false,
        });
    }
    Ok(records)
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

    fn signed(ca: &PrivateKey, host_key: &PrivateKey, principal: Option<&str>) -> Certificate {
        use russh::keys::ssh_key::certificate::{Builder, CertType};
        let now = crate::identity::unix_now();
        let mut builder = Builder::new_with_random_nonce(
            &mut rand::rng(),
            host_key.public_key(),
            now.saturating_sub(60),
            now + 3600,
        )
        .unwrap();
        builder.cert_type(CertType::Host).unwrap();
        if let Some(principal) = principal {
            builder.valid_principal(principal).unwrap();
        } else {
            builder.all_principals_valid().unwrap();
        }
        builder.sign(ca).unwrap()
    }

    fn present(cert: Certificate) -> PublicKeyOrCertificate {
        cert.into()
    }

    fn decide(text: &str, cert: Certificate) -> HostDecision {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, text).unwrap();
        decide_host_key(
            &[path],
            &[],
            &TrustStore::default(),
            "127.0.0.1",
            22,
            None,
            &present(cert),
        )
        .unwrap()
    }

    #[test]
    fn host_certificate_requires_a_matching_authority() {
        let ca = key();
        let other_ca = key();
        let host_key = key();
        let cert = signed(&ca, &host_key, Some("127.0.0.1"));
        let ca_line = format!(
            "@cert-authority 127.0.0.1 {}",
            ca.public_key().to_openssh().unwrap()
        );
        assert!(matches!(
            decide(&ca_line, cert.clone()),
            HostDecision::Accept
        ));
        let wildcard = signed(&ca, &host_key, Some("*.local"));
        assert!(matches!(
            decide(&ca_line, wildcard),
            HostDecision::Prompt { .. }
        ));
        let any = signed(&ca, &host_key, None);
        assert!(matches!(decide(&ca_line, any), HostDecision::Accept));
        let wrong = signed(&other_ca, &host_key, Some("127.0.0.1"));
        assert!(matches!(
            decide(&ca_line, wrong),
            HostDecision::Prompt { .. }
        ));
        let raw_and_wrong_cert = format!(
            "{ca_line}\n127.0.0.1 {}",
            host_key.public_key().to_openssh().unwrap()
        );
        let mismatched = signed(&other_ca, &host_key, Some("127.0.0.1"));
        assert!(matches!(
            decide(&raw_and_wrong_cert, mismatched),
            HostDecision::Accept
        ));
        let revoked = format!(
            "@revoked * {}\n{ca_line}",
            ca.public_key().to_openssh().unwrap()
        );
        let still_valid = signed(&ca, &host_key, Some("127.0.0.1"));
        assert!(matches!(
            decide(&revoked, still_valid),
            HostDecision::Reject {
                code: "host_cert_revoked",
                ..
            }
        ));
        let kept = tempfile::tempdir().unwrap();
        let file = kept.path().join("known_hosts");
        std::fs::write(
            &file,
            format!(
                "@cert-authority bastion.example {}",
                ca.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        let alias = decide_host_key(
            &[file],
            &[],
            &TrustStore::default(),
            "127.0.0.1",
            22,
            Some("bastion.example"),
            &present(signed(&ca, &host_key, Some("bastion.example"))),
        )
        .unwrap();
        assert!(matches!(alias, HostDecision::Accept));
    }
}
