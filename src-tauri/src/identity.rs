//! Choose SSH identities the way OpenSSH 9.6 does.
//!
//! A certificate is a public object. It never replaces the private key that
//! signs the authentication. Explicit `CertificateFile` entries are tried
//! first. An adjacent `*-cert.pub` is considered only when the configuration
//! lists no `CertificateFile` at all. `IdentitiesOnly` keeps agent keys that
//! match a configured identity or certificate and drops the rest.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use russh::keys::ssh_key::certificate::CertType;
use russh::keys::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanNote {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ListedAgentKey {
    pub public_key: PublicKey,
    pub certificate: Option<Certificate>,
    pub comment: String,
}

#[derive(Debug, Clone)]
pub enum KeySource {
    File(PathBuf),
    Agent(usize),
}

#[derive(Debug, Clone)]
pub struct AuthOffer {
    pub certificate: Option<Certificate>,
    pub source: KeySource,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct AuthPlan {
    pub offers: Vec<AuthOffer>,
    pub notes: Vec<PlanNote>,
}

pub fn plan_authentication(
    identity_files: &[String],
    certificate_files: &[String],
    identities_only: bool,
    pubkey_authentication: bool,
    agent_keys: &[ListedAgentKey],
    now: u64,
) -> AuthPlan {
    if !pubkey_authentication {
        return AuthPlan {
            offers: Vec::new(),
            notes: Vec::new(),
        };
    }
    let identities = identity_files
        .iter()
        .filter(|path| path.as_str() != "none")
        .map(|path| load_identity(Path::new(path), certificate_files.is_empty(), now))
        .collect::<Vec<_>>();
    let explicit = certificate_files
        .iter()
        .filter(|path| path.as_str() != "none")
        .map(|path| load_certificate_file(Path::new(path), now))
        .collect::<Vec<_>>();

    let mut offers = Vec::new();
    let mut notes = Vec::new();
    let mut used_certs: Vec<Vec<u8>> = Vec::new();
    let mut agent_plain_used: Vec<usize> = Vec::new();

    for loaded in &explicit {
        push_certificate_offer(
            loaded,
            &identities,
            agent_keys,
            &mut offers,
            &mut notes,
            &mut used_certs,
            &mut agent_plain_used,
        );
    }

    for (index, agent) in agent_keys.iter().enumerate() {
        if !agent_key_allowed(agent, &identities, &explicit, identities_only) {
            continue;
        }
        if let Some(cert) = &agent.certificate {
            if cert_bytes(cert).is_some_and(|bytes| used_certs.iter().any(|seen| seen == &bytes)) {
                continue;
            }
            if let Err(note) = classify_user_certificate(cert, now) {
                if identities_only {
                    notes.push(note);
                }
                continue;
            }
            if let Some(bytes) = cert_bytes(cert) {
                used_certs.push(bytes);
            }
            offers.push(AuthOffer {
                certificate: Some(cert.clone()),
                source: KeySource::Agent(index),
                label: agent_label(agent),
            });
        } else {
            agent_plain_used.push(index);
            offers.push(AuthOffer {
                certificate: None,
                source: KeySource::Agent(index),
                label: agent_label(agent),
            });
        }
    }

    for identity in &identities {
        let agent_has_plain = identity.public_key.as_ref().is_some_and(|public| {
            agent_keys.iter().enumerate().any(|(index, agent)| {
                agent.certificate.is_none()
                    && agent_plain_used.contains(&index)
                    && same_key_data(agent.public_key.key_data(), public.key_data())
            })
        });
        if identity.path.is_file()
            && !agent_has_plain
            && !is_security_key(identity.public_key.as_ref())
        {
            if let Some(public) = &identity.public_key
                && is_security_key_algorithm(&public.algorithm().to_string())
            {
                notes.push(PlanNote {
                    code: "security_key_unsupported",
                    message: format!(
                        "身份文件 {} 是 FIDO/安全密钥，TunnelDesk 不能代替硬件完成用户在场验证",
                        identity.path.display()
                    ),
                });
            } else {
                offers.push(AuthOffer {
                    certificate: None,
                    source: KeySource::File(identity.path.clone()),
                    label: identity.path.display().to_string(),
                });
            }
        }
        if let Some(auto) = &identity.auto_cert {
            push_certificate_offer(
                auto,
                &identities,
                agent_keys,
                &mut offers,
                &mut notes,
                &mut used_certs,
                &mut agent_plain_used,
            );
        }
    }

    for identity in &identities {
        notes.extend(identity.notes.clone());
    }
    AuthPlan { offers, notes }
}

pub fn classify_user_certificate(cert: &Certificate, now: u64) -> Result<(), PlanNote> {
    if cert.cert_type() != CertType::User {
        return Err(PlanNote {
            code: "not_user_certificate",
            message: "这是主机证书，不能当作客户端登录证书使用".into(),
        });
    }
    if !signature_algorithm_allowed(cert) {
        return Err(PlanNote {
            code: "certificate_signature_unsupported",
            message: format!(
                "证书签名算法 {} 不受支持。不会启用 SHA-1（ssh-rsa）",
                cert.signature().algorithm()
            ),
        });
    }
    if is_security_key_algorithm(&cert.algorithm().to_string()) {
        return Err(PlanNote {
            code: "security_key_unsupported",
            message: "证书绑定了 FIDO/安全密钥。TunnelDesk 没有验证过硬件交互，已跳过".into(),
        });
    }
    if now < cert.valid_after() {
        return Err(PlanNote {
            code: "certificate_not_yet_valid",
            message: "证书尚未到生效时间".into(),
        });
    }
    if now >= cert.valid_before() {
        return Err(PlanNote {
            code: "certificate_expired",
            message: "证书已过期".into(),
        });
    }
    for name in cert.critical_options().keys() {
        match name.as_str() {
            "force-command" | "source-address" => {}
            "verify-required" => {
                return Err(PlanNote {
                    code: "verify_required_unsupported",
                    message: "证书要求 verify-required。TunnelDesk 不能完成安全密钥的用户在场验证，已跳过".into(),
                });
            }
            other => {
                return Err(PlanNote {
                    code: "critical_option_unsupported",
                    message: format!("证书包含未实现的关键选项 {other}，已跳过"),
                });
            }
        }
    }
    Ok(())
}

pub fn signature_algorithm_allowed(cert: &Certificate) -> bool {
    match cert.signature().algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } => true,
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256 | HashAlg::Sha512),
        } => true,
        Algorithm::Rsa { hash: None } | Algorithm::Dsa => false,
        Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256 => false,
        Algorithm::Other(_) => false,
        _ => false,
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

struct LoadedIdentity {
    path: PathBuf,
    public_key: Option<PublicKey>,
    auto_cert: Option<LoadedCert>,
    notes: Vec<PlanNote>,
}

struct LoadedCert {
    path: PathBuf,
    cert: Option<Certificate>,
    problem: Option<PlanNote>,
}

fn load_identity(path: &Path, allow_auto_cert: bool, now: u64) -> LoadedIdentity {
    let mut notes = Vec::new();
    let public_key = read_public_half(path);
    if public_key
        .as_ref()
        .is_some_and(|key| is_security_key_algorithm(&key.algorithm().to_string()))
    {
        notes.push(PlanNote {
            code: "security_key_unsupported",
            message: format!(
                "身份文件 {} 是 FIDO/安全密钥，TunnelDesk 不能代替硬件完成用户在场验证",
                path.display()
            ),
        });
    }
    let auto_cert = if allow_auto_cert {
        let candidate = automatic_certificate_path(path);
        if candidate.is_file() {
            Some(load_certificate_file(&candidate, now))
        } else {
            None
        }
    } else {
        None
    };
    LoadedIdentity {
        path: path.to_path_buf(),
        public_key,
        auto_cert,
        notes,
    }
}

fn automatic_certificate_path(identity: &Path) -> PathBuf {
    PathBuf::from(format!("{}-cert.pub", identity.display()))
}

fn load_certificate_file(path: &Path, now: u64) -> LoadedCert {
    if !path.is_file() {
        return LoadedCert {
            path: path.to_path_buf(),
            cert: None,
            problem: Some(PlanNote {
                code: "certificate_missing",
                message: format!("找不到证书文件 {}", path.display()),
            }),
        };
    }
    let cert = match russh::keys::load_openssh_certificate(path) {
        Ok(cert) => cert,
        Err(_) => {
            return LoadedCert {
                path: path.to_path_buf(),
                cert: None,
                problem: Some(PlanNote {
                    code: "certificate_unreadable",
                    message: format!(
                        "{} 不是 OpenSSH 证书。证书文件是公钥，不能代替私钥",
                        path.display()
                    ),
                }),
            };
        }
    };
    if let Err(note) = classify_user_certificate(&cert, now) {
        return LoadedCert {
            path: path.to_path_buf(),
            cert: Some(cert),
            problem: Some(note),
        };
    }
    LoadedCert {
        path: path.to_path_buf(),
        cert: Some(cert),
        problem: None,
    }
}

fn push_certificate_offer(
    loaded: &LoadedCert,
    identities: &[LoadedIdentity],
    agent_keys: &[ListedAgentKey],
    offers: &mut Vec<AuthOffer>,
    notes: &mut Vec<PlanNote>,
    used_certs: &mut Vec<Vec<u8>>,
    agent_plain_used: &mut Vec<usize>,
) {
    let Some(cert) = &loaded.cert else {
        if let Some(problem) = &loaded.problem {
            notes.push(problem.clone());
        }
        return;
    };
    if let Some(problem) = &loaded.problem {
        notes.push(PlanNote {
            code: problem.code,
            message: format!("{}（{}）", problem.message, loaded.path.display()),
        });
        return;
    }
    if cert_bytes(cert).is_some_and(|bytes| used_certs.iter().any(|seen| seen == &bytes)) {
        return;
    }
    match find_signers(cert, &loaded.path, identities, agent_keys) {
        SignerMatch::Found(sources) => {
            if sources.is_empty() {
                return;
            }
            if let Some(bytes) = cert_bytes(cert) {
                used_certs.push(bytes);
            }
            for source in sources {
                if let KeySource::Agent(index) = &source {
                    agent_plain_used.push(*index);
                }
                let label = match &source {
                    KeySource::File(path) => {
                        format!("{} ({})", loaded.path.display(), path.display())
                    }
                    KeySource::Agent(_) => format!("{} (agent)", loaded.path.display()),
                };
                offers.push(AuthOffer {
                    certificate: Some(cert.clone()),
                    source,
                    label,
                });
            }
        }
        SignerMatch::Mismatch { identity } => notes.push(PlanNote {
            code: "certificate_key_mismatch",
            message: format!(
                "证书 {} 与私钥 {} 的公钥不一致。证书不能代替签名私钥",
                loaded.path.display(),
                identity.display()
            ),
        }),
        SignerMatch::Missing => notes.push(PlanNote {
            code: "certificate_needs_private_key",
            message: format!(
                "证书 {} 只是公钥，需要匹配的 IdentityFile，或 agent 中已解锁的同一把密钥",
                loaded.path.display()
            ),
        }),
    }
}

enum SignerMatch {
    Found(Vec<KeySource>),
    Mismatch { identity: PathBuf },
    Missing,
}

/// Agent identities come before the on-disk private file. OpenSSH offers an
/// unlocked agent key even when the same `IdentityFile` is still present and
/// encrypted. A filename match whose public key differs is a mismatch only
/// when no agent identity can sign the certificate.
fn find_signers(
    cert: &Certificate,
    cert_path: &Path,
    identities: &[LoadedIdentity],
    agent_keys: &[ListedAgentKey],
) -> SignerMatch {
    let agent_index = agent_keys.iter().position(|agent| {
        let agent_data = agent
            .certificate
            .as_ref()
            .map(|item| item.public_key())
            .unwrap_or_else(|| agent.public_key.key_data());
        same_key_data(agent_data, cert.public_key())
    });
    let mut file = None;
    let mut mismatch = None;
    for identity in identities {
        if private_key_readable(&identity.path)
            && identity
                .public_key
                .as_ref()
                .is_some_and(|public| same_key_data(public.key_data(), cert.public_key()))
        {
            file = Some(identity.path.clone());
            break;
        }
    }
    if file.is_none() {
        for identity in identities {
            if !filename_matches(cert_path, &identity.path) {
                continue;
            }
            match &identity.public_key {
                Some(public) if !same_key_data(public.key_data(), cert.public_key()) => {
                    mismatch = Some(identity.path.clone());
                }
                _ if private_key_readable(&identity.path) => {
                    file = Some(identity.path.clone());
                    break;
                }
                _ => {}
            }
        }
    }
    let mut sources = Vec::new();
    if let Some(index) = agent_index {
        sources.push(KeySource::Agent(index));
    }
    if let Some(path) = file {
        sources.push(KeySource::File(path));
    }
    if !sources.is_empty() {
        return SignerMatch::Found(sources);
    }
    if let Some(identity) = mismatch {
        SignerMatch::Mismatch { identity }
    } else {
        SignerMatch::Missing
    }
}

fn private_key_readable(path: &Path) -> bool {
    std::fs::File::open(path).is_ok()
}

fn filename_matches(cert_path: &Path, identity: &Path) -> bool {
    let cert = cert_path.to_string_lossy();
    let private = identity.to_string_lossy();
    if cert == private {
        return true;
    }
    cert == format!("{private}.pub") || cert == format!("{private}-cert.pub")
}

fn agent_key_allowed(
    agent: &ListedAgentKey,
    identities: &[LoadedIdentity],
    explicit: &[LoadedCert],
    identities_only: bool,
) -> bool {
    if !identities_only {
        return true;
    }
    let data = agent
        .certificate
        .as_ref()
        .map(|cert| cert.public_key())
        .unwrap_or_else(|| agent.public_key.key_data());
    if identities.iter().any(|identity| {
        identity
            .public_key
            .as_ref()
            .is_some_and(|public| same_key_data(public.key_data(), data))
            || identity.auto_cert.as_ref().is_some_and(|loaded| {
                loaded
                    .cert
                    .as_ref()
                    .is_some_and(|cert| same_key_data(cert.public_key(), data))
            })
    }) {
        return true;
    }
    explicit.iter().any(|loaded| {
        loaded
            .cert
            .as_ref()
            .is_some_and(|cert| same_key_data(cert.public_key(), data))
    })
}

fn agent_label(agent: &ListedAgentKey) -> String {
    if agent.comment.is_empty() {
        "agent".into()
    } else {
        format!("agent:{}", agent.comment)
    }
}

fn same_key_data(
    left: &russh::keys::ssh_key::public::KeyData,
    right: &russh::keys::ssh_key::public::KeyData,
) -> bool {
    left == right
}

fn cert_bytes(cert: &Certificate) -> Option<Vec<u8>> {
    cert.to_bytes().ok()
}

fn is_security_key(key: Option<&PublicKey>) -> bool {
    key.is_some_and(|key| is_security_key_algorithm(&key.algorithm().to_string()))
}

fn is_security_key_algorithm(algorithm: &str) -> bool {
    algorithm.starts_with("sk-")
}

fn read_public_half(path: &Path) -> Option<PublicKey> {
    let pub_path = format!("{}.pub", path.display());
    if let Ok(text) = std::fs::read_to_string(&pub_path) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(key) = PublicKey::from_openssh(line) {
                return Some(key);
            }
        }
    }
    PrivateKey::from_openssh(std::fs::read_to_string(path).ok()?)
        .ok()
        .map(|key| key.public_key().clone())
        .or_else(|| {
            russh::keys::load_secret_key(path, None)
                .ok()
                .map(|key| key.public_key().clone())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn key(algorithm: Algorithm) -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), algorithm).unwrap()
    }

    fn sign(
        ca: &PrivateKey,
        subject: &PrivateKey,
        kind: CertType,
        principal: Option<&str>,
        after: u64,
        before: u64,
        critical: Option<(&str, &str)>,
    ) -> Certificate {
        let mut builder =
            Builder::new_with_random_nonce(&mut rand::rng(), subject.public_key(), after, before)
                .unwrap();
        builder.cert_type(kind).unwrap();
        builder.key_id("fixture").unwrap();
        if let Some(principal) = principal {
            builder.valid_principal(principal).unwrap();
        } else {
            builder.all_principals_valid().unwrap();
        }
        if let Some((name, value)) = critical {
            builder.critical_option(name, value).unwrap();
        }
        builder.sign(ca).unwrap()
    }

    fn write_private(path: &Path, private: &PrivateKey) {
        private
            .write_openssh_file(path, russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        std::fs::write(
            format!("{}.pub", path.display()),
            private.public_key().to_openssh().unwrap(),
        )
        .unwrap();
    }

    fn write_cert(path: &Path, cert: &Certificate) {
        std::fs::write(path, cert.to_openssh().unwrap()).unwrap();
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn explicit_certificate_is_offered_before_the_plain_key_and_pairs_by_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let ca = key(Algorithm::Ed25519);
        let user = key(Algorithm::Ed25519);
        let other = key(Algorithm::Ed25519);
        let stamp = now();
        let cert = sign(
            &ca,
            &user,
            CertType::User,
            Some("ops"),
            stamp.saturating_sub(60),
            stamp + 3600,
            None,
        );
        let identity = dir.path().join("id_ed25519");
        let other_path = dir.path().join("other");
        let cert_path = dir.path().join("ops-cert.pub");
        write_private(&identity, &user);
        write_private(&other_path, &other);
        write_cert(&cert_path, &cert);
        let plan = plan_authentication(
            &[
                other_path.display().to_string(),
                identity.display().to_string(),
            ],
            &[cert_path.display().to_string()],
            true,
            true,
            &[],
            stamp,
        );
        assert!(plan.notes.is_empty(), "{:?}", plan.notes);
        assert!(plan.offers[0].certificate.is_some());
        assert!(matches!(&plan.offers[0].source, KeySource::File(path) if path == &identity));
        assert!(plan.offers.iter().any(|offer| offer.certificate.is_none()));
    }

    #[test]
    fn automatic_certificate_is_used_only_when_no_certificate_file_is_configured() {
        let dir = tempfile::tempdir().unwrap();
        let ca = key(Algorithm::Ed25519);
        let user = key(Algorithm::Ed25519);
        let stamp = now();
        let cert = sign(
            &ca,
            &user,
            CertType::User,
            Some("ops"),
            stamp.saturating_sub(60),
            stamp + 3600,
            None,
        );
        let identity = dir.path().join("id_ed25519");
        write_private(&identity, &user);
        write_cert(&automatic_certificate_path(&identity), &cert);
        let auto = plan_authentication(
            &[identity.display().to_string()],
            &[],
            true,
            true,
            &[],
            stamp,
        );
        assert!(auto.offers.iter().any(|offer| offer.certificate.is_some()));
        let explicit_other = dir.path().join("explicit-cert.pub");
        let other = key(Algorithm::Ed25519);
        let other_identity = dir.path().join("explicit");
        write_private(&other_identity, &other);
        write_cert(
            &explicit_other,
            &sign(
                &ca,
                &other,
                CertType::User,
                Some("ops"),
                stamp.saturating_sub(60),
                stamp + 3600,
                None,
            ),
        );
        let suppressed = plan_authentication(
            &[
                identity.display().to_string(),
                other_identity.display().to_string(),
            ],
            &[explicit_other.display().to_string()],
            false,
            true,
            &[],
            stamp,
        );
        let identity_label = identity.display().to_string();
        assert!(
            suppressed
                .offers
                .iter()
                .filter(|offer| offer.certificate.is_some())
                .all(|offer| !offer.label.contains(&identity_label))
        );
    }

    #[test]
    fn mismatched_and_missing_certificates_are_reported_and_not_offered() {
        let dir = tempfile::tempdir().unwrap();
        let ca = key(Algorithm::Ed25519);
        let user = key(Algorithm::Ed25519);
        let other = key(Algorithm::Ed25519);
        let stamp = now();
        let cert = sign(
            &ca,
            &user,
            CertType::User,
            Some("ops"),
            stamp.saturating_sub(60),
            stamp + 3600,
            None,
        );
        let identity = dir.path().join("id_ed25519");
        let cert_path = automatic_certificate_path(&identity);
        write_private(&identity, &other);
        write_cert(&cert_path, &cert);
        let mismatched = plan_authentication(
            &[identity.display().to_string()],
            &[cert_path.display().to_string()],
            true,
            true,
            &[],
            stamp,
        );
        assert!(
            mismatched
                .offers
                .iter()
                .all(|offer| offer.certificate.is_none())
        );
        assert!(
            mismatched
                .notes
                .iter()
                .any(|note| note.code == "certificate_key_mismatch")
        );

        let alone = dir.path().join("alone-cert.pub");
        write_cert(&alone, &cert);
        let missing =
            plan_authentication(&[], &[alone.display().to_string()], true, true, &[], stamp);
        assert!(missing.offers.is_empty());
        assert_eq!(missing.notes[0].code, "certificate_needs_private_key");

        std::fs::write(
            dir.path().join("not-a-cert.pub"),
            "ssh-ed25519 not-a-cert\n",
        )
        .unwrap();
        let unreadable = plan_authentication(
            &[],
            &[dir.path().join("not-a-cert.pub").display().to_string()],
            true,
            true,
            &[],
            stamp,
        );
        assert_eq!(unreadable.notes[0].code, "certificate_unreadable");
    }

    #[test]
    fn expired_future_host_and_critical_options_follow_openssh_client_rules() {
        let ca = key(Algorithm::Ed25519);
        let user = key(Algorithm::Ed25519);
        let stamp = now();
        let expired = sign(
            &ca,
            &user,
            CertType::User,
            Some("ops"),
            stamp.saturating_sub(7200),
            stamp.saturating_sub(60),
            None,
        );
        assert_eq!(
            classify_user_certificate(&expired, stamp).unwrap_err().code,
            "certificate_expired"
        );
        let future = sign(
            &ca,
            &user,
            CertType::User,
            Some("ops"),
            stamp + 3600,
            stamp + 7200,
            None,
        );
        assert_eq!(
            classify_user_certificate(&future, stamp).unwrap_err().code,
            "certificate_not_yet_valid"
        );
        let host = sign(
            &ca,
            &user,
            CertType::Host,
            Some("127.0.0.1"),
            stamp.saturating_sub(60),
            stamp + 3600,
            None,
        );
        assert_eq!(
            classify_user_certificate(&host, stamp).unwrap_err().code,
            "not_user_certificate"
        );
        let verify = sign(
            &ca,
            &user,
            CertType::User,
            Some("ops"),
            stamp.saturating_sub(60),
            stamp + 3600,
            Some(("verify-required", "")),
        );
        assert_eq!(
            classify_user_certificate(&verify, stamp).unwrap_err().code,
            "verify_required_unsupported"
        );
        let source = sign(
            &ca,
            &user,
            CertType::User,
            Some("ops"),
            stamp.saturating_sub(60),
            stamp + 3600,
            Some(("source-address", "10.0.0.0/8")),
        );
        assert!(classify_user_certificate(&source, stamp).is_ok());
        let unknown = sign(
            &ca,
            &user,
            CertType::User,
            Some("ops"),
            stamp.saturating_sub(60),
            stamp + 3600,
            Some(("mystery-option", "1")),
        );
        assert_eq!(
            classify_user_certificate(&unknown, stamp).unwrap_err().code,
            "critical_option_unsupported"
        );
    }

    #[test]
    fn identities_only_drops_unrelated_agent_keys_and_keeps_a_matching_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let ca = key(Algorithm::Ed25519);
        let user = key(Algorithm::Ed25519);
        let extra = key(Algorithm::Ed25519);
        let stamp = now();
        let cert = sign(
            &ca,
            &user,
            CertType::User,
            Some("ops"),
            stamp.saturating_sub(60),
            stamp + 3600,
            None,
        );
        let identity = dir.path().join("id_ed25519");
        write_private(&identity, &user);
        std::fs::remove_file(&identity).unwrap();
        let cert_path = dir.path().join("id_ed25519-cert.pub");
        write_cert(&cert_path, &cert);
        let agent = vec![
            ListedAgentKey {
                public_key: extra.public_key().clone(),
                certificate: None,
                comment: "extra".into(),
            },
            ListedAgentKey {
                public_key: user.public_key().clone(),
                certificate: Some(cert),
                comment: "user-cert".into(),
            },
        ];
        let plan = plan_authentication(
            &[identity.display().to_string()],
            &[cert_path.display().to_string()],
            true,
            true,
            &agent,
            stamp,
        );
        assert!(plan.notes.is_empty(), "{:?}", plan.notes);
        assert_eq!(plan.offers.len(), 1);
        assert!(plan.offers[0].certificate.is_some());
        assert!(matches!(plan.offers[0].source, KeySource::Agent(1)));

        let open = plan_authentication(&[], &[], false, true, &agent, stamp);
        assert!(open.offers.len() >= 2);
        let closed = plan_authentication(
            &[identity.display().to_string()],
            &[],
            true,
            true,
            &agent,
            stamp,
        );
        assert!(
            closed
                .offers
                .iter()
                .all(|offer| !offer.label.contains("extra"))
        );
    }

    #[test]
    fn unlocked_agent_key_signs_before_the_local_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let ca = key(Algorithm::Ed25519);
        let user = key(Algorithm::Ed25519);
        let other = key(Algorithm::Ed25519);
        let stamp = now();
        let cert = sign(
            &ca,
            &user,
            CertType::User,
            Some("ops"),
            stamp.saturating_sub(60),
            stamp + 3600,
            None,
        );
        let identity = dir.path().join("id_ed25519");
        write_private(&identity, &user);
        let cert_path = dir.path().join("id_ed25519-cert.pub");
        write_cert(&cert_path, &cert);
        let agent = vec![ListedAgentKey {
            public_key: user.public_key().clone(),
            certificate: None,
            comment: "plain".into(),
        }];
        let plan = plan_authentication(
            &[identity.display().to_string()],
            &[cert_path.display().to_string()],
            true,
            true,
            &agent,
            stamp,
        );
        assert!(plan.offers.len() >= 2, "{:?}", plan.offers);
        assert!(plan.offers[0].certificate.is_some());
        assert!(matches!(plan.offers[0].source, KeySource::Agent(0)));
        assert!(matches!(plan.offers[1].source, KeySource::File(_)));
        assert!(plan.offers[1].certificate.is_some());

        let unrelated = vec![ListedAgentKey {
            public_key: other.public_key().clone(),
            certificate: None,
            comment: "other".into(),
        }];
        let blocked = plan_authentication(
            &[identity.display().to_string()],
            &[cert_path.display().to_string()],
            true,
            true,
            &unrelated,
            stamp,
        );
        assert!(
            blocked
                .offers
                .iter()
                .any(|offer| matches!(offer.source, KeySource::File(_)))
        );
        assert!(
            blocked
                .offers
                .iter()
                .all(|offer| !matches!(offer.source, KeySource::Agent(_)))
        );

        write_private(&identity, &other);
        let mismatch = plan_authentication(
            &[identity.display().to_string()],
            &[cert_path.display().to_string()],
            true,
            true,
            &unrelated,
            stamp,
        );
        assert!(
            mismatch
                .offers
                .iter()
                .all(|offer| offer.certificate.is_none())
        );
        assert!(
            mismatch
                .notes
                .iter()
                .any(|note| note.code == "certificate_key_mismatch")
        );
        let none = plan_authentication(
            &[identity.display().to_string()],
            &[cert_path.display().to_string()],
            true,
            true,
            &[],
            stamp,
        );
        assert!(
            none.notes
                .iter()
                .any(|note| note.code == "certificate_key_mismatch")
        );
        assert!(none.offers.iter().all(|offer| offer.certificate.is_none()));
    }

    #[test]
    fn pubkey_authentication_no_offers_nothing() {
        let plan = plan_authentication(&["/tmp/id".into()], &[], false, false, &[], now());
        assert!(plan.offers.is_empty());
    }

    #[test]
    fn sha1_certificate_signature_is_rejected() {
        let cert_alg = Algorithm::Rsa { hash: None };
        assert!(!matches!(
            cert_alg,
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256 | HashAlg::Sha512)
            }
        ));
        assert!(signature_algorithm_allowed(&sign(
            &key(Algorithm::Ed25519),
            &key(Algorithm::Ed25519),
            CertType::User,
            Some("ops"),
            now().saturating_sub(10),
            now() + 60,
            None,
        )));
    }
}
