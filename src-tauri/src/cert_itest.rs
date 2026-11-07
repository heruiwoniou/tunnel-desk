//! Disposable OpenSSH certificate fixtures. Nothing here reads the user's
//! `~/.ssh`, agent socket, or real keys. Every secret is generated at runtime.

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

use crate::config::Resolver;
use crate::error::AppError;
use crate::model::{AuthMode, Direction, ForwardMapping, Profile, Target, now_rfc3339};
use crate::secrets::{SecretBackendStatus, SecretStore};
use crate::store::AppStore;
use crate::tunnel::{FixedPrompter, TunnelManager};

struct MemStore {
    values: Mutex<std::collections::BTreeMap<String, String>>,
}

impl SecretStore for MemStore {
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
            .expect("secrets")
            .get(account)
            .cloned()
            .map(Zeroizing::new))
    }
    fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
        self.values
            .lock()
            .expect("secrets")
            .insert(account.into(), secret.into());
        Ok(())
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.values.lock().expect("secrets").remove(account);
        Ok(())
    }
}

struct Server {
    user: String,
    port: u16,
    password: String,
    log: PathBuf,
    pid: PathBuf,
    child: Option<std::process::Child>,
    files: Option<tempfile::TempDir>,
}

impl Server {
    fn log_text(&self) -> String {
        Command::new("sudo")
            .args(["-n", "cat", self.log.to_str().unwrap_or_default()])
            .output()
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Ok(text) = std::fs::read_to_string(&self.pid) {
            if let Ok(pid) = text.trim().parse::<i32>() {
                let _ = Command::new("sudo")
                    .args(["-n", "kill", &pid.to_string()])
                    .status();
            }
        }
        let _ = Command::new("sudo")
            .args(["-n", "userdel", "-r", &self.user])
            .status();
        self.files.take();
    }
}

struct Agent {
    sock: PathBuf,
    child: Option<std::process::Child>,
}

impl Drop for Agent {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn openssh_available() -> bool {
    Path::new("/usr/sbin/sshd").is_file()
        && Path::new("/usr/sbin/useradd").is_file()
        && Command::new("sudo")
            .args(["-n", "true"])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
}

fn token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn sudo_ok(args: &[&str]) {
    let status = Command::new("sudo").arg("-n").args(args).status().unwrap();
    assert!(status.success(), "sudo {args:?}");
}

fn ssh_keygen(args: &[&str]) {
    let status = Command::new("ssh-keygen").args(args).status().unwrap();
    assert!(status.success(), "ssh-keygen {args:?}");
}

fn start_server(user_ca: Option<&Path>, principals: Option<&str>, password_auth: bool) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let user = format!("td{}", &token()[..8]);
    let password = format!("pw-{}", token());
    let port = free_port();
    let host_key = dir.path().join("host_ed25519");
    let host_cert = dir.path().join("host_ed25519-cert.pub");
    let log = dir.path().join("sshd.log");
    let pid = dir.path().join("sshd.pid");
    let home = dir.path().join("home");
    let config = dir.path().join("sshd_config");
    let auth = home.join(".ssh/authorized_keys");
    let principals_file = dir.path().join("principals");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        host_key.to_str().unwrap(),
        "-N",
        "",
    ]);
    let host_ca = dir.path().join("host_ca");
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        host_ca.to_str().unwrap(),
        "-N",
        "",
    ]);
    ssh_keygen(&[
        "-q",
        "-s",
        host_ca.to_str().unwrap(),
        "-I",
        "host",
        "-h",
        "-n",
        "127.0.0.1",
        "-V",
        "-1d:+1d",
        &format!("{}.pub", host_key.display()),
    ]);
    sudo_ok(&[
        "useradd",
        "-M",
        "-d",
        home.to_str().unwrap(),
        "-s",
        "/bin/bash",
        &user,
    ]);
    let mut chpasswd = Command::new("sudo")
        .args(["-n", "chpasswd"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(chpasswd.stdin.take().unwrap(), "{user}:{password}").unwrap();
    assert!(chpasswd.wait().unwrap().success());
    std::fs::write(&auth, "").unwrap();
    if let Some(principals) = principals {
        std::fs::write(&principals_file, format!("{principals}\n")).unwrap();
    }
    sudo_ok(&[
        "chown",
        "-R",
        &format!("{user}:{user}"),
        home.to_str().unwrap(),
    ]);
    let trusted = user_ca
        .map(|path| {
            let public = if path.extension().and_then(|ext| ext.to_str()) == Some("pub") {
                path.to_path_buf()
            } else {
                PathBuf::from(format!("{}.pub", path.display()))
            };
            format!("TrustedUserCAKeys {}\n", public.display())
        })
        .unwrap_or_default();
    let principal_line = principals
        .map(|_| format!("AuthorizedPrincipalsFile {}\n", principals_file.display()))
        .unwrap_or_default();
    std::fs::write(
        &config,
        format!(
            "\
Port {port}
ListenAddress 127.0.0.1
HostKey {host}
HostCertificate {host_cert}
PidFile {pid}
AuthorizedKeysFile {auth}
{trusted}{principal_line}PasswordAuthentication {password}
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM yes
AllowTcpForwarding yes
GatewayPorts no
PermitRootLogin no
AllowUsers {user}
StrictModes no
PrintMotd no
UseDNS no
LogLevel INFO
",
            host = host_key.display(),
            host_cert = host_cert.display(),
            pid = pid.display(),
            auth = auth.display(),
            password = if password_auth { "yes" } else { "no" },
        ),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("host_ca.pub"),
        std::fs::read(host_ca.with_extension("pub")).unwrap(),
    )
    .unwrap();
    sudo_ok(&["mkdir", "-p", "/run/sshd"]);
    sudo_ok(&["chmod", "0755", "/run/sshd"]);
    let child = Command::new("sudo")
        .args([
            "-n",
            "/usr/sbin/sshd",
            "-f",
            config.to_str().unwrap(),
            "-E",
            log.to_str().unwrap(),
            "-D",
        ])
        .spawn()
        .unwrap();
    let server = Server {
        user,
        port,
        password,
        log: log.clone(),
        pid: pid.clone(),
        child: Some(child),
        files: Some(dir),
    };
    for _ in 0..50 {
        if std::net::TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], server.port)),
            Duration::from_millis(80),
        )
        .is_ok()
        {
            return server;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    panic!("sshd did not start: {}", server.log_text());
}

fn read_pub(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn sign_user(ca: &Path, public_key: &Path, principal: &str, validity: &str) {
    ssh_keygen(&[
        "-q",
        "-s",
        ca.to_str().unwrap(),
        "-I",
        "user",
        "-n",
        principal,
        "-V",
        validity,
        public_key.to_str().unwrap(),
    ]);
}

fn resolver(dir: &Path, body: &str) -> Resolver {
    let config = dir.join("ssh-config");
    std::fs::write(&config, body).unwrap();
    Resolver {
        user_config: config,
        system_config: None,
        ssh_binary: which_ssh(),
        home: dir.to_path_buf(),
        local_user: "fixture".into(),
        local_host: "fixture".into(),
    }
}

fn which_ssh() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|entry| entry.join("ssh"))
            .find(|candidate| candidate.is_file())
    })
}

fn profile(id: &str, alias: &str, mode: AuthMode, forwards: Vec<ForwardMapping>) -> Profile {
    let forwards = if forwards.is_empty() {
        vec![mapping(Direction::Local, free_port(), free_port())]
    } else {
        forwards
    };
    Profile {
        id: id.into(),
        name: "证书测试".into(),
        target: Target::ConfigAlias {
            alias: alias.into(),
        },
        auth_mode: mode,
        remember_password: false,
        forwards,
        created_at: now_rfc3339(),
        updated_at: now_rfc3339(),
    }
}

fn mapping(direction: Direction, listen: u16, destination: u16) -> ForwardMapping {
    ForwardMapping {
        id: uuid::Uuid::new_v4().to_string(),
        direction,
        listen_host: "127.0.0.1".into(),
        listen_port: listen,
        destination_host: "127.0.0.1".into(),
        destination_port: destination,
        allow_external: false,
    }
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                if let Ok(size) = socket.read(&mut buffer).await {
                    let _ = socket.write_all(&buffer[..size]).await;
                }
            });
        }
    });
    addr
}

async fn exchange(addr: SocketAddr, payload: &[u8]) {
    let mut socket = TcpStream::connect(addr).await.unwrap();
    socket.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    socket.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);
}

fn manager(dir: &Path, config: &str) -> TunnelManager {
    TunnelManager::new(
        AppStore::open(dir).unwrap(),
        Arc::new(MemStore {
            values: Mutex::new(std::collections::BTreeMap::new()),
        }),
        resolver(dir, config),
    )
}

fn known_ca(port: u16, ca_pub: &str) -> String {
    format!("@cert-authority [127.0.0.1]:{port} {ca_pub}")
}

#[tokio::test]
async fn explicit_and_automatic_certificates_forward_and_trust_the_host_ca() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("user_ca");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", ca.to_str().unwrap(), "-N", ""]);
    let server = start_server(Some(&ca), Some("ops-team"), false);
    let echo = echo_server().await;
    let key = dir.path().join("id_ed25519");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", key.to_str().unwrap(), "-N", ""]);
    sign_user(&ca, &key.with_extension("pub"), "ops-team", "-1d:+1d");
    let cert = dir.path().join("id_ed25519-cert.pub");
    assert!(cert.is_file());
    let host_ca_pub = read_pub(&server_host_ca_pub(&server));
    let known = dir.path().join("known_hosts");
    std::fs::write(&known, known_ca(server.port, host_ca_pub.trim())).unwrap();
    let config = format!(
        "\
Host explicit
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {cert}
  IdentitiesOnly yes
  IdentityAgent none
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
Host automatic
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  IdentitiesOnly yes
  IdentityAgent none
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        port = server.port,
        user = server.user,
        key = key.display(),
        cert = cert.display(),
        known = known.display(),
    );
    let app = manager(dir.path(), &config);
    let local = free_port();
    app.store()
        .save_profiles(&[profile(
            "explicit",
            "explicit",
            AuthMode::PublicKey,
            vec![mapping(Direction::Local, local, echo.port())],
        )])
        .unwrap();
    app.connect(
        "explicit",
        None,
        None,
        false,
        false,
        Arc::new(FixedPrompter(false)),
    )
    .await
    .unwrap_or_else(|err| panic!("explicit certificate: {err}\n{}", server.log_text()));
    exchange(SocketAddr::from(([127, 0, 0, 1], local)), b"explicit-cert").await;
    app.disconnect("explicit").await.unwrap();

    let remote = free_port();
    let mut profiles = app.store().load_profiles().unwrap();
    profiles.push(profile(
        "automatic",
        "automatic",
        AuthMode::PublicKey,
        vec![mapping(Direction::Remote, remote, echo.port())],
    ));
    app.store().save_profiles(&profiles).unwrap();
    app.connect(
        "automatic",
        None,
        None,
        false,
        false,
        Arc::new(FixedPrompter(false)),
    )
    .await
    .expect("automatic -cert.pub");
    exchange(SocketAddr::from(([127, 0, 0, 1], remote)), b"auto-cert").await;
    app.disconnect_all().await.unwrap();
    assert!(
        server.log_text().contains("Accepted publickey"),
        "server did not accept a certificate: {}",
        server.log_text()
    );
}

fn server_host_ca_pub(server: &Server) -> PathBuf {
    server.log.parent().unwrap().join("host_ca.pub")
}

#[tokio::test]
async fn encrypted_certificate_key_uses_the_passphrase_not_the_login_password() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("user_ca");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", ca.to_str().unwrap(), "-N", ""]);
    let server = start_server(Some(&ca), Some("ops-team"), true);
    let key = dir.path().join("id_ed25519");
    let passphrase = "td-fixture-passphrase";
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        key.to_str().unwrap(),
        "-N",
        passphrase,
    ]);
    sign_user(&ca, &key.with_extension("pub"), "ops-team", "-1d:+1d");
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        known_ca(server.port, read_pub(&server_host_ca_pub(&server)).trim()),
    )
    .unwrap();
    let config = format!(
        "\
Host locked
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {key}-cert.pub
  IdentitiesOnly yes
  IdentityAgent none
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        port = server.port,
        user = server.user,
        key = key.display(),
        known = known.display(),
    );
    let app = manager(dir.path(), &config);
    app.store()
        .save_profiles(&[profile("locked", "locked", AuthMode::Auto, vec![])])
        .unwrap();
    let missing = app
        .connect(
            "locked",
            Some(Zeroizing::new(server.password.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect_err("missing passphrase");
    assert_eq!(missing.code, "passphrase_required");
    assert!(!missing.message.contains(&server.password));
    let wrong = app
        .connect_challenge_response(
            "locked",
            &missing,
            None,
            Some(Zeroizing::new(server.password.clone())),
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect_err("login password is not the key passphrase");
    assert_eq!(wrong.code, "passphrase_rejected");
    app.connect_challenge_response(
        "locked",
        &wrong,
        None,
        Some(Zeroizing::new(passphrase.into())),
        false,
        false,
        Arc::new(FixedPrompter(false)),
    )
    .await
    .expect("passphrase unlocks the certified key");
    app.disconnect_all().await.unwrap();
}

#[tokio::test]
async fn agent_certificate_works_without_the_private_file_and_identities_only_holds() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("user_ca");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", ca.to_str().unwrap(), "-N", ""]);
    let server = start_server(Some(&ca), Some("ops-team"), false);
    let key = dir.path().join("id_ed25519");
    let other = dir.path().join("other_ed25519");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", key.to_str().unwrap(), "-N", ""]);
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        other.to_str().unwrap(),
        "-N",
        "",
    ]);
    sign_user(&ca, &key.with_extension("pub"), "ops-team", "-1d:+1d");
    let sock = dir.path().join("agent.sock");
    let agent = Agent {
        child: Some(
            Command::new("ssh-agent")
                .args(["-D", "-a", sock.to_str().unwrap()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ),
        sock: sock.clone(),
    };
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    for path in [&key, &other] {
        let status = Command::new("ssh-add")
            .env("SSH_AUTH_SOCK", &sock)
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "ssh-add");
    }
    let mut perms = std::fs::metadata(&key).unwrap().permissions();
    perms.set_readonly(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0);
    }
    std::fs::set_permissions(&key, perms).unwrap();
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        known_ca(server.port, read_pub(&server_host_ca_pub(&server)).trim()),
    )
    .unwrap();
    let config = format!(
        "\
Host agentcert
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {key}-cert.pub
  IdentitiesOnly yes
  IdentityAgent {sock}
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        port = server.port,
        user = server.user,
        key = key.display(),
        sock = sock.display(),
        known = known.display(),
    );
    let app = manager(dir.path(), &config);
    app.store()
        .save_profiles(&[profile("agentcert", "agentcert", AuthMode::Agent, vec![])])
        .unwrap();
    app.connect(
        "agentcert",
        None,
        None,
        false,
        false,
        Arc::new(FixedPrompter(false)),
    )
    .await
    .expect("agent holds the certified key");
    app.disconnect_all().await.unwrap();
    drop(agent);

    let only_other = dir.path().join("authorized");
    std::fs::write(&only_other, read_pub(&other.with_extension("pub"))).unwrap();
    let restricted = start_authorized_server(&only_other);
    let known_raw = dir.path().join("known_raw");
    std::fs::write(&known_raw, restricted.public_line()).unwrap();
    let sock = dir.path().join("agent2.sock");
    let agent = Agent {
        child: Some(
            Command::new("ssh-agent")
                .args(["-D", "-a", sock.to_str().unwrap()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ),
        sock: sock.clone(),
    };
    std::thread::sleep(Duration::from_millis(100));
    for path in [&key, &other] {
        if path == &key {
            let mut perms = std::fs::metadata(path).unwrap().permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                perms.set_mode(0o600);
            }
            std::fs::set_permissions(path, perms).unwrap();
        }
        assert!(
            Command::new("ssh-add")
                .env("SSH_AUTH_SOCK", &sock)
                .arg(path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }
    let config = format!(
        "\
Host restricted
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  IdentitiesOnly yes
  IdentityAgent {sock}
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        port = restricted.port,
        user = restricted.user,
        key = key.display(),
        sock = sock.display(),
        known = known_raw.display(),
    );
    let app = manager(dir.path(), &config);
    app.store()
        .save_profiles(&[profile("restricted", "restricted", AuthMode::Agent, vec![])])
        .unwrap();
    let err = app
        .connect(
            "restricted",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect_err("unrelated agent key must not be offered");
    assert_ne!(err.code, "password_required");
    drop(agent);
    drop(restricted);
}

fn start_authorized_server(authorized: &Path) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let user = format!("td{}", &token()[..8]);
    let password = format!("pw-{}", token());
    let port = free_port();
    let host_key = dir.path().join("host_ed25519");
    let log = dir.path().join("sshd.log");
    let pid = dir.path().join("sshd.pid");
    let home = dir.path().join("home");
    let config = dir.path().join("sshd_config");
    let auth = home.join(".ssh/authorized_keys");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        host_key.to_str().unwrap(),
        "-N",
        "",
    ]);
    sudo_ok(&[
        "useradd",
        "-M",
        "-d",
        home.to_str().unwrap(),
        "-s",
        "/bin/bash",
        &user,
    ]);
    let mut chpasswd = Command::new("sudo")
        .args(["-n", "chpasswd"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(chpasswd.stdin.take().unwrap(), "{user}:{password}").unwrap();
    assert!(chpasswd.wait().unwrap().success());
    std::fs::copy(authorized, &auth).unwrap();
    sudo_ok(&[
        "chown",
        "-R",
        &format!("{user}:{user}"),
        home.to_str().unwrap(),
    ]);
    std::fs::write(
        &config,
        format!(
            "\
Port {port}
ListenAddress 127.0.0.1
HostKey {host}
PidFile {pid}
AuthorizedKeysFile {auth}
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM yes
AllowTcpForwarding yes
PermitRootLogin no
AllowUsers {user}
StrictModes no
UseDNS no
",
            host = host_key.display(),
            pid = pid.display(),
            auth = auth.display(),
        ),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("host.pub"),
        Command::new("ssh-keygen")
            .args(["-y", "-f", host_key.to_str().unwrap()])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let child = Command::new("sudo")
        .args([
            "-n",
            "/usr/sbin/sshd",
            "-f",
            config.to_str().unwrap(),
            "-E",
            log.to_str().unwrap(),
            "-D",
        ])
        .spawn()
        .unwrap();
    let server = Server {
        user,
        port,
        password,
        log,
        pid,
        child: Some(child),
        files: Some(dir),
    };
    for _ in 0..50 {
        if std::net::TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], server.port)),
            Duration::from_millis(80),
        )
        .is_ok()
        {
            return server;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    panic!("authorized sshd did not start: {}", server.log_text());
}

impl Server {
    fn public_line(&self) -> String {
        let pub_path = self.log.parent().unwrap().join("host.pub");
        if pub_path.is_file() {
            return format!("[127.0.0.1]:{} {}", self.port, read_pub(&pub_path).trim());
        }
        format!(
            "[127.0.0.1]:{} {}",
            self.port,
            read_pub(&self.log.parent().unwrap().join("host_ed25519.pub")).trim()
        )
    }
}

#[tokio::test]
async fn bad_certificates_stay_certificate_errors() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("user_ca");
    let wrong = dir.path().join("wrong_ca");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", ca.to_str().unwrap(), "-N", ""]);
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        wrong.to_str().unwrap(),
        "-N",
        "",
    ]);
    let server = start_server(Some(&ca), Some("ops-team"), true);
    let key = dir.path().join("id_ed25519");
    let other = dir.path().join("other");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", key.to_str().unwrap(), "-N", ""]);
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        other.to_str().unwrap(),
        "-N",
        "",
    ]);
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        known_ca(server.port, read_pub(&server_host_ca_pub(&server)).trim()),
    )
    .unwrap();
    let cases = [
        (
            "expired",
            "-5d:-1d",
            "ops-team",
            &key,
            "certificate_expired",
        ),
        (
            "future",
            "+1d:+2d",
            "ops-team",
            &key,
            "certificate_not_yet_valid",
        ),
        (
            "wrong-principal",
            "-1d:+1d",
            "someone-else",
            &key,
            "auth_failed",
        ),
        ("wrong-ca", "-1d:+1d", "ops-team", &key, "auth_failed"),
    ];
    for (name, validity, principal, subject, code) in cases {
        let signer = if name == "wrong-ca" { &wrong } else { &ca };
        let cert = dir.path().join(format!("{name}-cert.pub"));
        ssh_keygen(&[
            "-q",
            "-s",
            signer.to_str().unwrap(),
            "-I",
            name,
            "-n",
            principal,
            "-V",
            validity,
            subject.with_extension("pub").to_str().unwrap(),
        ]);
        let actual = PathBuf::from(format!("{}-cert.pub", subject.display()));
        if actual != cert {
            std::fs::copy(&actual, &cert).unwrap();
        }
        let config = format!(
            "\
Host {name}
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {subject}
  CertificateFile {cert}
  IdentitiesOnly yes
  IdentityAgent none
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
            port = server.port,
            user = server.user,
            subject = subject.display(),
            cert = cert.display(),
            known = known.display(),
        );
        let app = manager(dir.path(), &config);
        app.store()
            .save_profiles(&[profile(name, name, AuthMode::Auto, vec![])])
            .unwrap();
        let err = app
            .connect(
                name,
                Some(Zeroizing::new(server.password.clone())),
                None,
                false,
                false,
                Arc::new(FixedPrompter(false)),
            )
            .await
            .expect_err(name);
        assert_eq!(err.code, code, "{name}: {}", err.message);
        assert!(!err.message.contains(&server.password));
    }
    let mismatch_cert = PathBuf::from(format!("{}-cert.pub", key.display()));
    sign_user(&ca, &other.with_extension("pub"), "ops-team", "-1d:+1d");
    std::fs::copy(
        PathBuf::from(format!("{}-cert.pub", other.display())),
        &mismatch_cert,
    )
    .unwrap();
    let config = format!(
        "\
Host mismatch
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {cert}
  IdentitiesOnly yes
  IdentityAgent none
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        port = server.port,
        user = server.user,
        key = key.display(),
        cert = mismatch_cert.display(),
        known = known.display(),
    );
    let app = manager(dir.path(), &config);
    app.store()
        .save_profiles(&[profile("mismatch", "mismatch", AuthMode::Auto, vec![])])
        .unwrap();
    let err = app
        .connect(
            "mismatch",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect_err("mismatch");
    assert_eq!(err.code, "certificate_key_mismatch");
}

#[tokio::test]
async fn certificate_proxy_jump_keeps_each_hop_independent() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("user_ca");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", ca.to_str().unwrap(), "-N", ""]);
    let jump = start_server(Some(&ca), Some("ops-team"), false);
    let target = start_server(Some(&ca), Some("ops-team"), true);
    let jump_key = dir.path().join("jump_ed25519");
    let target_key = dir.path().join("target_ed25519");
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        jump_key.to_str().unwrap(),
        "-N",
        "",
    ]);
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        target_key.to_str().unwrap(),
        "-N",
        "",
    ]);
    sign_user(&ca, &jump_key.with_extension("pub"), "ops-team", "-1d:+1d");
    sign_user(
        &ca,
        &target_key.with_extension("pub"),
        "ops-team",
        "-1d:+1d",
    );
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        format!(
            "{}\n{}",
            known_ca(jump.port, read_pub(&server_host_ca_pub(&jump)).trim()),
            known_ca(target.port, read_pub(&server_host_ca_pub(&target)).trim()),
        ),
    )
    .unwrap();
    let echo = echo_server().await;
    let config = format!(
        "\
Host jump
  HostName 127.0.0.1
  Port {jport}
  User {juser}
  IdentityFile {jkey}
  CertificateFile {jkey}-cert.pub
  IdentitiesOnly yes
  IdentityAgent none
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
Host target
  HostName 127.0.0.1
  Port {tport}
  User {tuser}
  ProxyJump jump
  IdentityFile none
  IdentitiesOnly yes
  IdentityAgent none
  PreferredAuthentications password
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
Host both
  HostName 127.0.0.1
  Port {tport}
  User {tuser}
  ProxyJump jump
  IdentityFile {tkey}
  CertificateFile {tkey}-cert.pub
  IdentitiesOnly yes
  IdentityAgent none
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        jport = jump.port,
        juser = jump.user,
        jkey = jump_key.display(),
        tport = target.port,
        tuser = target.user,
        tkey = target_key.display(),
        known = known.display(),
    );
    let app = manager(dir.path(), &config);
    let local = free_port();
    app.store()
        .save_profiles(&[profile(
            "target",
            "target",
            AuthMode::Password,
            vec![mapping(Direction::Local, local, echo.port())],
        )])
        .unwrap();
    app.connect(
        "target",
        Some(Zeroizing::new(target.password.clone())),
        None,
        false,
        false,
        Arc::new(FixedPrompter(false)),
    )
    .await
    .expect("cert on the jump, password on the target");
    exchange(SocketAddr::from(([127, 0, 0, 1], local)), b"jump-cert").await;
    assert!(jump.log_text().contains("Accepted publickey"));
    assert!(!jump.log_text().contains("Accepted password"));
    app.disconnect("target").await.unwrap();
    let remote = free_port();
    let mut profiles = app.store().load_profiles().unwrap();
    profiles.push(profile(
        "both",
        "both",
        AuthMode::PublicKey,
        vec![mapping(Direction::Remote, remote, echo.port())],
    ));
    app.store().save_profiles(&profiles).unwrap();
    app.connect(
        "both",
        None,
        None,
        false,
        false,
        Arc::new(FixedPrompter(false)),
    )
    .await
    .expect("certificate on both hops");
    exchange(SocketAddr::from(([127, 0, 0, 1], remote)), b"both-cert").await;
    app.disconnect_all().await.unwrap();
}

#[tokio::test]
async fn unknown_and_revoked_host_authorities_are_rejected() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("user_ca");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", ca.to_str().unwrap(), "-N", ""]);
    let server = start_server(Some(&ca), Some("ops-team"), false);
    let key = dir.path().join("id_ed25519");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", key.to_str().unwrap(), "-N", ""]);
    sign_user(&ca, &key.with_extension("pub"), "ops-team", "-1d:+1d");
    let other = dir.path().join("other_ca");
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        other.to_str().unwrap(),
        "-N",
        "",
    ]);
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        known_ca(server.port, read_pub(&other.with_extension("pub")).trim()),
    )
    .unwrap();
    let config = format!(
        "\
Host badca
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {key}-cert.pub
  IdentitiesOnly yes
  IdentityAgent none
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        port = server.port,
        user = server.user,
        key = key.display(),
        known = known.display(),
    );
    let app = manager(dir.path(), &config);
    app.store()
        .save_profiles(&[profile("badca", "badca", AuthMode::PublicKey, vec![])])
        .unwrap();
    let err = app
        .connect(
            "badca",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect_err("unknown CA");
    assert_eq!(err.code, "host_key_rejected");

    let host_pub = read_pub(&server.log.parent().unwrap().join("host_ed25519.pub"));
    let pinned = dir.path().join("pinned_hosts");
    std::fs::write(
        &pinned,
        format!("[127.0.0.1]:{} {}", server.port, host_pub.trim()),
    )
    .unwrap();
    let config = format!(
        "\
Host downgrade
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {key}-cert.pub
  IdentitiesOnly yes
  IdentityAgent none
  UserKnownHostsFile {pinned}
  GlobalKnownHostsFile /dev/null
",
        port = server.port,
        user = server.user,
        key = key.display(),
        pinned = pinned.display(),
    );
    let app = manager(dir.path(), &config);
    app.store()
        .save_profiles(&[profile(
            "downgrade",
            "downgrade",
            AuthMode::PublicKey,
            vec![],
        )])
        .unwrap();
    app.connect(
        "downgrade",
        None,
        None,
        false,
        false,
        Arc::new(FixedPrompter(false)),
    )
    .await
    .expect("rejected host certificate falls back to the pinned raw host key");
    app.disconnect_all().await.unwrap();

    let host_ca = read_pub(&server_host_ca_pub(&server));
    let host_pub = read_pub(&server.log.parent().unwrap().join("host_ed25519.pub"));
    let revoked = dir.path().join("revoked_known");
    std::fs::write(
        &revoked,
        format!(
            "@revoked [127.0.0.1]:{port} {ca}\n[127.0.0.1]:{port} {host}",
            port = server.port,
            ca = host_ca.trim(),
            host = host_pub.trim(),
        ),
    )
    .unwrap();
    let config = format!(
        "\
Host revoked
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {key}-cert.pub
  IdentitiesOnly yes
  IdentityAgent none
  UserKnownHostsFile {revoked}
  GlobalKnownHostsFile /dev/null
",
        port = server.port,
        user = server.user,
        key = key.display(),
        revoked = revoked.display(),
    );
    let app = manager(dir.path(), &config);
    app.store()
        .save_profiles(&[profile("revoked", "revoked", AuthMode::PublicKey, vec![])])
        .unwrap();
    let err = app
        .connect(
            "revoked",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(true)),
        )
        .await
        .expect_err("revoked CA");
    assert_eq!(err.code, "host_cert_revoked");
}

#[tokio::test]
async fn rsa_sha2_certificate_and_proxy_command_use_the_same_user_ca() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("user_ca");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", ca.to_str().unwrap(), "-N", ""]);
    let server = start_server(Some(&ca), Some("ops-team"), false);
    let key = dir.path().join("id_rsa");
    ssh_keygen(&[
        "-q",
        "-t",
        "rsa",
        "-b",
        "2048",
        "-f",
        key.to_str().unwrap(),
        "-N",
        "",
    ]);
    sign_user(&ca, &key.with_extension("pub"), "ops-team", "-1d:+1d");
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        known_ca(server.port, read_pub(&server_host_ca_pub(&server)).trim()),
    )
    .unwrap();
    let script = dir.path().join("proxy.py");
    std::fs::write(
        &script,
        format!(
            "\
import os, select, socket
remote = socket.create_connection(('127.0.0.1', {port}))
remote.setblocking(False)
while True:
    readable, _, _ = select.select([0, remote], [], [])
    if 0 in readable:
        data = os.read(0, 65536)
        if not data:
            break
        remote.sendall(data)
    if remote in readable:
        data = remote.recv(65536)
        if not data:
            break
        os.write(1, data)
",
            port = server.port,
        ),
    )
    .unwrap();
    let config = format!(
        "\
Host rsa
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {key}-cert.pub
  IdentitiesOnly yes
  IdentityAgent none
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
Host via-proxy
  HostName 127.0.0.1
  Port {port}
  User {user}
  ProxyCommand python3 {script}
  IdentityFile {key}
  CertificateFile {key}-cert.pub
  IdentitiesOnly yes
  IdentityAgent none
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        port = server.port,
        user = server.user,
        key = key.display(),
        known = known.display(),
        script = script.display(),
    );
    let app = manager(dir.path(), &config);
    app.store()
        .save_profiles(&[
            profile("rsa", "rsa", AuthMode::PublicKey, vec![]),
            profile("via-proxy", "via-proxy", AuthMode::PublicKey, vec![]),
        ])
        .unwrap();
    app.connect(
        "rsa",
        None,
        None,
        false,
        false,
        Arc::new(FixedPrompter(false)),
    )
    .await
    .expect("RSA certificate signed with rsa-sha2");
    app.disconnect("rsa").await.unwrap();
    app.connect(
        "via-proxy",
        None,
        None,
        false,
        false,
        Arc::new(FixedPrompter(false)),
    )
    .await
    .expect("certificate authentication through ProxyCommand");
    app.disconnect_all().await.unwrap();
    assert!(server.log_text().contains("Accepted publickey"));
}

#[tokio::test]
async fn plain_revoked_public_key_blocks_a_trusted_host_certificate() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("user_ca");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", ca.to_str().unwrap(), "-N", ""]);
    let server = start_server(Some(&ca), Some("ops-team"), false);
    let key = dir.path().join("id_ed25519");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", key.to_str().unwrap(), "-N", ""]);
    sign_user(&ca, &key.with_extension("pub"), "ops-team", "-1d:+1d");
    let host_pub = read_pub(&server.log.parent().unwrap().join("host_ed25519.pub"));
    let revoked = dir.path().join("revoked.keys");
    std::fs::write(
        &revoked,
        format!(
            "# retired\n\n{host} fixture-comment\n",
            host = host_pub.trim()
        ),
    )
    .unwrap();
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        known_ca(server.port, read_pub(&server_host_ca_pub(&server)).trim()),
    )
    .unwrap();
    let config = format!(
        "\
Host revoked-list
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {key}-cert.pub
  IdentitiesOnly yes
  IdentityAgent none
  RevokedHostKeys {revoked}
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        port = server.port,
        user = server.user,
        key = key.display(),
        revoked = revoked.display(),
        known = known.display(),
    );
    let app = manager(dir.path(), &config);
    app.store()
        .save_profiles(&[profile(
            "revoked-list",
            "revoked-list",
            AuthMode::PublicKey,
            vec![],
        )])
        .unwrap();
    let err = app
        .connect(
            "revoked-list",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(true)),
        )
        .await
        .expect_err("revoked host public key");
    assert_eq!(err.code, "host_cert_revoked");
}

#[tokio::test]
async fn agent_signs_certificate_while_encrypted_private_file_remains() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("user_ca");
    ssh_keygen(&["-q", "-t", "ed25519", "-f", ca.to_str().unwrap(), "-N", ""]);
    let server = start_server(Some(&ca), Some("ops-team"), false);
    let key = dir.path().join("id_ed25519");
    let other = dir.path().join("other_ed25519");
    let passphrase = "td-fixture-agent-passphrase";
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        key.to_str().unwrap(),
        "-N",
        passphrase,
    ]);
    ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-f",
        other.to_str().unwrap(),
        "-N",
        "",
    ]);
    let sock = dir.path().join("agent.sock");
    let agent = Agent {
        child: Some(
            Command::new("ssh-agent")
                .args(["-D", "-a", sock.to_str().unwrap()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ),
        sock: sock.clone(),
    };
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    add_encrypted(&sock, &key, passphrase);
    let listed = Command::new("ssh-add")
        .env("SSH_AUTH_SOCK", &sock)
        .arg("-L")
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(
        !listing.contains("-cert-v01@openssh.com"),
        "the agent must hold only the ordinary signing key"
    );
    sign_user(&ca, &key.with_extension("pub"), "ops-team", "-1d:+1d");
    let mismatched_cert = PathBuf::from(format!("{}-cert.pub", other.display()));
    sign_user(&ca, &other.with_extension("pub"), "ops-team", "-1d:+1d");
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        known_ca(server.port, read_pub(&server_host_ca_pub(&server)).trim()),
    )
    .unwrap();
    let config = format!(
        "\
Host agentcert
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {key}-cert.pub
  IdentitiesOnly yes
  IdentityAgent {sock}
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
Host noagent
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {key}-cert.pub
  IdentitiesOnly yes
  IdentityAgent none
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
Host mismatch
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  CertificateFile {key}-cert.pub
  IdentitiesOnly yes
  IdentityAgent {sock}
  PreferredAuthentications publickey
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        port = server.port,
        user = server.user,
        key = key.display(),
        sock = sock.display(),
        known = known.display(),
    );
    let app = manager(dir.path(), &config);
    app.store()
        .save_profiles(&[
            profile("agent", "agentcert", AuthMode::Agent, vec![]),
            profile("auto", "agentcert", AuthMode::Auto, vec![]),
            profile("file", "agentcert", AuthMode::PublicKey, vec![]),
            profile("noagent", "noagent", AuthMode::Auto, vec![]),
            profile("mismatch", "mismatch", AuthMode::Auto, vec![]),
        ])
        .unwrap();
    app.connect(
        "agent",
        None,
        None,
        false,
        false,
        Arc::new(FixedPrompter(false)),
    )
    .await
    .expect("agent signs the certificate without the key passphrase");
    app.disconnect("agent").await.unwrap();
    app.connect(
        "auto",
        None,
        None,
        false,
        false,
        Arc::new(FixedPrompter(false)),
    )
    .await
    .expect("automatic mode uses the unlocked agent key");
    app.disconnect("auto").await.unwrap();
    let file_only = app
        .connect(
            "file",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect_err("file-only mode must not use the agent");
    assert_eq!(file_only.code, "passphrase_required");
    let disabled = app
        .connect(
            "noagent",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect_err("IdentityAgent none");
    assert_eq!(disabled.code, "passphrase_required");
    std::fs::copy(
        &mismatched_cert,
        PathBuf::from(format!("{}-cert.pub", key.display())),
    )
    .unwrap();
    let mismatched = app
        .connect(
            "mismatch",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect_err("mismatched certificate");
    assert_eq!(mismatched.code, "certificate_key_mismatch");
    assert!(!server.log_text().contains(&passphrase));
    drop(agent);
}

fn add_encrypted(sock: &Path, key: &Path, passphrase: &str) {
    let script = key.with_file_name("askpass.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf '%s\\n' \"$TD_ASKPASS\"\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&script, perms).unwrap();
    }
    let output = Command::new("ssh-add")
        .env("SSH_AUTH_SOCK", sock)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", "td-fixture")
        .env("SSH_ASKPASS", &script)
        .env("TD_ASKPASS", passphrase)
        .arg(key)
        .output()
        .unwrap();
    if !output.status.success() {
        let mut err = String::from_utf8_lossy(&output.stderr).into_owned();
        let out = String::from_utf8_lossy(&output.stdout);
        err.push_str(&out.replace(passphrase, "[redacted]"));
        let err = err.replace(passphrase, "[redacted]");
        panic!("ssh-add could not unlock the fixture key: {err}");
    }
}
