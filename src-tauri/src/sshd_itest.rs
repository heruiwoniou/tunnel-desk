//! Interoperability against a disposable OpenSSH sshd. The system sshd is not modified.

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

use crate::config::Resolver;
use crate::error::AppError;
use crate::model::{AuthMode, Direction, ForwardMapping, Phase, Profile, Target, now_rfc3339};
use crate::secrets::{self, OsSecretStore, SecretBackendStatus, SecretStore};
use crate::store::AppStore;
use crate::tunnel::{FixedPrompter, HostKeyPrompt, HostKeyPrompter, TunnelManager};

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

struct CountPrompter {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    accept: bool,
}

#[async_trait]
impl HostKeyPrompter for CountPrompter {
    async fn confirm_unknown(&self, _: &HostKeyPrompt) -> bool {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.accept
    }
}

struct Sshd {
    user: String,
    port: u16,
    password: String,
    log: PathBuf,
    pid: PathBuf,
    child: Option<std::process::Child>,
    _dir: tempfile::TempDir,
}

fn root_text(path: &Path) -> String {
    let Some(path) = path.to_str() else {
        return String::new();
    };
    Command::new("sudo")
        .args(["-n", "cat", path])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

fn kill_pidfile(path: &Path) {
    let pid = root_text(path);
    let pid = pid.trim();
    if !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()) {
        let _ = Command::new("sudo").args(["-n", "kill", pid]).status();
    }
}

fn stop_sshd(server: &Sshd) {
    kill_pidfile(&server.pid);
    let _ = Command::new("sudo")
        .args(["-n", "pkill", "-u", &server.user])
        .status();
}

impl Drop for Sshd {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        kill_pidfile(&self.pid);
        let _ = Command::new("sudo")
            .args(["-n", "pkill", "-KILL", "-u", &self.user])
            .status();
        let _ = Command::new("sudo")
            .args(["-n", "userdel", "-r", &self.user])
            .status();
    }
}

fn openssh_available() -> bool {
    Path::new("/usr/sbin/sshd").is_file()
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
    let output = Command::new("sudo").arg("-n").args(args).output().unwrap();
    if !output.status.success() {
        panic!(
            "sudo {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Sshd {
    fn start(
        forwarding: &str,
        pubkey: bool,
        password_auth: bool,
        authorized: Option<&Path>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let user = format!("td{}", &token()[..8]);
        let password = format!("pw-{}", token());
        let port = free_port();
        let host_key = dir.path().join("host_ed25519");
        let log = dir.path().join("sshd.log");
        let pid = dir.path().join("sshd.pid");
        let home = dir.path().join("home");
        let config = dir.path().join("sshd_config");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let status = Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-f",
                host_key.to_str().unwrap(),
                "-N",
                "",
            ])
            .status()
            .unwrap();
        assert!(status.success(), "ssh-keygen host key");
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
        assert!(chpasswd.wait().unwrap().success(), "chpasswd");
        if let Some(key) = authorized {
            std::fs::copy(key, home.join(".ssh/authorized_keys")).unwrap();
        }
        sudo_ok(&[
            "chown",
            "-R",
            &format!("{user}:{user}"),
            home.to_str().unwrap(),
        ]);
        let auth_file = home.join(".ssh/authorized_keys");
        std::fs::write(
            &config,
            format!(
                "\
Port {port}
ListenAddress 127.0.0.1
HostKey {host}
PidFile {pid}
AuthorizedKeysFile {auth}
PasswordAuthentication {password_auth}
KbdInteractiveAuthentication no
PubkeyAuthentication {pubkey}
UsePAM yes
AllowTcpForwarding {forwarding}
GatewayPorts no
PermitRootLogin no
AllowUsers {user}
StrictModes no
PrintMotd no
UseDNS no
X11Forwarding no
",
                host = host_key.display(),
                pid = pid.display(),
                auth = auth_file.display(),
                password_auth = if password_auth { "yes" } else { "no" },
                pubkey = if pubkey { "yes" } else { "no" },
            ),
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
        let mut server = Self {
            user,
            port,
            password,
            log,
            pid,
            child: Some(child),
            _dir: dir,
        };
        if !server.wait_ready() {
            let detail = root_text(&server.log);
            panic!("sshd did not accept connections: {detail}");
        }
        server
    }

    fn wait_ready(&mut self) -> bool {
        for _ in 0..50 {
            if std::net::TcpStream::connect_timeout(
                &SocketAddr::from(([127, 0, 0, 1], self.port)),
                Duration::from_millis(80),
            )
            .is_ok()
            {
                return true;
            }
            if let Some(child) = self.child.as_mut()
                && let Ok(Some(_)) = child.try_wait()
            {
                return false;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        false
    }

    fn public_line(&self) -> String {
        let output = Command::new("ssh-keygen")
            .args([
                "-y",
                "-f",
                self._dir.path().join("host_ed25519").to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }

    fn log_text(&self) -> String {
        root_text(&self.log)
    }
}

fn resolver(dir: &Path, body: &str) -> Resolver {
    let config = dir.join("ssh-config");
    std::fs::write(&config, body).unwrap();
    Resolver {
        user_config: config,
        system_config: None,
        ssh_binary: which_ssh(),
        home: dir.to_path_buf(),
        local_user: "td".into(),
        local_host: "testhost".into(),
    }
}

fn which_ssh() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("ssh"))
            .find(|candidate| candidate.is_file())
    })
}

fn profile(
    id: &str,
    target: Target,
    mode: AuthMode,
    forwards: Vec<ForwardMapping>,
    remember: bool,
) -> Profile {
    Profile {
        id: id.into(),
        name: "合成测试".into(),
        target,
        auth_mode: mode,
        remember_password: remember,
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

fn assert_no_secret(dir: &Path, secret: &str) {
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let bytes = std::fs::read(&path).unwrap_or_default();
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains(secret),
                "secret persisted in {}",
                path.display()
            );
        }
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
                let mut buffer = vec![0u8; 1024];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(size) => {
                            if socket.write_all(&buffer[..size]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn exchange(addr: SocketAddr, payload: &[u8]) {
    let mut last = String::from("not attempted");
    for _ in 0..40 {
        match exchange_once(addr, payload).await {
            Ok(()) => return,
            Err(err) => {
                last = err;
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        }
    }
    panic!("forward did not carry data: {last}");
}

async fn exchange_once(addr: SocketAddr, payload: &[u8]) -> Result<(), String> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|err| err.to_string())?;
    stream
        .write_all(payload)
        .await
        .map_err(|err| err.to_string())?;
    let mut buffer = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buffer))
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|err| err.to_string())?;
    if buffer != payload {
        return Err("payload mismatch".into());
    }
    Ok(())
}

fn port_is_free(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

async fn connect_alias(
    manager: &TunnelManager,
    id: &str,
    forwards: Vec<ForwardMapping>,
    password: Option<&str>,
    remember: bool,
    accept_key: bool,
) -> Result<(), AppError> {
    let item = profile(
        id,
        Target::ConfigAlias { alias: "db".into() },
        AuthMode::Password,
        forwards,
        remember,
    );
    manager.store().save_profiles(&[item.clone()]).unwrap();
    manager
        .connect(
            id,
            password.map(|value| Zeroizing::new(value.to_string())),
            None,
            remember,
            false,
            Arc::new(FixedPrompter(accept_key)),
        )
        .await
        .map(|_| ())
}

fn base_config(dir: &Path, _server: &Sshd) -> String {
    let known = dir.join("known_hosts");
    if !known.exists() {
        std::fs::write(&known, b"").unwrap();
    }
    format!(
        "\
Include {extra}
Host *
  User denied-user
  Port 1
  IdentityAgent none
  UserKnownHostsFile /dev/null
  GlobalKnownHostsFile /dev/null
",
        extra = dir.join("extra").display(),
    )
}

fn write_db_include(dir: &Path, server: &Sshd) {
    let known = dir.join("known_hosts");
    std::fs::write(
        dir.join("extra"),
        format!(
            "\
Host db
  HostName 127.0.0.1
  Port {port}
  User {user}
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
  IdentityFile none
  IdentitiesOnly yes
  IdentityAgent none
",
            port = server.port,
            user = server.user,
            known = known.display(),
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn openssh_password_forwards_both_ways_and_disconnect_frees_ports() {
    if !openssh_available() {
        return;
    }
    let server = Sshd::start("yes", false, true, None);
    let echo = echo_server().await;
    let local_port = free_port();
    let remote_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    write_db_include(dir.path(), &server);
    std::fs::write(
        dir.path().join("ssh-config"),
        base_config(dir.path(), &server),
    )
    .unwrap();
    let store = Arc::new(MemStore {
        values: Mutex::new(std::collections::BTreeMap::new()),
    });
    let manager = TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        store.clone(),
        resolver(
            dir.path(),
            &std::fs::read_to_string(dir.path().join("ssh-config")).unwrap(),
        ),
    );
    let resolved = manager.resolver().resolve("db").unwrap();
    assert_eq!(resolved.user, server.user);
    assert_eq!(resolved.port, server.port);
    assert_eq!(resolved.resolution, "openssh");
    connect_alias(
        &manager,
        "both",
        vec![
            mapping(Direction::Local, local_port, echo.port()),
            mapping(Direction::Remote, remote_port, echo.port()),
        ],
        Some(&server.password),
        true,
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        manager.snapshots()[0].phase,
        Phase::Connected,
        "connected only after both forwards bind"
    );
    exchange(SocketAddr::from(([127, 0, 0, 1], local_port)), b"local-l").await;
    exchange(SocketAddr::from(([127, 0, 0, 1], remote_port)), b"remote-r").await;
    manager.disconnect("both").await.unwrap();
    assert!(port_is_free(local_port), "local listener still held");
    assert!(port_is_free(remote_port), "remote listener still held");
    let history = manager.store().load_history().unwrap();
    assert_eq!(history[0].outcome, "disconnected");
    assert_no_secret(dir.path(), &server.password);
    manager
        .connect(
            "both",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect("reconnect should use the stored server password");
    manager.disconnect("both").await.unwrap();
    manager.forget_server_password("both").unwrap();
    assert!(
        store
            .get(&secrets::server_password_account("both"))
            .unwrap()
            .is_none()
    );
    let missing = manager
        .connect(
            "both",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .unwrap_err();
    assert_eq!(missing.code, "password_required");
    manager.disconnect_all().await.unwrap();
}

#[tokio::test]
async fn openssh_host_keys_trust_change_revoke_and_hash() {
    if !openssh_available() {
        return;
    }
    let server = Sshd::start("yes", false, true, None);
    let echo = echo_server().await;
    let dir = tempfile::tempdir().unwrap();
    let known = dir.path().join("known_hosts");
    std::fs::write(&known, b"").unwrap();
    write_db_include(dir.path(), &server);
    std::fs::write(
        dir.path().join("ssh-config"),
        base_config(dir.path(), &server),
    )
    .unwrap();
    let manager = TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        Arc::new(MemStore {
            values: Mutex::new(std::collections::BTreeMap::new()),
        }),
        resolver(
            dir.path(),
            &std::fs::read_to_string(dir.path().join("ssh-config")).unwrap(),
        ),
    );
    let item = profile(
        "db",
        Target::ConfigAlias { alias: "db".into() },
        AuthMode::Password,
        vec![mapping(Direction::Local, free_port(), echo.port())],
        false,
    );
    manager.store().save_profiles(&[item]).unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let rejected = manager
        .connect(
            "db",
            Some(Zeroizing::new(server.password.clone())),
            None,
            false,
            false,
            Arc::new(CountPrompter {
                calls: calls.clone(),
                accept: false,
            }),
        )
        .await
        .unwrap_err();
    assert_eq!(rejected.code, "host_key_rejected");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    std::fs::write(
        &known,
        format!("[127.0.0.1]:{} {}", server.port, server.public_line()),
    )
    .unwrap();
    let hashed = Command::new("ssh-keygen")
        .args(["-H", "-f", known.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(hashed.success());
    let hashed_text = std::fs::read_to_string(&known).unwrap();
    assert!(hashed_text.contains("|1|"), "known_hosts was not hashed");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    manager
        .connect(
            "db",
            Some(Zeroizing::new(server.password.clone())),
            None,
            false,
            false,
            Arc::new(CountPrompter {
                calls: calls.clone(),
                accept: false,
            }),
        )
        .await
        .expect("hashed known_hosts should trust the key without a prompt");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    manager.disconnect("db").await.unwrap();

    std::fs::write(
        &known,
        format!(
            "@revoked [127.0.0.1]:{} {}",
            server.port,
            server.public_line()
        ),
    )
    .unwrap();
    let revoked = manager
        .connect(
            "db",
            Some(Zeroizing::new(server.password.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(true)),
        )
        .await
        .unwrap_err();
    assert_eq!(revoked.code, "host_key_revoked");

    let other = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-f",
            dir.path().join("other").to_str().unwrap(),
            "-N",
            "",
        ])
        .status()
        .unwrap();
    assert!(other.success());
    let other_pub = std::fs::read_to_string(dir.path().join("other.pub")).unwrap();
    std::fs::write(&known, format!("[127.0.0.1]:{} {other_pub}", server.port)).unwrap();
    let changed = manager
        .connect(
            "db",
            Some(Zeroizing::new(server.password.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(true)),
        )
        .await
        .unwrap_err();
    assert_eq!(changed.code, "host_key_changed");
    assert_no_secret(dir.path(), &server.password);
}

#[tokio::test]
async fn openssh_rejects_early_conflict_and_refused_remote_without_leaking_ports() {
    if !openssh_available() {
        return;
    }
    let server = Sshd::start("local", false, true, None);
    let echo = echo_server().await;
    let dir = tempfile::tempdir().unwrap();
    write_db_include(dir.path(), &server);
    std::fs::write(
        dir.path().join("ssh-config"),
        base_config(dir.path(), &server),
    )
    .unwrap();
    let manager = TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        Arc::new(MemStore {
            values: Mutex::new(std::collections::BTreeMap::new()),
        }),
        resolver(
            dir.path(),
            &std::fs::read_to_string(dir.path().join("ssh-config")).unwrap(),
        ),
    );
    let closer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = closer.local_addr().unwrap().port();
    drop(closer);
    let listen = free_port();
    let bad = profile(
        "bad",
        Target::Manual {
            hostname: "127.0.0.1".into(),
            port: closed,
            user: server.user.clone(),
            identity_file: None,
            proxy_jump: Some(String::new()),
        },
        AuthMode::Password,
        vec![mapping(Direction::Local, listen, echo.port())],
        false,
    );
    manager.store().save_profiles(&[bad]).unwrap();
    let early = manager
        .connect(
            "bad",
            Some(Zeroizing::new(server.password.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(true)),
        )
        .await
        .unwrap_err();
    assert_ne!(early.code, "ok");
    assert!(port_is_free(listen), "failed connect left a listener");

    let occupied = free_port();
    let held = std::net::TcpListener::bind(("127.0.0.1", occupied)).unwrap();
    let other = free_port();
    let conflict = profile(
        "conflict",
        Target::ConfigAlias { alias: "db".into() },
        AuthMode::Password,
        vec![
            mapping(Direction::Local, other, echo.port()),
            mapping(Direction::Local, occupied, echo.port()),
        ],
        false,
    );
    manager
        .store()
        .save_profiles(&[manager.store().load_profiles().unwrap().remove(0), conflict])
        .unwrap();
    let busy = manager
        .connect(
            "conflict",
            Some(Zeroizing::new(server.password.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(true)),
        )
        .await
        .unwrap_err();
    assert_eq!(busy.code, "port_in_use");
    drop(held);
    assert!(
        port_is_free(other),
        "partial local bind was not rolled back"
    );
    assert!(port_is_free(occupied));

    let local = free_port();
    let remote = free_port();
    let refused = profile(
        "refused",
        Target::ConfigAlias { alias: "db".into() },
        AuthMode::Password,
        vec![
            mapping(Direction::Local, local, echo.port()),
            mapping(Direction::Remote, remote, echo.port()),
        ],
        false,
    );
    let mut profiles = manager.store().load_profiles().unwrap();
    profiles.push(refused);
    manager.store().save_profiles(&profiles).unwrap();
    let denied = manager
        .connect(
            "refused",
            Some(Zeroizing::new(server.password.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(true)),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.code, "forward_denied", "{}", denied.message);
    assert!(
        port_is_free(local),
        "local listener survived a refused remote"
    );
    assert!(port_is_free(remote));
    assert_no_secret(dir.path(), &server.password);
}

#[tokio::test]
async fn openssh_session_loss_marks_failed_and_releases_the_listener() {
    if !openssh_available() {
        return;
    }
    let server = Sshd::start("yes", false, true, None);
    let echo = echo_server().await;
    let dir = tempfile::tempdir().unwrap();
    write_db_include(dir.path(), &server);
    std::fs::write(
        dir.path().join("ssh-config"),
        base_config(dir.path(), &server),
    )
    .unwrap();
    let manager = TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        Arc::new(MemStore {
            values: Mutex::new(std::collections::BTreeMap::new()),
        }),
        resolver(
            dir.path(),
            &std::fs::read_to_string(dir.path().join("ssh-config")).unwrap(),
        ),
    );
    let local = free_port();
    connect_alias(
        &manager,
        "live",
        vec![mapping(Direction::Local, local, echo.port())],
        Some(&server.password),
        false,
        true,
    )
    .await
    .unwrap();
    exchange(SocketAddr::from(([127, 0, 0, 1], local)), b"before-drop").await;
    let pid_text = root_text(&server.pid);
    stop_sshd(&server);
    let mut saw_failed = false;
    for _ in 0..50 {
        if manager
            .snapshots()
            .iter()
            .any(|snapshot| snapshot.profile_id == "live" && snapshot.phase == Phase::Failed)
        {
            saw_failed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        saw_failed,
        "session loss did not update the phase; pid={pid_text:?} snapshots={:?}",
        manager.snapshots()
    );
    assert!(port_is_free(local), "listener survived session loss");
    let history = manager.store().load_history().unwrap();
    assert!(
        history.iter().any(|entry| entry.outcome == "failed"),
        "history did not record the dropped session"
    );
}

#[tokio::test]
async fn openssh_keeps_server_password_and_key_passphrase_distinct() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    let passphrase = format!("phrase-{}", token());
    let mut rng = russh::keys::key::safe_rng();
    let key = russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap();
    let encrypted = key.encrypt(&mut rng, passphrase.as_bytes()).unwrap();
    encrypted
        .write_openssh_file(&key_path, russh::keys::ssh_key::LineEnding::LF)
        .unwrap();
    key.public_key()
        .write_openssh_file(dir.path().join("id_ed25519.pub"))
        .unwrap();
    let server = Sshd::start("yes", true, true, Some(&dir.path().join("id_ed25519.pub")));
    let echo = echo_server().await;
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        format!("[127.0.0.1]:{} {}", server.port, server.public_line()),
    )
    .unwrap();
    let config = format!(
        "\
Host db
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {key}
  IdentitiesOnly yes
  IdentityAgent none
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        port = server.port,
        user = server.user,
        key = key_path.display(),
        known = known.display(),
    );
    std::fs::write(dir.path().join("ssh-config"), &config).unwrap();
    let manager = TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        Arc::new(MemStore {
            values: Mutex::new(std::collections::BTreeMap::new()),
        }),
        resolver(dir.path(), &config),
    );
    let by_key = profile(
        "key",
        Target::ConfigAlias { alias: "db".into() },
        AuthMode::PublicKey,
        vec![mapping(Direction::Local, free_port(), echo.port())],
        false,
    );
    manager.store().save_profiles(&[by_key]).unwrap();
    let missing_phrase = manager
        .connect(
            "key",
            Some(Zeroizing::new(server.password.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(true)),
        )
        .await
        .unwrap_err();
    assert_eq!(missing_phrase.code, "passphrase_required");
    assert!(
        !server.log_text().contains("Accepted password"),
        "a key passphrase prompt must not fall through to the server password"
    );
    manager
        .connect(
            "key",
            None,
            Some(Zeroizing::new(passphrase.clone())),
            false,
            true,
            Arc::new(FixedPrompter(true)),
        )
        .await
        .expect("the key passphrase should unlock the key");
    assert!(server.log_text().contains("Accepted publickey"));
    manager.disconnect("key").await.unwrap();

    let by_password = profile(
        "pw",
        Target::ConfigAlias { alias: "db".into() },
        AuthMode::Password,
        vec![mapping(Direction::Local, free_port(), echo.port())],
        false,
    );
    let mut profiles = manager.store().load_profiles().unwrap();
    profiles.push(by_password);
    manager.store().save_profiles(&profiles).unwrap();
    let wrong = manager
        .connect(
            "pw",
            Some(Zeroizing::new(passphrase.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(true)),
        )
        .await
        .unwrap_err();
    assert_eq!(wrong.code, "auth_failed");
    manager
        .connect(
            "pw",
            Some(Zeroizing::new(server.password.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(true)),
        )
        .await
        .expect("password mode should use the server password, not the key passphrase");
    manager.disconnect_all().await.unwrap();
    assert_no_secret(dir.path(), &server.password);
    assert_no_secret(dir.path(), &passphrase);
}

#[tokio::test]
async fn openssh_proxy_jump_and_proxy_command_carry_the_session() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let jump_key = dir.path().join("jump_ed25519");
    let status = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-f",
            jump_key.to_str().unwrap(),
            "-N",
            "",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let jump = Sshd::start(
        "yes",
        true,
        false,
        Some(&dir.path().join("jump_ed25519.pub")),
    );
    let target = Sshd::start("yes", false, true, None);
    let echo = echo_server().await;
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        format!(
            "[127.0.0.1]:{jp} {jpub}[127.0.0.1]:{tp} {tpub}",
            jp = jump.port,
            jpub = jump.public_line(),
            tp = target.port,
            tpub = target.public_line(),
        ),
    )
    .unwrap();
    let marker = dir.path().join("proxy-ran");
    let proxy_py = dir.path().join("proxy.py");
    std::fs::write(
        &proxy_py,
        r#"
import os, socket, sys
open(sys.argv[1], "w").write("ran")
remote = socket.create_connection(("127.0.0.1", int(sys.argv[2])))
remote.setblocking(False)
stdin = os.fdopen(sys.stdin.fileno(), "rb", buffering=0)
stdout = os.fdopen(sys.stdout.fileno(), "wb", buffering=0)
import select
sockets = [stdin, remote]
while True:
    readable, _, _ = select.select(sockets, [], [], 20)
    if not readable:
        break
    for item in readable:
        if item is remote:
            data = remote.recv(65536)
            if not data:
                raise SystemExit
            stdout.write(data)
            stdout.flush()
        else:
            data = stdin.read(65536)
            if not data:
                raise SystemExit
            remote.sendall(data)
"#,
    )
    .unwrap();
    let config = format!(
        "\
Host jump
  HostName 127.0.0.1
  Port {jport}
  User {juser}
  IdentityFile {jkey}
  IdentitiesOnly yes
  IdentityAgent none
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
Host viajump
  HostName 127.0.0.1
  Port {tport}
  User {tuser}
  ProxyJump jump
  IdentityFile none
  IdentityAgent none
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
Host viacmd
  HostName 127.0.0.1
  Port {tport}
  User {tuser}
  ProxyCommand python3 {py} {marker} {tport}
  IdentityFile none
  IdentityAgent none
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
",
        jport = jump.port,
        juser = jump.user,
        jkey = jump_key.display(),
        tport = target.port,
        tuser = target.user,
        known = known.display(),
        py = proxy_py.display(),
        marker = marker.display(),
    );
    std::fs::write(dir.path().join("ssh-config"), &config).unwrap();
    let manager = TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        Arc::new(MemStore {
            values: Mutex::new(std::collections::BTreeMap::new()),
        }),
        resolver(dir.path(), &config),
    );
    let echo_port = echo.port();
    let jump_profile = profile(
        "jump",
        Target::ConfigAlias {
            alias: "viajump".into(),
        },
        AuthMode::Password,
        vec![mapping(Direction::Local, free_port(), echo_port)],
        false,
    );
    manager.store().save_profiles(&[jump_profile]).unwrap();
    manager
        .connect(
            "jump",
            Some(Zeroizing::new(target.password.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect("ProxyJump should reach the target");
    assert!(
        jump.log_text().contains("Accepted publickey"),
        "jump host was not actually used"
    );
    assert!(
        !jump.log_text().contains("Accepted password"),
        "target password must not authenticate the jump"
    );
    manager.disconnect("jump").await.unwrap();

    let command_profile = profile(
        "cmd",
        Target::ConfigAlias {
            alias: "viacmd".into(),
        },
        AuthMode::Password,
        vec![mapping(Direction::Local, free_port(), echo_port)],
        false,
    );
    let mut profiles = manager.store().load_profiles().unwrap();
    profiles.push(command_profile);
    manager.store().save_profiles(&profiles).unwrap();
    manager
        .connect(
            "cmd",
            Some(Zeroizing::new(target.password.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect("ProxyCommand should carry the SSH session");
    assert_eq!(std::fs::read_to_string(&marker).unwrap_or_default(), "ran");
    manager.disconnect_all().await.unwrap();
    assert_no_secret(dir.path(), &target.password);
}

#[tokio::test]
async fn os_keyring_password_authenticates_and_forget_deletes_it() {
    if std::env::var("TUNNELDESK_KEYRING_TEST").ok().as_deref() != Some("1") || !openssh_available()
    {
        return;
    }
    let server = Sshd::start("yes", false, true, None);
    let echo = echo_server().await;
    let dir = tempfile::tempdir().unwrap();
    write_db_include(dir.path(), &server);
    std::fs::write(
        dir.path().join("ssh-config"),
        base_config(dir.path(), &server),
    )
    .unwrap();
    let manager = TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        Arc::new(OsSecretStore),
        resolver(
            dir.path(),
            &std::fs::read_to_string(dir.path().join("ssh-config")).unwrap(),
        ),
    );
    let local = free_port();
    connect_alias(
        &manager,
        "saved",
        vec![mapping(Direction::Local, local, echo.port())],
        Some(&server.password),
        true,
        true,
    )
    .await
    .unwrap();
    assert_no_secret(dir.path(), &server.password);
    manager.disconnect("saved").await.unwrap();
    manager
        .connect(
            "saved",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .expect("reconnect should read the password back from the OS keyring");
    manager.disconnect("saved").await.unwrap();
    manager.forget_server_password("saved").unwrap();
    assert!(
        OsSecretStore
            .get(&secrets::server_password_account("saved"))
            .unwrap()
            .is_none()
    );
    let missing = manager
        .connect(
            "saved",
            None,
            None,
            false,
            false,
            Arc::new(FixedPrompter(false)),
        )
        .await
        .unwrap_err();
    assert_eq!(missing.code, "password_required");
    assert_no_secret(dir.path(), &server.password);
}

/// OpenSSH sends a channel-open failure when the destination refuses.
/// That must not disconnect the session or drop the other listener.
#[tokio::test]
async fn openssh_refused_destination_keeps_the_session() {
    if !openssh_available() {
        return;
    }
    let server = Sshd::start("yes", false, true, None);
    let echo = echo_server().await;
    let good = free_port();
    let bad = free_port();
    let closed = free_port();
    let dir = tempfile::tempdir().unwrap();
    write_db_include(dir.path(), &server);
    std::fs::write(
        dir.path().join("ssh-config"),
        base_config(dir.path(), &server),
    )
    .unwrap();
    let manager = TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        Arc::new(MemStore {
            values: Mutex::new(std::collections::BTreeMap::new()),
        }),
        resolver(
            dir.path(),
            &std::fs::read_to_string(dir.path().join("ssh-config")).unwrap(),
        ),
    );
    connect_alias(
        &manager,
        "partial",
        vec![
            mapping(Direction::Local, good, echo.port()),
            mapping(Direction::Local, bad, closed),
        ],
        Some(&server.password),
        false,
        true,
    )
    .await
    .unwrap();
    let poke = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], bad))).await;
    assert!(poke.is_ok(), "the local listener should still accept");
    drop(poke);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(manager.snapshots()[0].phase, Phase::Connected);
    exchange(SocketAddr::from(([127, 0, 0, 1], good)), b"still-up").await;
    assert_eq!(manager.snapshots()[0].phase, Phase::Connected);
    manager.disconnect("partial").await.unwrap();
    assert_no_secret(dir.path(), &server.password);
}
