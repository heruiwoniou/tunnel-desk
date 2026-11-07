use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use russh::Channel;
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Server, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::config::Resolver;
use crate::error::AppError;
use crate::known_hosts::{self, TrustEntry, TrustStore};
use crate::model::{AuthMode, Direction, ForwardMapping, Phase, Profile, Target, now_rfc3339};
use crate::secrets::{SecretBackendStatus, SecretStore};
use crate::store::AppStore;
use crate::tunnel::{FixedPrompter, HostKeyPrompt, HostKeyPrompter, TunnelManager, bridge_tcp};

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

#[derive(Clone)]
struct TestServer {
    user: String,
    password: String,
    refuse_forward: bool,
    refuse_cancel_forward: bool,
    auth_hold: Option<Arc<tokio::sync::Notify>>,
    auth_delay: Duration,
    forwards: Arc<Mutex<std::collections::HashMap<u16, CancellationToken>>>,
}

impl Server for TestServer {
    type Handler = Self;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
        self.clone()
    }
}

impl Handler for TestServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if let Some(hold) = &self.auth_hold {
            hold.notify_one();
            tokio::time::sleep(self.auth_delay).await;
        }
        if user == self.user && password.as_bytes() == self.password.as_bytes() {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let host = host_to_connect.to_string();
        let port = u16::try_from(port_to_connect).unwrap_or(0);
        reply.accept().await;
        tokio::spawn(async move {
            match TcpStream::connect((host.as_str(), port)).await {
                Ok(socket) => {
                    let _ = socket.set_nodelay(true);
                    bridge_tcp(socket, channel, CancellationToken::new()).await;
                }
                Err(_) => {
                    let _ = channel.close().await;
                }
            }
        });
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if self.refuse_forward {
            return Ok(false);
        }
        let requested = u16::try_from(*port).unwrap_or(0);
        let listener = match TcpListener::bind((address, requested)).await {
            Ok(listener) => listener,
            Err(_) => return Ok(false),
        };
        let actual = listener
            .local_addr()
            .map(|addr| u32::from(addr.port()))
            .unwrap_or(*port);
        if *port == 0 {
            *port = actual;
        }
        let token = CancellationToken::new();
        self.forwards
            .lock()
            .expect("forwards")
            .insert(requested, token.clone());
        let handle = session.handle();
        let bound_address = address.to_string();
        let bound_port = *port;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((socket, peer)) = accepted else { break };
                        let handle = handle.clone();
                        let bound_address = bound_address.clone();
                        tokio::spawn(async move {
                            if let Ok(channel) = handle
                                .channel_open_forwarded_tcpip(bound_address, bound_port, peer.ip().to_string(), u32::from(peer.port()))
                                .await
                            {
                                let _ = socket.set_nodelay(true);
                                bridge_tcp(socket, channel, CancellationToken::new()).await;
                            }
                        });
                    }
                }
            }
        });
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        _address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if self.refuse_cancel_forward {
            return Ok(false);
        }
        if let Ok(port) = u16::try_from(port)
            && let Some(token) = self.forwards.lock().expect("forwards").remove(&port)
        {
            token.cancel();
        }
        Ok(true)
    }
}

fn fake_secret() -> String {
    format!("pw-{}", uuid::Uuid::new_v4().simple())
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn ssh_binary() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("ssh"))
            .find(|candidate| candidate.is_file())
    })
}

fn isolated_resolver(dir: &Path) -> Resolver {
    let known = dir.join("known_hosts");
    std::fs::write(&known, b"").unwrap();
    let config = dir.join("ssh-config");
    std::fs::write(
        &config,
        format!(
            "Host *\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile /dev/null\n  IdentityFile none\n  IdentitiesOnly yes\n",
            known.display()
        ),
    )
    .unwrap();
    Resolver {
        user_config: config,
        system_config: None,
        ssh_binary: ssh_binary(),
        home: dir.to_path_buf(),
        local_user: "td".into(),
        local_host: "testhost".into(),
    }
}

fn profile(id: &str, port: u16, forwards: Vec<ForwardMapping>, remember: bool) -> Profile {
    Profile {
        id: id.into(),
        name: "本地测试".into(),
        target: Target::Manual {
            hostname: "127.0.0.1".into(),
            port,
            user: "tdtest".into(),
            identity_file: None,
            proxy_jump: None,
        },
        auth_mode: AuthMode::Password,
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
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if String::from_utf8_lossy(&bytes).contains(secret) {
                panic!("persisted file contains a secret: {}", path.display());
            }
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
                let _ = socket.set_nodelay(true);
                let mut buffer = [0u8; 1024];
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

async fn ssh_server(password: String, refuse_forward: bool) -> SocketAddr {
    ssh_server_opts(password, refuse_forward, false).await
}

async fn ssh_server_opts(
    password: String,
    refuse_forward: bool,
    refuse_cancel_forward: bool,
) -> SocketAddr {
    ssh_server_delayed(
        password,
        refuse_forward,
        refuse_cancel_forward,
        None,
        Duration::ZERO,
    )
    .await
}

async fn ssh_server_delayed(
    password: String,
    refuse_forward: bool,
    refuse_cancel_forward: bool,
    auth_hold: Option<Arc<tokio::sync::Notify>>,
    auth_delay: Duration,
) -> SocketAddr {
    let mut config = russh::server::Config::default();
    config.auth_rejection_time = Duration::from_millis(1);
    config.auth_rejection_time_initial = Some(Duration::from_millis(1));
    config.inactivity_timeout = Some(Duration::from_secs(30));
    config.keys.push(
        russh::keys::PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap(),
    );
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let template = TestServer {
        user: "tdtest".into(),
        password,
        refuse_forward,
        refuse_cancel_forward,
        auth_hold,
        auth_delay,
        forwards: Arc::new(Mutex::new(std::collections::HashMap::new())),
    };
    tokio::spawn(async move {
        loop {
            let Ok((socket, peer)) = listener.accept().await else {
                break;
            };
            let config = config.clone();
            let mut server = template.clone();
            tokio::spawn(async move {
                let handler = server.new_client(Some(peer));
                let _ = russh::server::run_stream(config, socket, handler).await;
            });
        }
    });
    addr
}

async fn exchange(addr: SocketAddr, payload: &[u8]) {
    let mut last = String::from("not attempted");
    for _ in 0..30 {
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
    let _ = stream.set_nodelay(true);
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

async fn save_and_connect(
    manager: &TunnelManager,
    profile: &Profile,
    password: Option<&str>,
    remember: bool,
    prompter: Arc<dyn HostKeyPrompter>,
) -> Result<crate::tunnel::ConnectOutcome, AppError> {
    manager
        .store()
        .save_profiles(std::slice::from_ref(profile))
        .unwrap();
    manager
        .connect(
            &profile.id,
            password.map(|value| Zeroizing::new(value.to_string())),
            None,
            remember,
            false,
            prompter,
        )
        .await
}

#[tokio::test]
async fn local_and_remote_forward_data_then_release_the_listener() {
    let secret = fake_secret();
    let echo = echo_server().await;
    let ssh = ssh_server(secret.clone(), false).await;
    let dir = tempfile::tempdir().unwrap();
    let manager = TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        Arc::new(MemStore {
            values: Mutex::new(std::collections::BTreeMap::new()),
        }),
        isolated_resolver(dir.path()),
    );
    let local_port = free_port();
    let remote_port = free_port();
    let item = profile(
        "live",
        ssh.port(),
        vec![
            mapping(Direction::Local, local_port, echo.port()),
            mapping(Direction::Remote, remote_port, echo.port()),
        ],
        true,
    );
    let outcome = save_and_connect(
        &manager,
        &item,
        Some(&secret),
        true,
        Arc::new(FixedPrompter(true)),
    )
    .await
    .expect("connect");
    assert_eq!(outcome.snapshot.phase, Phase::Connected);
    assert!(
        outcome
            .snapshot
            .forwards
            .iter()
            .all(|forward| forward.state == "listening")
    );
    exchange(
        SocketAddr::from(([127, 0, 0, 1], local_port)),
        b"local-payload",
    )
    .await;
    exchange(
        SocketAddr::from(([127, 0, 0, 1], remote_port)),
        b"remote-payload",
    )
    .await;

    manager.disconnect("live").await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    TcpListener::bind(("127.0.0.1", local_port))
        .await
        .expect("local listener was released");
    TcpListener::bind(("127.0.0.1", remote_port))
        .await
        .expect("remote listener was released");
    assert!(manager.snapshots().is_empty());
    assert_eq!(std::fs::read(dir.path().join("known_hosts")).unwrap(), b"");
    assert_no_secret(dir.path(), &secret);

    let again = save_and_connect(&manager, &item, None, false, Arc::new(FixedPrompter(false)))
        .await
        .expect("reconnect from memory store");
    assert_eq!(again.snapshot.phase, Phase::Connected);
    manager.disconnect_all().await.unwrap();
    assert_no_secret(dir.path(), &secret);
}

#[tokio::test]
async fn rejects_bad_password_changed_key_occupied_port_and_forward_refusal() {
    let secret = fake_secret();
    let echo = echo_server().await;
    let ssh = ssh_server(secret.clone(), false).await;
    let dir = tempfile::tempdir().unwrap();
    let manager = TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        Arc::new(FailingStore),
        isolated_resolver(dir.path()),
    );
    let local_port = free_port();
    let item = profile(
        "bad",
        ssh.port(),
        vec![mapping(Direction::Local, local_port, echo.port())],
        true,
    );
    let other = russh::keys::PrivateKey::random(
        &mut russh::keys::key::safe_rng(),
        russh::keys::Algorithm::Ed25519,
    )
    .unwrap();
    let public = other.public_key();
    let mut trust = TrustStore::default();
    trust.insert(TrustEntry {
        host: "127.0.0.1".into(),
        port: ssh.port(),
        algorithm: known_hosts::algorithm_name(public),
        fingerprint: known_hosts::fingerprint(public),
        public_key: public.to_openssh().unwrap(),
        trusted_at: now_rfc3339(),
    });
    manager.store().save_trust(&trust).unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let changed = save_and_connect(
        &manager,
        &item,
        Some(&secret),
        false,
        Arc::new(CountPrompter {
            calls: calls.clone(),
            accept: true,
        }),
    )
    .await;
    let changed = changed.unwrap_err();
    assert_eq!(changed.code, "host_key_changed");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    manager.store().save_trust(&TrustStore::default()).unwrap();

    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let rejected = save_and_connect(
        &manager,
        &item,
        Some(&secret),
        true,
        Arc::new(CountPrompter {
            calls: calls.clone(),
            accept: false,
        }),
    )
    .await;
    assert_eq!(rejected.unwrap_err().code, "host_key_rejected");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    let wrong = save_and_connect(
        &manager,
        &item,
        Some("not-the-secret"),
        false,
        Arc::new(FixedPrompter(true)),
    )
    .await;
    assert_eq!(wrong.unwrap_err().code, "password_rejected");
    manager.cancel_connect("bad").await.unwrap();
    TcpListener::bind(("127.0.0.1", local_port))
        .await
        .expect("failed auth left no listener");
    assert_no_secret(dir.path(), &secret);
    assert_no_secret(dir.path(), "not-the-secret");

    let blocker = TcpListener::bind(("127.0.0.1", local_port)).await.unwrap();
    let occupied = save_and_connect(
        &manager,
        &item,
        Some(&secret),
        false,
        Arc::new(FixedPrompter(true)),
    )
    .await;
    assert_eq!(occupied.unwrap_err().code, "port_in_use");
    drop(blocker);

    let refusing = ssh_server(secret.clone(), true).await;
    let remote_port = free_port();
    let remote = profile(
        "remote",
        refusing.port(),
        vec![mapping(Direction::Remote, remote_port, echo.port())],
        false,
    );
    let denied = save_and_connect(
        &manager,
        &remote,
        Some(&secret),
        false,
        Arc::new(FixedPrompter(true)),
    )
    .await;
    assert_eq!(denied.unwrap_err().code, "forward_denied");
    assert_no_secret(dir.path(), &secret);
}

#[tokio::test]
async fn remote_forward_remove_reports_cancel_failure_and_keeps_mapping() {
    let secret = fake_secret();
    let echo = echo_server().await;
    let ssh = ssh_server_opts(secret.clone(), false, true).await;
    let dir = tempfile::tempdir().unwrap();
    let manager = TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        Arc::new(MemStore {
            values: Mutex::new(std::collections::BTreeMap::new()),
        }),
        isolated_resolver(dir.path()),
    );
    let remote_port = free_port();
    let item = profile(
        "remote-cancel",
        ssh.port(),
        vec![mapping(Direction::Remote, remote_port, echo.port())],
        false,
    );
    save_and_connect(
        &manager,
        &item,
        Some(&secret),
        false,
        Arc::new(FixedPrompter(true)),
    )
    .await
    .expect("connect");
    exchange(
        SocketAddr::from(([127, 0, 0, 1], remote_port)),
        b"remote-before",
    )
    .await;
    let forward_id = manager.snapshots()[0].forwards[0].id.clone();
    let err = manager
        .remove_runtime_forward("remote-cancel", &forward_id, false)
        .await
        .expect_err("server refused cancel");
    assert_eq!(err.code, "forward_cancel_failed");
    assert_eq!(manager.snapshots()[0].forwards.len(), 1);
    exchange(
        SocketAddr::from(([127, 0, 0, 1], remote_port)),
        b"remote-still",
    )
    .await;
    manager.disconnect("remote-cancel").await.unwrap();
}

#[tokio::test]
async fn cancel_during_slow_password_auth_converges_quickly() {
    let secret = fake_secret();
    let hold = Arc::new(tokio::sync::Notify::new());
    let ssh = ssh_server_delayed(
        secret.clone(),
        false,
        false,
        Some(Arc::clone(&hold)),
        Duration::from_secs(30),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = Arc::new(TunnelManager::new(
        AppStore::open(dir.path()).unwrap(),
        Arc::new(MemStore {
            values: Mutex::new(std::collections::BTreeMap::new()),
        }),
        isolated_resolver(dir.path()),
    ));
    let item = profile(
        "slow-auth",
        ssh.port(),
        vec![mapping(
            Direction::Local,
            free_port(),
            echo_server().await.port(),
        )],
        false,
    );
    let need = save_and_connect(&manager, &item, None, false, Arc::new(FixedPrompter(true)))
        .await
        .expect_err("password required");
    assert_eq!(need.code, "password_required");
    let mgr = Arc::clone(&manager);
    let join = tokio::spawn(async move {
        mgr.connect_challenge_response(
            "slow-auth",
            &need,
            Some(Zeroizing::new(secret.clone())),
            None,
            false,
            false,
            Arc::new(FixedPrompter(true)),
        )
        .await
    });
    hold.notified().await;
    manager.cancel_connect("slow-auth").await.unwrap();
    let finished = tokio::time::timeout(Duration::from_secs(3), join).await;
    let outcome = finished
        .expect("cancel should finish promptly")
        .expect("join");
    assert!(matches!(outcome, Err(err) if err.code == "cancelled"));
    assert!(manager.snapshots().is_empty());
}
