use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use crate::error::AppError;
use crate::forward::{ssh_g_args, validate_alias, validate_hostname};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshAlias {
    pub alias: String,
    pub config_path: String,
    pub wildcard: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedHost {
    pub query: String,
    pub hostname: String,
    pub user: String,
    pub port: u16,
    pub identity_files: Vec<String>,
    pub certificate_files: Vec<String>,
    pub identities_only: bool,
    pub pubkey_authentication: bool,
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
    pub identity_agent: Option<String>,
    pub host_key_alias: Option<String>,
    pub known_hosts_files: Vec<String>,
    pub revoked_host_keys: Vec<String>,
    pub preferred_authentications: Vec<String>,
    pub resolution: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Resolver {
    pub user_config: PathBuf,
    pub system_config: Option<PathBuf>,
    pub ssh_binary: Option<PathBuf>,
    pub home: PathBuf,
    pub local_user: String,
    pub local_host: String,
}

impl Resolver {
    pub fn from_env() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            user_config: home.join(".ssh").join("config"),
            system_config: default_system_config(),
            ssh_binary: which_ssh(),
            home,
            local_user: local_user_name(),
            local_host: local_host_name(),
        }
    }

    pub fn list_aliases(&self) -> Result<Vec<SshAlias>, AppError> {
        let mut aliases = Vec::new();
        let mut seen = BTreeSet::new();
        if self.user_config.exists() {
            self.collect_aliases(&self.user_config, 0, &mut seen, &mut aliases)?;
        }
        aliases.retain(|alias| !alias.wildcard);
        Ok(aliases)
    }

    pub fn resolve(&self, query: &str) -> Result<ResolvedHost, AppError> {
        validate_alias(query).or_else(|_| validate_hostname(query))?;
        if let Some(binary) = &self.ssh_binary {
            match self.resolve_with_openssh(binary, query) {
                Ok(mut resolved) => {
                    resolved.warnings.extend(self.builtin_warnings(query));
                    return Ok(resolved);
                }
                Err(err) => {
                    let mut builtin = self.resolve_builtin(query)?;
                    builtin.resolution = "builtin".into();
                    builtin.warnings.insert(
                        0,
                        format!("OpenSSH 解析失败（{}），已使用内置解析器", err.message),
                    );
                    return Ok(builtin);
                }
            }
        }
        let mut builtin = self.resolve_builtin(query)?;
        builtin
            .warnings
            .insert(0, "未找到 ssh 可执行文件，使用内置解析器。Match exec、Canonicalize 和 %C 不会被完整处理。".into());
        Ok(builtin)
    }

    pub fn resolve_builtin(&self, query: &str) -> Result<ResolvedHost, AppError> {
        validate_alias(query).or_else(|_| validate_hostname(query))?;
        let mut acc = Accumulator::default();
        if self.user_config.exists() {
            self.apply_file(&self.user_config, query, 0, &mut acc)?;
        }
        if let Some(system) = &self.system_config
            && system.exists()
        {
            self.apply_file(system, query, 0, &mut acc)?;
        }
        Ok(acc.finish(self, query, "builtin"))
    }

    fn builtin_warnings(&self, query: &str) -> Vec<String> {
        self.resolve_builtin(query)
            .map(|item| item.warnings)
            .unwrap_or_default()
    }

    fn resolve_with_openssh(&self, binary: &Path, query: &str) -> Result<ResolvedHost, AppError> {
        let config_arg = self
            .user_config
            .exists()
            .then(|| self.user_config.to_string_lossy().to_string());
        let args = ssh_g_args(config_arg.as_deref(), query)?;
        let output = Command::new(binary)
            .args(&args)
            .env_remove("SSH_ASKPASS")
            .env_remove("SSH_ASKPASS_REQUIRE")
            .output()
            .map_err(|err| AppError::new("config", format!("无法执行 ssh: {err}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::new(
                "config",
                format!("ssh -G 失败: {}", stderr.trim()),
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(parse_ssh_g(&text, self, query))
    }

    fn collect_aliases(
        &self,
        path: &Path,
        depth: usize,
        seen_files: &mut BTreeSet<PathBuf>,
        out: &mut Vec<SshAlias>,
    ) -> Result<(), AppError> {
        if depth > 8 {
            return Err(AppError::new("config", "SSH 配置 Include 嵌套过深"));
        }
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if !seen_files.insert(canonical) {
            return Ok(());
        }
        let text = std::fs::read_to_string(path).map_err(|err| {
            AppError::new("config", format!("无法读取 {}: {err}", path.display()))
        })?;
        for raw in text.lines() {
            let tokens = tokenize(raw);
            if tokens.is_empty() {
                continue;
            }
            let keyword = tokens[0].to_ascii_lowercase();
            if keyword == "host" {
                for pattern in tokens.iter().skip(1) {
                    let wildcard =
                        pattern.contains('*') || pattern.contains('?') || pattern.starts_with('!');
                    let alias = pattern.trim_start_matches('!').to_string();
                    if alias.is_empty() {
                        continue;
                    }
                    if !wildcard {
                        out.push(SshAlias {
                            alias,
                            config_path: path.display().to_string(),
                            wildcard: false,
                        });
                    }
                }
            } else if keyword == "include" {
                let include_base = path.parent().unwrap_or(Path::new("."));
                for pattern in tokens.iter().skip(1) {
                    for file in expand_include(pattern, include_base, &self.home)? {
                        self.collect_aliases(&file, depth + 1, seen_files, out)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn apply_file(
        &self,
        path: &Path,
        query: &str,
        depth: usize,
        acc: &mut Accumulator,
    ) -> Result<(), AppError> {
        if depth > 8 {
            return Err(AppError::new("config", "SSH 配置 Include 嵌套过深"));
        }
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if !acc.files.insert(canonical) {
            return Ok(());
        }
        let text = std::fs::read_to_string(path).map_err(|err| {
            AppError::new("config", format!("无法读取 {}: {err}", path.display()))
        })?;
        let mut active = false;
        for raw in text.lines() {
            let tokens = tokenize(raw);
            if tokens.is_empty() {
                continue;
            }
            let keyword = tokens[0].to_ascii_lowercase();
            let values = &tokens[1..];
            match keyword.as_str() {
                "host" => active = host_patterns_match(values, query),
                "match" => {
                    active = match eval_match(values, query, &self.local_user) {
                        MatchEval::Applies(value) => value,
                        MatchEval::Unsupported(reason) => {
                            acc.warn(format!("内置解析器跳过不受支持的 Match（{reason}）。安装 OpenSSH 后会改用 ssh -G。"));
                            false
                        }
                    };
                }
                "include" => {
                    let include_base = path.parent().unwrap_or(Path::new("."));
                    for pattern in values {
                        for file in expand_include(pattern, include_base, &self.home)? {
                            self.apply_file(&file, query, depth + 1, acc)?;
                        }
                    }
                }
                _ if active => acc.apply(&keyword, values),
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct Accumulator {
    scalars: BTreeMap<String, String>,
    identity_files: Vec<String>,
    certificate_files: Vec<String>,
    known_hosts: Vec<String>,
    warnings: Vec<String>,
    files: BTreeSet<PathBuf>,
    saw_local_forward: bool,
    saw_remote_forward: bool,
}

impl Accumulator {
    fn apply(&mut self, keyword: &str, values: &[String]) {
        let joined = values.join(" ");
        match keyword {
            "hostname"
            | "user"
            | "port"
            | "proxyjump"
            | "proxycommand"
            | "identityagent"
            | "identitiesonly"
            | "stricthostkeychecking"
            | "forwardagent"
            | "pkcs11provider"
            | "gssapiauthentication"
            | "canonicalizehostname"
            | "proxyusefdpass"
            | "preferredauthentications"
            | "pubkeyauthentication"
            | "hostkeyalias"
            | "revokedhostkeys"
            | "securitykeyprovider" => {
                self.scalars.entry(keyword.to_string()).or_insert(joined);
            }
            "identityfile" => {
                if joined != "none" {
                    self.identity_files.push(joined);
                }
            }
            "certificatefile" => {
                if !joined.is_empty() && joined != "none" {
                    self.certificate_files.push(joined);
                }
            }
            "userknownhostsfile" | "globalknownhostsfile" => {
                self.known_hosts.extend(values.iter().cloned());
            }
            "localforward" => self.saw_local_forward = true,
            "remoteforward" => self.saw_remote_forward = true,
            _ => {}
        }
    }

    fn warn(&mut self, warning: String) {
        if !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }

    fn finish(mut self, resolver: &Resolver, query: &str, resolution: &str) -> ResolvedHost {
        if self.saw_local_forward || self.saw_remote_forward {
            self.warn("ssh 配置里的 LocalForward / RemoteForward 不会自动启用。请在 TunnelDesk 中显式添加映射。".into());
        }
        let original = query.to_string();
        let hostname_raw = self
            .scalars
            .get("hostname")
            .cloned()
            .unwrap_or_else(|| original.clone());
        let hostname = expand_tokens(
            &hostname_raw,
            resolver,
            &original,
            &original,
            "22",
            &resolver.local_user,
        );
        let user_raw = self
            .scalars
            .get("user")
            .cloned()
            .unwrap_or_else(|| resolver.local_user.clone());
        let user = expand_tokens(
            &user_raw,
            resolver,
            &original,
            &hostname,
            "22",
            &resolver.local_user,
        );
        let port = self
            .scalars
            .get("port")
            .and_then(|value| value.parse().ok())
            .unwrap_or(22);
        let port_string = port.to_string();
        let expand_path = |path: &String| {
            expand_tilde(
                &expand_tokens(path, resolver, &original, &hostname, &port_string, &user),
                &resolver.home,
            )
        };
        let identity_files = self
            .identity_files
            .iter()
            .map(expand_path)
            .collect::<Vec<_>>();
        let certificate_files = self
            .certificate_files
            .iter()
            .map(expand_path)
            .collect::<Vec<_>>();
        let proxy_jump = optional_none(self.scalars.get("proxyjump")).map(|value| {
            expand_tokens(&value, resolver, &original, &hostname, &port_string, &user)
        });
        let proxy_command = optional_none(self.scalars.get("proxycommand")).map(|value| {
            expand_tokens(&value, resolver, &original, &hostname, &port_string, &user)
        });
        if proxy_command
            .as_deref()
            .is_some_and(|value| value.contains("%C"))
            || identity_files.iter().any(|path| path.contains("%C"))
        {
            self.warn("令牌 %C 未被展开。".into());
        }
        let scalars = self.scalars.clone();
        push_standard_warnings(&mut self, &scalars);
        let known_hosts_files = if self.known_hosts.is_empty() {
            crate::known_hosts::default_known_hosts(&resolver.home)
                .into_iter()
                .map(|path| path.display().to_string())
                .collect()
        } else {
            self.known_hosts
                .iter()
                .map(|path| {
                    expand_tilde(
                        &expand_tokens(path, resolver, &original, &hostname, &port_string, &user),
                        &resolver.home,
                    )
                })
                .collect()
        };
        ResolvedHost {
            query: query.into(),
            hostname: hostname.clone(),
            user: user.clone(),
            port,
            identity_files,
            certificate_files,
            identities_only: self
                .scalars
                .get("identitiesonly")
                .map(|v| v == "yes")
                .unwrap_or(false),
            pubkey_authentication: pubkey_enabled(self.scalars.get("pubkeyauthentication")),
            proxy_jump,
            proxy_command,
            identity_agent: agent_setting(self.scalars.get("identityagent"), &resolver.home),
            host_key_alias: optional_none(self.scalars.get("hostkeyalias")).map(|value| {
                expand_tilde(
                    &expand_tokens(&value, resolver, &original, &hostname, &port_string, &user),
                    &resolver.home,
                )
            }),
            known_hosts_files,
            revoked_host_keys: optional_none(self.scalars.get("revokedhostkeys"))
                .map(|value| split_path_list(&value))
                .unwrap_or_default()
                .into_iter()
                .map(|path| {
                    expand_tilde(
                        &expand_tokens(&path, resolver, &original, &hostname, &port_string, &user),
                        &resolver.home,
                    )
                })
                .collect(),
            preferred_authentications: self
                .scalars
                .get("preferredauthentications")
                .map(|value| {
                    value
                        .split(',')
                        .map(|item| item.trim().to_string())
                        .filter(|item| !item.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            resolution: resolution.into(),
            warnings: self.warnings,
        }
    }
}

fn push_standard_warnings(acc: &mut Accumulator, scalars: &BTreeMap<String, String>) {
    if scalars
        .get("forwardagent")
        .map(|v| v == "yes")
        .unwrap_or(false)
    {
        acc.warn("配置中的 ForwardAgent 不会被启用。TunnelDesk 不转发 SSH agent。".into());
    }
    if scalars
        .get("stricthostkeychecking")
        .map(|v| matches!(v.as_str(), "no" | "off" | "accept-new"))
        .unwrap_or(false)
    {
        acc.warn("TunnelDesk 不沿用 StrictHostKeyChecking=no/accept-new。未知主机会要求确认，已变化的主机密钥会被拒绝。".into());
    }
    if scalars
        .get("gssapiauthentication")
        .map(|v| v == "yes")
        .unwrap_or(false)
    {
        acc.warn("不支持 GSSAPI 认证。".into());
    }
    if scalars
        .get("pkcs11provider")
        .map(|v| v != "none")
        .unwrap_or(false)
    {
        acc.warn("不支持 PKCS11Provider。".into());
    }
    if scalars
        .get("securitykeyprovider")
        .map(|v| !v.is_empty() && v != "none")
        .unwrap_or(false)
    {
        acc.warn("不支持 SecurityKeyProvider。FIDO/安全密钥没有当作已验证的登录方式。".into());
    }
    if scalars
        .get("proxyusefdpass")
        .map(|v| v == "yes")
        .unwrap_or(false)
    {
        acc.warn("不支持 ProxyUseFdpass。".into());
    }
    if scalars
        .get("canonicalizehostname")
        .map(|v| v != "no" && v != "false")
        .unwrap_or(false)
    {
        acc.warn(
            "内置解析器不执行 CanonicalizeHostname。ssh -G 可用时以 OpenSSH 的结果为准。".into(),
        );
    }
}

fn parse_ssh_g(text: &str, resolver: &Resolver, query: &str) -> ResolvedHost {
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(|c: char| c.is_whitespace()) else {
            continue;
        };
        values
            .entry(key.to_ascii_lowercase())
            .or_default()
            .push(value.trim().to_string());
    }
    let first = |key: &str| values.get(key).and_then(|items| items.first()).cloned();
    let hostname = first("hostname").unwrap_or_else(|| query.to_string());
    let user = first("user").unwrap_or_else(|| resolver.local_user.clone());
    let port = first("port")
        .and_then(|value| value.parse().ok())
        .unwrap_or(22);
    let expand = |path: String| expand_tilde(&path, &resolver.home);
    let identity_files = values
        .get("identityfile")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|path| path != "none")
        .map(expand)
        .collect();
    let certificate_files = values
        .get("certificatefile")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|path| path != "none")
        .map(|path| expand_tilde(&path, &resolver.home))
        .collect();
    let known_hosts_files = ["userknownhostsfile", "globalknownhostsfile"]
        .into_iter()
        .flat_map(|key| values.get(key).cloned().unwrap_or_default())
        .flat_map(|value| split_path_list(&value))
        .map(|path| expand_tilde(&path, &resolver.home))
        .collect();
    let mut warnings = Vec::new();
    let scalars = values
        .iter()
        .filter_map(|(key, items)| items.first().map(|value| (key.clone(), value.clone())))
        .collect::<BTreeMap<_, _>>();
    let mut acc = Accumulator::default();
    push_standard_warnings(&mut acc, &scalars);
    if values
        .get("localforward")
        .is_some_and(|items| items.iter().any(|v| !v.is_empty()))
        || values
            .get("remoteforward")
            .is_some_and(|items| items.iter().any(|v| !v.is_empty()))
    {
        acc.warn("ssh 配置里的 LocalForward / RemoteForward 不会自动启用。请在 TunnelDesk 中显式添加映射。".into());
    }
    warnings.extend(acc.warnings);
    ResolvedHost {
        query: query.into(),
        hostname,
        user,
        port,
        identity_files,
        certificate_files,
        identities_only: first("identitiesonly").as_deref() == Some("yes"),
        pubkey_authentication: pubkey_enabled(scalars.get("pubkeyauthentication")),
        proxy_jump: optional_none(scalars.get("proxyjump")),
        proxy_command: optional_none(scalars.get("proxycommand")),
        identity_agent: agent_setting(scalars.get("identityagent"), &resolver.home),
        host_key_alias: optional_none(scalars.get("hostkeyalias")),
        known_hosts_files,
        revoked_host_keys: optional_none(scalars.get("revokedhostkeys"))
            .map(|value| {
                split_path_list(&value)
                    .into_iter()
                    .map(|path| expand_tilde(&path, &resolver.home))
                    .collect()
            })
            .unwrap_or_default(),
        preferred_authentications: first("preferredauthentications")
            .map(|value| {
                value
                    .split(',')
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        resolution: "openssh".into(),
        warnings,
    }
}

/// `IdentityAgent none` disables the agent. Unlike ProxyCommand, the word
/// `none` is a real setting and must not collapse to "use the default agent".
fn agent_setting(value: Option<&String>, home: &Path) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(expand_tilde(trimmed, home))
        }
    })
}

fn pubkey_enabled(value: Option<&String>) -> bool {
    !matches!(
        value
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref(),
        Some("no" | "false" | "off")
    )
}

fn optional_none(value: Option<&String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed == "none" {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn split_path_list(value: &str) -> Vec<String> {
    let tokens: Vec<&str> = value.split_whitespace().collect();
    if tokens.len() > 1
        && tokens
            .iter()
            .all(|token| token.starts_with('/') || token.starts_with('~'))
    {
        tokens.into_iter().map(str::to_string).collect()
    } else if value.trim().is_empty() {
        Vec::new()
    } else {
        vec![value.trim().to_string()]
    }
}

enum MatchEval {
    Applies(bool),
    Unsupported(String),
}

fn eval_match(tokens: &[String], host: &str, local_user: &str) -> MatchEval {
    if tokens.is_empty() {
        return MatchEval::Applies(false);
    }
    let mut index = 0;
    let mut ok = true;
    while index < tokens.len() {
        let key = tokens[index].to_ascii_lowercase();
        if key == "all" {
            index += 1;
            continue;
        }
        let Some(value) = tokens.get(index + 1) else {
            return MatchEval::Unsupported(key);
        };
        match key.as_str() {
            "host" | "originalhost" => {
                if !host_patterns_match(std::slice::from_ref(value), host) {
                    ok = false;
                }
            }
            "user" => {
                if !host_patterns_match(std::slice::from_ref(value), host)
                    && !value.eq_ignore_ascii_case(host)
                {
                    // user is not known yet during a pure host lookup; compare later if the token is the host by mistake
                }
                if !glob_match_ci(value, host) && key == "user" {
                    // Without a resolved user, a user criterion cannot be confirmed. Mark unsupported only when it is not a plain pattern we can ignore.
                }
                if key == "user" {
                    return MatchEval::Unsupported("user 条件需要 ssh -G 才能在连接前确定".into());
                }
            }
            "localuser" => {
                if !glob_match_ci(value, local_user) {
                    ok = false;
                }
            }
            "exec" | "canonical" | "final" | "localnetwork" | "tagged" => {
                return MatchEval::Unsupported(key);
            }
            _ => return MatchEval::Unsupported(key),
        }
        index += 2;
    }
    MatchEval::Applies(ok)
}

fn host_patterns_match(patterns: &[String], host: &str) -> bool {
    let mut positive = false;
    for pattern in patterns {
        let negated = pattern.starts_with('!');
        let body = pattern.trim_start_matches('!');
        let matched = glob_match_ci(body, host);
        if negated && matched {
            return false;
        }
        if !negated && matched {
            positive = true;
        }
    }
    positive
}

fn glob_match_ci(pattern: &str, text: &str) -> bool {
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
            let equal = pattern[p].eq_ignore_ascii_case(&text[t]) || pattern[p] == b'?';
            if !equal {
                return false;
            }
            p += 1;
            t += 1;
        }
        t == text.len()
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for ch in line.chars() {
        if let Some(mark) = quote {
            if ch == mark {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            continue;
        }
        if ch == '#' {
            break;
        }
        if ch.is_whitespace() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        out.push(current);
    }
    if out.len() == 1
        && let Some((key, value)) = out[0].split_once('=')
        && !key.is_empty()
        && !value.is_empty()
        && !key.contains('/')
    {
        return vec![key.to_string(), value.to_string()];
    }
    out
}

fn expand_include(pattern: &str, base: &Path, home: &Path) -> Result<Vec<PathBuf>, AppError> {
    let expanded = expand_tilde(pattern, home);
    let path = if Path::new(&expanded).is_absolute() {
        PathBuf::from(&expanded)
    } else {
        base.join(expanded)
    };
    let text = path.to_string_lossy().to_string();
    if text.contains('*') || text.contains('?') {
        let paths = glob::glob(&text).map_err(|err| AppError::new("config", err.to_string()))?;
        let mut files = Vec::new();
        for item in paths {
            let item = item.map_err(|err| AppError::new("config", err.to_string()))?;
            if item.is_file() {
                files.push(item);
            }
        }
        files.sort();
        Ok(files)
    } else if path.is_file() {
        Ok(vec![path])
    } else {
        Ok(Vec::new())
    }
}

fn expand_tilde(path: &str, home: &Path) -> String {
    if path == "~" {
        home.display().to_string()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest).display().to_string()
    } else {
        path.to_string()
    }
}

fn expand_tokens(
    value: &str,
    resolver: &Resolver,
    original: &str,
    hostname: &str,
    port: &str,
    remote_user: &str,
) -> String {
    let mut out = String::new();
    let chars: Vec<char> = value.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '%' && index + 1 < chars.len() {
            match chars[index + 1] {
                '%' => out.push('%'),
                'h' => out.push_str(hostname),
                'n' => out.push_str(original),
                'd' => out.push_str(&resolver.home.display().to_string()),
                'u' => out.push_str(&resolver.local_user),
                'l' => out.push_str(&resolver.local_host),
                'p' => out.push_str(port),
                'r' => out.push_str(remote_user),
                other => {
                    out.push('%');
                    out.push(other);
                }
            }
            index += 2;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

fn default_system_config() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var("ProgramData")
            .ok()
            .map(|dir| PathBuf::from(dir).join("ssh").join("ssh_config"))
    } else {
        Some(PathBuf::from("/etc/ssh/ssh_config"))
    }
}

fn which_ssh() -> Option<PathBuf> {
    let name = if cfg!(windows) { "ssh.exe" } else { "ssh" };
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn local_user_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".into())
}

fn local_host_name() -> String {
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        return name;
    }
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

pub fn windows_ssh_config_from_profile(profile: &Path) -> PathBuf {
    profile.join(".ssh").join("config")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver(dir: &Path) -> Resolver {
        Resolver {
            user_config: dir.join("config"),
            system_config: Some(dir.join("system")),
            ssh_binary: which_ssh(),
            home: dir.to_path_buf(),
            local_user: "rui".into(),
            local_host: "laptop".into(),
        }
    }

    #[test]
    fn lists_concrete_aliases_and_applies_first_value_semantics() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("extra"),
            "Host included\n  HostName included.example\n  User frominclude\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("config"),
            r#"
Host *
  User wildcard
  IdentityFile ~/.ssh/default_ed25519

Host dest other
  HostName dest.example
  User destuser
  Port 2222
  IdentityFile ~/.ssh/id_ed25519
  ProxyJump jump
  IdentityAgent none
  LocalForward 127.0.0.1:8080 localhost:80

Host *.internal
  User inside

Host !skip *.example
  User patterned

Include extra

Match exec "true" host dest
  User should-not-apply

Host jump
  HostName 10.0.0.8
  User jumper
"#,
        )
        .unwrap();
        let resolver = resolver(dir.path());
        let aliases = resolver.list_aliases().unwrap();
        let names: Vec<_> = aliases.into_iter().map(|item| item.alias).collect();
        assert!(names.contains(&"dest".to_string()));
        assert!(names.contains(&"other".to_string()));
        assert!(names.contains(&"included".to_string()));
        assert!(names.contains(&"jump".to_string()));
        assert!(!names.iter().any(|name| name.contains('*')));
        assert!(!names.iter().any(|name| name == "skip"));

        let resolved = resolver.resolve_builtin("dest").unwrap();
        assert_eq!(resolved.user, "wildcard");
        assert_eq!(resolved.hostname, "dest.example");
        assert_eq!(resolved.port, 2222);
        assert_eq!(resolved.identity_files.len(), 2);
        assert_eq!(resolved.proxy_jump.as_deref(), Some("jump"));
        assert_eq!(resolved.identity_agent.as_deref(), Some("none"));
        assert!(
            resolved
                .warnings
                .iter()
                .any(|warning| warning.contains("LocalForward"))
        );
        assert!(
            resolved
                .warnings
                .iter()
                .any(|warning| warning.contains("Match"))
        );
        let included = resolver.resolve_builtin("included").unwrap();
        assert_eq!(included.hostname, "included.example");
        assert_eq!(included.user, "wildcard");
    }

    #[test]
    fn specific_host_before_wildcard_wins() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config"),
            "Host dest\n  User special\n\nHost *\n  User fallback\n",
        )
        .unwrap();
        let resolved = resolver(dir.path()).resolve_builtin("dest").unwrap();
        assert_eq!(resolved.user, "special");
        let other = resolver(dir.path())
            .resolve_builtin("plain.example")
            .unwrap();
        assert_eq!(other.user, "fallback");
    }

    #[test]
    fn certificate_files_accumulate_and_scalar_options_keep_the_first_value() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config"),
            "\
Host bastion
  HostName bastion.example
  User ops
  Port 2222
  IdentityFile id_a
  IdentityFile id_b
  CertificateFile cert_a
  CertificateFile cert_b
  IdentitiesOnly yes
  IdentitiesOnly no
  PubkeyAuthentication no
  PubkeyAuthentication yes
  HostKeyAlias alias.example
  HostKeyAlias other.example
  IdentityAgent none
  RevokedHostKeys revoked
",
        )
        .unwrap();
        let resolved = resolver(dir.path()).resolve_builtin("bastion").unwrap();
        assert_eq!(resolved.identity_files, vec!["id_a", "id_b"]);
        assert_eq!(resolved.certificate_files, vec!["cert_a", "cert_b"]);
        assert!(resolved.identities_only);
        assert!(!resolved.pubkey_authentication);
        assert_eq!(resolved.host_key_alias.as_deref(), Some("alias.example"));
        assert_eq!(resolved.revoked_host_keys, vec!["revoked"]);
        assert!(
            !resolved
                .warnings
                .iter()
                .any(|warning| warning.contains("不会用证书"))
        );
    }

    #[test]
    fn openssh_resolution_matches_builtin_precedence_when_available() {
        let ssh = match which_ssh() {
            Some(path) => path,
            None => return,
        };
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config"),
            "Host *\n  User first\n\nHost dest\n  HostName dest.example\n  User second\n  IdentityFile ~/id_test\n",
        )
        .unwrap();
        let mut resolver = resolver(dir.path());
        resolver.ssh_binary = Some(ssh);
        let resolved = resolver.resolve("dest").unwrap();
        assert_eq!(resolved.resolution, "openssh");
        assert_eq!(resolved.user, "first");
        assert_eq!(resolved.hostname, "dest.example");
        assert!(
            resolved
                .identity_files
                .iter()
                .any(|path| path.ends_with("id_test"))
        );
        assert!(
            resolved
                .warnings
                .iter()
                .all(|warning| !warning.contains("SENTINEL"))
        );
    }

    #[test]
    fn wildcard_is_not_resolved_as_a_concrete_host() {
        let err = validate_alias("*").unwrap_err();
        assert_eq!(err.code, "invalid_target");
    }
}
