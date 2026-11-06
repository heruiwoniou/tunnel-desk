use std::net::IpAddr;

use crate::error::AppError;
use crate::model::{Direction, ForwardMapping};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedForward {
    pub id: String,
    pub direction: Direction,
    pub listen_ip: IpAddr,
    pub listen_port: u16,
    pub destination_host: String,
    pub destination_port: u16,
    pub exposes_network: bool,
}

pub fn validate_mapping(mapping: &ForwardMapping) -> Result<ValidatedForward, AppError> {
    if mapping.listen_port == 0 || mapping.destination_port == 0 {
        return Err(AppError::new("invalid_port", "端口必须在 1 到 65535 之间"));
    }
    let listen_ip: IpAddr = mapping.listen_host.trim().parse().map_err(|_| {
        AppError::new(
            "invalid_listen",
            "监听地址必须是 IP。默认请使用 127.0.0.1 或 ::1",
        )
    })?;
    let exposes_network = !is_loopback(listen_ip);
    if exposes_network && !mapping.allow_external {
        return Err(AppError::new(
            "external_listen",
            "监听地址不是本机回环。若确实要暴露到网络，请显式确认。",
        ));
    }
    let destination_host = normalize_destination(&mapping.destination_host)?;
    Ok(ValidatedForward {
        id: mapping.id.clone(),
        direction: mapping.direction,
        listen_ip,
        listen_port: mapping.listen_port,
        destination_host,
        destination_port: mapping.destination_port,
        exposes_network,
    })
}

pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

pub fn validate_alias(alias: &str) -> Result<(), AppError> {
    validate_token(alias, "invalid_target", "SSH 配置别名")?;
    if alias.contains('*') || alias.contains('?') {
        return Err(AppError::new(
            "invalid_target",
            "通配符主机模式不能当作具体主机连接",
        ));
    }
    Ok(())
}

pub fn validate_hostname(host: &str) -> Result<(), AppError> {
    let host = host.trim();
    if host.is_empty() || host.len() > 253 {
        return Err(AppError::new("invalid_destination", "主机名无效"));
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(host);
    if bare.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    validate_token(host, "invalid_destination", "主机名")?;
    if host.contains('*') || host.contains('?') {
        return Err(AppError::new("invalid_destination", "主机名不能包含通配符"));
    }
    Ok(())
}

pub fn validate_user(user: &str) -> Result<(), AppError> {
    validate_token(user, "invalid_target", "用户名")?;
    if user.contains('@') {
        return Err(AppError::new("invalid_target", "用户名不能包含 @"));
    }
    Ok(())
}

pub fn validate_path_field(path: &str) -> Result<(), AppError> {
    if path.trim().is_empty() || path.len() > 512 || path.chars().any(|c| c.is_control()) {
        return Err(AppError::new("invalid_target", "密钥路径无效"));
    }
    if path.contains('\n') || path.contains('\0') {
        return Err(AppError::new("invalid_target", "密钥路径无效"));
    }
    Ok(())
}

pub fn validate_proxy_jump(spec: &str) -> Result<(), AppError> {
    if spec.len() > 512 {
        return Err(AppError::new("invalid_target", "ProxyJump 无效"));
    }
    if spec.trim().is_empty() {
        return Ok(());
    }
    for hop in spec.split(',') {
        let hop = hop.trim();
        if hop.is_empty() {
            return Err(AppError::new("invalid_target", "ProxyJump 无效"));
        }
        validate_token(hop, "invalid_target", "ProxyJump")?;
    }
    Ok(())
}

pub fn normalize_destination(host: &str) -> Result<String, AppError> {
    let host = host.trim();
    if host.is_empty() || host.len() > 253 {
        return Err(AppError::new("invalid_destination", "目标主机无效"));
    }
    let bare = if host.starts_with('[') {
        host.strip_prefix('[')
            .and_then(|v| v.strip_suffix(']'))
            .ok_or_else(|| AppError::new("invalid_destination", "IPv6 目标地址需要成对的方括号"))?
    } else {
        host
    };
    if bare.parse::<IpAddr>().is_ok() {
        return Ok(bare.to_string());
    }
    if bare.contains(':') {
        return Err(AppError::new(
            "invalid_destination",
            "IPv6 目标地址无法解析。请使用方括号或不带空格的地址",
        ));
    }
    if !is_safe_hostname(bare) {
        return Err(AppError::new(
            "invalid_destination",
            "目标主机包含不允许的字符",
        ));
    }
    Ok(bare.to_string())
}

pub fn validate_token(value: &str, code: &str, label: &str) -> Result<(), AppError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 255 || value.starts_with('-') {
        return Err(AppError::new(code, format!("{label}无效")));
    }
    if value.chars().any(|c| !is_safe_char(c)) {
        return Err(AppError::new(
            code,
            format!("{label}包含不允许的字符，已拒绝以免注入选项或 shell"),
        ));
    }
    Ok(())
}

fn is_safe_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.starts_with('-') || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

fn is_safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '@' | '%' | '[' | ']' | ',')
}

/// Arguments passed to OpenSSH for configuration resolution. Never includes secrets.
pub fn ssh_g_args(config_file: Option<&str>, target: &str) -> Result<Vec<String>, AppError> {
    validate_alias(target).or_else(|_| validate_hostname(target))?;
    let mut args = vec!["-T".to_string()];
    if let Some(config_file) = config_file {
        if config_file.starts_with('-') || config_file.chars().any(|c| c.is_control()) {
            return Err(AppError::new("config", "SSH 配置路径无效"));
        }
        args.push("-F".into());
        args.push(config_file.to_string());
    }
    args.push("-G".into());
    args.push("--".into());
    args.push(target.to_string());
    Ok(args)
}

/// A spawned process is Connected only after authentication and every forward bind succeeds.
pub fn phase_after_bind(results: &[Result<(), ()>]) -> crate::model::Phase {
    if results.iter().all(Result::is_ok) {
        crate::model::Phase::Connected
    } else {
        crate::model::Phase::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Phase;

    fn mapping(
        direction: Direction,
        listen: &str,
        port: u16,
        dest: &str,
        allow_external: bool,
    ) -> ForwardMapping {
        ForwardMapping {
            id: "f".into(),
            direction,
            listen_host: listen.into(),
            listen_port: port,
            destination_host: dest.into(),
            destination_port: 80,
            allow_external,
        }
    }

    #[test]
    fn local_and_remote_defaults_are_loopback() {
        let local = validate_mapping(&mapping(
            Direction::Local,
            "127.0.0.1",
            18080,
            "10.0.0.8",
            false,
        ))
        .unwrap();
        assert_eq!(local.direction, Direction::Local);
        assert!(!local.exposes_network);
        let remote =
            validate_mapping(&mapping(Direction::Remote, "::1", 19090, "[::1]", false)).unwrap();
        assert_eq!(remote.direction, Direction::Remote);
        assert_eq!(remote.destination_host, "::1");
        assert!(!remote.exposes_network);
    }

    #[test]
    fn external_listen_requires_explicit_opt_in() {
        let err = validate_mapping(&mapping(
            Direction::Local,
            "0.0.0.0",
            80,
            "localhost",
            false,
        ))
        .unwrap_err();
        assert_eq!(err.code, "external_listen");
        let ok =
            validate_mapping(&mapping(Direction::Local, "0.0.0.0", 80, "localhost", true)).unwrap();
        assert!(ok.exposes_network);
        let v6 = validate_mapping(&mapping(Direction::Remote, "::", 80, "example.com", false))
            .unwrap_err();
        assert_eq!(v6.code, "external_listen");
    }

    #[test]
    fn rejects_injection_and_bad_ports() {
        assert!(validate_alias("-oProxyCommand=evil").is_err());
        assert!(validate_hostname("example.com;id").is_err());
        assert!(validate_hostname("host\nProxyCommand evil").is_err());
        assert!(validate_alias("*.internal").is_err());
        assert!(normalize_destination("$(id)").is_err());
        assert!(normalize_destination("example.com|nc").is_err());
        let mut bad = mapping(Direction::Local, "127.0.0.1", 0, "example.com", false);
        assert_eq!(validate_mapping(&bad).unwrap_err().code, "invalid_port");
        bad.listen_port = 22;
        bad.destination_host = "bad host".into();
        assert!(validate_mapping(&bad).is_err());
    }

    #[test]
    fn ssh_g_args_are_structured_and_secret_free() {
        let args = ssh_g_args(Some("/tmp/ssh_config"), "dest").unwrap();
        assert_eq!(
            args,
            vec!["-T", "-F", "/tmp/ssh_config", "-G", "--", "dest"]
        );
        assert!(ssh_g_args(None, "-oStrictHostKeyChecking=no").is_err());
        let joined = args.join(" ");
        assert!(!joined.contains("SENTINEL"));
        assert!(!joined.contains("sshpass"));
    }

    #[test]
    fn connected_phase_requires_every_forward() {
        assert_eq!(phase_after_bind(&[Ok(()), Ok(())]), Phase::Connected);
        assert_eq!(phase_after_bind(&[Ok(()), Err(())]), Phase::Failed);
        assert_eq!(phase_after_bind(&[]), Phase::Connected);
    }

    #[test]
    fn ipv6_loopback_is_not_an_exposure() {
        assert!(is_loopback("::1".parse().unwrap()));
        assert!(!is_loopback("::".parse().unwrap()));
        assert!(is_loopback("127.8.8.8".parse().unwrap()));
    }
}
