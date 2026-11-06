use serde::Serialize;

/// User-facing error. `code` is stable for the UI; `message` never includes secrets.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppError {
    pub code: String,
    pub message: String,
}

impl AppError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AppError {}

impl From<russh::Error> for AppError {
    fn from(err: russh::Error) -> Self {
        let raw = err.to_string();
        let code = if matches!(err, russh::Error::RequestDenied)
            || raw.to_ascii_lowercase().contains("denied")
        {
            "forward_denied"
        } else {
            "ssh"
        };
        Self::new(code, sanitize_message(&raw))
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::AddrInUse {
            Self::new("port_in_use", "本地端口已被占用")
        } else {
            Self::new("io", sanitize_message(&err.to_string()))
        }
    }
}

/// Drop anything that looks like a credential accidentally interpolated into an error.
pub fn sanitize_message(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    const MAX: usize = 400;
    if out.chars().count() > MAX {
        out = out.chars().take(MAX).collect();
        out.push('…');
    }
    out
}

pub fn sanitize_secret(text: &str, secret: Option<&str>) -> String {
    let cleaned = sanitize_message(text);
    if let Some(secret) = secret.filter(|s| s.len() >= 4) {
        return cleaned.replace(secret, "••••");
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_controls_and_known_secret() {
        let msg = sanitize_secret(
            "bad\npassword SENTINEL-SECRET-VALUE",
            Some("SENTINEL-SECRET-VALUE"),
        );
        assert!(!msg.contains('\n'));
        assert!(!msg.contains("SENTINEL-SECRET-VALUE"));
        assert!(msg.contains('•'));
    }
}
