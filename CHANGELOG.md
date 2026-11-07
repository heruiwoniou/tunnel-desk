# Changelog

All notable changes to TunnelDesk are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- On-demand SSH credential prompts after keys, certificates, the agent, and saved
  secrets are tried. The connect flow no longer opens a password dialog first.
- Runtime add and remove of local and remote port forwards on an active tunnel,
  with optional persistence to the profile.
- OpenSSH user certificates from `~/.ssh/config`. Explicit `CertificateFile`
  entries are paired with the matching `IdentityFile`, and `<identity>-cert.pub`
  is discovered automatically when no `CertificateFile` is set. An unlocked
  agent key can sign that certificate without exporting the private key.
- Host certificates signed by a `@cert-authority` key in known_hosts. Revoked
  certificates and authorities are rejected. A certificate that fails for
  another reason falls back to the raw host key inside it.

### Changed

- Tunnel detail layout: clearer spacing, live forward status, and focused
  authentication dialogs with loading states and keyboard-friendly controls.
- `PubkeyAuthentication`, `HostKeyAlias`, and `RevokedHostKeys` are read from
  the resolved host. `IdentitiesOnly` still limits which agent keys are offered.
  Expired, not-yet-valid, mismatched, and unsupported certificates report their
  own error instead of asking for the server password. SHA-1 certificate
  signatures stay disabled.

### Fixed

- Wrong server passwords and key passphrases (including jump hosts) surface as
  `password_rejected` / `passphrase_rejected` so the UI can retry in place.
  Closing the challenge dialog cancels the in-flight SSH attempt; secrets are
  written to the keyring only after a successful connect.
- Runtime forward add/remove is serialized, rolls back on profile save failure,
  and does not report success when remote `cancel_tcpip_forward` fails.
  Natural disconnect and explicit teardown always release jump hops, proxy
  children, listeners, and channels even when multiple handles share the session.
- Tray “Show window” and left-click restore focus on Linux when returning from
  the status icon after hide-to-tray.
- `RevokedHostKeys` is read as one OpenSSH public key per line. A listed host
  key, certificate subject, or signing CA is rejected even when `known_hosts`
  would otherwise trust it. A KRL or a line that is not a public key fails
  closed. Key revocation lists are still not parsed.
- An unlocked agent signing key is used for a configured certificate before
  the matching encrypted `IdentityFile`. Agent-only and automatic connections
  do not ask for that passphrase. `IdentityAgent none` and public-key-only
  mode still use the file.

## [0.1.0] - 2026-11-07

### Added

- Desktop SSH local and remote port forwarding. The app resolves OpenSSH host
  aliases, opens tunnels with an in-process russh client, and stores remembered
  secrets only in the operating system keyring.
- Confirmation for unknown host keys, trust for hashed known_hosts entries, and
  rejection of changed or revoked keys.
- A system tray, Chinese and English interface text, and a theme that can follow
  the system or stay light or dark.
- GitHub Actions workflows that test the app and build unsigned Linux amd64,
  Windows x64, macOS Apple Silicon, and macOS Intel installers. Publishing waits
  until every required platform build has succeeded.

### Fixed

- A destination that refuses a connection no longer drops the whole SSH session.
- The bundle identifier is `dev.tunneldesk.desktop`, so it does not end in
  `.app`. Remembered private-key passphrases are stored separately from server
  passwords.
- Closing the window quits and tears down tunnels when no StatusNotifier host
  is available.

[Unreleased]: https://github.com/heruiwoniou/tunnel-desk/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/heruiwoniou/tunnel-desk/releases/tag/v0.1.0
