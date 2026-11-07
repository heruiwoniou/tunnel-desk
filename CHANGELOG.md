# Changelog

All notable changes to TunnelDesk are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
