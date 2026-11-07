# Releasing TunnelDesk

TunnelDesk versions are [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
without build metadata. The same version string is stored in:

- `package.json`
- `package-lock.json` (the root package only)
- `src-tauri/Cargo.toml`
- `src-tauri/Cargo.lock` (the `tunneldesk` package only)
- `src-tauri/tauri.conf.json`

The running app reports `CARGO_PKG_VERSION` from `Cargo.toml`. The installer
version comes from `tauri.conf.json`. `npm run version:check` rejects drift,
a `v` prefix, build metadata (`+`), and numbers Windows installers cannot
encode (`major` or `minor` above 255, `patch` above 65535).

`0.1.0` is the preview already described in this repository. Do not bump it
only to exercise this workflow.

## Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Put new notes under `## [Unreleased]`. Version headings look like
`## [0.2.0] - 2026-11-07` and stay in newest-first order. Release notes are
that section plus a generated unsigned-build notice.

## Prepare a version

From a clean tree, with notes already under `Unreleased`:

```bash
npm run version:prepare -- 0.2.0
npm run version:check
```

`version:prepare` writes the version into every manifest above and moves the
Unreleased notes under `## [0.2.0] - <UTC date>`. It does not create a commit
or a tag. Pass `--date YYYY-MM-DD` only when the UTC date should not be used.
Review the diff, then commit it.

A prerelease is a normal SemVer tag such as `v0.2.0-rc.1`. The GitHub Release
is marked as a prerelease.

Windows packaging follows Tauri 2.12:

- An MSI is built when the version has no prerelease, or when the prerelease
  is a single integer from 0 through 65535 (`0.2.0-1`). WiX rejects other
  prerelease labels.
- NSIS is always built. For a label such as `rc.1`, its numeric product
  version keeps only `major.minor.patch`. Do not expect Windows to order
  `0.2.0-rc.1` and `0.2.0` as different installer versions.
- Those prereleases publish the NSIS installer and do not publish an MSI.
  The release is still gated on every asset that version is supposed to ship.

## CI

`.github/workflows/ci.yml` runs on pull requests, on pushes to `main`, and
from the Actions tab. It does not create tags or GitHub Releases.

The checks job runs actionlint 1.7.12, shellcheck, frontend lint, typecheck,
Vitest, `version:check`, `cargo fmt --check`, and `cargo test --locked`.

The package job builds installers and uploads them as workflow artifacts:

| Runner | Rust target | Asset |
| --- | --- | --- |
| `ubuntu-24.04` | `x86_64-unknown-linux-gnu` | `TunnelDesk_<version>_linux_amd64.deb` |
| `windows-2025` | `x86_64-pc-windows-msvc` | `TunnelDesk_<version>_windows_x64-setup.exe` and, when WiX accepts the version, `TunnelDesk_<version>_windows_x64.msi` |
| `macos-26` | `aarch64-apple-darwin` | `TunnelDesk_<version>_macos_aarch64.dmg` |
| `macos-15-intel` | `x86_64-apple-darwin` | `TunnelDesk_<version>_macos_x64.dmg` |

`ubuntu-24.04` is pinned because `ubuntu-latest` is moving to Ubuntu 26.04
through 2026-11-19. `windows-2025` and `macos-26` are the current x64 and
Apple Silicon images. `macos-latest` is Apple Silicon, so it is not used as
an Intel label. GitHub documents `macos-15-intel` as the Intel image
available through August 2027. No arm64 Windows or Linux installer is built.

Fork pull requests still build. They skip artifact upload because their
token cannot write artifacts. The workflow never uses `pull_request_target`.

These runs need outbound network access for npm, crates.io, and the Tauri
tool download. They need no repository secrets. Rust is installed from
`dtolnay/rust-toolchain@stable` because `Cargo.toml` requires Rust 1.90.
Node is 22.

A green installer build does not show that the window, tray, or OS keyring
was used on that platform. Linux is the only system where those behaviors
have been exercised in a desktop session.

## First release

Do this after the release workflow is on `main` and CI for that commit is
green. The tag push has to come from credentials that are allowed to start
workflows. A tag created by `GITHUB_TOKEN` does not start another workflow.
This repository therefore does not use one workflow to push a tag and a
second workflow to notice that tag.

1. Check out the commit you intend to ship and confirm
   `npm run version:check` passes. For the first release the version is
   already `0.1.0`, with notes in `## [0.1.0]`.
2. Create the tag locally and push that tag yourself:

   ```bash
   git switch main
   git pull origin main
   git tag -a v0.1.0 -m "TunnelDesk 0.1.0"
   git push origin v0.1.0
   ```

3. Open the `release` workflow run for `v0.1.0`. The publish job is skipped
   unless the Linux, Windows, Apple Silicon, and Intel jobs all succeed.
   It then checks the asset names, writes `SHA256SUMS.txt`, creates a draft,
   and publishes the draft only after the asset set matches.
4. Confirm the Release is not a draft and that every file below is attached.
   `sha256sum -c SHA256SUMS.txt` checks the downloads.

The manual path is the same workflow, not a follow-up workflow. In the
Actions tab choose `release`, then Run workflow on the commit you want to
ship. Set `tag` to `v0.1.0` and set `confirm` to `publish`. The run builds
that commit and publishes at the end. The tag it creates with `GITHUB_TOKEN`
does not start a second run. Leave `confirm` empty and the run stops before
building.

Do not start both the tag push and the manual run for the same version.
Publishing refuses to replace a release that is already public. A failed
run may leave a draft; a later run for the same commit deletes that draft
and tries again. It does not delete the git tag. If GitHub reports a draft
target this script does not recognize, delete the draft in the Releases UI
and run the workflow again.

Later releases use the same tag shape: `v` plus the manifest version, for
example `v0.2.0` or `v0.2.0-rc.1`.

## Unsigned builds

No signing or notarization secrets are configured, and this setup does not
ask for them.

- The Linux `.deb` is unsigned.
- The Windows NSIS and MSI installers are unsigned. SmartScreen will warn.
- macOS builds set `APPLE_SIGNING_IDENTITY=-`. That is an ad-hoc signature,
  which Tauri documents for Apple Silicon apps downloaded without an Apple
  certificate. It is not a Developer ID signature and it is not notarization.
  Gatekeeper will still warn. The DMG itself is not Apple-notarized; Tauri
  skips DMG signing for the ad-hoc identity.

An owner can add signing later with certificates they already control:

- macOS: a Developer ID Application certificate and App Store Connect
  notarization credentials, passed as the `APPLE_CERTIFICATE`,
  `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, and notarization
  variables documented by Tauri.
- Windows: an Authenticode certificate for `signtool`, configured outside
  this workflow.

Until those secrets exist, releases stay unsigned. Do not describe an
artifact as signed or notarized.
