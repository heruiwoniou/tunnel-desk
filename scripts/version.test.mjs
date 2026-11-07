import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  assertDraftRelease,
  assertSupportedVersion,
  checkRepository,
  collectBundles,
  compareSemver,
  parseChangelog,
  parseSemver,
  prepareRepository,
  releaseAssetNames,
  releaseNotes,
  renderChangelog,
  stageAssets,
  VersionError,
  windowsBundles,
  windowsMsiSupported,
} from "./version.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function writeFixture(root, version = "0.1.0", changelogBody = "### Added\n\n- notes") {
  mkdirSync(path.join(root, "src-tauri"), { recursive: true });
  writeFileSync(
    path.join(root, "package.json"),
    `{\n  "name": "tunneldesk",\n  "version": "${version}",\n  "private": true\n}\n`,
  );
  writeFileSync(
    path.join(root, "package-lock.json"),
    `{
  "name": "tunneldesk",
  "version": "${version}",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "tunneldesk",
      "version": "${version}"
    },
    "node_modules/yocto-queue": {
      "version": "0.1.0"
    }
  }
}
`,
  );
  writeFileSync(
    path.join(root, "src-tauri", "Cargo.toml"),
    `[package]
name = "tunneldesk"
version = "${version}"
description = "fixture"

[dependencies]
serde = { version = "1", features = ["derive"] }
`,
  );
  writeFileSync(
    path.join(root, "src-tauri", "Cargo.lock"),
    `[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "tunneldesk"
version = "${version}"
dependencies = [
 "serde",
]

[[package]]
name = "other"
version = "0.1.0"
`,
  );
  writeFileSync(
    path.join(root, "src-tauri", "tauri.conf.json"),
    `{\n  "productName": "TunnelDesk",\n  "version": "${version}",\n  "identifier": "dev.tunneldesk.desktop"\n}\n`,
  );
  writeFileSync(
    path.join(root, "CHANGELOG.md"),
    `# Changelog

Notes for the fixture.

## [Unreleased]

## [${version}] - 2026-11-07

${changelogBody}

[Unreleased]: https://github.com/heruiwoniou/tunnel-desk/compare/v${version}...HEAD
[${version}]: https://github.com/heruiwoniou/tunnel-desk/releases/tag/v${version}
`,
  );
}

function tempRepo(version) {
  const root = mkdtempSync(path.join(tmpdir(), "tunneldesk-version-"));
  writeFixture(root, version);
  return root;
}

describe("semver", () => {
  it("accepts release and prerelease versions", () => {
    expect(parseSemver("0.1.0")).toMatchObject({ major: 0, minor: 1, patch: 0, prerelease: [] });
    expect(parseSemver("255.255.65535").raw).toBe("255.255.65535");
    expect(parseSemver("1.2.3-rc.1").prerelease).toEqual(["rc", "1"]);
    expect(parseSemver("1.2.3-0").prerelease).toEqual(["0"]);
  });

  it.each([
    "",
    " ",
    "v0.1.0",
    "V0.1.0",
    "0.1",
    "0.1.0.1",
    "01.2.3",
    "1.02.3",
    "1.2.03",
    "1.2.3-",
    "1.2.3-rc.",
    "1.2.3-01",
    "1.2.3+build",
    "1.2.3-rc.1+5",
    "1.2.3-β",
  ])("rejects %j", (input) => {
    expect(() => parseSemver(input)).toThrow(VersionError);
  });

  it("rejects Windows numeric limits", () => {
    expect(() => assertSupportedVersion("256.0.0")).toThrow(/major/);
    expect(() => assertSupportedVersion("1.256.0")).toThrow(/minor/);
    expect(() => assertSupportedVersion("1.0.65536")).toThrow(/patch/);
  });

  it("orders prerelease below the final release", () => {
    expect(compareSemver("1.0.0-alpha", "1.0.0")).toBeLessThan(0);
    expect(compareSemver("1.0.0-alpha.1", "1.0.0-alpha.beta")).toBeLessThan(0);
    expect(compareSemver("1.0.0-1", "1.0.0-alpha")).toBeLessThan(0);
    expect(compareSemver("1.0.0", "1.0.0")).toBe(0);
  });
});

describe("Windows bundles", () => {
  it("builds MSI for stable versions and numeric prereleases only", () => {
    expect(windowsMsiSupported("0.1.0")).toBe(true);
    expect(windowsMsiSupported("0.2.0-1")).toBe(true);
    expect(windowsMsiSupported("0.2.0-65535")).toBe(true);
    expect(windowsMsiSupported("0.2.0-rc.1")).toBe(false);
    expect(windowsMsiSupported("0.2.0-1.2")).toBe(false);
    expect(windowsMsiSupported("0.2.0-65536")).toBe(false);
    expect(windowsBundles("0.1.0")).toBe("nsis,msi");
    expect(windowsBundles("0.2.0-rc.1")).toBe("nsis");
  });
});

describe("repository versions", () => {
  it("accepts the real workspace", () => {
    expect(checkRepository(repoRoot)).toBe("0.1.0");
    const changelog = readFileSync(path.join(repoRoot, "CHANGELOG.md"), "utf8");
    expect(renderChangelog(parseChangelog(changelog))).toBe(changelog.replace(/\r\n/g, "\n"));
  });

  it("reports a mismatch and an invalid manifest", () => {
    const root = tempRepo();
    const cargo = path.join(root, "src-tauri", "Cargo.toml");
    writeFileSync(cargo, readFileSync(cargo, "utf8").replace('version = "0.1.0"', 'version = "0.1.1"'));
    expect(() => checkRepository(root)).toThrow(/version mismatch:.*Cargo\.toml=0\.1\.1/);

    const broken = tempRepo("1.2");
    expect(() => checkRepository(broken)).toThrow(VersionError);
    rmSync(root, { recursive: true, force: true });
    rmSync(broken, { recursive: true, force: true });
  });

  it("prepares a new version without moving dependency versions", () => {
    const root = tempRepo();
    writeFileSync(
      path.join(root, "CHANGELOG.md"),
      readFileSync(path.join(root, "CHANGELOG.md"), "utf8").replace(
        "## [Unreleased]\n",
        "## [Unreleased]\n\n- next change\n",
      ),
    );
    expect(prepareRepository(root, "0.2.0-rc.1", "2026-12-01")).toBe("0.2.0-rc.1");
    expect(checkRepository(root)).toBe("0.2.0-rc.1");
    const lock = readFileSync(path.join(root, "package-lock.json"), "utf8");
    expect(lock).toContain('"version": "0.2.0-rc.1"');
    expect(lock).toContain('"node_modules/yocto-queue"');
    expect(lock).toContain('"version": "0.1.0"');
    const cargoLock = readFileSync(path.join(root, "src-tauri", "Cargo.lock"), "utf8");
    expect(cargoLock).toContain('name = "tunneldesk"\nversion = "0.2.0-rc.1"');
    expect(cargoLock).toContain('name = "other"\nversion = "0.1.0"');
    expect(readFileSync(path.join(root, "src-tauri", "Cargo.toml"), "utf8")).toContain(
      'serde = { version = "1", features = ["derive"] }',
    );
    const notes = releaseNotes(readFileSync(path.join(root, "CHANGELOG.md"), "utf8"), "0.2.0-rc.1");
    expect(notes).toContain("next change");
    expect(notes).toContain("does not publish an MSI");
    expect(windowsBundles("0.2.0-rc.1")).toBe("nsis");
    rmSync(root, { recursive: true, force: true });
  });

  it("rejects prepare when Unreleased has no notes or the version is invalid", () => {
    const root = tempRepo();
    expect(() => prepareRepository(root, "0.2.0", "2026-12-01")).toThrow(/Unreleased/);
    expect(() => prepareRepository(root, "v0.2.0", "2026-12-01")).toThrow(VersionError);
    expect(() => prepareRepository(root, "0.2.0", "2026-02-31")).toThrow(/date/);
    rmSync(root, { recursive: true, force: true });
  });

  it("keeps the real package-lock dependency version while updating both root fields", () => {
    const source = readFileSync(path.join(repoRoot, "package-lock.json"), "utf8");
    const root = tempRepo();
    writeFileSync(path.join(root, "package-lock.json"), source);
    writeFileSync(
      path.join(root, "CHANGELOG.md"),
      readFileSync(path.join(root, "CHANGELOG.md"), "utf8").replace(
        "## [Unreleased]\n",
        "## [Unreleased]\n\n- lock bump\n",
      ),
    );
    prepareRepository(root, "0.1.1", "2026-12-02");
    const updated = readFileSync(path.join(root, "package-lock.json"), "utf8");
    expect(updated.match(/"version": "0\.1\.1"/g)).toHaveLength(2);
    expect(updated).toContain('"node_modules/yocto-queue"');
    expect(updated).toContain('"version": "0.1.0"');
    rmSync(root, { recursive: true, force: true });
  });
});

describe("bundles and draft releases", () => {
  it("renames the one bundle for a platform and fails on a mismatch", () => {
    const root = tempRepo();
    const bundle = path.join(
      root,
      "src-tauri",
      "target",
      "x86_64-unknown-linux-gnu",
      "release",
      "bundle",
      "deb",
    );
    mkdirSync(bundle, { recursive: true });
    writeFileSync(path.join(bundle, "TunnelDesk_0.1.0_amd64.deb"), "deb-bytes");
    const output = path.join(root, "out");
    const written = collectBundles({
      root,
      platform: "linux-amd64",
      target: "x86_64-unknown-linux-gnu",
      output,
    });
    expect(path.basename(written[0])).toBe("TunnelDesk_0.1.0_linux_amd64.deb");
    expect(readFileSync(written[0], "utf8")).toBe("deb-bytes");

    writeFileSync(path.join(bundle, "extra.deb"), "other");
    expect(() =>
      collectBundles({
        root,
        platform: "linux-amd64",
        target: "x86_64-unknown-linux-gnu",
        output,
      }),
    ).toThrow(/expected one/);
    rmSync(root, { recursive: true, force: true });
  });

  it("requires MSI only when the version can produce one", () => {
    expect(releaseAssetNames("TunnelDesk", "0.1.0")).toEqual([
      "TunnelDesk_0.1.0_linux_amd64.deb",
      "TunnelDesk_0.1.0_windows_x64-setup.exe",
      "TunnelDesk_0.1.0_windows_x64.msi",
      "TunnelDesk_0.1.0_macos_aarch64.dmg",
      "TunnelDesk_0.1.0_macos_x64.dmg",
    ]);
    expect(releaseAssetNames("TunnelDesk", "0.2.0-rc.1")).not.toContain(
      "TunnelDesk_0.2.0-rc.1_windows_x64.msi",
    );
  });

  it("stages checksums and rejects a published or incomplete draft", () => {
    const root = tempRepo();
    const assets = path.join(root, "assets");
    mkdirSync(assets);
    for (const name of releaseAssetNames("TunnelDesk", "0.1.0")) {
      writeFileSync(path.join(assets, name), `bytes-${name}`);
    }
    const staged = stageAssets({
      root,
      assetsDir: assets,
      notesPath: path.join(root, "notes.md"),
      tag: "v0.1.0",
    });
    expect(staged.map((file) => path.basename(file))).toContain("SHA256SUMS.txt");
    const sums = readFileSync(path.join(assets, "SHA256SUMS.txt"), "utf8");
    expect(sums).toMatch(/^[0-9a-f]{64} {2}TunnelDesk_0\.1\.0_linux_amd64\.deb$/m);
    expect(readFileSync(path.join(root, "notes.md"), "utf8")).toContain("unsigned");

    expect(() =>
      stageAssets({
        root,
        assetsDir: assets,
        notesPath: path.join(root, "notes.md"),
        tag: "v0.2.0",
      }),
    ).toThrow(/does not match/);

    const release = {
      isDraft: true,
      assets: [...releaseAssetNames("TunnelDesk", "0.1.0"), "SHA256SUMS.txt"].map((name) => ({ name })),
    };
    expect(() => assertDraftRelease(release, "v0.1.0", "TunnelDesk")).not.toThrow();
    expect(() => assertDraftRelease({ ...release, isDraft: false }, "v0.1.0", "TunnelDesk")).toThrow(
      /not a draft/,
    );
    expect(() =>
      assertDraftRelease(
        { isDraft: true, assets: release.assets.filter((asset) => !asset.name.endsWith(".msi")) },
        "v0.1.0",
        "TunnelDesk",
      ),
    ).toThrow(/missing/);
    rmSync(root, { recursive: true, force: true });
  });
});

describe("publish-release.sh", () => {
  function git(root, args) {
    const result = spawnSync("git", args, {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, GIT_CONFIG_COUNT: "0" },
    });
    if (result.status !== 0) {
      throw new Error(result.stderr || result.stdout);
    }
    return result.stdout.trim();
  }

  function initGit(root) {
    git(root, ["init"]);
    git(root, ["config", "user.email", "release-test@example.com"]);
    git(root, ["config", "user.name", "Release Test"]);
    git(root, ["add", "."]);
    git(root, ["commit", "-m", "fixture"]);
    return git(root, ["rev-parse", "HEAD"]);
  }

  function fakeGh(binDir) {
    mkdirSync(binDir, { recursive: true });
    const script = `#!/usr/bin/env node
const { appendFileSync, readFileSync } = require("node:fs");
const args = process.argv.slice(2);
appendFileSync(process.env.FAKE_GH_LOG, JSON.stringify(args) + "\\n");
if ((process.env.GH_TOKEN || "").length > 0 && JSON.stringify(args).includes(process.env.GH_TOKEN)) {
  console.error("token leaked into argv");
  process.exit(3);
}
const state = JSON.parse(readFileSync(process.env.FAKE_GH_STATE, "utf8"));
const command = args.slice(0, 2).join(" ");
if (command === "release view" && args.includes("--jq")) {
  if (!state.existing) {
    console.error("release not found");
    process.exit(1);
  }
  process.stdout.write(String(state.existing.isDraft) + "\\t" + state.existing.targetCommitish + "\\n");
  process.exit(0);
}
if (command === "release delete") process.exit(0);
if (command === "release create") process.exit(state.createStatus ?? 0);
if (command === "release view") {
  process.stdout.write(JSON.stringify(state.after));
  process.exit(0);
}
if (command === "release edit") process.exit(0);
console.error("unexpected gh command");
process.exit(2);
`;
    const file = path.join(binDir, "gh");
    writeFileSync(file, script);
    chmodSync(file, 0o755);
    return file;
  }

  function runPublish(root, state, assetsReady) {
    const bin = path.join(root, "fake-bin");
    const log = path.join(root, "gh.log");
    const statePath = path.join(root, "gh-state.json");
    fakeGh(bin);
    writeFileSync(statePath, JSON.stringify(state));
    writeFileSync(log, "");
    if (assetsReady) {
      const assets = path.join(root, "assets");
      mkdirSync(assets, { recursive: true });
      for (const name of releaseAssetNames("TunnelDesk", "0.1.0")) {
        writeFileSync(path.join(assets, name), `bytes-${name}`);
      }
    }
    const sha = initGit(root);
    const result = spawnSync("bash", [path.join(repoRoot, "scripts", "publish-release.sh")], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        GH_TOKEN: "sentinel-token-not-for-logs",
        GITHUB_SHA: sha,
        RELEASE_TAG: "v0.1.0",
        RELEASE_ASSETS: path.join(root, "assets"),
        RELEASE_ROOT: root,
        RELEASE_NOTES: path.join(root, "notes.md"),
        FAKE_GH_LOG: log,
        FAKE_GH_STATE: statePath,
      },
    });
    const commands = readFileSync(log, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    return { result, commands };
  }

  it("does not call gh when an installer is missing", () => {
    const root = tempRepo();
    const { result, commands } = runPublish(root, { existing: null, after: {} }, false);
    expect(result.status).not.toBe(0);
    expect(commands).toEqual([]);
    expect(`${result.stdout}${result.stderr}`).not.toContain("sentinel-token");
    rmSync(root, { recursive: true, force: true });
  });

  it("publishes a draft only after the asset set matches", () => {
    const root = tempRepo();
    const names = [...releaseAssetNames("TunnelDesk", "0.1.0"), "SHA256SUMS.txt"];
    const { result, commands } = runPublish(
      root,
      {
        existing: null,
        after: { isDraft: true, assets: names.map((name) => ({ name })) },
      },
      true,
    );
    expect(result.status).toBe(0);
    const flat = commands.map((args) => args.join(" "));
    expect(flat.some((line) => line.includes("release create") && line.includes("--draft"))).toBe(true);
    expect(flat.some((line) => line.includes("--cleanup-tag"))).toBe(false);
    expect(flat.at(-1)).toContain("release edit");
    expect(flat.at(-1)).toContain("--draft=false");
    expect(`${result.stdout}${result.stderr}`).not.toContain("sentinel-token");
    rmSync(root, { recursive: true, force: true });
  });

  it("leaves a draft unpublished when an asset is missing from the draft", () => {
    const root = tempRepo();
    const { result, commands } = runPublish(
      root,
      {
        existing: null,
        after: { isDraft: true, assets: [{ name: "SHA256SUMS.txt" }] },
      },
      true,
    );
    expect(result.status).not.toBe(0);
    expect(commands.some((args) => args.slice(0, 2).join(" ") === "release edit")).toBe(false);
    rmSync(root, { recursive: true, force: true });
  });

  it("refuses to replace a release that is already public", () => {
    const root = tempRepo();
    const { result, commands } = runPublish(
      root,
      {
        existing: { isDraft: false, targetCommitish: "ignored" },
        after: { isDraft: true, assets: [] },
      },
      true,
    );
    expect(result.status).not.toBe(0);
    expect(commands.some((args) => args[1] === "create")).toBe(false);
    expect(`${result.stderr}`).toContain("already published");
    rmSync(root, { recursive: true, force: true });
  });
});
