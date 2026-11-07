#!/usr/bin/env node
// Version, changelog, and release-asset checks for TunnelDesk.
// The module is dependency-free so CI can run it before npm ci.

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REPO = "https://github.com/heruiwoniou/tunnel-desk";

export class VersionError extends Error {
  constructor(message) {
    super(message);
    this.name = "VersionError";
  }
}

const VERSION_SOURCES = [
  ["package.json", readPackageJsonVersion],
  ["package-lock.json", readPackageLockRootVersion],
  ["package-lock.json packages", readPackageLockPackageVersion],
  ["src-tauri/Cargo.toml", readCargoTomlVersion],
  ["src-tauri/Cargo.lock", readCargoLockVersion],
  ["src-tauri/tauri.conf.json", readTauriVersion],
];

function fail(message) {
  throw new VersionError(message);
}

function readText(root, relativePath) {
  const fullPath = path.join(root, relativePath);
  if (!existsSync(fullPath)) {
    fail(`missing ${relativePath}`);
  }
  return readFileSync(fullPath, "utf8").replace(/\r\n/g, "\n");
}

function writeText(root, relativePath, text) {
  writeFileSync(path.join(root, relativePath), text.endsWith("\n") ? text : `${text}\n`);
}

function parseUint(source, label) {
  if (!/^(0|[1-9]\d*)$/.test(source)) {
    fail(`${label} is not an unsigned integer: ${source}`);
  }
  const value = BigInt(source);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail(`${label} is too large`);
  }
  return Number(value);
}

const NUMERIC_ID = /^(0|[1-9]\d*)$/;
const ALPHANUMERIC_ID = /^(?=.*[A-Za-z-])[0-9A-Za-z-]+$/;

export function parseSemver(input) {
  if (typeof input !== "string" || input.length === 0 || input !== input.trim()) {
    fail(`invalid version: ${JSON.stringify(input)}`);
  }
  if (input.startsWith("v") || input.startsWith("V")) {
    fail(`version must not include a v prefix: ${input}`);
  }
  if (input.includes("+")) {
    fail(`build metadata is not allowed: ${input}`);
  }
  const dash = input.indexOf("-");
  const core = dash === -1 ? input : input.slice(0, dash);
  const prereleaseText = dash === -1 ? undefined : input.slice(dash + 1);
  const coreMatch = core.match(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
  if (!coreMatch) {
    fail(`invalid version: ${input}`);
  }
  const prerelease = [];
  if (prereleaseText !== undefined) {
    if (prereleaseText.length === 0) {
      fail(`invalid prerelease: ${input}`);
    }
    for (const identifier of prereleaseText.split(".")) {
      if (NUMERIC_ID.test(identifier)) {
        parseUint(identifier, "prerelease identifier");
      } else if (!ALPHANUMERIC_ID.test(identifier)) {
        fail(`invalid prerelease identifier in ${input}`);
      }
      prerelease.push(identifier);
    }
  }
  return {
    raw: input,
    major: parseUint(coreMatch[1], "major"),
    minor: parseUint(coreMatch[2], "minor"),
    patch: parseUint(coreMatch[3], "patch"),
    prerelease,
  };
}

export function assertSupportedVersion(input) {
  const parsed = parseSemver(input);
  if (parsed.major > 255 || parsed.minor > 255 || parsed.patch > 65535) {
    fail(
      "Windows installers require major <= 255, minor <= 255, and patch <= 65535",
    );
  }
  return parsed;
}

export function isPrerelease(version) {
  return assertSupportedVersion(version).prerelease.length > 0;
}

// Tauri 2.12 WiX only accepts a prerelease when the whole identifier parses as
// one integer no greater than 65535. NSIS accepts normal prerelease labels,
// but its numeric product version keeps major.minor.patch only.
export function windowsMsiSupported(version) {
  const parsed = assertSupportedVersion(version);
  if (parsed.prerelease.length === 0) {
    return true;
  }
  if (parsed.prerelease.length !== 1 || !NUMERIC_ID.test(parsed.prerelease[0])) {
    return false;
  }
  return parseUint(parsed.prerelease[0], "prerelease identifier") <= 65535;
}

export function windowsBundles(version) {
  return windowsMsiSupported(version) ? "nsis,msi" : "nsis";
}

export function compareSemver(leftInput, rightInput) {
  const left = parseSemver(leftInput);
  const right = parseSemver(rightInput);
  if (left.major !== right.major) return left.major - right.major;
  if (left.minor !== right.minor) return left.minor - right.minor;
  if (left.patch !== right.patch) return left.patch - right.patch;
  if (left.prerelease.length === 0 && right.prerelease.length === 0) return 0;
  if (left.prerelease.length === 0) return 1;
  if (right.prerelease.length === 0) return -1;
  const length = Math.max(left.prerelease.length, right.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftId = left.prerelease[index];
    const rightId = right.prerelease[index];
    if (leftId === undefined) return -1;
    if (rightId === undefined) return 1;
    const leftNumeric = NUMERIC_ID.test(leftId);
    const rightNumeric = NUMERIC_ID.test(rightId);
    if (leftNumeric && rightNumeric) {
      const diff = parseUint(leftId, "prerelease") - parseUint(rightId, "prerelease");
      if (diff !== 0) return diff;
    } else if (leftNumeric) {
      return -1;
    } else if (rightNumeric) {
      return 1;
    } else if (leftId !== rightId) {
      return leftId < rightId ? -1 : 1;
    }
  }
  return 0;
}

function readPackageJsonVersion(text) {
  const parsed = JSON.parse(text);
  if (typeof parsed.version !== "string") fail("package.json has no version");
  return parsed.version;
}

function readPackageLockRootVersion(text) {
  const parsed = JSON.parse(text);
  if (typeof parsed.version !== "string") fail("package-lock.json has no root version");
  return parsed.version;
}

function readPackageLockPackageVersion(text) {
  const parsed = JSON.parse(text);
  const version = parsed.packages?.[""]?.version;
  if (typeof version !== "string") fail("package-lock.json has no packages[\"\"] version");
  return version;
}

function readCargoTomlVersion(text) {
  const match = text.match(/^\[package\][^\[]*?^version = "([^"]+)"/m);
  if (!match) fail("src-tauri/Cargo.toml has no [package] version");
  return match[1];
}

function readCargoLockVersion(text) {
  const matches = [
    ...text.matchAll(/^\[\[package\]\]\nname = "tunneldesk"\nversion = "([^"]+)"/gm),
  ];
  if (matches.length !== 1) {
    fail(`expected one tunneldesk package in src-tauri/Cargo.lock, found ${matches.length}`);
  }
  return matches[0][1];
}

function readTauriVersion(text) {
  const parsed = JSON.parse(text);
  if (typeof parsed.version !== "string") fail("src-tauri/tauri.conf.json has no version");
  return parsed.version;
}

function readProductName(root) {
  const parsed = JSON.parse(readText(root, "src-tauri/tauri.conf.json"));
  if (typeof parsed.productName !== "string" || !/^[A-Za-z0-9._-]+$/.test(parsed.productName)) {
    fail("src-tauri/tauri.conf.json productName must be a simple filename token");
  }
  return parsed.productName;
}

export function readVersions(root) {
  const found = VERSION_SOURCES.map(([label, reader]) => {
    const relativePath = label.startsWith("package-lock")
      ? "package-lock.json"
      : label;
    return { label, version: reader(readText(root, relativePath)) };
  });
  return found;
}

export function alignedVersion(root) {
  const found = readVersions(root);
  const distinct = [...new Set(found.map((item) => item.version))];
  if (distinct.length !== 1) {
    const detail = found.map((item) => `${item.label}=${item.version}`).join(", ");
    fail(`version mismatch: ${detail}`);
  }
  return assertSupportedVersion(distinct[0]).raw;
}

function replaceOnce(text, regex, next) {
  const match = regex.exec(text);
  if (!match) fail(`could not update version with ${regex}`);
  return `${text.slice(0, match.index)}${match[1]}${next}${match[3]}${text.slice(match.index + match[0].length)}`;
}

function writePackageJsonVersion(text, from, to) {
  const current = readPackageJsonVersion(text);
  if (current !== from) fail(`package.json version is ${current}, expected ${from}`);
  return replaceOnce(text, /^(\s*"version": ")([^"]+)(")/m, to);
}

function writePackageLockVersions(text, from, to) {
  const rootVersion = readPackageLockRootVersion(text);
  const packageVersion = readPackageLockPackageVersion(text);
  if (rootVersion !== from || packageVersion !== from) {
    fail(`package-lock.json root versions are ${rootVersion} and ${packageVersion}, expected ${from}`);
  }
  let next = replaceOnce(text, /^(\{\n\s*"name": "tunneldesk",\n\s*"version": ")([^"]+)(")/, to);
  next = replaceOnce(
    next,
    /(\n\s*"packages": \{\n\s*"": \{\n\s*"name": "tunneldesk",\n\s*"version": ")([^"]+)(")/,
    to,
  );
  if (readPackageLockRootVersion(next) !== to || readPackageLockPackageVersion(next) !== to) {
    fail("package-lock.json version update did not apply to both root entries");
  }
  return next;
}

function writeCargoTomlVersion(text, from, to) {
  if (readCargoTomlVersion(text) !== from) {
    fail(`src-tauri/Cargo.toml version is not ${from}`);
  }
  return replaceOnce(text, /(\[package\][^\[]*?^version = ")([^"]+)(")/m, to);
}

function writeCargoLockVersion(text, from, to) {
  if (readCargoLockVersion(text) !== from) {
    fail(`src-tauri/Cargo.lock tunneldesk version is not ${from}`);
  }
  return replaceOnce(text, /(\[\[package\]\]\nname = "tunneldesk"\nversion = ")([^"]+)(")/, to);
}

function writeTauriVersion(text, from, to) {
  if (readTauriVersion(text) !== from) {
    fail(`src-tauri/tauri.conf.json version is not ${from}`);
  }
  return replaceOnce(text, /^(\s*"version": ")([^"]+)(")/m, to);
}

const LINK_LINE = /^\[[^\]]+\]: \S+$/;
const VERSION_HEADING = /^## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})$/;
const UNRELEASED_HEADING = "## [Unreleased]";

function isIsoDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const [year, month, day] = value.split("-").map((part) => Number(part));
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

export function parseChangelog(text) {
  const normalized = text.replace(/\r\n/g, "\n");
  const lines = normalized.split("\n");
  if (lines.at(-1) === "") lines.pop();
  const preamble = [];
  const sections = [];
  let unreleased = null;
  let current = null;
  const links = [];

  for (const line of lines) {
    if (LINK_LINE.test(line)) {
      links.push(line);
      continue;
    }
    if (line === UNRELEASED_HEADING) {
      if (unreleased) fail("changelog has more than one Unreleased heading");
      current = { kind: "unreleased", body: [] };
      unreleased = current;
      continue;
    }
    const heading = line.match(VERSION_HEADING);
    if (line.startsWith("## ")) {
      if (!heading) fail(`invalid changelog heading: ${line}`);
      if (!isIsoDate(heading[2])) fail(`invalid changelog date: ${line}`);
      assertSupportedVersion(heading[1]);
      current = { kind: "version", version: heading[1], date: heading[2], body: [] };
      sections.push(current);
      continue;
    }
    if (!current) preamble.push(line);
    else current.body.push(line);
  }

  if (!unreleased) fail("changelog is missing ## [Unreleased]");
  if (!preamble.join("\n").includes("# Changelog")) {
    fail("changelog is missing its title");
  }
  const versions = sections.map((section) => section.version);
  if (new Set(versions).size !== versions.length) {
    fail("changelog repeats a version heading");
  }
  for (let index = 1; index < sections.length; index += 1) {
    if (compareSemver(sections[index - 1].version, sections[index].version) <= 0) {
      fail("changelog versions must be listed from newest to oldest");
    }
  }
  return {
    preamble: preamble.join("\n").trim(),
    unreleased: unreleased.body.join("\n").trim(),
    sections: sections.map((section) => ({
      ...section,
      body: section.body.join("\n").trim(),
    })),
    links,
  };
}

function meaningful(body) {
  return body.replace(/<!--[\s\S]*?-->/g, "").trim().length > 0;
}

function renderLinks(versions) {
  const lines = [];
  if (versions.length > 0) {
    lines.push(`[Unreleased]: ${REPO}/compare/v${versions[0]}...HEAD`);
  } else {
    lines.push(`[Unreleased]: ${REPO}/commits/HEAD`);
  }
  for (const version of versions) {
    lines.push(`[${version}]: ${REPO}/releases/tag/v${version}`);
  }
  return `${lines.join("\n")}\n`;
}

export function renderChangelog(doc) {
  let out = `${doc.preamble.trim()}\n\n## [Unreleased]\n\n`;
  if (doc.unreleased.trim()) out += `${doc.unreleased.trim()}\n\n`;
  for (const section of doc.sections) {
    out += `## [${section.version}] - ${section.date}\n\n`;
    if (section.body.trim()) out += `${section.body.trim()}\n\n`;
  }
  out += renderLinks(doc.sections.map((section) => section.version));
  return out;
}

export function changelogSection(text, version) {
  const doc = parseChangelog(text);
  const section = doc.sections.find((item) => item.version === version);
  if (!section) fail(`changelog is missing ## [${version}]`);
  if (!meaningful(section.body)) fail(`changelog section ${version} is empty`);
  return section;
}

export function prepareChangelog(text, version, date) {
  assertSupportedVersion(version);
  if (!isIsoDate(date)) fail(`invalid release date: ${date}`);
  const doc = parseChangelog(text);
  if (!doc.sections.some((section) => section.version === version)) {
    if (!meaningful(doc.unreleased)) {
      fail("Unreleased changelog notes are empty; add them before preparing a version");
    }
    doc.sections.unshift({
      kind: "version",
      version,
      date,
      body: doc.unreleased,
    });
    doc.unreleased = "";
  }
  return renderChangelog(doc);
}

export function releaseNotes(text, version) {
  const section = changelogSection(text, version);
  const lines = [
    `Installers for ${version} are unsigned.`,
    "Windows SmartScreen will warn.",
    "macOS Gatekeeper will warn. Apple Silicon builds are ad-hoc signed with identity `-`, which is not an Apple Developer ID signature and is not notarization.",
    "Verify the files with `sha256sum -c SHA256SUMS.txt`.",
    "",
  ];
  if (!windowsMsiSupported(version)) {
    lines.push(
      "This prerelease publishes an NSIS installer and does not publish an MSI. Tauri's WiX bundler rejects a prerelease identifier unless it is a single integer no greater than 65535. The NSIS numeric product version keeps major.minor.patch and does not encode the prerelease label.",
      "",
    );
  }
  lines.push(section.body.trim(), "");
  return `${lines.join("\n")}`;
}

export function releaseAssetNames(product, version) {
  const names = [
    `${product}_${version}_linux_amd64.deb`,
    `${product}_${version}_windows_x64-setup.exe`,
  ];
  if (windowsMsiSupported(version)) {
    names.push(`${product}_${version}_windows_x64.msi`);
  }
  names.push(
    `${product}_${version}_macos_aarch64.dmg`,
    `${product}_${version}_macos_x64.dmg`,
  );
  return names;
}

export function tagForVersion(version) {
  assertSupportedVersion(version);
  return `v${version}`;
}

export function versionFromTag(tag) {
  if (typeof tag !== "string" || !tag.startsWith("v")) {
    fail(`tag must look like vX.Y.Z, received ${JSON.stringify(tag)}`);
  }
  const version = tag.slice(1);
  assertSupportedVersion(version);
  if (tagForVersion(version) !== tag) fail(`tag does not match its version: ${tag}`);
  return version;
}

function gitTagCommit(root, tag) {
  versionFromTag(tag);
  const result = spawnSync("git", ["rev-parse", "-q", "--verify", `refs/tags/${tag}^{commit}`], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    const errorText = `${result.stderr ?? ""}${result.stdout ?? ""}`;
    if (errorText.includes("not a git repository")) {
      fail("git repository is required to compare the release tag");
    }
    return null;
  }
  return result.stdout.trim();
}

export function assertTagCommit(root, tag, githubSha) {
  if (!githubSha) return;
  if (!/^[0-9a-f]{40}$/i.test(githubSha)) fail("GITHUB_SHA must be a 40 character commit id");
  const commit = gitTagCommit(root, tag);
  if (commit && commit.toLowerCase() !== githubSha.toLowerCase()) {
    fail(`tag ${tag} points at ${commit}, not ${githubSha}`);
  }
}

export function assertReleaseReady(root, tag, githubSha) {
  const version = versionFromTag(tag);
  const current = alignedVersion(root);
  if (current !== version) {
    fail(`tag ${tag} does not match manifest version ${current}`);
  }
  changelogSection(readText(root, "CHANGELOG.md"), version);
  assertTagCommit(root, tag, githubSha);
  return version;
}

export function checkRepository(root) {
  const version = alignedVersion(root);
  changelogSection(readText(root, "CHANGELOG.md"), version);
  return version;
}

export function prepareRepository(root, version, date) {
  const next = assertSupportedVersion(version).raw;
  const current = alignedVersion(root);
  const changelog = prepareChangelog(readText(root, "CHANGELOG.md"), next, date);
  changelogSection(changelog, next);
  if (current !== next) {
    writeText(root, "package.json", writePackageJsonVersion(readText(root, "package.json"), current, next));
    writeText(
      root,
      "package-lock.json",
      writePackageLockVersions(readText(root, "package-lock.json"), current, next),
    );
    writeText(
      root,
      "src-tauri/Cargo.toml",
      writeCargoTomlVersion(readText(root, "src-tauri/Cargo.toml"), current, next),
    );
    writeText(
      root,
      "src-tauri/Cargo.lock",
      writeCargoLockVersion(readText(root, "src-tauri/Cargo.lock"), current, next),
    );
    writeText(
      root,
      "src-tauri/tauri.conf.json",
      writeTauriVersion(readText(root, "src-tauri/tauri.conf.json"), current, next),
    );
  }
  writeText(root, "CHANGELOG.md", changelog);
  if (alignedVersion(root) !== next) fail("version prepare left the manifests inconsistent");
  return next;
}

function findOne(directory, extension, label) {
  if (!existsSync(directory)) fail(`${label} directory does not exist: ${directory}`);
  const found = readdirSync(directory).filter((name) => name.endsWith(extension));
  if (found.length !== 1) {
    fail(`${label}: expected one ${extension} file, found ${found.length}: ${found.join(", ") || "(none)"}`);
  }
  return path.join(directory, found[0]);
}

export function collectBundles({ root, platform, target, output }) {
  const version = alignedVersion(root);
  const product = readProductName(root);
  const bundleRoot = path.join(root, "src-tauri", "target", target, "release", "bundle");
  const wanted = new Set(releaseAssetNames(product, version));
  const plan = [];
  if (platform === "linux-amd64") {
    plan.push(["deb", ".deb", `${product}_${version}_linux_amd64.deb`]);
  } else if (platform === "windows-x64") {
    plan.push(["nsis", ".exe", `${product}_${version}_windows_x64-setup.exe`]);
    if (windowsMsiSupported(version)) {
      plan.push(["msi", ".msi", `${product}_${version}_windows_x64.msi`]);
    }
  } else if (platform === "macos-aarch64") {
    plan.push(["dmg", ".dmg", `${product}_${version}_macos_aarch64.dmg`]);
  } else if (platform === "macos-x64") {
    plan.push(["dmg", ".dmg", `${product}_${version}_macos_x64.dmg`]);
  } else {
    fail(`unknown platform: ${platform}`);
  }
  mkdirSync(output, { recursive: true });
  const written = [];
  for (const [directory, extension, name] of plan) {
    if (!wanted.has(name)) fail(`internal asset name was not required: ${name}`);
    const source = findOne(path.join(bundleRoot, directory), extension, `${platform} ${directory}`);
    const destination = path.join(output, name);
    copyFileSync(source, destination);
    if (statSync(destination).size === 0) fail(`bundle is empty: ${name}`);
    written.push(destination);
  }
  return written;
}

export function sha256File(filePath) {
  const hash = createHash("sha256");
  hash.update(readFileSync(filePath));
  return hash.digest("hex");
}

export function stageAssets({ root, assetsDir, notesPath, tag, githubSha }) {
  const version = assertReleaseReady(root, tag, githubSha);
  const product = readProductName(root);
  const names = releaseAssetNames(product, version);
  const paths = names.map((name) => path.join(assetsDir, name));
  for (const assetPath of paths) {
    if (!existsSync(assetPath) || !statSync(assetPath).isFile() || statSync(assetPath).size === 0) {
      fail(`required release asset is missing or empty: ${path.basename(assetPath)}`);
    }
  }
  const present = new Set(readdirSync(assetsDir));
  for (const name of names) present.delete(name);
  present.delete("SHA256SUMS.txt");
  if (present.size > 0) {
    fail(`unexpected files in release assets: ${[...present].sort().join(", ")}`);
  }
  const sums = names
    .slice()
    .sort()
    .map((name) => `${sha256File(path.join(assetsDir, name))}  ${name}`)
    .join("\n");
  const sumsPath = path.join(assetsDir, "SHA256SUMS.txt");
  writeFileSync(sumsPath, `${sums}\n`);
  writeFileSync(notesPath, releaseNotes(readText(root, "CHANGELOG.md"), version));
  return [...paths, sumsPath];
}

export function assertDraftRelease(release, tag, product) {
  const version = versionFromTag(tag);
  if (!release || release.isDraft !== true) {
    fail("refusing to publish because the release is not a draft");
  }
  if (!/^[A-Za-z0-9._-]+$/.test(product)) fail("product name is not a filename token");
  const expected = new Set([...releaseAssetNames(product, version), "SHA256SUMS.txt"]);
  const actual = new Set((release.assets ?? []).map((asset) => asset.name));
  const missing = [...expected].filter((name) => !actual.has(name));
  const extra = [...actual].filter((name) => !expected.has(name));
  if (missing.length > 0 || extra.length > 0) {
    fail(
      `draft assets do not match the required set; missing: ${missing.join(", ") || "(none)"}; extra: ${extra.join(", ") || "(none)"}`,
    );
  }
}

function optionValue(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) fail(`missing value for ${name}`);
  return value;
}

function writeGithubOutput(values) {
  if (!process.env.GITHUB_OUTPUT) return;
  const lines = Object.entries(values).map(([key, value]) => `${key}=${value}`);
  appendFileSync(process.env.GITHUB_OUTPUT, `${lines.join("\n")}\n`);
}

function utcToday() {
  return new Date().toISOString().slice(0, 10);
}

async function main(argv) {
  const command = argv[0];
  const root = path.resolve(optionValue(argv, "--root") ?? process.cwd());
  if (command === "check") {
    const version = checkRepository(root);
    console.log(version);
    return;
  }
  if (command === "prepare") {
    const version = argv[1];
    if (!version || version.startsWith("--")) fail("usage: version.mjs prepare <version> [--date YYYY-MM-DD]");
    const date = optionValue(argv, "--date") ?? utcToday();
    console.log(prepareRepository(root, version, date));
    return;
  }
  if (command === "notes") {
    const version = optionValue(argv, "--version") ?? alignedVersion(root);
    process.stdout.write(releaseNotes(readText(root, "CHANGELOG.md"), version));
    return;
  }
  if (command === "windows-bundles") {
    console.log(windowsBundles(alignedVersion(root)));
    return;
  }
  if (command === "is-prerelease") {
    const version = versionFromTag(optionValue(argv, "--tag") ?? process.env.RELEASE_TAG);
    console.log(isPrerelease(version) ? "true" : "false");
    return;
  }
  if (command === "release-check") {
    const tag = optionValue(argv, "--tag") ?? process.env.RELEASE_TAG;
    const confirm = process.env.RELEASE_CONFIRM;
    if (confirm && confirm !== "tag-push" && confirm !== "publish") {
      fail("workflow_dispatch requires the confirm input to be exactly publish");
    }
    const version = assertReleaseReady(root, tag, process.env.GITHUB_SHA);
    writeGithubOutput({
      tag,
      version,
      prerelease: isPrerelease(version) ? "true" : "false",
      msi: windowsMsiSupported(version) ? "true" : "false",
      windows_bundles: windowsBundles(version),
    });
    console.log(`${tag} ${version}`);
    return;
  }
  if (command === "collect") {
    const written = collectBundles({
      root,
      platform: optionValue(argv, "--platform"),
      target: optionValue(argv, "--target"),
      output: path.resolve(root, optionValue(argv, "--output") ?? "release-assets"),
    });
    for (const filePath of written) console.log(filePath);
    return;
  }
  if (command === "stage-assets") {
    const assetsDir = path.resolve(root, optionValue(argv, "--assets") ?? "release-assets");
    const notesPath = path.resolve(root, optionValue(argv, "--notes") ?? "release-notes.md");
    const tag = optionValue(argv, "--tag") ?? process.env.RELEASE_TAG;
    const written = stageAssets({
      root,
      assetsDir,
      notesPath,
      tag,
      githubSha: process.env.GITHUB_SHA,
    });
    for (const filePath of written) console.log(filePath);
    return;
  }
  if (command === "verify-draft") {
    const tag = optionValue(argv, "--tag") ?? process.env.RELEASE_TAG;
    const jsonPath = optionValue(argv, "--json");
    assertDraftRelease(JSON.parse(readFileSync(jsonPath, "utf8")), tag, readProductName(root));
    console.log(`draft ${tag} contains the required assets`);
    return;
  }
  fail("usage: version.mjs check|prepare|notes|windows-bundles|release-check|collect|stage-assets|verify-draft");
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  return pathToFileURL(path.resolve(entry)).href === import.meta.url;
}

if (invokedDirectly()) {
  main(process.argv.slice(2)).catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
