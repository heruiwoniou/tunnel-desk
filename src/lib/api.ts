import { invoke } from "@tauri-apps/api/core"
import { listen, type UnlistenFn } from "@tauri-apps/api/event"

import type {
  AppErrorBody,
  BackendInfo,
  ConnectRequest,
  ForwardMapping,
  HistoryEntry,
  HostKeyEvent,
  Profile,
  ResolvedHost,
  SecretMeta,
  Settings,
  SshAlias,
  TrustStore,
  TunnelSnapshot,
} from "@/lib/types"

export function isDesktop() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window
}

export function asAppError(error: unknown): AppErrorBody {
  if (error && typeof error === "object") {
    const record = error as Partial<AppErrorBody>
    if (typeof record.message === "string") {
      return {
        code: record.code ?? "ssh",
        message: record.message,
        challengeHost: record.challengeHost ?? null,
        challengeHop: record.challengeHop ?? null,
        runtimeApplied: record.runtimeApplied ?? null,
        persistApplied: record.persistApplied ?? null,
      }
    }
  }
  if (typeof error === "string" && error.trim()) {
    return { code: "ssh", message: error }
  }
  return { code: "ssh", message: "操作失败" }
}

export const previewProfiles: Profile[] = [
  {
    id: "preview-local",
    name: "预览示例 · 数据库",
    target: { kind: "configAlias", alias: "db" },
    authMode: "auto",
    rememberPassword: false,
    forwards: [
      {
        id: "preview-forward",
        direction: "local",
        listenHost: "127.0.0.1",
        listenPort: 15432,
        destinationHost: "127.0.0.1",
        destinationPort: 5432,
        allowExternal: false,
      },
    ],
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  },
]

export const previewSettings: Settings = {
  theme: "system",
  language: "zh",
  closeBehavior: "minimizeToTray",
  startMinimized: false,
}

export function listProfiles() {
  return invoke<Profile[]>("list_profiles")
}

export function saveProfile(profile: Profile) {
  return invoke<Profile>("save_profile", { profile })
}

export function deleteProfile(id: string) {
  return invoke<void>("delete_profile", { id })
}

export function listHosts() {
  return invoke<SshAlias[]>("list_hosts")
}

export function resolveHost(query: string) {
  return invoke<ResolvedHost>("resolve_host", { query })
}

export function listHistory() {
  return invoke<HistoryEntry[]>("list_history")
}

export function clearHistory() {
  return invoke<void>("clear_history")
}

export function getSettings() {
  return invoke<Settings>("get_settings")
}

export function saveSettings(settings: Settings) {
  return invoke<Settings>("save_settings", { settings })
}

export function runtimeSnapshots() {
  return invoke<TunnelSnapshot[]>("runtime_snapshots")
}

export function secretMeta(profileId: string) {
  return invoke<SecretMeta>("secret_meta", { profileId })
}

export function forgetServerPassword(profileId: string) {
  return invoke<void>("forget_server_password", { profileId })
}

export function forgetPassphrases(profileId: string) {
  return invoke<void>("forget_passphrases", { profileId })
}

export function listTrust() {
  return invoke<TrustStore>("list_trust")
}

export function forgetTrust(host: string, port: number) {
  return invoke<boolean>("forget_trust", { host, port })
}

export function backendInfo() {
  return invoke<BackendInfo>("backend_info")
}

export function connectProfile(request: ConnectRequest) {
  return invoke<{ snapshot: TunnelSnapshot; warnings: AppErrorBody[] }>("connect_profile", { request })
}

export function cancelConnect(profileId: string) {
  return invoke<void>("cancel_connect", { profileId })
}

export function disconnectProfile(profileId: string) {
  return invoke<void>("disconnect_profile", { profileId })
}

export function disconnectAll() {
  return invoke<void>("disconnect_all")
}

export function addRuntimeForward(profileId: string, mapping: ForwardMapping, persist: boolean) {
  return invoke<TunnelSnapshot>("add_runtime_forward", {
    request: { profileId, mapping, persist },
  })
}

export function removeRuntimeForward(profileId: string, forwardId: string, persist: boolean) {
  return invoke<TunnelSnapshot>("remove_runtime_forward", {
    request: { profileId, forwardId, persist },
  })
}

export function respondHostKey(requestId: string, accept: boolean) {
  return invoke<void>("respond_host_key", { answer: { requestId, accept } })
}

export function onTunnelState(handler: (snapshots: TunnelSnapshot[]) => void): Promise<UnlistenFn> {
  return listen<TunnelSnapshot[]>("tunnel-state", (event) => handler(event.payload))
}

export function onHostKey(handler: (prompt: HostKeyEvent) => void): Promise<UnlistenFn> {
  return listen<HostKeyEvent>("hostkey-required", (event) => handler(event.payload))
}

export function onNeedsInput(
  handler: (payload: {
    profileId: string
    code: string
    message: string
    challengeHost?: string | null
    challengeHop?: string | null
  }) => void,
) {
  return listen<{ profileId: string; code: string; message: string }>("connect-needs-input", (event) => handler(event.payload))
}
