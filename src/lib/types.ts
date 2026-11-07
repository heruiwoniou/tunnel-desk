export type Direction = "local" | "remote"
export type AuthMode = "auto" | "password" | "publicKey" | "agent"
export type Phase =
  | "disconnected"
  | "connecting"
  | "authenticating"
  | "binding"
  | "connected"
  | "failed"
export type Theme = "system" | "light" | "dark"
export type Language = "zh" | "en"
export type CloseBehavior = "minimizeToTray" | "quit"

export type Target =
  | { kind: "configAlias"; alias: string }
  | {
      kind: "manual"
      hostname: string
      port: number
      user: string
      identityFile?: string | null
      proxyJump?: string | null
    }

export type ForwardMapping = {
  id: string
  direction: Direction
  listenHost: string
  listenPort: number
  destinationHost: string
  destinationPort: number
  allowExternal: boolean
}

export type Profile = {
  id: string
  name: string
  target: Target
  authMode: AuthMode
  rememberPassword: boolean
  forwards: ForwardMapping[]
  createdAt: string
  updatedAt: string
}

export type Settings = {
  theme: Theme
  language: Language
  closeBehavior: CloseBehavior
  startMinimized: boolean
}

export type HistoryEntry = {
  id: string
  profileId: string
  name: string
  target: string
  startedAt: string
  endedAt: string | null
  outcome: string
  message: string
}

export type ForwardStatus = {
  id: string
  direction: Direction
  listen: string
  destination: string
  state: string
  message: string
}

export type TunnelSnapshot = {
  profileId: string
  name: string
  phase: Phase
  message: string
  forwards: ForwardStatus[]
  connectedAt: string | null
}

export type SecretMeta = {
  serverPasswordStored: boolean
  keyPassphraseStored: boolean
  keyringAvailable: boolean
  keyringMessage: string | null
}

export type BackendInfo = {
  version: string
  engine: string
  trayAvailable: boolean
  keyringAvailable: boolean
  keyringMessage: string | null
  sshBinary: string | null
}

export type SshAlias = {
  alias: string
  configPath: string
  wildcard: boolean
}

export type ResolvedHost = {
  query: string
  hostname: string
  user: string
  port: number
  identityFiles: string[]
  certificateFiles: string[]
  identitiesOnly: boolean
  pubkeyAuthentication: boolean
  proxyJump: string | null
  proxyCommand: string | null
  identityAgent: string | null
  hostKeyAlias: string | null
  knownHostsFiles: string[]
  revokedHostKeys: string[]
  preferredAuthentications: string[]
  resolution: string
  warnings: string[]
}

export type TrustEntry = {
  host: string
  port: number
  algorithm: string
  fingerprint: string
  publicKey: string
  trustedAt: string
}

export type TrustStore = {
  entries: TrustEntry[]
}

export type AppErrorBody = {
  code: string
  message: string
}

export type ConnectRequest = {
  profileId: string
  serverPassword: string | null
  keyPassphrase: string | null
  rememberServerPassword: boolean
  rememberKeyPassphrase: boolean
}

export type HostKeyEvent = {
  requestId: string
  host: string
  port: number
  algorithm: string
  fingerprint: string
}
