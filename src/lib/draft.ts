import type { AuthMode, Direction, ForwardMapping, Language, Profile, Target } from "@/lib/types"

export type DraftForward = {
  id: string
  direction: Direction
  listenHost: string
  listenPort: string
  destinationHost: string
  destinationPort: string
  allowExternal: boolean
}

export type Draft = {
  id: string
  name: string
  mode: "alias" | "manual"
  alias: string
  hostname: string
  port: string
  user: string
  identityFile: string
  proxyJump: string
  clearJump: boolean
  authMode: AuthMode
  rememberPassword: boolean
  forwards: DraftForward[]
  createdAt: string
  /** Present only while the form is open. Never copied into a saved profile. */
  typedPassword?: string
  typedPassphrase?: string
}

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost", "[::1]"])

export function isLoopbackHost(host: string) {
  const value = host.trim().toLowerCase()
  if (LOOPBACK.has(value)) return true
  if (value.startsWith("127.")) return true
  return false
}

export function directionLabel(direction: Direction, language: Language) {
  if (direction === "local") {
    return language === "en" ? "Local forward (-L)" : "本地转发 (-L)"
  }
  return language === "en" ? "Remote forward (-R)" : "远程转发 (-R)"
}

export function directionHelp(direction: Direction, language: Language) {
  if (direction === "local") {
    return language === "en"
      ? "This computer listens. The destination is reached from the SSH server."
      : "本机监听。目标地址由 SSH 服务器去访问。"
  }
  return language === "en"
    ? "The SSH server listens. The destination is reached from this computer."
    : "SSH 服务器监听。目标地址由这台电脑去访问。"
}

export function newForward(direction: Direction = "local"): DraftForward {
  return {
    id: crypto.randomUUID(),
    direction,
    listenHost: "127.0.0.1",
    listenPort: direction === "local" ? "15432" : "9000",
    destinationHost: "127.0.0.1",
    destinationPort: direction === "local" ? "5432" : "3000",
    allowExternal: false,
  }
}

export function emptyDraft(): Draft {
  const now = new Date().toISOString()
  return {
    id: crypto.randomUUID(),
    name: "",
    mode: "alias",
    alias: "",
    hostname: "",
    port: "22",
    user: "",
    identityFile: "",
    proxyJump: "",
    clearJump: false,
    authMode: "auto",
    rememberPassword: false,
    forwards: [newForward("local")],
    createdAt: now,
  }
}

export function draftFromProfile(profile: Profile): Draft {
  if (profile.target.kind === "configAlias") {
    return {
      id: profile.id,
      name: profile.name,
      mode: "alias",
      alias: profile.target.alias,
      hostname: "",
      port: "22",
      user: "",
      identityFile: "",
      proxyJump: "",
      clearJump: false,
      authMode: profile.authMode,
      rememberPassword: profile.rememberPassword,
      forwards: profile.forwards.map(forwardToDraft),
      createdAt: profile.createdAt,
    }
  }
  return {
    id: profile.id,
    name: profile.name,
    mode: "manual",
    alias: "",
    hostname: profile.target.hostname,
    port: String(profile.target.port),
    user: profile.target.user,
    identityFile: profile.target.identityFile ?? "",
    proxyJump: profile.target.proxyJump ?? "",
    clearJump: profile.target.proxyJump === "",
    authMode: profile.authMode,
    rememberPassword: profile.rememberPassword,
    forwards: profile.forwards.map(forwardToDraft),
    createdAt: profile.createdAt,
  }
}

function forwardToDraft(forward: ForwardMapping): DraftForward {
  return {
    id: forward.id,
    direction: forward.direction,
    listenHost: forward.listenHost,
    listenPort: String(forward.listenPort),
    destinationHost: forward.destinationHost,
    destinationPort: String(forward.destinationPort),
    allowExternal: forward.allowExternal,
  }
}

export function draftIssues(draft: Draft, language: Language): string[] {
  const issues: string[] = []
  const say = (zh: string, en: string) => issues.push(language === "en" ? en : zh)
  if (!draft.name.trim()) say("请填写隧道名称。", "Enter a tunnel name.")
  if (draft.mode === "alias") {
    if (!draft.alias.trim()) say("请选择或填写 SSH 配置中的别名。", "Choose an SSH config alias.")
    if (/[*?]/.test(draft.alias)) say("通配符不能当作具体主机。", "Wildcard patterns are not concrete hosts.")
  } else {
    if (!draft.hostname.trim()) say("请填写主机名或地址。", "Enter a hostname or address.")
    if (!draft.user.trim()) say("请填写用户名。", "Enter a user name.")
    if (!validPort(draft.port)) say("SSH 端口必须在 1 到 65535 之间。", "The SSH port must be from 1 to 65535.")
  }
  if (draft.forwards.length === 0) say("至少需要一条端口映射。", "Add at least one port mapping.")
  const seen = new Set<string>()
  draft.forwards.forEach((forward, index) => {
    const label = language === "en" ? `Mapping ${index + 1}` : `映射 ${index + 1}`
    if (!validPort(forward.listenPort) || !validPort(forward.destinationPort)) {
      say(`${label}：端口必须在 1 到 65535 之间。`, `${label}: ports must be from 1 to 65535.`)
    }
    if (!forward.listenHost.trim() || !forward.destinationHost.trim()) {
      say(`${label}：请填写监听地址和目标地址。`, `${label}: enter a listen address and a destination.`)
    }
    if (forward.listenHost.trim() && !isLoopbackHost(forward.listenHost) && !forward.allowExternal) {
      say(
        `${label}：非本机监听必须明确允许对外暴露。`,
        `${label}: a non-loopback listener needs an explicit exposure confirmation.`,
      )
    }
    const key = `${forward.direction}|${forward.listenHost.trim()}|${forward.listenPort.trim()}`
    if (seen.has(key)) {
      say(`${label}：同一方向的监听地址和端口不能重复。`, `${label}: that listen endpoint is already used.`)
    }
    seen.add(key)
  })
  return issues
}

export function profileFromDraft(draft: Draft): Profile {
  const target: Target =
    draft.mode === "alias"
      ? { kind: "configAlias", alias: draft.alias.trim() }
      : {
          kind: "manual",
          hostname: draft.hostname.trim(),
          port: Number(draft.port),
          user: draft.user.trim(),
          identityFile: draft.identityFile.trim() ? draft.identityFile.trim() : null,
          proxyJump: draft.clearJump ? "" : draft.proxyJump.trim() ? draft.proxyJump.trim() : null,
        }
  return {
    id: draft.id,
    name: draft.name.trim(),
    target,
    authMode: draft.authMode,
    rememberPassword: draft.rememberPassword,
    forwards: draft.forwards.map((forward) => ({
      id: forward.id,
      direction: forward.direction,
      listenHost: forward.listenHost.trim(),
      listenPort: Number(forward.listenPort),
      destinationHost: forward.destinationHost.trim(),
      destinationPort: Number(forward.destinationPort),
      allowExternal: forward.allowExternal,
    })),
    createdAt: draft.createdAt,
    updatedAt: new Date().toISOString(),
  }
}

export function targetLabel(profile: Profile) {
  if (profile.target.kind === "configAlias") return profile.target.alias
  return `${profile.target.user}@${profile.target.hostname}:${profile.target.port}`
}

function validPort(value: string) {
  if (!/^\d+$/.test(value.trim())) return false
  const port = Number(value)
  return port >= 1 && port <= 65535
}

export function assertNoSecretFields(value: unknown): void {
  const walk = (node: unknown) => {
    if (Array.isArray(node)) {
      node.forEach(walk)
      return
    }
    if (!node || typeof node !== "object") return
    for (const [key, child] of Object.entries(node)) {
      const lower = key.toLowerCase()
      if (lower === "password" || lower === "passphrase" || lower === "secret" || lower === "privatekey") {
        throw new Error(`secret field ${key}`)
      }
      walk(child)
    }
  }
  walk(value)
}
