import type { AppErrorBody, ConnectRequest, Language } from "@/lib/types"

export const AUTH_CHALLENGE_CODES = [
  "password_required",
  "passphrase_required",
  "password_rejected",
  "passphrase_rejected",
] as const

export type AuthChallengeCode = (typeof AUTH_CHALLENGE_CODES)[number]

export type AuthChallengeContext = {
  profileId: string
  code: AuthChallengeCode
  message: string
  challengeHost?: string | null
  challengeHop?: "jump" | "target" | string | null
}

export function isAuthChallengeCode(code: string): code is AuthChallengeCode {
  return (AUTH_CHALLENGE_CODES as readonly string[]).includes(code)
}

export function challengeFields(code: AuthChallengeCode): {
  needPassword: boolean
  needPassphrase: boolean
} {
  const needPassword = code === "password_required" || code === "password_rejected"
  const needPassphrase = code === "passphrase_required" || code === "passphrase_rejected"
  return { needPassword, needPassphrase }
}

export function connectRequestFromChallenge(
  challenge: AuthChallengeContext,
  secrets: {
    serverPassword?: string | null
    keyPassphrase?: string | null
    rememberServerPassword?: boolean
    rememberKeyPassphrase?: boolean
  },
): ConnectRequest {
  const { needPassword, needPassphrase } = challengeFields(challenge.code)
  return {
    profileId: challenge.profileId,
    serverPassword: needPassword ? (secrets.serverPassword ?? null) : null,
    keyPassphrase: needPassphrase ? (secrets.keyPassphrase ?? null) : null,
    rememberServerPassword: secrets.rememberServerPassword ?? false,
    rememberKeyPassphrase: secrets.rememberKeyPassphrase ?? false,
    challengeHost: challenge.challengeHost ?? null,
  }
}

export function challengeHopLabel(hop: string | null | undefined, language: Language): string | null {
  if (!hop) return null
  const zh = language !== "en"
  if (hop === "jump") return zh ? "跳板" : "Jump host"
  if (hop === "target") return zh ? "目标主机" : "Target host"
  return hop
}

export function challengeScopeLine(
  challenge: Pick<AuthChallengeContext, "challengeHost" | "challengeHop">,
  language: Language,
): string | null {
  if (!challenge.challengeHost) return null
  const hop = challengeHopLabel(challenge.challengeHop ?? null, language)
  const zh = language !== "en"
  if (hop) {
    return zh
      ? `凭据用于 ${hop}（${challenge.challengeHost}）。`
      : `Credentials apply to ${hop} (${challenge.challengeHost}).`
  }
  return zh
    ? `凭据用于 ${challenge.challengeHost}。`
    : `Credentials apply to ${challenge.challengeHost}.`
}

export function mergeAuthChallenge(error: AppErrorBody, profileId: string): AuthChallengeContext | null {
  if (!isAuthChallengeCode(error.code)) return null
  return {
    profileId,
    code: error.code,
    message: error.message,
    challengeHost: error.challengeHost ?? null,
    challengeHop: error.challengeHop ?? null,
  }
}
