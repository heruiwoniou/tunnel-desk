import { describe, expect, it } from "vitest"

import {
  challengeFields,
  challengeScopeLine,
  connectRequestFromChallenge,
  isAuthChallengeCode,
  mergeAuthChallenge,
} from "@/lib/auth-challenge"
import type { AppErrorBody } from "@/lib/types"

describe("auth challenge routing", () => {
  it("only treats credential prompts as dialog challenges", () => {
    expect(isAuthChallengeCode("passphrase_required")).toBe(true)
    expect(isAuthChallengeCode("auth_failed")).toBe(false)
    expect(isAuthChallengeCode("cancelled")).toBe(false)
  })

  it("shows password only for password challenges", () => {
    expect(challengeFields("password_required")).toEqual({ needPassword: true, needPassphrase: false })
    expect(challengeFields("passphrase_rejected")).toEqual({ needPassword: false, needPassphrase: true })
  })

  it("binds challenge host for per-hop resume without reusing other secrets", () => {
    const request = connectRequestFromChallenge(
      {
        profileId: "jump-chain",
        code: "passphrase_required",
        message: "needs key",
        challengeHost: "jump.internal",
        challengeHop: "jump",
      },
      { keyPassphrase: "hop-only", rememberKeyPassphrase: true },
    )
    expect(request.serverPassword).toBeNull()
    expect(request.keyPassphrase).toBe("hop-only")
    expect(request.challengeHost).toBe("jump.internal")
  })

  it("maps invoke errors into dialog state", () => {
    const body: AppErrorBody = {
      code: "password_rejected",
      message: "wrong",
      challengeHost: "db.internal",
      challengeHop: "target",
    }
    const merged = mergeAuthChallenge(body, "p1")
    expect(merged?.code).toBe("password_rejected")
    expect(merged?.challengeHost).toBe("db.internal")
    expect(challengeScopeLine(merged!, "zh")).toContain("目标主机")
  })

  it("does not treat server key rejection as a passphrase retry", () => {
    const body: AppErrorBody = { code: "auth_failed", message: "server rejected key" }
    expect(mergeAuthChallenge(body, "p1")).toBeNull()
  })
})
