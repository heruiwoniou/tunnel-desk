import { describe, expect, it } from "vitest"

import { assertNoSecretFields, directionHelp, directionLabel, draftIssues, emptyDraft, profileFromDraft } from "@/lib/draft"
import { previewProfiles } from "@/lib/api"
import type { SecretMeta } from "@/lib/types"

describe("saved profiles exclude secrets", () => {
  it("does not copy typed passwords into the profile payload", () => {
    const draft = emptyDraft()
    draft.name = "数据库"
    draft.mode = "manual"
    draft.hostname = "db.internal"
    draft.user = "rui"
    draft.port = "22"
    draft.typedPassword = "SENTINEL-SECRET-VALUE"
    draft.typedPassphrase = "SENTINEL-PASSPHRASE"
    draft.forwards[0] = {
      ...draft.forwards[0],
      direction: "remote",
      listenHost: "127.0.0.1",
      listenPort: "9000",
      destinationHost: "127.0.0.1",
      destinationPort: "3000",
      allowExternal: false,
    }
    const profile = profileFromDraft(draft)
    const encoded = JSON.stringify(profile)
    assertNoSecretFields(profile)
    expect(encoded).not.toContain("SENTINEL")
    expect(encoded).not.toContain("typedPassword")
    expect(profile.rememberPassword).toBe(false)
    expect(profile.forwards[0]?.direction).toBe("remote")
  })

  it("rejects an external listener that was not explicitly allowed", () => {
    const draft = emptyDraft()
    draft.name = "暴露"
    draft.mode = "alias"
    draft.alias = "db"
    draft.forwards[0] = {
      ...draft.forwards[0],
      listenHost: "0.0.0.0",
      allowExternal: false,
    }
    expect(draftIssues(draft, "zh").some((issue) => issue.includes("对外暴露"))).toBe(true)
  })

  it("labels local and remote directions differently", () => {
    expect(directionLabel("local", "zh")).toContain("-L")
    expect(directionLabel("remote", "zh")).toContain("-R")
    expect(directionHelp("local", "zh")).toContain("服务器")
    expect(directionHelp("remote", "zh")).toContain("这台电脑")
  })

  it("keeps browser fixtures disconnected and free of secret fields", () => {
    for (const profile of previewProfiles) {
      assertNoSecretFields(profile)
      expect(profile.name).toContain("预览")
    }
    const meta: SecretMeta = {
      serverPasswordStored: true,
      keyPassphraseStored: false,
      keyringAvailable: false,
      keyringMessage: "Secret Service is unavailable",
    }
    expect(JSON.stringify(meta)).not.toMatch(/SENTINEL|password":/i)
    expect("serverPassword" in meta).toBe(false)
  })
})
