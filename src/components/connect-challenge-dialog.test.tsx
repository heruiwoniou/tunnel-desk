/** @vitest-environment jsdom */
import { fireEvent, render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { ConnectChallengeDialog } from "@/components/connect-challenge-dialog"

describe("ConnectChallengeDialog", () => {
  const challenge = {
    profileId: "p1",
    code: "passphrase_required" as const,
    message: "需要口令",
    challengeHost: "jump.internal",
    challengeHop: "jump",
    challengeId: "ticket-1",
    challengeEndpoint: "ops@jump.internal:22",
  }

  it("submits a challenge-bound connect request", async () => {
    const submit = vi.fn().mockResolvedValue(undefined)
    render(
      <ConnectChallengeDialog
        open
        challenge={challenge}
        language="zh"
        keyringAvailable
        keyringMessage={null}
        onOpenChange={() => {}}
        onSubmit={submit}
      />,
    )
    fireEvent.change(screen.getByLabelText("私钥口令"), { target: { value: "hop-secret" } })
    fireEvent.click(screen.getByRole("button", { name: "继续连接" }))
    expect(submit).toHaveBeenCalledWith({
      profileId: "p1",
      serverPassword: null,
      keyPassphrase: "hop-secret",
      rememberServerPassword: false,
      rememberKeyPassphrase: false,
      challengeHost: "jump.internal",
      challengeId: "ticket-1",
      challengeEndpoint: "ops@jump.internal:22",
    })
  })

})
