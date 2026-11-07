import { useEffect, useMemo, useState } from "react"

import {
  type AuthChallengeContext,
  challengeFields,
  challengeScopeLine,
  connectRequestFromChallenge,
  isStaleChallengeSubmission,
} from "@/lib/auth-challenge"
import type { ConnectRequest, Language } from "@/lib/types"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"

export function buildConnectChallengeRequest(
  challenge: AuthChallengeContext,
  values: {
    serverPassword: string
    keyPassphrase: string
    rememberServerPassword: boolean
    rememberKeyPassphrase: boolean
  },
): { request: ConnectRequest } | { error: "stale" | "empty" } {
  const { needPassword, needPassphrase } = challengeFields(challenge.code)
  const request = connectRequestFromChallenge(challenge, {
    serverPassword: needPassword ? values.serverPassword : null,
    keyPassphrase: needPassphrase ? values.keyPassphrase : null,
    rememberServerPassword: values.rememberServerPassword,
    rememberKeyPassphrase: values.rememberKeyPassphrase,
  })
  if (isStaleChallengeSubmission(challenge, request)) {
    return { error: "stale" }
  }
  if (needPassword && !values.serverPassword.trim()) {
    return { error: "empty" }
  }
  if (needPassphrase && !values.keyPassphrase.trim()) {
    return { error: "empty" }
  }
  return { request }
}

export function ConnectChallengeDialog({
  open,
  challenge,
  language,
  keyringAvailable,
  keyringMessage,
  onOpenChange,
  onSubmit,
}: {
  open: boolean
  challenge: AuthChallengeContext | null
  language: Language
  keyringAvailable: boolean
  keyringMessage: string | null
  onOpenChange: (open: boolean) => void
  onSubmit: (request: ConnectRequest) => Promise<void>
}) {
  const zh = language !== "en"
  const challengeCode = challenge?.code ?? null
  const [serverPassword, setServerPassword] = useState("")
  const [keyPassphrase, setKeyPassphrase] = useState("")
  const [rememberServer, setRememberServer] = useState(false)
  const [rememberKey, setRememberKey] = useState(false)
  const [pending, setPending] = useState(false)
  const [stale, setStale] = useState(false)
  const { needPassword, needPassphrase } = challengeCode
    ? challengeFields(challengeCode)
    : { needPassword: false, needPassphrase: false }

  const title = useMemo(() => {
    if (!challengeCode) return ""
    if (challengeCode === "password_rejected") return zh ? "密码被拒绝" : "Password rejected"
    if (challengeCode === "passphrase_rejected") return zh ? "口令不正确" : "Passphrase incorrect"
    if (needPassword) return zh ? "需要服务器密码" : "Server password required"
    return zh ? "需要私钥口令" : "Key passphrase required"
  }, [challengeCode, needPassword, zh])

  useEffect(() => {
    if (!open) {
      setServerPassword("")
      setKeyPassphrase("")
      setRememberServer(false)
      setRememberKey(false)
      setStale(false)
    }
  }, [open, challenge?.challengeId])

  if (!challenge || !challengeCode) {
    return null
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {challengeScopeLine(challenge, language) ? (
              <span className="block pb-2 text-muted-foreground">
                {challengeScopeLine(challenge, language)}
              </span>
            ) : null}
            {challenge.message}
          </DialogDescription>
        </DialogHeader>
        {stale ? (
          <Alert variant="destructive">
            <AlertTitle>{zh ? "挑战已过期" : "Challenge expired"}</AlertTitle>
            <AlertDescription>
              {zh ? "请关闭对话框后使用最新提示重试。" : "Close the dialog and retry with the newest prompt."}
            </AlertDescription>
          </Alert>
        ) : null}
        <FieldGroup>
          {needPassword ? (
            <>
              <Field>
                <FieldLabel htmlFor="server-password">{zh ? "服务器密码" : "Server password"}</FieldLabel>
                <Input
                  id="server-password"
                  type="password"
                  autoComplete="off"
                  value={serverPassword}
                  onChange={(event) => setServerPassword(event.target.value)}
                />
              </Field>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={rememberServer && keyringAvailable}
                  disabled={!keyringAvailable}
                  onCheckedChange={(checked) => setRememberServer(checked === true)}
                />
                {zh ? "把服务器密码记入系统钥匙串" : "Store the server password in the OS keyring"}
              </label>
            </>
          ) : null}
          {needPassphrase ? (
            <>
              <Field>
                <FieldLabel htmlFor="key-passphrase">{zh ? "私钥口令" : "Key passphrase"}</FieldLabel>
                <Input
                  id="key-passphrase"
                  type="password"
                  autoComplete="off"
                  value={keyPassphrase}
                  onChange={(event) => setKeyPassphrase(event.target.value)}
                />
                <FieldDescription>
                  {zh ? "只用于解开私钥，不会当作服务器密码。" : "Used only to unlock a private key, not as the server password."}
                </FieldDescription>
              </Field>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={rememberKey && keyringAvailable}
                  disabled={!keyringAvailable}
                  onCheckedChange={(checked) => setRememberKey(checked === true)}
                />
                {zh ? "把私钥口令记入系统钥匙串" : "Store the key passphrase in the OS keyring"}
              </label>
            </>
          ) : null}
          {!keyringAvailable ? (
            <Alert>
              <AlertTitle>{zh ? "不能记住密码" : "Cannot remember a password"}</AlertTitle>
              <AlertDescription>
                {keyringMessage ??
                  (zh ? "钥匙串不可用时不会改用明文文件。" : "There is no plaintext fallback when the keyring is unavailable.")}
              </AlertDescription>
            </Alert>
          ) : null}
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {zh ? "取消" : "Cancel"}
          </Button>
          <Button
            disabled={pending}
            onClick={() => {
              const built = buildConnectChallengeRequest(challenge, {
                serverPassword,
                keyPassphrase,
                rememberServerPassword: rememberServer,
                rememberKeyPassphrase: rememberKey,
              })
              if ("error" in built) {
                if (built.error === "stale") {
                  setStale(true)
                }
                return
              }
              setServerPassword("")
              setKeyPassphrase("")
              setPending(true)
              void onSubmit(built.request).finally(() => setPending(false))
            }}
          >
            {pending ? <Spinner data-icon="inline-start" /> : null}
            {zh ? "继续连接" : "Continue"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
