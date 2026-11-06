import { useMemo, useState } from "react"
import { PlusIcon, Trash2Icon } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command"
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
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { draftFromProfile, draftIssues, emptyDraft, isLoopbackHost, newForward, profileFromDraft, type Draft } from "@/lib/draft"
import type { Language, Profile, SshAlias } from "@/lib/types"

type ProfileDialogProps = {
  open: boolean
  language: Language
  hosts: SshAlias[]
  keyringAvailable: boolean
  keyringMessage: string | null
  initial: Profile | null
  suggestedAlias?: string
  onOpenChange: (open: boolean) => void
  onSave: (profile: Profile) => Promise<void>
}

export function ProfileDialog({
  open,
  language,
  hosts,
  keyringAvailable,
  keyringMessage,
  initial,
  suggestedAlias,
  onOpenChange,
  onSave,
}: ProfileDialogProps) {
  const [draft, setDraft] = useState<Draft>(() => {
    const next = initial ? draftFromProfile(initial) : emptyDraft()
    if (!initial && suggestedAlias) {
      next.mode = "alias"
      next.alias = suggestedAlias
    }
    return next
  })
  const [saving, setSaving] = useState(false)
  const zh = language !== "en"
  const issues = useMemo(() => draftIssues(draft, language), [draft, language])

  function update(patch: Partial<Draft>) {
    setDraft((current) => ({ ...current, ...patch }))
  }

  async function submit() {
    if (issues.length > 0) return
    setSaving(true)
    try {
      await onSave(profileFromDraft(draft))
      onOpenChange(false)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) {
          const seeded = initial ? draftFromProfile(initial) : emptyDraft()
          if (!initial && suggestedAlias) {
            seeded.mode = "alias"
            seeded.alias = suggestedAlias
          }
          setDraft(seeded)
        }
        onOpenChange(next)
      }}
    >
      <DialogContent className="max-h-[86vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{initial ? (zh ? "编辑隧道" : "Edit tunnel") : zh ? "新建隧道" : "New tunnel"}</DialogTitle>
          <DialogDescription>
            {zh
              ? "规则保存在本机。密码和密钥口令不会写入这条规则。"
              : "The rule stays on this computer. Passwords and key passphrases are not stored in it."}
          </DialogDescription>
        </DialogHeader>
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="tunnel-name">{zh ? "名称" : "Name"}</FieldLabel>
            <Input
              id="tunnel-name"
              value={draft.name}
              onChange={(event) => update({ name: event.target.value })}
              placeholder={zh ? "例如：数据库" : "For example: database"}
            />
          </Field>
          <Field>
            <FieldLabel>{zh ? "主机来源" : "Host source"}</FieldLabel>
            <ToggleGroup
              type="single"
              variant="outline"
              value={draft.mode}
              onValueChange={(value) => {
                if (value === "alias" || value === "manual") update({ mode: value })
              }}
            >
              <ToggleGroupItem value="alias">{zh ? "SSH 配置别名" : "SSH config alias"}</ToggleGroupItem>
              <ToggleGroupItem value="manual">{zh ? "手动填写" : "Manual host"}</ToggleGroupItem>
            </ToggleGroup>
          </Field>
          {draft.mode === "alias" ? (
            <Field>
              <FieldLabel>{zh ? "别名" : "Alias"}</FieldLabel>
              <Command className="rounded-lg border">
                <CommandInput
                  placeholder={zh ? "搜索别名，或直接输入" : "Search aliases, or type one"}
                  value={draft.alias}
                  onValueChange={(alias) => update({ alias })}
                />
                <CommandList>
                  <CommandEmpty>{zh ? "配置里没有匹配的具体主机。" : "No concrete host matches."}</CommandEmpty>
                  <CommandGroup heading={zh ? "来自 SSH 配置" : "From SSH config"}>
                    {hosts
                      .filter((host) => !host.wildcard)
                      .map((host) => (
                        <CommandItem key={host.alias} value={host.alias} onSelect={(alias) => update({ alias })}>
                          {host.alias}
                        </CommandItem>
                      ))}
                  </CommandGroup>
                </CommandList>
              </Command>
              <FieldDescription>
                {zh
                  ? "只列出具体别名。Host * 这类通配符不会被当成一台主机。"
                  : "Only concrete aliases are listed. Patterns such as Host * are not hosts."}
              </FieldDescription>
            </Field>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <FieldLabel htmlFor="manual-host">{zh ? "主机" : "Host"}</FieldLabel>
                <Input id="manual-host" value={draft.hostname} onChange={(event) => update({ hostname: event.target.value })} />
              </Field>
              <Field>
                <FieldLabel htmlFor="manual-port">{zh ? "端口" : "Port"}</FieldLabel>
                <Input id="manual-port" inputMode="numeric" value={draft.port} onChange={(event) => update({ port: event.target.value })} />
              </Field>
              <Field>
                <FieldLabel htmlFor="manual-user">{zh ? "用户" : "User"}</FieldLabel>
                <Input id="manual-user" value={draft.user} onChange={(event) => update({ user: event.target.value })} />
              </Field>
              <Field>
                <FieldLabel htmlFor="manual-key">{zh ? "私钥文件" : "Identity file"}</FieldLabel>
                <Input
                  id="manual-key"
                  value={draft.identityFile}
                  placeholder="~/.ssh/id_ed25519"
                  onChange={(event) => update({ identityFile: event.target.value })}
                />
              </Field>
              <Field className="sm:col-span-2">
                <FieldLabel htmlFor="manual-jump">ProxyJump</FieldLabel>
                <Input
                  id="manual-jump"
                  value={draft.proxyJump}
                  disabled={draft.clearJump}
                  placeholder={zh ? "留空则沿用 SSH 配置" : "Empty inherits the SSH config"}
                  onChange={(event) => update({ proxyJump: event.target.value })}
                />
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox checked={draft.clearJump} onCheckedChange={(checked) => update({ clearJump: checked === true })} />
                  {zh ? "不使用跳板，即使配置里有 ProxyJump" : "Do not use a jump host, even if the config has one"}
                </label>
              </Field>
            </div>
          )}
          <Field>
            <FieldLabel>{zh ? "认证方式" : "Authentication"}</FieldLabel>
            <Select value={draft.authMode} onValueChange={(authMode) => update({ authMode: authMode as Draft["authMode"] })}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="auto">{zh ? "自动（代理、密钥，然后密码）" : "Automatic (agent, key, then password)"}</SelectItem>
                  <SelectItem value="password">{zh ? "服务器密码" : "Server password"}</SelectItem>
                  <SelectItem value="publicKey">{zh ? "私钥文件" : "Private key file"}</SelectItem>
                  <SelectItem value="agent">{zh ? "SSH agent" : "SSH agent"}</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
            <FieldDescription>
              {zh
                ? "服务器密码和私钥口令是两回事，连接时分开询问。"
                : "The server password and the private-key passphrase are asked separately."}
            </FieldDescription>
          </Field>
          <Field orientation="horizontal" data-disabled={!keyringAvailable || undefined}>
            <Switch
              id="remember-password"
              checked={draft.rememberPassword && keyringAvailable}
              disabled={!keyringAvailable}
              onCheckedChange={(rememberPassword) => update({ rememberPassword })}
            />
            <FieldLabel htmlFor="remember-password">{zh ? "记住服务器密码" : "Remember the server password"}</FieldLabel>
          </Field>
          {!keyringAvailable ? (
            <Alert>
              <AlertTitle>{zh ? "钥匙串不可用" : "Keyring unavailable"}</AlertTitle>
              <AlertDescription>
                {keyringMessage ??
                  (zh
                    ? "无法写入系统钥匙串，所以不能记住密码。本次输入的密码只用于这一次连接。"
                    : "The OS keyring is unavailable, so the password cannot be remembered. A typed password is used only for this connection.")}
              </AlertDescription>
            </Alert>
          ) : null}
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-sm font-medium">{zh ? "端口映射" : "Port mappings"}</h3>
              <Button type="button" variant="outline" size="sm" onClick={() => update({ forwards: [...draft.forwards, newForward()] })}>
                <PlusIcon data-icon="inline-start" />
                {zh ? "添加" : "Add"}
              </Button>
            </div>
            {draft.forwards.map((forward, index) => {
              const exposed = !isLoopbackHost(forward.listenHost)
              return (
                <div key={forward.id} className="flex flex-col gap-3 rounded-lg border p-3">
                  <div className="flex items-center justify-between gap-3">
                    <ToggleGroup
                      type="single"
                      size="sm"
                      variant="outline"
                      value={forward.direction}
                      onValueChange={(direction) => {
                        if (direction !== "local" && direction !== "remote") return
                        update({
                          forwards: draft.forwards.map((item) => (item.id === forward.id ? { ...item, direction } : item)),
                        })
                      }}
                    >
                      <ToggleGroupItem value="local">{zh ? "本地 -L" : "Local -L"}</ToggleGroupItem>
                      <ToggleGroupItem value="remote">{zh ? "远程 -R" : "Remote -R"}</ToggleGroupItem>
                    </ToggleGroup>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-sm"
                      aria-label={zh ? "删除映射" : "Remove mapping"}
                      onClick={() => update({ forwards: draft.forwards.filter((item) => item.id !== forward.id) })}
                    >
                      <Trash2Icon />
                    </Button>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {forward.direction === "local"
                      ? zh
                        ? "本机监听这个地址，流量送到服务器能访问的目标。"
                        : "This computer listens here and the server reaches the destination."
                      : zh
                        ? "服务器监听这个地址，流量送到这台电脑能访问的目标。"
                        : "The server listens here and this computer reaches the destination."}
                  </p>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <Field>
                      <FieldLabel htmlFor={`listen-host-${index}`}>{zh ? "监听地址" : "Listen address"}</FieldLabel>
                      <Input
                        id={`listen-host-${index}`}
                        value={forward.listenHost}
                        onChange={(event) =>
                          update({
                            forwards: draft.forwards.map((item) =>
                              item.id === forward.id ? { ...item, listenHost: event.target.value } : item,
                            ),
                          })
                        }
                      />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor={`listen-port-${index}`}>{zh ? "监听端口" : "Listen port"}</FieldLabel>
                      <Input
                        id={`listen-port-${index}`}
                        inputMode="numeric"
                        value={forward.listenPort}
                        onChange={(event) =>
                          update({
                            forwards: draft.forwards.map((item) =>
                              item.id === forward.id ? { ...item, listenPort: event.target.value } : item,
                            ),
                          })
                        }
                      />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor={`dest-host-${index}`}>{zh ? "目标地址" : "Destination"}</FieldLabel>
                      <Input
                        id={`dest-host-${index}`}
                        value={forward.destinationHost}
                        onChange={(event) =>
                          update({
                            forwards: draft.forwards.map((item) =>
                              item.id === forward.id ? { ...item, destinationHost: event.target.value } : item,
                            ),
                          })
                        }
                      />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor={`dest-port-${index}`}>{zh ? "目标端口" : "Destination port"}</FieldLabel>
                      <Input
                        id={`dest-port-${index}`}
                        inputMode="numeric"
                        value={forward.destinationPort}
                        onChange={(event) =>
                          update({
                            forwards: draft.forwards.map((item) =>
                              item.id === forward.id ? { ...item, destinationPort: event.target.value } : item,
                            ),
                          })
                        }
                      />
                    </Field>
                  </div>
                  {exposed ? (
                    <Alert>
                      <AlertTitle>{zh ? "这个监听地址不是本机回环" : "This listener is not loopback"}</AlertTitle>
                      <AlertDescription>
                        {zh
                          ? "对外监听会让同一网络上的其他机器访问这条转发。TunnelDesk 不会修改防火墙或 sshd。"
                          : "A non-loopback listener can be reached by other machines. TunnelDesk does not change the firewall or sshd."}
                      </AlertDescription>
                    </Alert>
                  ) : null}
                  <label className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={forward.allowExternal}
                      onCheckedChange={(checked) =>
                        update({
                          forwards: draft.forwards.map((item) =>
                            item.id === forward.id ? { ...item, allowExternal: checked === true } : item,
                          ),
                        })
                      }
                    />
                    {zh ? "我确认允许这个监听地址对外暴露" : "I confirm this listen address may be exposed"}
                  </label>
                </div>
              )
            })}
          </div>
          {issues.length > 0 ? (
            <Alert>
              <AlertTitle>{zh ? "还不能保存" : "Cannot save yet"}</AlertTitle>
              <AlertDescription>
                <ul className="flex list-disc flex-col gap-1 pl-4">
                  {issues.map((issue) => (
                    <li key={issue}>{issue}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          ) : null}
        </FieldGroup>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            {zh ? "取消" : "Cancel"}
          </Button>
          <Button type="button" disabled={issues.length > 0 || saving} onClick={() => void submit()}>
            {zh ? "保存规则" : "Save rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
