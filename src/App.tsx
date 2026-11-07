import { useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { CableIcon, PlusIcon, Trash2Icon, UnplugIcon } from "lucide-react"

import {
  type AuthChallengeCode,
  type AuthChallengeContext,
  challengeScopeLine,
  connectRequestFromChallenge,
  isAuthChallengeCode,
  mergeAuthChallenge,
} from "@/lib/auth-challenge"
import { ProfileDialog } from "@/components/profile-dialog"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
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
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import {
  addRuntimeForward,
  asAppError,
  backendInfo,
  clearHistory,
  cancelConnect,
  connectProfile,
  deleteProfile,
  disconnectAll,
  disconnectProfile,
  forgetPassphrases,
  forgetServerPassword,
  forgetTrust,
  getSettings,
  isDesktop,
  listHistory,
  listHosts,
  listProfiles,
  listTrust,
  onHostKey,
  onNeedsInput,
  onTunnelState,
  previewProfiles,
  previewSettings,
  resolveHost,
  removeRuntimeForward,
  respondHostKey,
  runtimeSnapshots,
  saveProfile,
  saveSettings,
  secretMeta,
} from "@/lib/api"
import { directionHelp, directionLabel, targetLabel } from "@/lib/draft"
import type {
  BackendInfo,
  Direction,
  ForwardMapping,
  HistoryEntry,
  HostKeyEvent,
  Language,
  Phase,
  Profile,
  ResolvedHost,
  SecretMeta,
  Settings,
  SshAlias,
  Theme,
  TrustStore,
  TunnelSnapshot,
} from "@/lib/types"

const busy = new Set<Phase>(["connecting", "authenticating", "binding", "connected"])

export default function App() {
  const desktop = isDesktop()
  const [loading, setLoading] = useState(desktop)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [profiles, setProfiles] = useState<Profile[]>(desktop ? [] : previewProfiles)
  const [snapshots, setSnapshots] = useState<TunnelSnapshot[]>([])
  const [hosts, setHosts] = useState<SshAlias[]>([])
  const [history, setHistory] = useState<HistoryEntry[]>([])
  const [settings, setSettings] = useState<Settings>(previewSettings)
  const [info, setInfo] = useState<BackendInfo | null>(null)
  const [trust, setTrust] = useState<TrustStore>({ entries: [] })
  const [selectedId, setSelectedId] = useState<string | null>(desktop ? null : previewProfiles[0]?.id ?? null)
  const [editor, setEditor] = useState<Profile | "new" | null>(null)
  const [authChallenge, setAuthChallenge] = useState<AuthChallengeContext | null>(null)
  const [connectingId, setConnectingId] = useState<string | null>(null)
  const [removingForwardId, setRemovingForwardId] = useState<string | null>(null)
  const [hostKey, setHostKey] = useState<HostKeyEvent | null>(null)
  const [pendingDelete, setPendingDelete] = useState<Profile | null>(null)
  const [meta, setMeta] = useState<SecretMeta | null>(null)
  const [hostQuery, setHostQuery] = useState("")
  const [resolved, setResolved] = useState<ResolvedHost | null>(null)
  const [resolving, setResolving] = useState(false)

  const zh = settings.language !== "en"
  const selected = profiles.find((profile) => profile.id === selectedId) ?? null
  const snapshot = snapshots.find((item) => item.profileId === selectedId)
  const phase: Phase = snapshot?.phase ?? "disconnected"

  useEffect(() => {
    const root = document.documentElement
    const media = window.matchMedia("(prefers-color-scheme: dark)")
    const apply = () => {
      const dark = settings.theme === "dark" || (settings.theme === "system" && media.matches)
      root.classList.toggle("dark", dark)
    }
    apply()
    media.addEventListener("change", apply)
    return () => media.removeEventListener("change", apply)
  }, [settings.theme])

  useEffect(() => {
    if (!desktop) return
    const unlisteners: Array<() => void> = []
    let cancelled = false
    void (async () => {
      unlisteners.push(await onTunnelState((next) => setSnapshots(next)))
      unlisteners.push(await onHostKey((prompt) => setHostKey(prompt)))
      unlisteners.push(
        await onNeedsInput((payload) => {
          if (isAuthChallengeCode(payload.code)) {
            setAuthChallenge({
              profileId: payload.profileId,
              code: payload.code,
              message: payload.message,
              challengeHost: payload.challengeHost ?? null,
              challengeHop: payload.challengeHop ?? null,
            })
            setSelectedId(payload.profileId)
          } else {
            toast.error(explain(payload.code, payload.message, settings.language))
          }
        }),
      )
      if (cancelled) unlisteners.forEach((unlisten) => unlisten())
    })()
    return () => {
      cancelled = true
      unlisteners.forEach((unlisten) => unlisten())
    }
  }, [desktop, settings.language])

  useEffect(() => {
    if (!desktop) return
    void refresh()
  }, [desktop])

  useEffect(() => {
    if (!desktop || !selected) {
      setMeta(null)
      return
    }
    void secretMeta(selected.id)
      .then(setMeta)
      .catch(() => setMeta(null))
  }, [desktop, selected])

  async function refresh() {
    setLoading(true)
    setLoadError(null)
    try {
      const [nextProfiles, nextHosts, nextHistory, nextSettings, nextInfo, nextSnapshots, nextTrust] = await Promise.all([
        listProfiles(),
        listHosts(),
        listHistory(),
        getSettings(),
        backendInfo(),
        runtimeSnapshots(),
        listTrust(),
      ])
      setProfiles(nextProfiles)
      setHosts(nextHosts.filter((host) => !host.wildcard))
      setHistory(nextHistory)
      setSettings(nextSettings)
      setInfo(nextInfo)
      setSnapshots(nextSnapshots)
      setTrust(nextTrust)
      setSelectedId((current) => current ?? nextProfiles[0]?.id ?? null)
    } catch (error) {
      setLoadError(asAppError(error).message)
    } finally {
      setLoading(false)
    }
  }

  async function persistSettings(next: Settings) {
    setSettings(next)
    if (!desktop) return
    try {
      setSettings(await saveSettings(next))
    } catch (error) {
      toast.error(asAppError(error).message)
    }
  }

  async function onSave(profile: Profile) {
    if (!desktop) {
      toast.message(zh ? "浏览器预览不会保存规则。" : "Browser preview does not save rules.")
      return
    }
    try {
      const saved = await saveProfile(profile)
      setProfiles((current) => {
        const exists = current.some((item) => item.id === saved.id)
        return exists ? current.map((item) => (item.id === saved.id ? saved : item)) : [...current, saved]
      })
      setSelectedId(saved.id)
      toast.success(zh ? "规则已保存" : "Rule saved")
    } catch (error) {
      toast.error(asAppError(error).message)
      throw error
    }
  }

  const runningCount = snapshots.filter((item) => busy.has(item.phase)).length

  async function attemptConnect(
    profileId: string,
    secrets?: {
      serverPassword?: string | null
      keyPassphrase?: string | null
      rememberServerPassword?: boolean
      rememberKeyPassphrase?: boolean
    },
    challenge?: Pick<AuthChallengeContext, "challengeHost" | "challengeHop" | "code"> | null,
  ) {
    if (!desktop) return
    setConnectingId(profileId)
    try {
      const active =
        challenge ??
        (authChallenge?.profileId === profileId
          ? {
              code: authChallenge.code,
              challengeHost: authChallenge.challengeHost,
              challengeHop: authChallenge.challengeHop,
            }
          : null)
      const outcome = await connectProfile(
        active && isAuthChallengeCode(active.code)
          ? connectRequestFromChallenge(
              {
                profileId,
                code: active.code,
                message: "",
                challengeHost: active.challengeHost,
                challengeHop: active.challengeHop,
              },
              secrets ?? {},
            )
          : {
              profileId,
              serverPassword: secrets?.serverPassword ?? null,
              keyPassphrase: secrets?.keyPassphrase ?? null,
              rememberServerPassword: secrets?.rememberServerPassword ?? false,
              rememberKeyPassphrase: secrets?.rememberKeyPassphrase ?? false,
            },
      )
      outcome.warnings.forEach((warning) => toast.warning(warning.message))
      toast.success(zh ? "隧道已建立" : "Tunnel is up")
      setAuthChallenge(null)
      setSnapshots(await runtimeSnapshots())
      if (selected?.id === profileId) {
        setMeta(await secretMeta(profileId).catch(() => null))
      }
    } catch (error) {
      const body = asAppError(error)
      const nextChallenge = mergeAuthChallenge(body, profileId)
      if (nextChallenge) {
        setAuthChallenge(nextChallenge)
      } else if (body.code === "cancelled" || body.code === "already_connecting") {
        setAuthChallenge(null)
      } else {
        toast.error(explain(body.code, body.message, settings.language))
        setAuthChallenge(null)
      }
    } finally {
      setConnectingId(null)
    }
  }

  return (
    <main className="flex h-svh flex-col bg-background text-foreground">
      {!desktop ? (
        <Alert className="rounded-none border-x-0 border-t-0">
          <AlertTitle>{zh ? "浏览器预览" : "Browser preview"}</AlertTitle>
          <AlertDescription>
            {zh
              ? "未连接桌面后端。示例隧道保持未连接，不能代表托盘、钥匙串或真实端口转发。"
              : "The desktop backend is not connected. The sample tunnel stays disconnected and does not exercise the tray, keyring, or real forwarding."}
          </AlertDescription>
        </Alert>
      ) : null}
      <header className="flex items-center justify-between gap-3 px-4 py-3">
        <div className="flex min-w-0 flex-col">
          <h1 className="truncate text-base font-semibold tracking-tight">TunnelDesk</h1>
          <p className="truncate text-xs text-muted-foreground">
            {zh ? "SSH 端口转发" : "SSH port forwarding"}
            {info ? ` · ${info.engine}` : ""}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={runningCount > 0 ? "default" : "secondary"}>
            {zh ? `${runningCount} 条活动` : `${runningCount} active`}
          </Badge>
          <Button variant="outline" size="sm" disabled={!desktop || runningCount === 0} onClick={() => void disconnectEverything(zh)}>
            <UnplugIcon data-icon="inline-start" />
            {zh ? "断开全部" : "Disconnect all"}
          </Button>
        </div>
      </header>
      <Separator />
      <Tabs defaultValue="tunnels" className="min-h-0 flex-1 gap-0">
        <div className="px-4 py-2">
          <TabsList>
            <TabsTrigger value="tunnels">{zh ? "隧道" : "Tunnels"}</TabsTrigger>
            <TabsTrigger value="hosts">{zh ? "主机" : "Hosts"}</TabsTrigger>
            <TabsTrigger value="history">{zh ? "历史" : "History"}</TabsTrigger>
            <TabsTrigger value="settings">{zh ? "设置" : "Settings"}</TabsTrigger>
          </TabsList>
        </div>
        <TabsContent value="tunnels" className="flex min-h-0 flex-1 flex-col px-4 pb-4">
          {loading ? (
            <div className="flex flex-col gap-3">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-40 w-full" />
            </div>
          ) : loadError ? (
            <Alert>
              <AlertTitle>{zh ? "没有读到本地数据" : "Local data could not be read"}</AlertTitle>
              <AlertDescription className="flex flex-col items-start gap-3">
                <span>{loadError}</span>
                <Button size="sm" variant="outline" onClick={() => void refresh()}>
                  {zh ? "重试" : "Retry"}
                </Button>
              </AlertDescription>
            </Alert>
          ) : (
            <div className="grid min-h-0 flex-1 items-start gap-3 md:grid-cols-[minmax(15rem,18rem)_minmax(0,1fr)]">
              <div className="flex min-h-0 flex-col gap-2">
                <Button onClick={() => setEditor("new")}>
                  <PlusIcon data-icon="inline-start" />
                  {zh ? "新建隧道" : "New tunnel"}
                </Button>
                {profiles.length === 0 ? (
                  <Empty className="border">
                    <EmptyHeader>
                      <EmptyMedia variant="icon">
                        <CableIcon />
                      </EmptyMedia>
                      <EmptyTitle>{zh ? "还没有隧道" : "No tunnels yet"}</EmptyTitle>
                      <EmptyDescription>
                        {zh
                          ? "从主机页选一个 SSH 别名，或手动填写地址。规则保存在本机，密码只进系统钥匙串。"
                          : "Pick an SSH alias from Hosts, or enter an address. Rules stay on this computer; passwords go only to the OS keyring."}
                      </EmptyDescription>
                    </EmptyHeader>
                    <EmptyContent>
                      <Button size="sm" variant="outline" onClick={() => setEditor("new")}>
                        {zh ? "创建第一条" : "Create the first one"}
                      </Button>
                    </EmptyContent>
                  </Empty>
                ) : (
                  <ScrollArea className="min-h-0 flex-1 md:max-h-[calc(100svh-11rem)]">
                    <div className="flex flex-col gap-1.5 pr-3">
                      {profiles.map((profile) => {
                        const itemPhase = snapshots.find((item) => item.profileId === profile.id)?.phase ?? "disconnected"
                        return (
                          <button
                            key={profile.id}
                            type="button"
                            onClick={() => setSelectedId(profile.id)}
                            className={`flex items-center justify-between gap-2 rounded-lg border px-3 py-2 text-left focus-visible:ring-3 focus-visible:ring-ring/50 ${
                              profile.id === selectedId ? "bg-muted" : "bg-card"
                            }`}
                          >
                            <span className="flex min-w-0 flex-col gap-0.5">
                              <span className="truncate text-sm font-medium">{profile.name}</span>
                              <span className="truncate text-xs text-muted-foreground">{targetLabel(profile)}</span>
                            </span>
                            <PhaseBadge phase={itemPhase} language={settings.language} />
                          </button>
                        )
                      })}
                    </div>
                  </ScrollArea>
                )}
              </div>
              <Card className="min-h-0 min-w-0">
                {selected ? (
                  <>
                    <CardHeader>
                      <CardTitle className="flex flex-wrap items-center gap-2">
                        {selected.name}
                        <PhaseBadge phase={phase} language={settings.language} />
                      </CardTitle>
                      <CardDescription>{targetLabel(selected)}</CardDescription>
                    </CardHeader>
                    <CardContent className="flex flex-col gap-4">
                      {snapshot?.message ? <p className="text-sm text-muted-foreground">{snapshot.message}</p> : null}
                      <div className="flex flex-col gap-3 rounded-lg border bg-muted/30 p-3">
                        <div className="flex items-center justify-between gap-2">
                          <p className="text-sm font-medium">{zh ? "端口映射" : "Port forwards"}</p>
                          {phase === "connected" ? (
                            <Badge variant="secondary">{zh ? "运行时可改" : "Live editable"}</Badge>
                          ) : null}
                        </div>
                        {(phase === "connected" && snapshot ? snapshot.forwards : selected.forwards.map((forward) => ({
                          id: forward.id,
                          direction: forward.direction,
                          listen: `${forward.listenHost}:${forward.listenPort}`,
                          destination: `${forward.destinationHost}:${forward.destinationPort}`,
                          state: zh ? "未启动" : "stopped",
                          message: "",
                        }))).length === 0 ? (
                          <p className="text-sm text-muted-foreground">{zh ? "没有端口映射。" : "No forwards configured."}</p>
                        ) : (
                          <div className="flex flex-col gap-3">
                            {(phase === "connected" && snapshot
                              ? snapshot.forwards
                              : selected.forwards.map((forward) => ({
                                  id: forward.id,
                                  direction: forward.direction,
                                  listen: `${forward.listenHost}:${forward.listenPort}`,
                                  destination: `${forward.destinationHost}:${forward.destinationPort}`,
                                  state: zh ? "未启动" : "stopped",
                                  message: "",
                                }))
                            ).map((forward, index) => {
                              const config = selected.forwards.find((item) => item.id === forward.id)
                              return (
                                <div key={forward.id} className="flex flex-col gap-2">
                                  {index > 0 ? <Separator /> : null}
                                  <div className="flex flex-wrap items-center justify-between gap-2">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <Badge variant="outline">
                                        {directionLabel((config?.direction ?? forward.direction) as Direction, settings.language)}
                                      </Badge>
                                      <span className="text-xs text-muted-foreground">
                                        {directionHelp((config?.direction ?? forward.direction) as Direction, settings.language)}
                                      </span>
                                    </div>
                                    {phase === "connected" && desktop ? (
                                      <Button
                                        variant="ghost"
                                        size="sm"
                                        disabled={removingForwardId === forward.id}
                                        onClick={() => {
                                          setRemovingForwardId(forward.id)
                                          void removeRuntimeForward(selected.id, forward.id, false)
                                            .then(() => runtimeSnapshots().then(setSnapshots))
                                            .then(() => toast.success(zh ? "映射已移除" : "Forward removed"))
                                            .catch((error) => toast.error(asAppError(error).message))
                                            .finally(() => setRemovingForwardId(null))
                                        }}
                                      >
                                        <Trash2Icon data-icon="inline-start" />
                                        {zh ? "移除" : "Remove"}
                                      </Button>
                                    ) : null}
                                  </div>
                                  <div className="grid gap-2 sm:grid-cols-2">
                                    <div className="flex flex-col gap-0.5">
                                      <span className="text-xs text-muted-foreground">{zh ? "监听" : "Listen"}</span>
                                      <span className="font-medium tabular-nums">{forward.listen}</span>
                                    </div>
                                    <div className="flex flex-col gap-0.5">
                                      <span className="text-xs text-muted-foreground">{zh ? "目标" : "Destination"}</span>
                                      <span className="font-medium tabular-nums">{forward.destination}</span>
                                    </div>
                                  </div>
                                  <span className="text-xs text-muted-foreground">
                                    {zh ? "状态" : "State"}
                                    {" · "}
                                    {forward.state}
                                    {forward.message ? ` · ${forward.message}` : ""}
                                  </span>
                                </div>
                              )
                            })}
                          </div>
                        )}
                        {phase === "connected" && desktop ? (
                          <RuntimeForwardAdd
                            language={settings.language}
                            onAdd={async (mapping, persist) => {
                              await addRuntimeForward(selected.id, mapping, persist)
                              setSnapshots(await runtimeSnapshots())
                              if (persist) {
                                setProfiles((current) =>
                                  current.map((item) =>
                                    item.id === selected.id ? { ...item, forwards: [...item.forwards, mapping] } : item,
                                  ),
                                )
                              }
                              toast.success(zh ? "映射已添加" : "Forward added")
                            }}
                          />
                        ) : null}
                      </div>
                      {meta ? (
                        <p className="text-sm text-muted-foreground">
                          {zh ? "已保存的服务器密码：" : "Saved server password: "}
                          {meta.serverPasswordStored ? (zh ? "有" : "yes") : zh ? "无" : "no"}
                          {zh ? "。已保存的密钥口令：" : ". Saved key passphrase: "}
                          {meta.keyPassphraseStored ? (zh ? "有" : "yes") : zh ? "无" : "no"}
                        </p>
                      ) : null}
                      <div className="flex flex-wrap gap-2">
                        {busy.has(phase) ? (
                          <Button variant="outline" disabled={!desktop} onClick={() => void stop(selected.id, zh)}>
                            {zh ? "断开" : "Disconnect"}
                          </Button>
                        ) : (
                          <Button
                            disabled={!desktop || connectingId === selected.id}
                            onClick={() => void attemptConnect(selected.id)}
                          >
                            {connectingId === selected.id ? <Spinner data-icon="inline-start" /> : null}
                            {zh ? "连接" : "Connect"}
                          </Button>
                        )}
                        <Button variant="outline" onClick={() => setEditor(selected)}>
                          {zh ? "编辑" : "Edit"}
                        </Button>
                        <Button
                          variant="outline"
                          disabled={!desktop || !meta?.serverPasswordStored}
                          onClick={() => void forgetPassword(selected.id, zh)}
                        >
                          {zh ? "忘记密码" : "Forget password"}
                        </Button>
                        <Button variant="ghost" onClick={() => setPendingDelete(selected)}>
                          {zh ? "删除" : "Delete"}
                        </Button>
                      </div>
                    </CardContent>
                  </>
                ) : (
                  <CardContent className="py-10 text-sm text-muted-foreground">
                    {zh ? "选择一条隧道查看映射和状态。" : "Select a tunnel to see its mappings and status."}
                  </CardContent>
                )}
              </Card>
            </div>
          )}
        </TabsContent>
        <TabsContent value="hosts" className="px-4 pb-4">
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <Command className="rounded-lg border">
              <CommandInput
                placeholder={zh ? "搜索 SSH 配置别名" : "Search SSH config aliases"}
                value={hostQuery}
                onValueChange={setHostQuery}
              />
              <CommandList>
                <CommandEmpty>
                  {hosts.length === 0
                    ? zh
                      ? "没有读到具体别名。可以在新建隧道时手动填写主机。"
                      : "No concrete aliases were found. You can enter a host manually."
                    : zh
                      ? "没有匹配的别名。"
                      : "No alias matches."}
                </CommandEmpty>
                <CommandGroup heading={zh ? "具体主机" : "Concrete hosts"}>
                  {hosts.map((host) => (
                    <CommandItem key={`${host.configPath}:${host.alias}`} value={host.alias} onSelect={(value) => void lookup(value)}>
                      {host.alias}
                    </CommandItem>
                  ))}
                </CommandGroup>
              </CommandList>
            </Command>
            <Card>
              <CardHeader>
                <CardTitle>{zh ? "解析结果" : "Resolution"}</CardTitle>
                <CardDescription>
                  {zh
                    ? "优先使用本机 ssh -G。没有 ssh 时使用内置解析器，并标明未处理的选项。"
                    : "OpenSSH ssh -G is preferred. Without ssh, the built-in parser is used and names the options it does not apply."}
                </CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-3 text-sm">
                {resolving ? <Skeleton className="h-20 w-full" /> : null}
                {resolved ? (
                  <>
                    <p>
                      {resolved.user}@{resolved.hostname}:{resolved.port}
                    </p>
                    <p className="text-muted-foreground">
                      {resolved.resolution === "openssh" ? "ssh -G" : zh ? "内置解析器" : "Built-in parser"}
                    </p>
                    {resolved.proxyJump ? <p>ProxyJump {resolved.proxyJump}</p> : null}
                    {resolved.proxyCommand ? <p>ProxyCommand</p> : null}
                    {resolved.identityFiles.length > 0 ? (
                      <p className="break-all text-muted-foreground">{resolved.identityFiles.join(", ")}</p>
                    ) : null}
                    {resolved.certificateFiles.length > 0 ? (
                      <p className="break-all text-muted-foreground">
                        CertificateFile {resolved.certificateFiles.join(", ")}
                      </p>
                    ) : null}
                    {resolved.warnings.map((warning) => (
                      <Alert key={warning}>
                        <AlertDescription>{warning}</AlertDescription>
                      </Alert>
                    ))}
                    <Button
                      size="sm"
                      onClick={() => {
                        setEditor("new")
                      }}
                    >
                      {zh ? "用这个别名新建" : "Create from this alias"}
                    </Button>
                  </>
                ) : (
                  <p className="text-muted-foreground">{zh ? "选择一个别名查看它会怎样被解析。" : "Choose an alias to see how it resolves."}</p>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
        <TabsContent value="history" className="px-4 pb-4">
          <div className="mb-3 flex justify-end">
            <Button variant="outline" size="sm" disabled={!desktop || history.length === 0} onClick={() => void wipeHistory(zh)}>
              {zh ? "清空历史" : "Clear history"}
            </Button>
          </div>
          {history.length === 0 ? (
            <Empty className="border">
              <EmptyHeader>
                <EmptyTitle>{zh ? "还没有连接记录" : "No connection history"}</EmptyTitle>
                <EmptyDescription>{zh ? "连接或失败之后会记在这里，不包含密码。" : "Connections and failures are recorded here, without passwords."}</EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{zh ? "名称" : "Name"}</TableHead>
                  <TableHead>{zh ? "目标" : "Target"}</TableHead>
                  <TableHead>{zh ? "结果" : "Outcome"}</TableHead>
                  <TableHead>{zh ? "说明" : "Detail"}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {history.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell>{entry.name}</TableCell>
                    <TableCell>{entry.target}</TableCell>
                    <TableCell>{entry.outcome}</TableCell>
                    <TableCell>{entry.message}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </TabsContent>
        <TabsContent value="settings" className="px-4 pb-4">
          <Card>
            <CardHeader>
              <CardTitle>{zh ? "偏好" : "Preferences"}</CardTitle>
              <CardDescription>
                {info?.trayAvailable
                  ? zh
                    ? "关闭窗口时可以留在托盘，隧道继续运行。退出菜单会断开并结束进程。"
                    : "Closing the window can leave it in the tray with tunnels running. Quit disconnects them and exits."
                  : zh
                    ? "当前环境没有可用的系统托盘。关闭窗口会断开隧道并退出，避免窗口被藏起来。"
                    : "No system tray is available. Closing the window disconnects tunnels and quits, so the window cannot be hidden."}
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-5">
              <FieldGroup>
                <Field>
                  <FieldLabel>{zh ? "主题" : "Theme"}</FieldLabel>
                  <ToggleGroup
                    type="single"
                    variant="outline"
                    value={settings.theme}
                    onValueChange={(value) => {
                      if (value === "system" || value === "light" || value === "dark") {
                        void persistSettings({ ...settings, theme: value satisfies Theme })
                      }
                    }}
                  >
                    <ToggleGroupItem value="system">{zh ? "跟随系统" : "System"}</ToggleGroupItem>
                    <ToggleGroupItem value="light">{zh ? "浅色" : "Light"}</ToggleGroupItem>
                    <ToggleGroupItem value="dark">{zh ? "深色" : "Dark"}</ToggleGroupItem>
                  </ToggleGroup>
                </Field>
                <Field>
                  <FieldLabel>{zh ? "语言" : "Language"}</FieldLabel>
                  <ToggleGroup
                    type="single"
                    variant="outline"
                    value={settings.language}
                    onValueChange={(value) => {
                      if (value === "zh" || value === "en") void persistSettings({ ...settings, language: value })
                    }}
                  >
                    <ToggleGroupItem value="zh">中文</ToggleGroupItem>
                    <ToggleGroupItem value="en">English</ToggleGroupItem>
                  </ToggleGroup>
                </Field>
                <Field>
                  <FieldLabel>{zh ? "关闭窗口" : "Close window"}</FieldLabel>
                  <ToggleGroup
                    type="single"
                    variant="outline"
                    value={settings.closeBehavior}
                    onValueChange={(value) => {
                      if (value === "minimizeToTray" || value === "quit") {
                        void persistSettings({ ...settings, closeBehavior: value })
                      }
                    }}
                  >
                    <ToggleGroupItem value="minimizeToTray">{zh ? "最小化到托盘" : "Minimize to tray"}</ToggleGroupItem>
                    <ToggleGroupItem value="quit">{zh ? "退出并断开" : "Quit and disconnect"}</ToggleGroupItem>
                  </ToggleGroup>
                  <FieldDescription>
                    {zh
                      ? "没有托盘时，最小化选项会自动变成退出。"
                      : "Without a tray, minimize becomes quit."}
                  </FieldDescription>
                </Field>
                <Field orientation="horizontal">
                  <Switch
                    id="start-minimized"
                    checked={settings.startMinimized}
                    onCheckedChange={(startMinimized) => void persistSettings({ ...settings, startMinimized })}
                  />
                  <FieldLabel htmlFor="start-minimized">{zh ? "启动后先收到托盘" : "Start in the tray"}</FieldLabel>
                </Field>
              </FieldGroup>
              <Alert>
                <AlertTitle>{zh ? "钥匙串" : "Keyring"}</AlertTitle>
                <AlertDescription>
                  {info?.keyringAvailable
                    ? zh
                      ? "密码可以保存到系统钥匙串。界面只知道有没有保存，拿不到密码本身。"
                      : "Passwords can be stored in the OS keyring. The interface only knows whether one is saved."
                    : info?.keyringMessage ??
                      (zh
                        ? "系统钥匙串不可用。可以继续输入密码连接，但不能记住它。"
                        : "The OS keyring is unavailable. You can still type a password, but it cannot be remembered.")}
                </AlertDescription>
              </Alert>
              <div className="flex flex-col gap-2">
                <h3 className="text-sm font-medium">{zh ? "已信任的主机密钥" : "Trusted host keys"}</h3>
                {trust.entries.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    {zh ? "首次连接时会询问指纹。这里的记录不会写回 known_hosts。" : "The first connection asks for the fingerprint. These records are not written back to known_hosts."}
                  </p>
                ) : (
                  trust.entries.map((entry) => (
                    <div key={`${entry.host}:${entry.port}:${entry.algorithm}`} className="flex items-center justify-between gap-3 rounded-lg border px-3 py-2">
                      <div className="min-w-0">
                        <p className="truncate text-sm">
                          {entry.host}:{entry.port}
                        </p>
                        <p className="truncate text-xs text-muted-foreground">
                          {entry.algorithm} {entry.fingerprint}
                        </p>
                      </div>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={!desktop}
                        onClick={() => void dropTrust(entry.host, entry.port, zh)}
                      >
                        {zh ? "忘记" : "Forget"}
                      </Button>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
      <ProfileDialog
        key={editor === "new" ? `new-${resolved?.query ?? "blank"}` : editor?.id ?? "closed"}
        open={editor !== null}
        language={settings.language}
        hosts={hosts}
        keyringAvailable={info?.keyringAvailable ?? false}
        keyringMessage={info?.keyringMessage ?? null}
        suggestedAlias={editor === "new" ? resolved?.query : undefined}
        initial={editor && editor !== "new" ? editor : null}
        onOpenChange={(open) => {
          if (!open) setEditor(null)
        }}
        onSave={onSave}
      />
      <ConnectDialog
        open={authChallenge !== null}
        challengeCode={authChallenge && isAuthChallengeCode(authChallenge.code) ? authChallenge.code : null}
        challengeMessage={authChallenge?.message ?? null}
        challengeScope={
          authChallenge ? challengeScopeLine(authChallenge, settings.language) : null
        }
        language={settings.language}
        keyringAvailable={info?.keyringAvailable ?? false}
        keyringMessage={info?.keyringMessage ?? null}
        onOpenChange={(open) => {
          if (!open && authChallenge) {
            void cancelConnect(authChallenge.profileId).finally(() => setAuthChallenge(null))
          }
        }}
        onSubmit={async (serverPassword, keyPassphrase, rememberServerPassword, rememberKeyPassphrase) => {
          if (!authChallenge) return
          await attemptConnect(authChallenge.profileId, {
            serverPassword,
            keyPassphrase,
            rememberServerPassword,
            rememberKeyPassphrase,
          })
        }}
      />
      <Dialog open={hostKey !== null} onOpenChange={(open) => !open && hostKey && void answerHostKey(false)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{zh ? "确认主机密钥" : "Confirm host key"}</DialogTitle>
            <DialogDescription>
              {zh
                ? "这台主机还不在 TunnelDesk 的信任记录里。请核对指纹后再继续。密钥变化会被拒绝，不会静默接受。"
                : "This host is not in TunnelDesk's trust store. Check the fingerprint before continuing. A changed key is refused."}
            </DialogDescription>
          </DialogHeader>
          {hostKey ? (
            <div className="flex flex-col gap-2 text-sm">
              <p>
                {hostKey.host}:{hostKey.port}
              </p>
              <p>{hostKey.algorithm}</p>
              <p className="break-all font-mono text-xs">{hostKey.fingerprint}</p>
            </div>
          ) : null}
          <DialogFooter>
            <Button variant="outline" onClick={() => void answerHostKey(false)}>
              {zh ? "拒绝" : "Reject"}
            </Button>
            <Button onClick={() => void answerHostKey(true)}>{zh ? "信任并继续" : "Trust and continue"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <AlertDialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{zh ? "删除这条隧道？" : "Delete this tunnel?"}</AlertDialogTitle>
            <AlertDialogDescription>
              {zh ? "规则和对应的已保存密码会被删除。SSH 配置文件不会被修改。" : "The rule and any saved secrets for it are removed. Your SSH config is not modified."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{zh ? "取消" : "Cancel"}</AlertDialogCancel>
            <AlertDialogAction onClick={() => pendingDelete && void removeProfile(pendingDelete, zh)}>
              {zh ? "删除" : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </main>
  )

  async function disconnectEverything(chinese: boolean) {
    try {
      await disconnectAll()
      setSnapshots([])
      toast.success(chinese ? "已全部断开" : "All tunnels disconnected")
    } catch (error) {
      toast.error(asAppError(error).message)
    }
  }

  async function stop(id: string, chinese: boolean) {
    try {
      await disconnectProfile(id)
      setSnapshots(await runtimeSnapshots())
      toast.success(chinese ? "已断开" : "Disconnected")
    } catch (error) {
      toast.error(asAppError(error).message)
    }
  }

  async function forgetPassword(id: string, chinese: boolean) {
    try {
      await forgetServerPassword(id)
      await forgetPassphrases(id)
      setMeta(await secretMeta(id))
      toast.success(chinese ? "已从钥匙串删除" : "Removed from the keyring")
    } catch (error) {
      toast.error(asAppError(error).message)
    }
  }

  async function removeProfile(profile: Profile, chinese: boolean) {
    try {
      if (busy.has(snapshots.find((item) => item.profileId === profile.id)?.phase ?? "disconnected")) {
        await disconnectProfile(profile.id)
      }
      await deleteProfile(profile.id)
      setProfiles((current) => current.filter((item) => item.id !== profile.id))
      setSelectedId((current) => (current === profile.id ? null : current))
      setPendingDelete(null)
      toast.success(chinese ? "已删除" : "Deleted")
    } catch (error) {
      toast.error(asAppError(error).message)
    }
  }

  async function lookup(query: string) {
    if (!desktop) {
      setResolved({
        query,
        hostname: `${query}.example`,
        user: "preview",
        port: 22,
        identityFiles: [],
        certificateFiles: [],
        identitiesOnly: false,
        pubkeyAuthentication: true,
        proxyJump: null,
        proxyCommand: null,
        identityAgent: null,
        hostKeyAlias: null,
        knownHostsFiles: [],
        revokedHostKeys: [],
        preferredAuthentications: [],
        resolution: "preview",
        warnings: [zh ? "浏览器预览没有读取你的 SSH 配置。" : "Browser preview did not read your SSH config."],
      })
      return
    }
    setResolving(true)
    try {
      setResolved(await resolveHost(query))
    } catch (error) {
      toast.error(asAppError(error).message)
    } finally {
      setResolving(false)
    }
  }

  async function wipeHistory(chinese: boolean) {
    try {
      await clearHistory()
      setHistory([])
      toast.success(chinese ? "历史已清空" : "History cleared")
    } catch (error) {
      toast.error(asAppError(error).message)
    }
  }

  async function dropTrust(host: string, port: number, chinese: boolean) {
    try {
      await forgetTrust(host, port)
      setTrust(await listTrust())
      toast.success(chinese ? "已忘记这台主机的应用内信任" : "Forgot the in-app trust for this host")
    } catch (error) {
      toast.error(asAppError(error).message)
    }
  }

  async function answerHostKey(accept: boolean) {
    if (!hostKey) return
    const requestId = hostKey.requestId
    setHostKey(null)
    try {
      await respondHostKey(requestId, accept)
    } catch (error) {
      toast.error(asAppError(error).message)
    }
  }
}

function PhaseBadge({ phase, language }: { phase: Phase; language: Language }) {
  const zh = language !== "en"
  const label =
    phase === "connected"
      ? zh
        ? "已连接"
        : "Connected"
      : phase === "connecting" || phase === "authenticating" || phase === "binding"
        ? zh
          ? "连接中"
          : "Connecting"
        : phase === "failed"
          ? zh
            ? "失败"
            : "Failed"
          : zh
            ? "未连接"
            : "Disconnected"
  const variant = phase === "connected" ? "default" : phase === "failed" ? "destructive" : "secondary"
  return <Badge variant={variant}>{label}</Badge>
}

function explain(code: string, fallback: string, language: Language) {
  const zh = language !== "en"
  const known: Record<string, string> = {
    password_required: zh ? "需要服务器密码。" : "A server password is required.",
    password_rejected: zh ? "服务器拒绝了该密码。" : "The server rejected that password.",
    passphrase_required: zh ? "私钥已加密，需要口令。" : "The private key is encrypted and needs its passphrase.",
    passphrase_rejected: zh ? "私钥口令不正确。" : "The private-key passphrase is incorrect.",
    already_connecting: zh ? "已有连接正在进行。" : "A connection is already in progress.",
    forward_cancel_failed: zh ? "服务器未确认取消远程转发。" : "The server did not confirm cancelling the remote forward.",
    cancelled: zh ? "连接已取消。" : "The connection was cancelled.",
    auth_failed: zh ? "认证失败。" : "Authentication failed.",
    host_key_rejected: zh ? "未信任主机密钥，连接已取消。" : "The host key was not trusted.",
    host_key_changed: zh ? "主机密钥与已记录的值不一致，连接已拒绝。" : "The host key changed and the connection was refused.",
    host_key_revoked: zh ? "主机密钥已被吊销。" : "The host key is revoked.",
    port_in_use: zh ? "本地端口已被占用。" : "The local port is already in use.",
    forward_denied: zh ? "服务器拒绝了端口转发。" : "The server refused the forward.",
    keyring_unavailable: zh ? "系统钥匙串不可用，密码没有被保存。" : "The OS keyring is unavailable, so the password was not saved.",
    keyring_locked: zh ? "系统钥匙串已锁定。" : "The OS keyring is locked.",
  }
  return known[code] ?? fallback
}

function RuntimeForwardAdd({
  language,
  onAdd,
}: {
  language: Language
  onAdd: (mapping: ForwardMapping, persist: boolean) => Promise<void>
}) {
  const zh = language !== "en"
  const [direction, setDirection] = useState<Direction>("local")
  const [listenPort, setListenPort] = useState("")
  const [destinationPort, setDestinationPort] = useState("")
  const [persist, setPersist] = useState(false)
  const [pending, setPending] = useState(false)

  return (
    <div className="flex flex-col gap-3 border-t pt-3">
      <p className="text-sm font-medium">{zh ? "添加运行时映射" : "Add runtime forward"}</p>
      <ToggleGroup type="single" value={direction} onValueChange={(value) => value && setDirection(value as Direction)}>
        <ToggleGroupItem value="local" aria-label={zh ? "本地转发" : "Local forward"}>
          L
        </ToggleGroupItem>
        <ToggleGroupItem value="remote" aria-label={zh ? "远程转发" : "Remote forward"}>
          R
        </ToggleGroupItem>
      </ToggleGroup>
      <div className="grid gap-2 sm:grid-cols-2">
        <Field>
          <FieldLabel htmlFor="runtime-listen">{zh ? "监听端口" : "Listen port"}</FieldLabel>
          <Input
            id="runtime-listen"
            inputMode="numeric"
            value={listenPort}
            onChange={(event) => setListenPort(event.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="runtime-dest">{zh ? "目标端口" : "Destination port"}</FieldLabel>
          <Input
            id="runtime-dest"
            inputMode="numeric"
            value={destinationPort}
            onChange={(event) => setDestinationPort(event.target.value)}
          />
        </Field>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <Checkbox checked={persist} onCheckedChange={(checked) => setPersist(checked === true)} />
        {zh ? "同时写入隧道配置" : "Also save in tunnel profile"}
      </label>
      <Button
        size="sm"
        variant="outline"
        disabled={pending}
        onClick={() => {
          const listen = Number.parseInt(listenPort, 10)
          const destination = Number.parseInt(destinationPort, 10)
          if (!Number.isFinite(listen) || !Number.isFinite(destination)) {
            toast.error(zh ? "请填写有效端口。" : "Enter valid ports.")
            return
          }
          const mapping: ForwardMapping = {
            id: crypto.randomUUID(),
            direction,
            listenHost: "127.0.0.1",
            listenPort: listen,
            destinationHost: "127.0.0.1",
            destinationPort: destination,
            allowExternal: false,
          }
          setPending(true)
          void onAdd(mapping, persist)
            .then(() => {
              setListenPort("")
              setDestinationPort("")
            })
            .catch((error) => toast.error(asAppError(error).message))
            .finally(() => setPending(false))
        }}
      >
        {pending ? <Spinner data-icon="inline-start" /> : <PlusIcon data-icon="inline-start" />}
        {zh ? "添加" : "Add"}
      </Button>
    </div>
  )
}

function ConnectDialog({
  open,
  challengeCode,
  challengeMessage,
  challengeScope,
  language,
  keyringAvailable,
  keyringMessage,
  onOpenChange,
  onSubmit,
}: {
  open: boolean
  challengeCode: AuthChallengeCode | null
  challengeMessage: string | null
  challengeScope: string | null
  language: Language
  keyringAvailable: boolean
  keyringMessage: string | null
  onOpenChange: (open: boolean) => void
  onSubmit: (
    serverPassword: string | null,
    keyPassphrase: string | null,
    rememberServerPassword: boolean,
    rememberKeyPassphrase: boolean,
  ) => Promise<void>
}) {
  const zh = language !== "en"
  const [serverPassword, setServerPassword] = useState("")
  const [keyPassphrase, setKeyPassphrase] = useState("")
  const [rememberServer, setRememberServer] = useState(false)
  const [rememberKey, setRememberKey] = useState(false)
  const [pending, setPending] = useState(false)
  const needPassword = challengeCode === "password_required" || challengeCode === "password_rejected"
  const needPassphrase = challengeCode === "passphrase_required" || challengeCode === "passphrase_rejected"
  const title = useMemo(() => {
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
    }
  }, [open])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {challengeScope ? <span className="block pb-2 text-muted-foreground">{challengeScope}</span> : null}
            {challengeMessage ??
              (needPassword
                ? zh
                  ? "SSH 服务器要求密码。密钥与证书已尝试完毕。"
                  : "The SSH server wants a password. Keys and certificates were already tried."
                : zh
                  ? "需要口令来解密私钥或签名证书。"
                  : "A passphrase is needed to decrypt the private key or sign the certificate.")}
          </DialogDescription>
        </DialogHeader>
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
                <FieldDescription>{zh ? "只用于解开私钥，不会当作服务器密码。" : "Used only to unlock a private key, not as the server password."}</FieldDescription>
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
            disabled={pending || (needPassword && !serverPassword.trim()) || (needPassphrase && !keyPassphrase.trim())}
            onClick={() => {
              const password = needPassword ? serverPassword : null
              const passphrase = needPassphrase ? keyPassphrase : null
              const rememberPassword = rememberServer
              const rememberPassphrase = rememberKey
              setServerPassword("")
              setKeyPassphrase("")
              setPending(true)
              void onSubmit(
                password?.trim() ? password : null,
                passphrase?.trim() ? passphrase : null,
                rememberPassword,
                rememberPassphrase,
              ).finally(() => setPending(false))
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
