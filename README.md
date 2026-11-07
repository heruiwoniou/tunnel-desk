# TunnelDesk

TunnelDesk 是一个跨平台桌面 SSH 端口转发工具。它在本机用 Rust 进程内的 SSH 客户端建立真实的本地转发（`-L`）和远程转发（`-R`），并把可选记住的密码只放进操作系统钥匙串。界面默认中文，可切换英文，主题跟随系统、浅色或深色。

当前版本 `0.1.0`。本仓库是桌面应用源码，不是网站。

这台 Linux 虚拟机验证过的是 Linux 路径。Windows 和 macOS 的代码与打包配置已经按目标写好，但没有在对应系统上编译或运行。下面的「支持」和「本机已验证」是两张不同的表。

## 环境要求

- Rust stable，`rustc` **不低于 1.90**（本机验证用的是 1.99.1）。不要用更旧的工具链，工程使用 edition 2024。
- Node.js 22（本机 22.23.4）和 npm。
- 系统里的 OpenSSH 客户端（`ssh`）。有它时，主机解析优先走 `ssh -G`。没有它时使用内置解析器，并在界面里标明。
- Linux 桌面依赖：
  - `libwebkit2gtk-4.1-dev`
  - `libayatana-appindicator3-dev`（系统托盘）
  - `librsvg2-dev`
  - `patchelf`
  - `libsecret-1-dev`（编译期链接 Secret Service）
  - 运行期记住密码还需要已解锁的 Secret Service，例如 `gnome-keyring`。没有钥匙串时应用拒绝保存密码，不会改成明文。
- macOS 需要 Xcode 命令行工具。记住密码使用钥匙串（Keychain）。
- Windows 需要 WebView2。SSH 配置默认读 `%USERPROFILE%\.ssh\config`。记住密码使用凭据管理器（Credential Manager）。

本机没有签名证书。不要把 Linux 包描述成已签名或已公证的 Windows / macOS 安装包。

## 架构

```
React + Vite + Tailwind + shadcn/ui
        |  Tauri 命令（窄权限，仅 core:default）
Rust：配置解析、校验、钥匙串、known_hosts、隧道会话、托盘
        |
   russh 0.65 进程内 SSH
```

选择 russh，而不是把密码交给外部 `ssh` 进程，原因是：

- 服务器密码和私钥口令留在进程内存里，用 `zeroize` 包住，不进入命令行参数、环境变量或 shell。
- 主机密钥检查在回调里完成，不能被某个 `-o StrictHostKeyChecking=no` 关掉。
- `-L` 是本机监听后走 `direct-tcpip`；`-R` 是 `tcpip-forward` / `forwarded-tcpip`。监听是否成功决定连接阶段，不会“进程起来了就算已连接”。
- 失败时取消监听并断开会话，避免留下孤儿转发。单个目标拒绝连接只关掉这一条 TCP，不拆掉整个会话。

主机别名优先用本机 OpenSSH：

```text
ssh -T [-F 文件] -G -- 目标
```

`-T` 避免分配终端。不附加 `BatchMode`，也不从界面拼接任意 `-o`。`ssh -G` 不可用时，内置解析器负责列出别名和解析，并写出它没有处理的项。传输实际使用的是解析后的主机、端口、用户、身份文件、`ProxyJump` 和 `ProxyCommand`。解析结果里出现但传输不支持的选项会被拒绝或标明，而不是悄悄忽略后假装兼容全部 OpenSSH 配置。

数据目录（配置、历史、设置、应用自己的主机信任）在 Tauri 的应用数据目录。开发时可以用 `TUNNELDESK_DATA_DIR` 指到别的目录。这个目录里只有 JSON，没有密码。

## 安全设计

记住的秘密只进操作系统钥匙串：

| 平台 | 设施 | 本机是否做过存取 |
| --- | --- | --- |
| macOS | Keychain | 否 |
| Windows | Credential Manager | 否 |
| Linux | Secret Service（gnome-keyring 等） | 是，独立一次性钥匙串 |

实现是 `keyring` 4.2，只开 `v1`（`default-features = false`）。这个 feature 按编译目标选择后端：macOS `apple-native-keyring-store`，Windows `windows-native-keyring-store`，Linux `zbus-secret-service-keyring-store`。不要再打开 `db-keystore` 或 `linux-keyutils`。服务名与包标识相同，都是 `dev.tunneldesk.desktop`。账号名是 `server-password:<规则 id>` 和 `key-passphrase:<规则 id>:<身份文件路径的 SHA-256>`。服务器密码和私钥口令分开存放。`IdentityAgent none` 会关掉代理，不会退回 `SSH_AUTH_SOCK`。

前端只能看到“已保存 / 未保存”。用户当场输入的密码只在连接时传到后端，界面随后清空。钥匙串不可用或已锁定时，保存失败，并说明原因。不会写入 JSON、SQLite、历史、localStorage、日志、环境变量或命令行，也没有明文备用文件。

其他边界：

- 只读 `~/.ssh/config` 和 `known_hosts`，不改写它们，也不改 `sshd`、`GatewayPorts` 或防火墙。
- 未知主机密钥必须在界面里明确信任。已变化或已吊销的密钥直接拒绝，不会自动替换。应用自己的信任记录在单独的 `trust.json`。哈希过的 `known_hosts` 可以信任。
- 主机证书只在 `known_hosts` 或 `UserKnownHostsFile` 里有匹配的 `@cert-authority` 时才信任。证书失败时，按 OpenSSH 的做法退回证书里的原始主机公钥；被吊销的证书或 CA 不会退回。
- `RevokedHostKeys` 是一行一把公钥（可带注释），不是 `known_hosts`。列出的公钥会吊销对应的主机公钥、由它签出的主机证书，以及用它当 CA 的主机证书。空行和 `#` 注释会被忽略。读不了、KRL（`SSHKRL`），或某一行不是公钥时，连接直接拒绝。KRL 本身没有实现。
- 监听地址默认回环。写成 `0.0.0.0` 或 `::` 必须勾选对外暴露，并看到警告。
- 别名、主机、用户、路径、跳板和端口都做校验，拒绝空格、控制字符和把额外选项塞进字段。
- `ProxyCommand` 只来自 SSH 配置，按 OpenSSH 的方式整段交给 shell（Unix `/bin/sh -c`，Windows `cmd.exe /C`），不是界面上的自由命令框。子进程在取消时被结束。
- Tauri capability 只有 `core:default`。没有 shell、fs、opener 插件。CSP 只允许自身、Tauri IPC 和本机开发服务器的热更新。

## SSH 配置语义

内置解析器和 `ssh -G` 都遵守 OpenSSH 的“先出现的值获胜”。更具体的 `Host` 要写在 `Host *` 前面。`IdentityFile` 会累积。相对路径的 `Include` 相对于**包含它的那个文件所在目录**（本机 OpenSSH 9.6 的行为，已对照）。

`Host` 模式里带通配符的名字不会出现在可连接别名列表里，也不能当成一台具体主机去解析。

会表面标明、但不会静默当成已支持的情况：

- `Match exec`、`canonical`、`final`、`localnetwork`、`tagged`，以及 `CanonicalizeHostname`：内置解析器不执行。`ssh -G` 可用时以 OpenSSH 的结果为准。
- 令牌 `%C` 不展开。支持 `%%`、`%h`、`%n`、`%d`、`%u`、`%l`、`%p`、`%r` 和 `~`。
- `ForwardAgent` 不启用。
- `StrictHostKeyChecking=no/off/accept-new` 不沿用。未知主机仍要确认，变化的密钥仍拒绝。
- `GSSAPIAuthentication`、`PKCS11Provider`、`ProxyUseFdpass` 不支持。
- `CertificateFile` 会和匹配的 `IdentityFile` 一起用于登录。没有配置任何 `CertificateFile` 时，会自动尝试旁边的 `<私钥>-cert.pub`。证书本身是公钥，不能代替签名私钥。
- `SecurityKeyProvider`、FIDO/`sk-` 密钥、`verify-required`、未知的证书关键选项，以及 SHA-1（`ssh-rsa`）证书签名，会说明原因并跳过，不会当成已经支持。
- 配置文件里的 `LocalForward` / `RemoteForward` 不会自动变成隧道。映射必须在 TunnelDesk 里显式添加。
- 跳板（`ProxyJump`）只用代理或私钥认证，不用目标机器的密码。键盘交互认证使用的是服务器密码，不是私钥口令。

手动主机可以覆盖解析结果。身份文件留空则继承配置；填写身份文件会替换该主机的 `IdentityFile`，并清掉配置里的 `CertificateFile`，避免把另一把密钥配上原来的证书。旁边的 `<私钥>-cert.pub` 仍会自动发现。跳板留空并勾选清除时，表示明确不要跳板。

用户证书和主机证书是两件事。下面只是占位示例，不是任何真实密钥：

```sshconfig
Host app
  HostName app.example
  User deploy
  IdentityFile ~/.ssh/id_ed25519
  CertificateFile ~/.ssh/id_ed25519-cert.pub
  IdentitiesOnly yes

Host jump
  HostName jump.example
  IdentityFile ~/.ssh/jump_ed25519
  CertificateFile ~/.ssh/jump_ed25519-cert.pub
  IdentitiesOnly yes

Host db
  HostName db.internal
  User db
  ProxyJump jump
  IdentityFile ~/.ssh/id_ed25519
```

只写 `IdentityFile ~/.ssh/id_ed25519`、并且完全没有 `CertificateFile` 时，才会自动使用 `~/.ssh/id_ed25519-cert.pub`。只要配置了任何一个 `CertificateFile`，就不会再自动发现其他证书。agent 里已经解锁同一把签名密钥时，优先用 agent 给证书签名，即使本地私钥文件还在而且加了密；不会把私钥从 agent 里导出。`IdentityAgent none` 或公钥模式不会去问 agent。加密私钥要的是口令，不是服务器登录密码。

```text
# RevokedHostKeys 示例。占位公钥，不是真实密钥。
ssh-ed25519 AAAA...example retired-host
ssh-rsa AAAA...example old-ca
```

主机信任示例：

```text
@cert-authority app.example ssh-ed25519 AAAA...example-ca
```

这只信任这把 CA 签过的主机证书。不会因为解析到 `CertificateFile` 就接受任意服务器证书。

Windows 上配置路径是用户配置目录下的 `.ssh/config`。

## 本地转发和远程转发

本地转发（`-L`）：TunnelDesk 在本机监听，把进来的连接转到 **SSH 服务器能访问** 的目标。

```text
本机 127.0.0.1:15432  ->  SSH 服务器  ->  127.0.0.1:5432
```

远程转发（`-R`）：SSH 服务器监听，把进来的连接转到 **这台电脑能访问** 的目标。

```text
服务器 127.0.0.1:9000  ->  TunnelDesk  ->  127.0.0.1:3000
```

服务器上的 `127.0.0.1` 只在那台服务器自己可见。若要让别的机器连上远程转发，需要服务器管理员自己改 `GatewayPorts` 或防火墙。TunnelDesk 不会去改。

一条规则可以有多条映射。任一监听失败（端口被占用，或服务器拒绝 `tcpip-forward`）时，已经打开的监听会撤掉，会话断开，状态不会停在“已连接”。目标端口拒绝连接时，只结束这一次 TCP，会话和其他监听保持。会话本身断开（对端关闭）时，状态变为失败，监听被释放，历史记为失败，规则仍留在列表里。

## 开发

```bash
npm install
cd src-tauri && cargo test && cd ..
npm run tauri dev
```

开发服务器固定在 [http://127.0.0.1:43123](http://127.0.0.1:43123)。没有 Tauri 时用浏览器打开这个地址，会看到一条标明“预览”的断开规则，不会假装已经连上。

常用检查：

```bash
npm run lint
npm run typecheck
npm test
npm run build
cd src-tauri && cargo fmt --all -- --check && cargo test
```

## 构建

Linux 安装包（本机实际跑过的命令）：

```bash
bash scripts/package-linux.sh
# 等价于
npm run build
npm run tauri build -- --bundles deb
```

产物在 `src-tauri/target/release/bundle/deb/`。本机这次得到 `TunnelDesk_0.1.0_amd64.deb`，3,273,362 字节。包内二进制 `tunneldesk` 7,322,232 字节。未签名。本环境的 AppImage / fuse 依赖不完整，所以实际打出来的只有 `deb`。

`tauri.conf.json` 的 `bundle.targets` 列出了 `deb`、`app`、`dmg`、`nsis`、`msi`，这只是打包配置，不是那些系统上已经成功的构建。在对应系统上可以执行：

```bash
npm run tauri build -- --bundles app          # macOS
npm run tauri build -- --bundles msi nsis     # Windows
```

GitHub Actions 的检查和安装包构建写在 `.github/workflows/ci.yml`，发布写在 `.github/workflows/release.yml`。版本、Changelog 和第一次发布的步骤见 [docs/releasing.md](docs/releasing.md)。工作流产物是未签名安装包。安装包构建成功不等于 Windows 或 macOS 上的窗口、托盘和钥匙串已经验证。

包标识是 `dev.tunneldesk.desktop`，不以 `.app` 结尾。钥匙串服务名使用同一个字符串，并有测试锁住两者一致。

## 密码、钥匙串和忘记

连接对话框把服务器密码和私钥口令分成两个字段。勾选记住之后，后端写入钥匙串。下次连接可以不再输入。再次连接时，若规则仍标记为记住密码，会从钥匙串读出服务器密码；私钥口令同样按身份文件分开读取。

钥匙串不可用或已锁定时：

- 记住开关不可用，并说明 Linux 需要 Secret Service，且不会把密码存成明文。
- 本次仍然可以手动输入密码来连接。这次输入不会落盘。
- 已勾选记住、但钥匙串写入失败时，连接仍使用这次输入的密码，历史和界面里不会出现密码本身。读钥匙串失败会变成警告，不会挡住当场输入的密码。

规则详情里的“忘记密码”删除该规则的服务器密码。设置里可以忘记已信任的主机。钥匙串里的条目由 Rust 删除；前端没有删除接口可以碰到明文。

没有钥匙串时不要期待自动重连出密码。这是故意的。

在一次性钥匙串里验证过的做法（不要对现有用户的钥匙串做这件事）：新建空的 `HOME`，在 `dbus-run-session` 里用 `gnome-keyring-daemon --unlock` 再 `--start --components=secrets`，然后设置 `TUNNELDESK_KEYRING_TEST=1` 跑 `os_keyring_password_authenticates`。这个测试会保存、用保存的密码对临时 OpenSSH 认证、再忘记并确认下一次要求密码。未设置该环境变量时，这个测试立刻返回，不接触任何钥匙串。

## 托盘

菜单包含：显示窗口、最多 16 条规则的连接或断开、断开全部、退出。隐藏窗口不会拆掉正在跑的隧道。退出和“断开全部”会断开本应用拥有的会话并释放监听。

关闭按钮的行为可以在设置里选：最小化到托盘，或退出并清理。只有在托盘对象创建成功，并且会话总线上有 `org.kde.StatusNotifierWatcher` 时，关闭才会隐藏窗口。没有这个宿主时，即使设置选了最小化，关闭也会断开并退出，避免窗口被藏起来以后找不到。Linux 上托盘图标的单击事件经常不会到来，所以“显示窗口”是菜单项，不依赖左键。

本机面板没有出现可点击的托盘图标，托盘菜单没有被交互验证。设置页会写明当前环境没有可用托盘。

## 本机测试结果

命令都在这台 Linux 虚拟机上执行。日期 2026-11-06。工具链：rustc 1.99.1，Node v22.23.4，OpenSSH 9.6p1，Tauri 2，russh 0.65。没有使用用户的 Mac、GCE 或真实 SSH。

| 命令 | 结果 |
| --- | --- |
| `cd src-tauri && cargo fmt --all` | 已格式化 |
| `cd src-tauri && cargo test --offline --lib` | 通过。36 项，约 11.2 秒。未设置钥匙串环境变量，实机钥匙串测试在其中直接返回 |
| `npm run lint` | 通过（eslint，0 warning） |
| `npm run typecheck` | 通过（tsc --noEmit） |
| `npm test` | 通过。Vitest 4 项 |
| `npm run build` | 通过。Vite 8 生产构建成功，有一条大于 500 kB 的包体积警告 |
| `CARGO_BUILD_JOBS=1 bash scripts/package-linux.sh` | 通过。`TunnelDesk_0.1.0_amd64.deb` 3,273,362 字节，二进制 7,322,232 字节。release 编译约 1 分 15 秒。未签名 |

另有一次在一次性 `dbus-run-session` + 已解锁 `gnome-keyring` 里、`TUNNELDESK_KEYRING_TEST=1` 的 `os_keyring_password_authenticates_and_forget_deletes_it`，通过，约 0.33 秒。它走应用自己的保存、读取、认证、忘记路径，密码不在命令行里。

对临时 OpenSSH `sshd`（`/usr/sbin/sshd -f` 指向临时配置，不改系统 sshd）的测试：

- 密码认证的 `-L` 和 `-R` 都能把字节送到回显服务。`Include` 里更具体的 `Host` 写在 `Host *` 前面，`ssh -G` 的解析和实际 TCP 连接使用的是同一个用户和端口。断开后两个监听端口都可以再次绑定。JSON 里没有口令。记住密码后可以不再输入并重连，忘记之后下一次要求密码。
- 未知主机要确认。`ssh-keygen -H` 之后的哈希 `known_hosts` 可以信任且不再询问。`@revoked` 拒绝。换成另一把密钥拒绝。
- 连一个没人听的端口不会留下监听。两条本地转发里有一条端口被占用时返回 `port_in_use` 并释放另一条。`AllowTcpForwarding local` 时远程转发被拒绝，本地监听也被释放。
- 会话建立之后杀掉 sshd，状态变为失败，本地端口释放，历史结果是 `failed`。
- 加密的 ed25519 只接受私钥口令，不接受把口令当成服务器密码。只有服务器密码、没有口令时，公钥模式返回 `passphrase_required`，sshd 日志里没有 `Accepted password`。
- `ProxyJump` 的跳板日志是 `Accepted publickey`，没有 `Accepted password`。`ProxyCommand` 会真正执行并留下标记文件。
- 目标端口拒绝时（OpenSSH 对 `direct-tcpip` 回 channel-open 失败），会话保持已连接，另一条转发仍能传数据。

russh 测试服务器仍覆盖：双向数据、断开释放端口、错误口令、变化的主机密钥、端口占用、服务器拒绝转发。它和 OpenSSH 不是同一个实现，不能互相代替。

原生窗口在本机 X 显示（`DISPLAY=:1`）里打开过。截图是真实 WebKit 窗口。其中「已连接」来自对临时 sshd 的密码认证，sshd 日志有 `Accepted password`，两条监听都处于 listening。目标端口 9 拒绝之后，监听仍然接受新连接，会话没有被拆掉。界面上的主机名是合成夹具。密码没有出现在截图或日志说明里。桌面会话本身没有可用的 Secret Service，所以这次图形界面连接没有勾选记住密码；记住密码的往返是上面的一次性钥匙串测试，不是这张截图。

## 平台

代码按这些平台编写（尚未在该系统上构建或运行的，不能写成已验证）：

| 平台 | 代码里准备了什么 |
| --- | --- |
| Linux x86_64 | deb 包、Secret Service、Ayatana 托盘、WebKitGTK |
| macOS | `app` / `dmg` 目标、Keychain、`~/.ssh/config` |
| Windows | `nsis` / `msi` 目标、Credential Manager、`%USERPROFILE%\.ssh\config` |

这台虚拟机实际验证过的：

| 平台 | 实际发生的事 |
| --- | --- |
| Linux x86_64 | 编译、36 项 Rust 测试、前端检查、russh 集成测试、临时 OpenSSH 的 L/R、主机密钥、跳板、口令与密码区分、会话丢失、一次性钥匙串往返、原生窗口截图、关闭窗口会退出并释放端口。已打出未签名的 `TunnelDesk_0.1.0_amd64.deb`（3,273,362 字节，二进制 7,322,232 字节）。 |
| macOS | 未构建，未签名，未公证。 |
| Windows | 未构建，未签名。SSH agent 只在 Unix 上连接。 |

## 已知限制

- 不支持 GSSAPI、PKCS#11、FIDO/安全密钥、Pageant、OpenSSH KRL、`ProxyUseFdpass`、agent 转发。
- 用户证书的 principal 和 `source-address` 由服务器判定。客户端不把 principal 当成必须等于登录用户名，也不在本机猜测 NAT 之后的源地址。
- 主机证书的 principal 按 OpenSSH 9.6 做精确比较，不把 `*.example` 当成通配。`HostKeyAlias` 同时用于 known_hosts 查找和 principal。空的 principal 列表表示任意主机名。
- Windows 命名管道 agent（`\\.\pipe\openssh-ssh-agent`）有代码，但没有在 Windows 上用真实 agent 验证。macOS agent 与 Linux 一样走 Unix socket；macOS CI 没有 `useradd`，因此没有在 macOS 上跑 sshd 证书集成测试。Pageant 没有接入。
- 跳板不用目标主机的密码。
- 配置文件里的 `LocalForward` / `RemoteForward` 不会自动套用。
- 没有用户会话总线或钥匙串已锁定时，不能记住密码。普通桌面会话若没有已解锁的 Secret Service，设置页会显示钥匙串不可用。
- 本机没有可点击的托盘宿主（会话总线上没有 `org.kde.StatusNotifierWatcher`）。托盘菜单的显示、隐藏、恢复和退出没有被点击验证。没有宿主时关闭窗口会退出并清理。
- 不修改服务器的 `GatewayPorts`。远程转发默认只出现在服务器的回环地址上。
- 未做自动更新、多用户和同步。
- Windows 和 macOS 没有在这台虚拟机上编译。GitHub Actions 会在对应系统上打未签名安装包；那次构建成功仍然不等于窗口、托盘或钥匙串已经在该系统上验证。
