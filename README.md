# TunnelDesk

TunnelDesk 是一个跨平台桌面 SSH 端口转发工具。它在本机用 Rust 进程内的 SSH 客户端建立真实的本地转发（`-L`）和远程转发（`-R`），并把可选记住的密码只放进操作系统钥匙串。界面默认中文，可切换英文，主题跟随系统、浅色或深色。

当前版本 `0.1.0`。本仓库是桌面应用源码，不是网站。

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
  - 运行期记住密码还需要可用的 Secret Service，例如已解锁的 `gnome-keyring`。没有钥匙串时应用拒绝保存密码，不会改成明文。
- macOS 需要 Xcode 命令行工具。记住密码使用钥匙串（Keychain）。
- Windows 需要 WebView2。SSH 配置默认读 `%USERPROFILE%\.ssh\config`。记住密码使用凭据管理器（Credential Manager）。

本机没有签名证书。不要把下面的 Linux 包描述成已签名或已公证的 Windows / macOS 安装包。

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
- 失败时取消监听并断开会话，避免留下孤儿转发。

主机别名优先用本机 OpenSSH：

```text
ssh -T [-F 文件] -G -- 目标
```

`-T` 避免分配终端。不附加 `BatchMode`，也不从界面拼接任意 `-o`。`ssh -G` 不可用时，内置解析器负责列出别名和解析，并写出它没有处理的项。

数据目录（配置、历史、设置、应用自己的主机信任）在 Tauri 的应用数据目录。开发时可以用 `TUNNELDESK_DATA_DIR` 指到别的目录。这个目录里只有 JSON，没有密码。

## 安全设计

记住的秘密只进操作系统钥匙串：

| 平台 | 设施 |
| --- | --- |
| macOS | Keychain |
| Windows | Credential Manager |
| Linux | Secret Service（gnome-keyring 等） |

实现是 `keyring` 4.2（`v1` API）。服务名 `dev.tunneldesk.app`。账号名是 `server-password:<规则 id>` 和 `key-passphrase:<规则 id>:<身份文件路径的 SHA-256>`。服务器密码和私钥口令分开存放。

前端只能看到“已保存 / 未保存”。用户当场输入的密码只在连接或保存时传到后端，界面随后清空。钥匙串不可用或已锁定时，保存失败，并说明原因。不会写入 JSON、SQLite、历史、localStorage、日志、环境变量或命令行，也没有明文备用文件。

其他边界：

- 只读 `~/.ssh/config` 和 `known_hosts`，不改写它们，也不改 `sshd`、`GatewayPorts` 或防火墙。
- 未知主机密钥必须在界面里明确信任。已变化或已吊销的密钥直接拒绝，不会自动替换。应用自己的信任记录在单独的 `trust.json`。
- 证书密钥（`@cert-authority`、主机证书）不当作普通公钥信任。
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
- `CertificateFile` 只会被点名，不用于登录。
- 配置文件里的 `LocalForward` / `RemoteForward` 不会自动变成隧道。映射必须在 TunnelDesk 里显式添加。
- 跳板（`ProxyJump`）只用代理或私钥认证，不用目标机器的密码。键盘交互认证使用的是服务器密码，不是私钥口令。

手动主机可以覆盖解析结果。身份文件留空则继承配置；跳板留空并勾选清除时，表示明确不要跳板。

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

一条规则可以有多条映射。任一监听失败（端口被占用，或服务器拒绝 `tcpip-forward`）时，已经打开的监听会撤掉，会话断开，状态不会停在“已连接”。

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

产物在 `src-tauri/target/release/bundle/deb/`。本机这次得到 `TunnelDesk_0.1.0_amd64.deb`，3,267,180 字节。包内二进制约 7.3 MB。未签名。本环境的 AppImage / fuse 依赖不完整，所以打包目标只设了 `deb`。

在对应系统上可以打其他包，本仓库没有在那些系统上执行：

```bash
npm run tauri build -- --bundles app          # macOS
npm run tauri build -- --bundles msi nsis     # Windows
```

`.github/workflows/ci.yml` 是一份 Ubuntu / macOS / Windows 的检查与打包模板。Origin 草稿不会运行 GitHub Actions。它不是一次已经通过的 CI。

包标识 `dev.tunneldesk.app` 以 `.app` 结尾。Tauri 会警告这和 macOS 的应用包扩展名容易混淆。Linux 的 deb 不受影响。真正打 macOS 包之前应改成不以 `.app` 结尾的标识。

## 密码、钥匙串和忘记

连接对话框把服务器密码和私钥口令分成两个字段。勾选记住之后，后端写入钥匙串。下次连接可以不再输入。

钥匙串不可用或已锁定时：

- 记住开关不可用，并说明 Linux 需要 Secret Service，且不会把密码存成明文。
- 本次仍然可以手动输入密码来连接。这次输入不会落盘。
- 已勾选记住、但钥匙串写入失败时，连接仍使用这次输入的密码，历史和界面里不会出现密码本身。

规则详情里的“忘记密码”删除该规则的服务器密码。设置里可以忘记已信任的主机。钥匙串里的条目由 Rust 删除；前端没有删除接口可以碰到明文。

没有钥匙串时不要期待自动重连出密码。这是故意的。

## 托盘

菜单包含：显示窗口、最多 16 条规则的连接或断开、断开全部、退出。隐藏窗口不会拆掉正在跑的隧道。退出和“断开全部”会断开本应用拥有的会话并释放监听。

关闭按钮的行为可以在设置里选：最小化到托盘，或退出并清理。Linux 上托盘图标的单击事件经常不会到来，所以“显示窗口”是菜单项，不依赖左键。若托盘创建失败，关闭窗口会直接退出并清理，避免窗口被藏起来以后找不到。

## 本机测试结果

命令都在这台 Linux 虚拟机上执行。日期 2026-11-06。工具链：rustc 1.99.1，Node v22.23.4，OpenSSH 9.6p1，Tauri 2。

| 命令 | 结果 |
| --- | --- |
| `cd src-tauri && cargo fmt --all -- --check` | 通过 |
| `cd src-tauri && cargo test` | 通过。库测试 25 项，主程序 0 项，文档测试 0 项。耗时约 0.27 秒 |
| `npm run lint` | 通过（eslint，0 warning） |
| `npm run typecheck` | 通过（tsc --noEmit） |
| `npm test` | 通过。Vitest 4 项 |
| `npm run build` | 通过。Vite 8 生产构建成功，有一条大于 500 kB 的包体积警告 |

25 项 Rust 测试覆盖：配置别名与先值获胜、通配符不当成主机、有 `ssh` 时对照 `ssh -G`、本地/远程校验、对外监听必须显式允许、注入与端口、`ssh -G` 参数不含秘密、连接阶段必须等全部转发成功、IPv6 回环、known_hosts 的端口与哈希与吊销、证书权威行不信任普通公钥、模型拒绝密码字段、历史与设置不含秘密、钥匙串失败不写明文文件、跳板解析拒绝注入、跳板环检测。

集成测试在临时目录里起一个 russh 测试服务器，不读取真实的 `~/.ssh`，也不打印测试口令：

- 本地转发和远程转发都能把字节送到回显服务，断开后两个监听端口都可以再次绑定。`known_hosts` 保持为空，JSON 里没有口令。信任之后可以用钥匙串替身里的口令重连，不再弹出主机确认。
- 预先写入不同的主机密钥时拒绝，且不会询问信任。拒绝未知密钥、错误口令、本机端口占用、服务器拒绝远程转发，都会断开且不留下监听。失败的“记住密码”不会把口令写进数据目录。

钥匙串实机：

- 未设置 `TUNNELDESK_KEYRING_TEST=1` 时，实机钥匙串测试直接返回，不接触钥匙串。上面的 `cargo test` 就是这条路径。
- 桌面会话没有可用的用户 D-Bus（`DBUS_SESSION_BUS_ADDRESS=autolaunch:`，没有 `/run/user/1000/bus`）。正在运行的应用在设置页显示钥匙串不可用，并写明不会保存明文。截图与此一致。
- 在独立的 `dbus-run-session` 里启动 `gnome-keyring-daemon` 后，状态能变为已锁定而不是超时。写入被拒绝，错误码 `keyring_locked`，耗时约 0.04 秒。创建默认密码库会弹出系统提示，而 `gcr-prompter` 连不上这个临时会话总线，因此**没能完成一次真实的存、读、删往返**。这是这台虚拟机的限制，不是改走明文的理由。

原生窗口在本机 Xvfb（`DISPLAY=:1`）里打开过。截图是真实 WebKit 窗口，不是浏览器预览。托盘图标窗口已创建，但面板里没有状态图标宿主，托盘菜单没有截到。不要把托盘菜单当成已经肉眼验证。

## 平台

| 平台 | 本仓库里实际发生的事 |
| --- | --- |
| Linux x86_64 | 编译、25 项 Rust 测试、前端检查、L/R 集成测试、原生窗口截图。已打出未签名的 `TunnelDesk_0.1.0_amd64.deb`（3,267,180 字节，release 配置，链接约 6 分 45 秒）。 |
| macOS | 未构建，未签名，未公证。代码路径包含 Keychain 和 `.ssh/config`。 |
| Windows | 未构建，未签名。代码路径包含凭据管理器和 `%USERPROFILE%\.ssh\config`。SSH agent 只在 Unix 上连接。 |

## 已知限制

- 不支持 GSSAPI、PKCS#11、SSH 证书、`ProxyUseFdpass`、agent 转发。
- 跳板不用目标主机的密码。
- 配置文件里的 `LocalForward` / `RemoteForward` 不会自动套用。
- 没有用户会话总线或钥匙串已锁定时，不能记住密码。
- Linux 托盘依赖 Ayatana AppIndicator。没有托盘时关闭即退出。
- 不修改服务器的 `GatewayPorts`。远程转发默认只出现在服务器的回环地址上。
- 未做自动更新、多用户和同步。
