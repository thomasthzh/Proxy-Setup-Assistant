# Proxy-Setup-Assistant

一个中文 Windows 桌面向导，帮助检查本地代理环境、准备 Clash Verge Rev、导入和整理配置，也保留独立的 VPS 命令行向导：配置 SSH 密钥和别名，在 VPS 部署 **Hysteria 2 + Trojan 备用**，生成私人 HTTPS 导入页面。支持 **Clash Verge Rev / Mihomo** 和 **Shadowrocket（小火箭）**。

源码不包含用户的真实 VPS 地址、密码、私钥或私人订阅链接。代理凭据在每台服务器上独立随机生成，重复运行保留原凭据。

## Windows：下载一个 BAT，双击开始（v0.2.1）

**[下载 Proxy-Setup-Assistant.bat](https://github.com/thomasthzh/Proxy-Setup-Assistant/releases/download/v0.2.1/Proxy-Setup-Assistant.bat)**

1. 保存这个 BAT 文件，双击运行。无需自行下载 ZIP、解压或安装 Python。
2. 首次启动自动从官方 GitHub Release 下载本版本程序包、核对 SHA-256 并准备到本机缓存，随后打开中文向导；以后双击同一 BAT 直接使用已核验的缓存。BAT 本身很小，首次仍需联网下载约 24 MB 的运行程序。
3. 选择适合自己的入口：零基础引导、已有客户端，或已有 VPS；配置可以来自私人 HTTPS 订阅、本地 Clash/Mihomo YAML 文件，或手动选择已有客户端的配置文件。
4. 先检查和预览，再执行导入、打开安装程序或开始 VPS 部署。客户端安装和卸载都需要明确确认；卸载入口打开 Windows 应用设置，由你选择实际要卸载的程序。

桌面版会根据注册信息和正在运行的进程识别部分已知客户端，不能保证发现所有便携版、自定义安装和未知软件。判断“维护状态”依赖当次官方仓库查询，查询失败会保留未知状态；识别出旧客户端不等于获准卸载。

直接写入客户端配置目前**仅支持 Clash Verge Rev 2.5.8**；HTTPS 自动更新还需已核对的 **Mihomo 1.19.32**。需要先启动一次并完全退出客户端/核心。输入须包含完整 `proxies` 节点；不接受 URI/Base64 列表、嵌套 `proxy-providers`、不支持的协议、插件或高级参数。URL 导入生成固定本地配置，由 Mihomo 原生节点提供器每日更新节点；上游顶层规则与 DNS 不会替换本地模板。文件导入是快照。具体范围、撤销导入与首次规则下载要求见 [桌面使用说明](docs/desktop.md)。

Windows 包目前未签名，可能触发 SmartScreen 或企业策略提示。请核实仓库、发布来源和校验值；无法确认时停止运行，或审阅源码后自行构建。不要关闭系统防护来运行。

向导中的注册地址含仓库所有者提供的**推广邀请码**，推荐人可能获得佣金或奖励。注册、付款和套餐条款需要你在服务商页面自行核实。可达性检查只证明当前网络的一次 HTTPS 访问结果；不代表服务背书或线路测速。

**流量优先看真实账单。** 不把在线时间当作持续传输时间，也不默认让普通用户按视频码率购买大套餐。没有历史记录时，先选可追加的小套餐，用 7 天看看实际消耗；已有记录可输入累计 GB、统计时段和人数，换算全组及人均月用量。持续开播、视频观看或大文件传输另有高级计算，按实际经过代理的传输量估算。

需要离线搬运时，仍可在 [v0.2.1 Release](https://github.com/thomasthzh/Proxy-Setup-Assistant/releases/tag/v0.2.1) 下载 Windows x64 ZIP，核对校验值后完整解压，双击其中的 `Proxy-Setup-Assistant.exe`。BAT 固定到对应版本，不会静默改用未来版本；升级时下载新版本 BAT。缓存不包含需要提前填写的 VPS 密码或订阅链接。

下载源比较仅反映本次下载速度，节点延迟检测也不等于吞吐量或直播稳定性。没有任何步骤保证“最快线路”。完整说明、配置隐私、客户端操作和构建步骤见 [桌面使用说明](docs/desktop.md)。

## 准备条件

| 项目 | 要求 |
| --- | --- |
| 本地电脑 | Windows、macOS 或 Linux；Python 3.10+；OpenSSH 的 `ssh`、`scp`、`ssh-keygen` |
| VPS | **全新** Debian 12/13 或 Ubuntu 22.04/24.04；systemd；root SSH 登录；公网 IPv4 |
| 域名 | 可选。支持直接为公网 IPv4 申请证书；如用域名，A 记录必须指向 VPS，关闭 CDN 代理 |
| 资源 | 建议至少 512 MB 内存，预留磁盘空间用于软件和规则 |
| 网络 | VPS 能访问 Debian/Ubuntu 软件源、GitHub、PyPI、Let's Encrypt；电脑能访问 VPS |

在商家安全组 / 防火墙中开放：

| 用途 | 默认端口 | 说明 |
| --- | --- | --- |
| SSH | TCP 22，或商家给出的端口 | 例如面板给 `地址:30022`，向导中单独填端口 |
| 证书申请和续期 | **TCP 80** | 必须持续可从公网访问，不能只在首次安装时开放 |
| HTTPS 导入页面 | TCP 8443 | 可自定义 |
| Hysteria 2 | UDP 8443 | 可与 HTTPS 使用相同端口数字，因为协议不同 |
| Trojan 备用 | TCP 9443 | 可自定义，不能与订阅 TCP 端口冲突 |

NAT VPS 需要商家提供上述端口映射，当前版本要求代理端口内外一致，且公网 **80 → 本机 80**。只有一个 SSH 映射端口的套餐无法直接使用本方案。安装器不修改云安全组，也不清空系统防火墙。

安装器面向专用新机。发现其他程序占用所需端口、已有非本工具管理的 nginx 或冲突配置时停止，避免覆盖已有网站或代理。现有业务机器请先另行迁移或使用新 VPS。

## Windows 使用保留的 VPS 命令行向导

桌面 ZIP 中也可双击 `Proxy-Setup-Console.exe`，或从 PowerShell 传入下面的 CLI 参数；执行结束后窗口保留结果，按 Enter 关闭。`--no-pause` 适合脚本调用。源码方式如下：

安装 [Python 3.10 或更新版本](https://www.python.org/downloads/)，并确认 Windows“可选功能”中已安装 OpenSSH 客户端。打开普通 PowerShell：

```powershell
git clone https://github.com/thomasthzh/Proxy-Setup-Assistant.git
cd Proxy-Setup-Assistant
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1
```

也可以从 GitHub 下载 ZIP，解压后进入该目录运行最后一行。这里的执行策略仅针对这次 PowerShell 进程，不永久修改系统策略。

## macOS / Linux 开始使用

```bash
git clone https://github.com/thomasthzh/Proxy-Setup-Assistant.git
cd Proxy-Setup-Assistant
bash setup.sh
```

所有平台也可以在源码目录运行：

```text
python -m vps_proxy_setup
```

Linux/macOS 通常使用 `python3`。VPS CLI 本身使用 Python 标准库，可直接从源码运行；桌面配置解析需要 PyYAML，源码启动桌面版见 [桌面使用说明](docs/desktop.md)。

## 向导会做什么

1. 询问 SSH 地址、端口、别名、代理公网地址、服务端口、证书邮箱，以及是否安装 Tailscale。
2. 创建专用 Ed25519 密钥，或使用你选择的已有密钥。新密钥默认存于 `~/.ssh/vps-proxy-setup/`。密钥保护口令由 `ssh-keygen` 询问；可以留空，设置了口令则后续连接可能仍需输入口令。
3. 通过系统 OpenSSH 连接。**首次连接请对照商家控制台核对 SSH 主机指纹**。密码由 OpenSSH 的密码提示读取，向导不会把它保存到 JSON、命令参数或日志中。
4. 只将**公钥**追加到服务器 `authorized_keys`，验证密钥登录成功后配置本地别名。原有 SSH 配置先备份，不覆盖同名的非托管配置。
5. 上传服务器程序，检查系统和端口，下载固定版本并校验 SHA-256，创建独立服务和随机凭据，申请 HTTPS 证书，生成订阅。
6. 输出私人导入 URL，验证当前网络能否打开页面。所有客户端配置均正常校验证书，不使用“跳过证书验证”。

此后连接服务器：

```text
ssh MyVPS
```

安装不会关闭密码登录、修改 SSH 监听端口、禁止 root 登录或改动你已有的密钥。可以在确认恢复途径和密钥都可用后自行加固 SSH。

## 导入 Clash 和小火箭

打开安装结束时给出的私人 HTTPS 页面，其中包含两个按钮以及可复制的配置 URL：

- **Clash Verge Rev**：点击导入完整配置，启用该配置，模式选 **规则**。代理组 `PROXY` 默认选择 `AUTO`，优先 Hysteria 2，失败时回退 Trojan。
- **小火箭**：用 Safari 打开页面，导入并启用完整配置，然后将 **全局路由 → 配置**。仅在首页添加节点订阅不会自动应用全部分流规则。

两端请启用客户端的每日配置更新。服务器会每天生成新规则，但已导入的客户端仍需更新配置才能取得新内容。第一次下载得到完整内嵌规则，不依赖客户端先访问 GitHub 拉取规则文件。

国内域名、国内 IP、局域网和 Tailscale 地址直连，国内 DNS 也直连。其他流量走代理。规则来源是 MetaCubeX 的 CN 域名 / IP 列表，并非对所有新出现或无法识别的网站作绝对地理保证。遇到遗漏可在客户端加入具体 `DOMAIN-SUFFIX,...,DIRECT` 规则并向规则上游反馈；更新订阅时请使用客户端覆写功能保留自定义规则。

订阅 URL 含随机访问令牌，等同私人凭据。不要放进公开 Issue、截图、仓库、第三方订阅转换站或公开二维码服务。服务器不会记录包含该 URL 的访问日志。

## 速度、稳定性与 Tailscale

- Hysteria 2 使用 UDP；Trojan 使用 TCP，适合作为 UDP 不可用时的备用。自动检测不等于无缝切换，现有直播连接在切换时可能重连。
- 在内核支持时启用 BBR 和 fq；不会写夸大的固定带宽参数或承诺突破线路限制。
- 直播优先检查实际上传速率、丢包和晚高峰波动。两个协议仍共用同一台 VPS 和同一条出口，不能解决整台服务器或机房离线。
- 选择 Tailscale 后，安装器会提供浏览器登录授权地址；完成账户授权才算加入你的内网。这里把 Tailscale 用作管理通道，**不会自动设为出口节点，也不把登录授权算成已完成**。

## 配置文件、预览与重新运行

交互向导适合首次使用。需要保存参数时，将示例复制到本地忽略文件并修改：

```powershell
Copy-Item .\examples\setup.example.json .\setup.local.json
python -m vps_proxy_setup --config setup.local.json --plan
python -m vps_proxy_setup --config setup.local.json
```

示例使用文档保留地址与 `example.com`，**不能直接部署**。公网 `address` 与 `tls_name` 要一致；`ssh.host` 可与它们不同，例如用 Tailscale 地址管理。

`--plan` / `--dry-run` 只校验参数、打印计划，不创建文件、不连接服务器。JSON 不接受服务器密码、代理密码或私钥内容字段；`acme_accept_terms: true` 表示你已阅读并接受 [Let's Encrypt 服务条款](https://letsencrypt.org/repository/)。

`--ssh-only` 仅完成 SSH 配置。使用同一份配置重新运行会保留服务器已有凭据；服务器地址和服务端口等不能通过重跑静默替换，涉及迁移时会要求先处理现有部署。

本地私有状态与 SSH 配置备份位于：

- Windows：`%LOCALAPPDATA%\vps-proxy-setup\<别名>\`
- macOS / Linux：`${XDG_STATE_HOME:-~/.local/state}/vps-proxy-setup/<别名>/`

其中 `result.json` 含私人 URL，请勿分享。私钥始终只保留在本机。不要把真实状态复制进源码仓库。

## 排查

| 现象 | 先检查 |
| --- | --- |
| SSH 超时 | 面板给的端口、实例运行状态、安全组、本地网络；不要默认所有 VPS 都是 22 |
| SSH 密码被拒绝 | 用户名是否为 root，密码是否为实例密码，可否从商家控制台登录 |
| 主机指纹变化 | 是否重装或换机；从商家控制台核实后再处理 known_hosts，不要直接跳过校验 |
| 证书申请失败 | 公网 TCP 80、NAT 映射、域名 A/AAAA 记录、CDN 状态、CA 限流；反复重试不会修复端口问题 |
| 导入页面打不开 | TCP 8443 或自定义 HTTPS 端口，证书续期是否成功 |
| HY2 不通但 Trojan 正常 | UDP 防火墙 / 映射 / 运营商限制，可手动选择 Trojan |
| 国内网站走代理 | Clash 是否“规则”，小火箭是否“配置”，是否启用了正确的完整配置 |
| 配置仍旧 | 客户端执行更新配置；服务端更新不等于客户端自动刷新 |

服务名、路径与维护命令见 [运维说明](docs/operations.md)。

## 开发与验证

```text
python -m unittest discover -s tests -v
python tools/check_public_tree.py
python -m vps_proxy_setup --config examples/setup.example.json --plan
```

CI 在 Windows 和 Linux 上运行测试，覆盖参数校验、SSH 配置合并、文件打包边界、服务器预检 / 重跑、分流配置、HTTP 鉴权和规则更新失败回退。部署需要真实公网网络与证书颁发服务；单元测试与配置解析不等同于在所有云厂商完整安装成功。小火箭为闭源客户端，导入后请在自己的 iPhone 上验证实际直播。

v0.2.0 的 Windows 构建流程会检查桌面运行时、CLI 计划和打包后的服务器资源。当前没有以本版本在一台全新公网 VPS 上完成实机部署认证，也没有代表你的网络验证注册、付款或直播结果。测试、打包通过不能替代这些实际检查。

## 上游与许可

本项目代码采用 [MIT](LICENSE)。下载和使用的上游组件保留其各自许可；不将上游二进制或完整规则库复制到仓库。

- [Hysteria 2](https://github.com/apernet/hysteria) / [官方配置文档](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)
- [Xray-core](https://github.com/XTLS/Xray-core) / [Trojan 配置](https://xtls.github.io/config/inbounds/trojan.html)
- [Mihomo DNS](https://wiki.metacubex.one/config/dns/) / [规则集](https://wiki.metacubex.one/config/rule-providers/)
- [Shadowrocket 配置示例](https://github.com/LOWERTOP/Shadowrocket)
- [MetaCubeX 规则源](https://github.com/MetaCubeX/meta-rules-dat)
- [Let's Encrypt IP 证书](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability) / [Certbot](https://eff-certbot.readthedocs.io/en/stable/using.html)
- [Tailscale Linux 安装](https://tailscale.com/download/linux) / [OpenSSH 配置](https://man.openbsd.org/ssh_config)
