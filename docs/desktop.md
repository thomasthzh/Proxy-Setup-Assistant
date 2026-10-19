# Proxy Setup Assistant · Windows 桌面向导

v0.2.0 将本地客户端准备和配置导入放进中文桌面窗口，保留 VPS 安装 CLI。当前发布目标为 Windows x64；客户端安装器可根据系统架构检查兼容版本，但这不表示桌面 EXE 已提供原生 ARM64 包。

## 下载和启动

从项目官方 GitHub Releases 下载 `Proxy-Setup-Assistant-0.2.0-windows-x64.zip` 与对应 `.zip.sha256`。在 PowerShell 运行：

```powershell
Get-FileHash .\Proxy-Setup-Assistant-0.2.0-windows-x64.zip -Algorithm SHA256
```

将结果与发布的校验文件核对，再完整解压并双击 `Proxy-Setup-Assistant.exe`。两份 EXE 应放在同一目录。不要从 ZIP 内直接运行。普通桌面操作无需管理员权限，客户端自己的安装器或 TUN 组件可能另行请求提升权限。

| 文件 | 用途 |
| --- | --- |
| `Proxy-Setup-Assistant.exe` | 无黑色终端窗口的桌面向导 |
| `Proxy-Setup-Console.exe` | VPS 安装与 OpenSSH 密码、主机指纹交互；也可独立运行 |
| `SHA256SUMS.txt` | 两个 EXE 的 SHA-256；整个 ZIP 的校验另在 `.zip.sha256` |
| `licenses/`、`THIRD-PARTY-NOTICES.txt` | Python/Tk、PyYAML 及打包工具随附的许可文本与版本说明 |
| `examples/setup.example.json` | 使用保留地址的 CLI 示例，不能直接部署 |

当前二进制未做代码签名。Windows SmartScreen 或企业策略可能提示风险。检查项目来源和散列，疑虑未消除时停止运行或审阅源码后自行构建；本项目不要求关闭防护或绕过组织策略。

## 选择入口

**初次接触代理**：先阅读规则模式、系统代理、TUN 和私人订阅的说明，再检查本地环境。需要客户端时，查看官方项目维护信息与下载来源。下载比较只比较当次可达源，安装器必须通过官方发布 SHA-256 校验后才可交给你运行。使用第三方下载源需要单独同意；校验失败应停止。

GitHub 最新版本接口不可用时，向导会明确提示使用 **2026-10-19 核验的 v2.5.8 固定版本**，仍从官方发布资源或经你同意的镜像下载，并核对固定官方 SHA-256。这不表示已经查询到最新版本，也不保证离线时能下载安装包。

**已有客户端或订阅**：可以从私人 HTTPS 订阅、本地 Clash/Mihomo YAML（含兼容的 JSON），或手动选择已有客户端配置文件开始。扫描只是线索，尤其是未运行的便携版可能完全无法发现；需要时手动选择文件。先查看解析和规则变更结果，再导入客户端。

直接导入目前仅验证 **Clash Verge Rev 2.5.8**，其他版本会阻止写入；HTTPS 订阅自动更新额外要求 **Mihomo 1.19.32**，需从客户端关于页核对内核版本，无法确认时不会开启该导入路径。文件快照导入不要求填写内核版本。客户端须已启动过一次，所选目录须含 `verge.yaml`、`profiles.yaml` 和 `profiles/`。预览后从托盘完全退出客户端并停止 Mihomo 核心，再明确确认导入；原有订阅文件保留，配置索引备份后增加独立配置，激活由确认界面的选项决定。系统代理、TUN 和全局设置不由向导自动开启；如现有扩展与生成配置冲突，需先在客户端处理再重新预览。新版安装器的可下载状态不等于其配置格式已兼容。

配置输入限 4 MiB，须直接包含 1–2000 个 `proxies` 节点。支持 `ss`、`trojan`、`hysteria2`、`vmess`、`vless` 的受限参数；常见的 `ssr`、`socks5`、`http`、`tuic`、`wireguard`、`snell` 等节点类型会被拒绝。URI 列表、Base64 订阅、嵌套 `proxy-providers`、YAML 引用/别名、插件、任意本地文件引用及未支持的高级字段也不会转换。请向服务商索取符合范围的 Clash/Mihomo 配置，不能将任意节点链接无损导入。

导入只取支持的节点，原订阅规则、策略组、DNS 和其他顶层设置由向导模板替换；不要将它当成已有复杂配置的无损迁移器。HTTPS URL 导入也创建**固定本地配置**，关闭 Clash 的整份远程配置更新，由 Mihomo 原生 HTTP 节点提供器每天更新节点。每次节点更新应用支持类型与字段的白名单，保留证书校验；上游整份配置中的规则、DNS、监听地址等顶层设置不会替换本地模板。配置扩展还用于保护模板不被已有全局扩展改写，自动更新不依赖执行远程 JavaScript。文件输入保留本地快照，不自动读取原文件后续变化。

新建本地配置的国内域名/IP 规则通过 `VPS-PROXY` 从 MetaCubeX 官方 HTTPS 源首次下载并每日更新，因而首次启动需要至少一个可用代理节点。首次下载失败需检查节点、客户端日志与网络。这与 VPS 路径生成的内嵌完整规则配置不同。

完成页面可以“撤销本次导入”，只针对本次向导会话最近一次导入，需先完全退出 Clash/Mihomo 并确认操作。它恢复原配置索引、移除本次新增配置；如果导入后的文件或索引已经变化，会停止回滚，避免覆盖后续改动。请保存完成页面显示的备份位置。

**已有 VPS**：填写 SSH 地址、端口、别名、私钥路径和公网入口，检查服务端口与证书条款，再明确开始部署。桌面会打开独立控制台，系统 OpenSSH 在该窗口询问密码、私钥口令和首次主机指纹；请从云商控制台核对指纹。控制台结束后保留成功结果或错误，按 Enter 关闭。不要在部署完成前关闭它。

VPS 路径仍要求系统安装 OpenSSH 客户端，并使用全新 Debian 12/13 或 Ubuntu 22.04/24.04、root 与 systemd。公网 TCP 80 必须长期可达。完整端口和 NAT 限制见 [README](../README.md)。没有本版本在全新公网 VPS 完整部署的实机认证，请先在可重建的专用实例验证。

**更换旧客户端**：查看识别依据及官方项目当前信息，再自行决定保留或迁移。安装前必须确认具体安装程序；卸载功能打开 Windows“已安装的应用”，不会根据软件名称自动删除。未知软件、名称相似软件、已有配置和其他 VPN 都需要你核实。

## 配置隐私和客户端检查

订阅 URL 与下载的配置可能同时包含访问令牌、节点密码和服务器地址。仅导入你信任的来源，不要公开截图、日志、生成文件或配置。HTTPS 来源地址保留在私人配置、节点提供器和索引的来源记录中；节点缓存保存在所选客户端目录的 `.vps-proxy-setup-providers/` 私人文件夹。这些都应按凭据保护，路径中的散列不能使缓存内容匿名。文件输入是快照，HTTPS 输入只自动更新节点；需要更改规则时先核对模板和客户端扩展的最终效果。

桌面会展示或生成规则配置，但实际接管流量需要在客户端中完成：

1. 导入并启用正确配置，选择“规则”模式。
2. 先启用系统代理，使用浏览器测试，并在客户端连接记录核对国内请求命中 `DIRECT`。
3. 本地导入生成 `VPS-PROXY` / `VPS-AUTO` 策略组；`VPS-AUTO` 按节点顺序进行可用性探测和故障回退，不承诺选择最快节点。VPS 生成的完整配置使用 `PROXY` / `AUTO`。可在总组中选择自动或手动节点。探测不能证明直播带宽；直播前实测稳定性，必要时固定节点。
4. 需要接管忽略系统代理的软件时，再按客户端说明启用 TUN。避免多个 VPN/TUN 同时接管。

分流依据国内域名/IP 列表，不能保证所有中国业务都识别正确。服务端规则更新、客户端订阅更新和客户端覆写是不同环节，应在连接记录中验证最终结果。

## 注册链接和流量估算

向导提供的服务商注册链接包含仓库所有者指定的推广邀请码，推荐人可能获得奖励或佣金。点击前可查看目标；打开网页不等于注册或付款授权。工具只检查当前网络能否安全访问，不验证服务商资质、套餐价格、长期可用性或退款承诺。

1 元 / 10 GB 等低价小流量套餐不能保证视频直播需求。按十进制估算：

```text
月流量 GB = 平均总码率 Mbps × 每天小时 × 每月天数 × 0.45
```

4 Mbps × 2 小时 × 30 天约 108 GB，按 20% 余量约 129.6 GB；码率应计算通过代理的上传与下载总量，服务商的计费倍率和双向计费可能进一步增加用量。延迟低、下载源快或某次网页可达都不能保证最快线路或直播不中断。

## 源码运行

安装 Python 3.10+（包含 Tkinter），在项目目录执行：

```powershell
python -m pip install .
python .\launch-desktop.pyw
```

也可用 `python -m vps_proxy_setup.desktop.app` 启动桌面；桌面部署使用 `python -m vps_proxy_setup.desktop.console` 打开可保留结果的独立控制台。该模块也支持 `--self-test`、`--config` 和 `--no-pause`。

只运行原有 VPS CLI 时仍可使用 `python -m vps_proxy_setup`、`setup.ps1` 或 `setup.sh`。已安装本项目后，可运行 `proxy-setup-assistant` 打开桌面，`proxy-setup-console` 打开保留结果的控制台；兼容命令 `vps-proxy-desktop`、`vps-proxy-setup` 继续可用。Python 包名和本地状态路径保留 `vps_proxy_setup` / `vps-proxy-setup`，方便旧部署继续使用。

控制台支持全部现有 CLI 参数，示例：

```powershell
.\Proxy-Setup-Console.exe --config .\examples\setup.example.json --plan --no-pause
```

`--plan` 不连接服务器或修改 SSH；真实部署前需要将示例换成本地配置。`--self-test` 检查打包资源，无须服务器，也不会生成 SSH 配置或发起部署。

## 构建与验证

必须在 Windows x64 上使用 64 位 Python 构建，包含 Tkinter。构建依赖固定在 `pyproject.toml` 的 `desktop-build` 额外依赖中；这些版本从 [PyPI PyInstaller](https://pypi.org/project/pyinstaller/6.22.3/)、[hooks](https://pypi.org/project/pyinstaller-hooks-contrib/2026.8/) 和 [PyYAML](https://pypi.org/project/PyYAML/6.0.3/) 发布元数据核对。构建命令：

```powershell
python -m pip install ".[desktop-build]"
python -m unittest discover -s tests -v
python tools/check_public_tree.py
python tools/build_desktop.py
```

构建器用 PyInstaller 为 GUI 和控制台各生成一个单文件 EXE，将服务器 Python 源码和 `assets.json` 原样作为资源打包；VPS 上传过程需要读取这些文件。随后运行两个 EXE 的 `--self-test` 和控制台计划检查，使用临时用户目录隔离状态。验证通过后生成：

```text
dist/Proxy-Setup-Assistant-0.2.0-windows-x64.zip
dist/Proxy-Setup-Assistant-0.2.0-windows-x64.zip.sha256
```

`.github/workflows/desktop.yml` 支持手动触发或版本标签触发，上传 ZIP 与校验文件为构建产物；工作流本身不发布 GitHub Release。实际发布前还应检查解压后的双击启动、客户端确认流程与网络环境。构建和自检通过不等于新 VPS 部署、第三方注册付款或真实直播通过验证。
