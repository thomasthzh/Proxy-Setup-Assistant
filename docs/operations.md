# 运维说明

本文适用于本项目新建的部署。示例没有任何真实服务器信息。以下命令在 `ssh MyVPS` 连接后以 root 运行。

## 文件和服务

| 路径 / 服务 | 用途 |
| --- | --- |
| `/etc/vps-proxy-setup/settings.json` | 随机令牌、两端代理凭据和部署参数，root 0600 |
| `/etc/vps-proxy-setup/result.json` | 私人导入 URL 与部署状态，root 0600 |
| `/etc/vps-proxy-setup/hysteria.json`、`xray.json` | 代理配置，仅 root 与对应服务用户可读 |
| `/etc/vps-proxy-setup/subscription.json` | HTTP 后端需要的令牌，不含代理密码 |
| `/etc/vps-proxy-setup/acme/` | Certbot 独立配置、账户、证书与日志 |
| `/etc/vps-proxy-setup/tls/current/` | 当前证书与私钥，仅 TLS 服务组可读 |
| `/opt/vps-proxy-setup/app/server/` | 已部署程序 |
| `/opt/vps-proxy-setup/bin/` | 校验后的固定版本代理程序 |
| `/var/lib/vps-proxy-setup/current/` | 当前完整配置和导入页，由原子符号链接发布 |
| `/var/lib/vps-proxy-setup/rules/` | 上次通过检查的国内域名 / IP 列表 |
| `vpsproxy-hy2` / `vpsproxy-xray` | HY2 主用 / Trojan 备用 |
| `vpsproxy-sub` / `vpsproxy-nginx` | 回环 HTTP 后端 / 公网 HTTPS 和 ACME |
| `vpsproxy-refresh.timer` | 每日规则更新 |
| `vpsproxy-renew.timer` | 每 6 小时检查证书续期，另有随机延迟 |

计时器按 VPS 的时区调度。查看准确的下次执行时间：

```bash
systemctl list-timers 'vpsproxy-*'
systemctl is-active vpsproxy-hy2 vpsproxy-xray vpsproxy-sub vpsproxy-nginx
systemctl --no-pager --full status vpsproxy-hy2 vpsproxy-xray vpsproxy-sub vpsproxy-nginx
ss -lntup
```

日志可能包含机器的公网地址或运行环境。向公开 Issue 提交诊断前请删去个人信息，尤其不要提交 `settings.json`、客户端配置或私人 URL。

## 更新国内规则

```bash
systemctl start vpsproxy-refresh.service
systemctl --no-pager status vpsproxy-refresh.service
journalctl -u vpsproxy-refresh.service -n 30 --no-pager
```

更新会校验官方域名和 CIDR 列表，生成新版本后整体切换。下载失败会使用之前完整且重新校验过的缓存；首次没有缓存时会停止，不会发布空规则。保留有限个旧版本，避免磁盘持续增长。

客户端需要执行“更新配置”才会获取最新内容。也可在客户端设置每日更新。不要对生成的 `current` 文件手工改动，下一次刷新会覆盖它；持久自定义规则请使用客户端覆写功能。

## 证书维护

公网 IP 证书有效期较短，因此必须持续开放公网 TCP 80。正常续期复用证书私钥，检查名称、有效期、证书链与公私钥匹配后原子切换证书，随后 reload nginx。HY2 和 Xray 会重新读取证书，不为了续期强行重启代理连接；Xray 的证书缓存刷新存在延迟。

```bash
systemctl start vpsproxy-renew.service
systemctl --no-pager status vpsproxy-renew.service
journalctl -u vpsproxy-renew.service -n 40 --no-pager
openssl x509 -in /etc/vps-proxy-setup/tls/current/fullchain.pem -noout -dates
```

Certbot 的详细日志在 `/etc/vps-proxy-setup/acme/logs/`。域名解析变化、关闭 80 端口、NAT 映射失效或 CA 限流都可能导致续期失败；不要通过客户端关闭证书校验来绕过它。

## 重新运行与升级

保留相同地址、端口和部署配置，重新运行本地向导即可恢复中断的步骤。代理密码和订阅令牌保持不变。重新安装会重启**本工具自己的**代理服务，可能中断直播，宜在空闲时执行。

`--plan` 仅做静态参数预览，不证明远程端口、防火墙或证书条件已满足。

代理二进制版本和哈希固定在 `vps_proxy_setup/server/assets.json`；不会自动追踪 GitHub 的 latest。升级需要先从上游核对版本与 SHA-256、执行配置和协议测试，再发布新的项目版本。Certbot 安装在独立 venv；Tailscale（选择安装时）通过官方签名 APT 源安装。系统软件的常规安全更新仍由服务器管理员负责。

若最小系统镜像提示缺少基本命令，可先安装基础依赖后重试：

```bash
apt-get update
apt-get install -y python3 openssl iproute2 util-linux
```

如果安装器报告“未托管路径/端口已存在”，先确认归属。不要为了让检查通过而删除其他程序的配置或占用端口。

## Tailscale

可选安装只负责安装官方客户端并发起登录。安装结果中的登录链接由用户在浏览器完成授权：

```bash
tailscale status
tailscale ip -4
tailscale up --accept-dns=false --accept-routes=false
```

如果已经安装了其他人管理的 Tailscale，向导会拒绝接管；将 `tailscale` 设为 `false`，继续由原配置管理。不会启用 Tailscale SSH、出口节点或路由广播。SSH 仍使用系统 OpenSSH 和本机密钥。

## 停止服务和恢复本地 SSH 配置

只想停止这套代理，可以执行：

```bash
systemctl disable --now vpsproxy-refresh.timer vpsproxy-renew.timer
systemctl disable --now vpsproxy-hy2 vpsproxy-xray vpsproxy-sub vpsproxy-nginx
```

状态、凭据和密钥仍然保留，方便恢复。未自动删除系统软件或 Tailscale，避免影响其他用途。

本地 `~/.ssh/config` 中的管理块以 `# BEGIN VPS-PROXY-SETUP <别名>` 开头，以对应 `# END ...` 结束。原配置备份位于本机私有状态目录。恢复备份前先比较是否还有后来新增的 SSH 主机，不要直接覆盖新改动。

## 验证边界

项目测试包含：

- 本地输入校验、SSH 配置合并，以及 `ssh -G` 实际解析。
- 服务器预检、端口归属、重复运行、证书命令和服务配置。
- HTTP 真实回环请求、错误令牌与路径、完整配置规则和缓存回退。
- Linux CI 运行固定版本 HY2、Xray 和 Mihomo，在临时端口完成 TLS 校验及两个协议的 HTTPS 出口请求。测试 CA 只给子进程使用，不安装到系统信任库。

CI 不会部署到任何生产 VPS，也不向 Let's Encrypt 申请真实证书。云防火墙、各商家 NAT、实机 systemd 安装全过程及 iPhone 上的实际直播仍需在目标环境验证。此前某条线路的测速不作为这个通用项目的性能承诺。
