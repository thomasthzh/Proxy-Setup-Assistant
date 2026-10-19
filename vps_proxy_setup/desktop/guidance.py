"""Small, inspectable decisions used by the desktop wizard."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import math
import time
import urllib.parse
import urllib.request

from ..cli import SetupError

# These are the repository owner's explicitly supplied promotional links.
# They are public advertisements, not private subscription endpoints.
REFERRAL_LINKS = (
    "https://mojie.net/#/register?code=M8vOM5WT",
    "https://mojie.co/#/register?code=M8vOM5WT",
    "https://43.129.207.58:8000/#/register?code=M8vOM5WT",
    "https://mojie.me/#/register?code=M8vOM5WT",
)


@dataclass(frozen=True)
class LinkCheck:
    url: str
    reachable: bool
    seconds: float | None
    message: str


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if new.scheme != "https" or (old.hostname, old.port) != (new.hostname, new.port):
            raise SetupError("注册站点跳转到了其他地址，需自行核实。")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_referral(url: str, timeout: float = 6) -> LinkCheck:
    if url not in REFERRAL_LINKS:
        raise SetupError("未知注册地址。")
    # A fragment never belongs in an HTTP request. No registration or payment.
    target = urllib.parse.urldefrag(url)[0]
    started = time.monotonic()
    try:
        request = urllib.request.Request(target, headers={"User-Agent": "VPS-Proxy-SetUP link check"})
        with urllib.request.build_opener(SameOriginRedirect()).open(request, timeout=timeout) as response:
            response.read(1024)
            if not 200 <= response.status < 300:
                raise OSError("HTTP status")
        return LinkCheck(url, True, time.monotonic() - started, "HTTPS 可达；尚未验证注册或套餐服务")
    except Exception:
        return LinkCheck(url, False, None, "当前网络无法安全验证（网络、证书或跳转问题）")


def check_referrals(timeout: float = 6) -> tuple[LinkCheck, ...]:
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda url: check_referral(url, timeout), REFERRAL_LINKS))
    return tuple(sorted(results, key=lambda result: (not result.reachable, result.seconds or float("inf"))))


def monthly_traffic(mbps: float, hours: float, days: int = 30, reserve: float = 1.2) -> float:
    """Decimal GB, averaged aggregate upload+download bitrate, with headroom."""
    values = (float(mbps), float(hours), float(days), float(reserve))
    if (not all(math.isfinite(value) for value in values)
            or not 0 < values[0] <= 10000 or not 0 < values[1] <= 24
            or not 1 <= values[2] <= 31 or not 1 <= values[3] <= 3):
        raise SetupError("请输入有效数值：平均码率 0–10000 Mbps、每天 0–24 小时、每月 1–31 天。")
    return values[0] * values[1] * values[2] * 0.45 * values[3]


HELP_TEXT = """规则模式：每个连接按规则选择直连或代理。日常使用请选“规则”；全局模式会让国内网站也走代理。

国内直连：助手配置 LAN、Tailscale、CN 域名和 CN IP 直连，其他流量交给 PROXY。地域库可能有遗漏；遇到误判，在客户端连接记录查看命中规则，再添加该域名的直连规则。不能保证所有中国业务都能被地域库识别。

策略组：本机向导使用 VPS-PROXY / VPS-AUTO；VPS 服务器导入页使用 PROXY / AUTO。总选择组可选自动故障切换或手选节点。自动组定期探测可用性，优先使用顺序靠前的可用节点；这不是吞吐量测速，也不能保证直播不中断。开播时建议选择已实测稳定的固定节点，避免会话中途切换。

系统代理：适合浏览器和遵守系统代理的应用。先启用它再测试；某些程序会忽略系统代理。

TUN：接管更多程序的连接，通常需要管理员权限。先用系统代理验证，再按需开启 TUN；避免同时运行两个 TUN/VPN。助手不自动开启 TUN 或更改系统代理。

DNS：国内域名使用国内解析，其他域名使用加密解析。配置文件的规则和客户端自己的扩展配置会一起影响结果；请在客户端“连接”中确认命中 DIRECT 或 PROXY。

订阅：它是含凭据的私人配置地址。不要截图、发群或提交到 GitHub。URL 导入保留更新；文件导入是快照，需重新导入新文件。助手不会上传订阅到转换网站。

速度与稳定性：取决于本地网络、运营商路由、节点负载和服务商限速。先更新订阅、检查套餐余量、手选节点对比，再决定是否切换协议。下载测速只比较本次实际可达的下载源。

故障排查：无法导入→确认是 Clash/Mihomo 格式且证书有效；无法启动→检查端口占用和客户端日志；能连接但慢→查看丢包与节点负载；国内走代理→确认规则模式、没有其他全局扩展覆盖。不要通过关闭 TLS 验证解决连接故障。"""
