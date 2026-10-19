"""Private, additive Clash Verge Rev 2.5.8 profile integration.

Schema verified against the upstream v2.5.8 config/{profiles,prfitem}.rs.
No Tauri IPC is exposed for external callers. Only the user-selected data
directory is changed, with the application closed. Its settings win over
extensions, so incompatible settings are reported instead of silently changed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import time
import urllib.parse
import urllib.request
import uuid

import yaml

from ..cli import SetupError, private_write, protect

ProfileError = SetupError

MAX_BYTES = 4 * 1024 * 1024
SUPPORTED_CLASH_VERSIONS = ("2.5.8",)
SUPPORTED_MIHOMO_VERSIONS = ("1.19.32",)
GROUP = "VPS-PROXY"
AUTO = "VPS-AUTO"
PROXY_TYPES = ("ss", "trojan", "hysteria2", "vmess", "vless")
# Explicitly exclude plugin executables, certificate paths, dialer-proxy and
# transport fields requiring arbitrary nested structures or file access.
PROXY_KEYS = ("name", "type", "server", "port", "password", "cipher", "uuid",
              "alterId", "tls", "servername", "sni", "skip-cert-verify", "udp",
              "network", "obfs", "obfs-password", "alpn", "client-fingerprint",
              "fingerprint", "flow", "packet-encoding", "tfo", "fast-open")
PROXY_KEYS += ("ws-opts", "grpc-opts", "http-opts", "reality-opts")
TRANSPORT_KEYS = {"ws-opts": ("path", "headers", "max-early-data", "early-data-header-name"),
                  "grpc-opts": ("grpc-service-name",), "http-opts": ("method", "path", "headers"),
                  "reality-opts": ("public-key", "short-id", "support-x25519mlkem768")}


@dataclass(frozen=True)
class Subscription:
    source_kind: str
    source_label: str
    proxy_count: int
    protocols: tuple[str, ...]
    warnings: tuple[str, ...]
    source: str = field(repr=False)
    document: dict = field(repr=False)


@dataclass(frozen=True)
class ImportPlan:
    clash_dir: Path
    clash_version: str
    mihomo_version: str | None
    subscription: Subscription
    profile_name: str
    existing_profile_count: int
    conflicts: tuple[str, ...]
    summary: str
    snapshots: dict[str, str | None] = field(repr=False)
    index: dict = field(repr=False)


@dataclass(frozen=True)
class ImportResult:
    profile_uid: str
    backup_dir: Path
    activated: bool
    message: str


class _Loader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise SetupError("不支持 YAML 引用/别名；请导出展开后的 Clash YAML。")
        self._nodes = getattr(self, "_nodes", 0) + 1
        self._depth = getattr(self, "_depth", 0) + 1
        if self._nodes > 100000 or self._depth > 40:
            raise SetupError("YAML 配置结构过于复杂。")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise SetupError("YAML 字段必须为唯一的文本键。")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
                        _Loader.construct_mapping)


def _yaml(data: bytes) -> dict:
    if len(data) > MAX_BYTES:
        raise SetupError("配置超过 4 MiB 限制。")
    try:
        result = yaml.load(data.decode("utf-8-sig"), Loader=_Loader)
    except SetupError:
        raise
    except (UnicodeError, yaml.YAMLError, ValueError, RecursionError):
        raise SetupError("无法读取 UTF-8 Clash YAML；不支持 URI 列表或 Base64 订阅，请向服务商索取 Clash/Mihomo 格式。") from None
    if not isinstance(result, dict):
        raise SetupError("需要 Clash/Mihomo YAML 配置；不支持 URI 列表或 Base64 订阅。")
    return result


def _https_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        valid = (parsed.scheme == "https" and parsed.hostname and not parsed.username
                 and not parsed.password and not parsed.fragment and parsed.port != 0
                 and not re.search(r"[\s\\\x00-\x1f\x7f]", value))
    except ValueError:
        valid = False
    if not valid:
        raise SetupError("订阅 URL 必须为有效 HTTPS 地址，不允许账号、片段或控制字符。")
    return value


class _HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 4
    max_repeats = 2

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _https_url(newurl)
        # Do not forward secrets between origins; only a new URL supplied by the
        # server is followed, with no Authorization or Cookie headers.
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str) -> bytes:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _HTTPSRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={"User-Agent": "Clash-Verge/v2.5.8 VPS-Proxy-Setup",
                                                  "Accept": "application/yaml,text/plain"})
    try:
        with opener.open(request, timeout=15) as response:
            _https_url(response.geturl())
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise SetupError("订阅响应使用了不支持的压缩格式。")
            deadline = time.monotonic() + 30
            chunks, size = [], 0
            while size <= MAX_BYTES:
                if time.monotonic() > deadline:
                    raise SetupError("订阅下载超过时间限制，请稍后重试。")
                chunk = response.read1(min(65536, MAX_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            result = b"".join(chunks)
    except SetupError:
        raise
    except Exception:
        # urllib errors can contain the full token-bearing URL and response.
        raise SetupError("无法安全下载订阅。请检查网络、HTTPS 证书和订阅有效期。") from None
    if len(result) > MAX_BYTES:
        raise SetupError("订阅超过 4 MiB 限制。")
    return result


def _proxies(document: dict) -> list[dict]:
    if document.get("proxy-providers"):
        raise SetupError("暂不支持 proxy-providers 嵌套订阅；请提供直接包含 proxies 的 Clash YAML。")
    nodes = document.get("proxies")
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 2000:
        raise SetupError("Clash YAML 需包含 1–2000 个 proxies 节点。")
    result, names = [], {GROUP, AUTO, "DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL"}
    for node in nodes:
        if not isinstance(node, dict) or node.get("type") not in PROXY_TYPES:
            raise SetupError("当前仅支持 ss、trojan、hysteria2、vmess、vless 节点。")
        name, server = node.get("name"), node.get("server")
        if (not isinstance(name, str) or not name or len(name) > 128
                or any(c in name for c in ",\r\n\x00") or name in names):
            raise SetupError("节点名称重复、为保留名称或包含不支持的字符。")
        names.add(name)
        if (not isinstance(server, str) or len(server) > 253
                or not re.fullmatch(r"[A-Za-z0-9_.:\-]+", server)):
            raise SetupError("节点服务器地址格式无效。")
        if type(node.get("port")) is not int or not 1 <= node["port"] <= 65535:
            raise SetupError("节点端口格式无效。")
        if node.get("skip-cert-verify") is not None and node.get("skip-cert-verify") is not False:
            raise SetupError("节点要求跳过 TLS 证书校验，请修复订阅后重试。")
        if set(node) - set(PROXY_KEYS):
            raise SetupError("节点含暂不支持的插件或高级字段；不会执行插件或读取节点指定的本地文件。")
        if node.get("network", "tcp") not in ("tcp", "ws", "grpc", "http"):
            raise SetupError("此向导仅支持标准 TCP/WebSocket/gRPC/HTTP 传输。")
        for key, value in node.items():
            if key in TRANSPORT_KEYS:
                _transport(key, value)
            elif key == "alpn":
                if not isinstance(value, list) or not all(isinstance(v, str) and len(v) < 64 for v in value) or len(value) > 8:
                    raise SetupError("节点 ALPN 格式无效。")
            elif not isinstance(value, (str, int, bool, float)) or isinstance(value, str) and len(value) > 4096:
                raise SetupError("节点字段必须为简单标量。")
        kind = node["type"]
        if kind in ("ss", "trojan", "hysteria2") and not isinstance(node.get("password"), (str, int)):
            raise SetupError("节点缺少密码。")
        if kind == "ss" and not isinstance(node.get("cipher"), str):
            raise SetupError("SS 节点缺少 cipher 加密算法。")
        if kind in ("vmess", "vless"):
            try:
                uuid.UUID(node.get("uuid", ""))
            except (ValueError, TypeError, AttributeError):
                raise SetupError("节点 UUID 无效。") from None
        safe = copy.deepcopy(node)
        if kind in ("vmess", "vless"):
            safe["uuid"] = str(uuid.UUID(node["uuid"]))
        if kind in ("trojan", "hysteria2") or node.get("tls"):
            safe["skip-cert-verify"] = False
        result.append(safe)
    return result


def _transport(kind: str, value):
    """Validate bounded transport data only; no plugins or filesystem paths."""
    valid = isinstance(value, dict) and not set(value) - set(TRANSPORT_KEYS[kind])
    if not valid:
        raise SetupError("节点传输选项包含未知字段。")
    for key, item in value.items():
        if key == "headers":
            if not isinstance(item, dict) or len(item) > 32:
                raise SetupError("节点 HTTP 请求头格式无效。")
            for name, header in item.items():
                values = header if isinstance(header, list) and kind == "http-opts" else [header]
                if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name)
                        or len(values) > 16 or not all(isinstance(v, str) and len(v) <= 4096
                        and not re.search(r"[\r\n\x00]", v) for v in values)):
                    raise SetupError("节点 HTTP 请求头格式无效。")
        elif key == "max-early-data":
            if type(item) is not int or not 0 <= item <= 65536:
                raise SetupError("WebSocket early-data 大小无效。")
        elif key == "support-x25519mlkem768":
            if type(item) is not bool:
                raise SetupError("Reality 选项类型无效。")
        else:
            values = item if isinstance(item, list) and kind == "http-opts" and key == "path" else [item]
            if len(values) > 32 or not all(isinstance(v, str) and len(v) <= 4096 and not re.search(r"[\r\n\x00]", v) for v in values):
                raise SetupError("节点传输选项格式无效。")


def load_subscription(source: str | Path) -> Subscription:
    value = str(source).strip()
    remote = value.lower().startswith(("https:", "http:"))
    if remote:
        value = _https_url(value)
        data = _fetch(value)
        label = "HTTPS 订阅（地址及令牌已隐藏）"
    else:
        try:
            path = Path(value).expanduser()
            if not path.is_file() or path.stat().st_size > MAX_BYTES:
                raise SetupError("请选择不超过 4 MiB 的本地 Clash YAML 文件。")
            with path.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
            value = str(path.absolute())
        except OSError:
            raise SetupError("无法读取本地订阅文件。") from None
        label = "本地 Clash YAML 文件（路径已隐藏）"
    document = _yaml(data)
    nodes = _proxies(document)
    warnings = ("将使用向导的分流、DNS 和安全设置；原订阅的规则、组及其他顶层设置不导入。",
                "中国域名/IP 规则依赖 Mihomo 首次联网下载 MetaCubeX 规则并每日更新。")
    if not remote:
        warnings += ("本地文件以快照导入，不会自动跟随源文件更新。",)
    else:
        warnings += ("订阅通过 Mihomo 原生代理集合每日更新节点；分流规则和本机监听设置固定保留，不导入订阅的全局配置。",)
    return Subscription("remote" if remote else "local", label, len(nodes),
                        tuple(sorted({n["type"] for n in nodes})), warnings, value, {"proxies": nodes})


def render_profile(subscription: Subscription) -> dict:
    nodes = _proxies(subscription.document)
    names = [node["name"] for node in nodes]
    rules = ["DOMAIN,localhost,DIRECT", "DOMAIN-SUFFIX,local,DIRECT", "DOMAIN-SUFFIX,lan,DIRECT",
             "DOMAIN-SUFFIX,ts.net,DIRECT", "DOMAIN-SUFFIX,tailscale.com,DIRECT"]
    for network in ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4"):
        rules.append("IP-CIDR," + network + ",DIRECT,no-resolve")
    for network in ("::1/128", "fc00::/7", "fe80::/10"):
        rules.append("IP-CIDR6," + network + ",DIRECT,no-resolve")
    rules += ["DOMAIN-SUFFIX,cn,DIRECT", "RULE-SET,vps-cn-domain,DIRECT",
              "RULE-SET,vps-cn-ip,DIRECT", "MATCH," + GROUP]
    providers = {}
    for name, folder, behavior in (("vps-cn-domain", "geosite", "domain"), ("vps-cn-ip", "geoip", "ipcidr")):
        providers[name] = {"type": "http", "behavior": behavior, "format": "mrs", "interval": 86400,
                           "proxy": GROUP,
                           "url": f"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/{folder}/cn.mrs",
                           "path": f"./ruleset/{name}.mrs"}
    result = {"mixed-port": 7897, "allow-lan": False, "bind-address": "127.0.0.1", "mode": "rule",
            "ipv6": False, "log-level": "warning", "external-controller": "", "tun": {"enable": False},
            "dns": {"enable": True, "ipv6": False, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                    "fake-ip-filter": ["*.lan", "*.local", "+.ts.net", "localhost"],
                    "nameserver": ["https://1.1.1.1/dns-query#" + GROUP, "https://8.8.8.8/dns-query#" + GROUP],
                    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
                    "proxy-server-nameserver": ["https://dns.alidns.com/dns-query"],
                    "direct-nameserver": ["https://dns.alidns.com/dns-query"],
                    "nameserver-policy": {"+.cn": ["https://dns.alidns.com/dns-query"],
                                          "rule-set:vps-cn-domain": ["https://dns.alidns.com/dns-query"],
                                          "+.ts.net": ["100.100.100.100#DIRECT"], "+.lan": ["system"], "+.local": ["system"]}},
            "proxies": nodes, "proxy-groups": [
                {"name": GROUP, "type": "select", "proxies": [AUTO] + names},
                {"name": AUTO, "type": "fallback", "proxies": names,
                 "url": "https://www.gstatic.com/generate_204", "interval": 300}],
            "rule-providers": providers, "rules": rules}
    if subscription.source_kind == "remote":
        _https_url(subscription.source)
        # Native providers parse proxies only. Whole-profile remote updates are
        # unsafe here: Verge returns raw upstream config if JS is skipped/fails.
        # Use a fixed local profile; this URL can only change its provider nodes.
        allowed = " or ".join(".key == " + json.dumps(key) for key in PROXY_KEYS)
        kinds = " or ".join(".type == " + json.dumps(kind) for kind in PROXY_TYPES)
        expressions = ["select(" + kinds + ") | with_entries(select(" + allowed + "))"]
        # Per-transport projections keep cache updates from adding local file
        # or plugin options inside an otherwise allowed nested dictionary.
        # A missing mapping is left absent: creating empty reality-opts would
        # make Mihomo require a Reality public key even for ordinary Trojan.
        for key, keys in TRANSPORT_KEYS.items():
            options = " or ".join(".key == " + json.dumps(option) for option in keys)
            expressions.append('.["' + key + '"] |= (select(. != null) | with_entries(select(' + options + ')))')
        expressions.append(".skip-cert-verify = false")
        result["proxies"] = []
        result["proxy-providers"] = {"vps-upstream": {
            "type": "http", "url": subscription.source, "interval": 86400,
            "path": "./.vps-proxy-setup-providers/" + hashlib.sha256(subscription.source.encode("utf-8")).hexdigest()[:32] + ".yaml",
            "size-limit": MAX_BYTES, "proxy": "DIRECT", "payload": nodes,
            "header": {"User-Agent": ["Clash-Verge/v2.5.8 VPS-Proxy-Setup"]},
            "health-check": {"enable": True, "url": "https://www.gstatic.com/generate_204", "interval": 300,
                             "timeout": 5000, "lazy": True},
            "override": {"skip-cert-verify": False, "additional-prefix": "VPS | ",
                         "override-expr": expressions}}}
        result["proxy-groups"] = [
            {"name": GROUP, "type": "select", "proxies": [AUTO], "use": ["vps-upstream"]},
            {"name": AUTO, "type": "fallback", "use": ["vps-upstream"],
             "url": "https://www.gstatic.com/generate_204", "interval": 300}]
    return result


def profile_script(subscription: Subscription | None = None) -> str:
    # Build from a constant template. Never interpolate node names or tokens into
    # executable JavaScript. On invalid upstream updates return REJECT, because
    # throwing makes Clash Verge fall back to the untrusted upstream config.
    if subscription is not None and subscription.source_kind == "remote":
        return ("// Fixed local profile; native HTTP provider updates nodes only.\nfunction main(input) { return "
                + json.dumps(render_profile(subscription), ensure_ascii=True) + "; }\n")
    dummy = Subscription("local", "", 1, ("trojan",), (), "", {"proxies": [
        {"name": "placeholder", "type": "trojan", "server": "example.com", "port": 443, "password": "placeholder"}]})
    template = render_profile(dummy)
    template["proxies"] = []
    return "// VPS Proxy Setup: per-profile extension, reapplied after subscription updates.\n" + "function main(input) {\n  var out = " + json.dumps(template, ensure_ascii=False) + ";\n" + """
  var allowed = KEYS;
  var kinds = TYPES;
  var transports = TRANSPORTS;
  function strings(v, list, max) {
    var values = list && Array.isArray(v) ? v : [v];
    return values.length <= max && values.every(function(s) { return typeof s === 'string' && s.length <= 4096 && !/[\\r\\n\\x00]/.test(s); });
  }
  function transport(kind, v) {
    if (!v || Array.isArray(v) || typeof v !== 'object') return false;
    var keys = Object.keys(v);
    if (keys.some(function(k) { return transports[kind].indexOf(k) < 0; })) return false;
    return keys.every(function(k) {
      var item = v[k];
      if (k === 'headers') {
        if (!item || Array.isArray(item) || typeof item !== 'object' || Object.keys(item).length > 32) return false;
        return Object.keys(item).every(function(h) { return /^[A-Za-z0-9_-]{1,128}$/.test(h) && strings(item[h], kind === 'http-opts', 16); });
      }
      if (k === 'max-early-data') return Number.isInteger(item) && item >= 0 && item <= 65536;
      if (k === 'support-x25519mlkem768') return typeof item === 'boolean';
      return strings(item, kind === 'http-opts' && k === 'path', 32);
    });
  }
  var names = ['VPS-PROXY','VPS-AUTO','DIRECT','REJECT','REJECT-DROP','PASS','GLOBAL'];
  var raw = input && input.proxies;
  var good = Array.isArray(raw) && raw.length > 0 && raw.length <= 2000;
  if (good) for (var i = 0; i < raw.length; i++) {
    var p = raw[i];
    if (!p || kinds.indexOf(p.type) < 0 || typeof p.name !== 'string' || !p.name || p.name.length > 128 || /[,\\r\\n\\x00]/.test(p.name) || names.indexOf(p.name) >= 0 || typeof p.server !== 'string' || !/^[A-Za-z0-9_.:\\-]+$/.test(p.server) || p.server.length > 253 || !Number.isInteger(p.port) || p.port < 1 || p.port > 65535 || (p['skip-cert-verify'] !== undefined && p['skip-cert-verify'] !== false) || (p.network !== undefined && ['tcp','ws','grpc','http'].indexOf(p.network) < 0)) { good = false; break; }
    var keys = Object.keys(p), clean = {};
    for (var j = 0; j < keys.length; j++) {
      var k = keys[j], v = p[k];
      if (allowed.indexOf(k) < 0 || (transports[k] ? !transport(k, v) : k === 'alpn' ? !Array.isArray(v) || v.length > 8 || v.some(function(s) { return typeof s !== 'string' || s.length >= 64; }) : !['string','number','boolean'].includes(typeof v) || typeof v === 'string' && v.length > 4096)) { good = false; break; }
      clean[k] = v;
    }
    if (!good) break;
    if (['ss','trojan','hysteria2'].indexOf(p.type) >= 0 && !['string','number'].includes(typeof p.password)) { good = false; break; }
    if (p.type === 'ss' && typeof p.cipher !== 'string') { good = false; break; }
    if (['vmess','vless'].indexOf(p.type) >= 0 && (typeof p.uuid !== 'string' || !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(p.uuid))) { good = false; break; }
    if (p.tls || ['trojan','hysteria2'].indexOf(p.type) >= 0) clean['skip-cert-verify'] = false;
    names.push(p.name); out.proxies.push(clean);
  }
  if (!good) {
    out.proxies = []; out['proxy-groups'] = [];
    out.rules = ['MATCH,REJECT']; out['rule-providers'] = {};
    out.dns.nameserver = ['https://dns.alidns.com/dns-query']; out.dns['nameserver-policy'] = {};
    return out;
  }
  var nodes = out.proxies.map(function(p) { return p.name; });
  out['proxy-groups'][0].proxies = ['VPS-AUTO'].concat(nodes);
  out['proxy-groups'][1].proxies = nodes;
  return out;
}
""".replace("KEYS", json.dumps(PROXY_KEYS)).replace("TYPES", json.dumps(PROXY_TYPES)).replace("TRANSPORTS", json.dumps(TRANSPORT_KEYS))


def default_clash_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "io.github.clash-verge-rev.clash-verge-rev"
    if os.sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "io.github.clash-verge-rev.clash-verge-rev"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "io.github.clash-verge-rev.clash-verge-rev"


def export_profile(subscription: Subscription, destination: str | Path, *, mihomo_version: str | None = None) -> Path:
    """Export a private, standalone full configuration for manual import.

    Local inputs produce snapshots. HTTPS inputs include a native provider URL
    and require the supported Mihomo core for safe node overrides on updates.
    It does not inspect or alter any installed application's state.
    """
    target = Path(destination).expanduser().absolute()
    if subscription.source_kind == "remote" and str(mihomo_version or "").lstrip("v") not in SUPPORTED_MIHOMO_VERSIONS:
        raise SetupError("导出 HTTPS 自动更新配置前需确认目标使用 Mihomo 1.19.32。")
    _plain_path(target)
    if target.exists() or not target.parent.is_dir():
        raise SetupError("导出文件已存在或目标目录不存在；请选择新的文件名。")
    try:
        private_write(target, json.dumps(render_profile(subscription), ensure_ascii=False, indent=2) + "\n")
    except SetupError:
        raise
    except Exception:
        raise SetupError("无法私密导出完整 Clash 配置，请检查目标目录权限。") from None
    return target


def clash_running() -> bool:
    """Fail closed if process enumeration fails; never terminate processes."""
    try:
        if os.name == "nt":
            result = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True,
                                    timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode:
                raise OSError()
            # The persistent clash-verge-service helper alone is safe; unlike
            # the UI/core it does not own or save profiles.yaml.
            return bool(re.search(rb'"(?:clash-verge(?:-rev)?|(?:verge-mihomo|mihomo)(?:-[A-Za-z0-9_-]+)?)\.exe"', result.stdout, re.I))
        result = subprocess.run(["ps", "-A", "-o", "comm="], capture_output=True, timeout=10)
        if result.returncode:
            raise OSError()
        return any(re.fullmatch(rb"(?:.*/)?(?:clash-verge(?:-rev)?|(?:verge-mihomo|mihomo)(?:-[A-Za-z0-9_-]+)?)", line.strip(), re.I)
                   for line in result.stdout.splitlines())
    except (OSError, subprocess.SubprocessError):
        raise SetupError("无法确认 Clash/Mihomo 已退出，未写入配置。") from None


def _plain_path(path: Path):
    # Reject symlinks/junctions through every existing component, including the
    # selected root, rather than resolving an attacker-controlled escape.
    for parent in (path,) + tuple(path.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise SetupError("无法验证 Clash 配置目录路径。") from None
        # is_junction is unavailable before Python 3.12. Reject all Windows
        # reparse points using lstat, covering 3.10 junctions and mount points.
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise SetupError("Clash 配置目录不能包含符号链接或目录联接。")


def _read(path: Path) -> bytes | None:
    _plain_path(path)
    try:
        if not path.exists():
            return None
        if not path.is_file() or path.stat().st_size > MAX_BYTES:
            raise SetupError("Clash 配置文件大小或类型不受支持。")
        return path.read_bytes()
    except OSError:
        raise SetupError("无法读取 Clash 配置目录。") from None


def _hash(data: bytes | None) -> str | None:
    return hashlib.sha256(data).hexdigest() if data is not None else None


def _settings_conflicts(root: Path) -> list[str]:
    conflicts = []
    data = _read(root / "clash.yaml")
    settings = _yaml(data) if data else {}
    if settings.get("allow-lan", False) is not False:
        conflicts.append("Clash 设置已允许局域网连接；请在 Clash 中关闭后重新预览。")
    if settings.get("mode", "rule") != "rule":
        conflicts.append("Clash 当前模式不是规则模式；请在 Clash 中切换规则模式后重新预览。")
    for key in ("external-controller", "external-controller-tls", "external-controller-doh"):
        address = settings.get(key)
        if address and (not isinstance(address, str) or not re.fullmatch(r"(?:127\.0\.0\.1|localhost|\[::1\]):[0-9]+", address)):
            conflicts.append("Clash 控制器监听非本机地址；请改为回环地址后重新预览。")
    dns = settings.get("dns")
    if isinstance(dns, dict) and dns.get("listen") and not str(dns["listen"]).startswith(("127.0.0.1:", "[::1]:")):
        conflicts.append("Clash DNS 已监听非本机地址；请关闭对外监听后重新预览。")
    data = _read(root / "verge.yaml")
    verge = _yaml(data) if data else {}
    if verge.get("enable_dns_settings"):
        data = _read(root / "dns_config.yaml")
        dns_settings = _yaml(data) if data else {}
        dns = dns_settings.get("dns", dns_settings)
        if isinstance(dns, dict) and dns.get("listen") and not str(dns["listen"]).startswith(("127.0.0.1:", "[::1]:")):
            conflicts.append("Clash 独立 DNS 设置已监听非本机地址；请关闭后重新预览。")
        conflicts.append("Clash 已开启独立 DNS 覆写，会替换向导的中国/Tailscale DNS 分流；请先在 Clash 中关闭独立 DNS 覆写。")
    return conflicts


def preview_import(subscription: Subscription, clash_dir: str | Path, *, clash_version: str = "2.5.8",
                   mihomo_version: str | None = None,
                   profile_name: str = "VPS Proxy Setup") -> ImportPlan:
    version = str(clash_version).lstrip("v")
    if version not in SUPPORTED_CLASH_VERSIONS:
        raise SetupError("仅验证了 Clash Verge Rev 2.5.8；请安装此版本后导入。")
    core_version = str(mihomo_version or "").lstrip("v") or None
    if subscription.source_kind == "remote" and core_version not in SUPPORTED_MIHOMO_VERSIONS:
        raise SetupError("HTTPS 订阅自动更新需要已验证的 Mihomo 1.19.32；请在 Clash 关于页核对核心版本。")
    if not profile_name.strip() or len(profile_name) > 80 or re.search(r"[\x00-\x1f]", profile_name):
        raise SetupError("配置名称不能为空、超过 80 字或包含控制字符。")
    root = Path(clash_dir).expanduser().absolute()
    _plain_path(root)
    if not root.is_dir() or not (root / "profiles").is_dir() or not (root / "verge.yaml").is_file():
        raise SetupError("请选择已经启动过的 Clash Verge Rev 配置目录（需含 verge.yaml、profiles.yaml 和 profiles 文件夹）。")
    snapshots = {name: _hash(_read(root / name)) for name in ("profiles.yaml", "clash.yaml", "verge.yaml", "dns_config.yaml")}
    raw = _read(root / "profiles.yaml")
    if raw is None:
        raise SetupError("Clash 配置索引不存在；请先启动 Clash Verge Rev 一次。")
    index = _yaml(raw)
    items = index.get("items") or []
    if set(index) - {"current", "items"} or not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        raise SetupError("Clash profiles.yaml 结构不受支持，未修改任何配置。")
    conflicts = _settings_conflicts(root)
    seen = set()
    for item in items:
        uid, filename = item.get("uid"), item.get("file")
        if not isinstance(uid, str) or uid in seen or not re.fullmatch(r"[A-Za-z0-9_-]+", uid):
            raise SetupError("Clash 配置索引含无效或重复 UID，请先在 Clash 中修复。")
        seen.add(uid)
        if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+\.(?:yaml|js)", filename):
            raise SetupError("Clash 配置索引文件路径不受支持。")
        _plain_path(root / "profiles" / filename)
        if not (root / "profiles" / filename).is_file():
            raise SetupError("Clash 配置索引引用文件缺失，请先在 Clash 中修复。")
        if item.get("name") == profile_name:
            conflicts.append("同名配置已存在；请改用新名称，向导不会覆盖已有订阅。")
        if subscription.source_kind == "remote" and item.get("url") == subscription.source:
            conflicts.append("此订阅 URL 已存在；请在 Clash 中管理已有订阅，避免重复导入。")
    if index.get("current") is not None and index["current"] not in seen:
        raise SetupError("Clash 当前配置引用无效，请先在 Clash 中修复。")
    count = sum(i.get("type") in ("local", "remote") for i in items)
    render_profile(subscription)  # revalidate caller-owned data before preview
    summary = (f"{subscription.source_label}；{subscription.proxy_count} 个节点（{'、'.join(subscription.protocols)}）。\n"
               f"新增配置：{profile_name}；保留 {count} 个现有订阅。\n"
               "局域网/Tailscale 与中国域名/IP 直连；其余流量使用 VPS-PROXY。\n"
               "VPS-PROXY 可手选节点，默认 VPS-AUTO 自动故障切换（非最低延迟竞速）。\n"
               + "\n".join(subscription.warnings) + "\n需完全退出 Clash/Mihomo 后写入；写入前备份，激活需另行选择。")
    return ImportPlan(root, version, core_version, subscription, profile_name, count, tuple(conflicts), summary, snapshots, index)


def apply_import(plan: ImportPlan, *, consent: bool = False, activate: bool = False) -> ImportResult:
    if consent is not True:
        raise SetupError("请先确认导入预览并同意写入所选 Clash 目录。")
    if plan.conflicts:
        raise SetupError("导入预览存在冲突，请处理并重新预览。")
    if clash_running():
        raise SetupError("请从系统托盘完全退出 Clash Verge Rev，并停止其 Mihomo 核心后重试。")
    root = plan.clash_dir
    current = preview_import(plan.subscription, root, clash_version=plan.clash_version,
                             mihomo_version=plan.mihomo_version, profile_name=plan.profile_name)
    if current.conflicts or current.snapshots != plan.snapshots or current.index != plan.index:
        raise SetupError("Clash 配置在预览后已变化，请重新预览。")
    lock = root / ".vps-proxy-setup.lock"
    _plain_path(lock)
    try:
        lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise SetupError("检测到未完成的导入锁；确认向导未运行后，检查备份并移除 .vps-proxy-setup.lock 再重试。") from None
    backup = root / ("vps-proxy-backup-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
    try:
        os.close(lock_fd)
        protect(lock)
        backup.mkdir()
        protect(backup, directory=True)
        if plan.subscription.source_kind == "remote":
            cache = root / ".vps-proxy-setup-providers"
            _plain_path(cache)
            cache.mkdir(exist_ok=True)
            protect(cache, directory=True)
        original = _read(root / "profiles.yaml")
        private_write(backup / "profiles.yaml", original.decode("utf-8"))
        uid, sid = "L" + uuid.uuid4().hex[:12], "s" + uuid.uuid4().hex[:12]
        files = {uid + ".yaml": json.dumps(render_profile(plan.subscription), ensure_ascii=False, indent=2) + "\n",
                 sid + ".js": profile_script(plan.subscription)}
        index = copy.deepcopy(plan.index)
        items = index.setdefault("items", [])
        if items is None:
            items = index["items"] = []
        item = {"uid": uid, "type": "local", "name": plan.profile_name,
                "file": uid + ".yaml", "updated": int(time.time()),
                "option": {"script": sid, "merge": None, "rules": None, "proxies": None, "groups": None,
                           "allow_auto_update": False, "update_interval": 1440,
                           "timeout_seconds": 15, "danger_accept_invalid_certs": False}}
        if plan.subscription.source_kind == "remote":
            item["url"] = plan.subscription.source
        items += [{"uid": sid, "type": "script", "file": sid + ".js", "updated": int(time.time())}, item]
        if activate:
            index["current"] = uid
        index_text = yaml.safe_dump(index, allow_unicode=True, sort_keys=False)
        manifest = {"status": "prepared", "profile_uid": uid, "files": list(files), "activated": activate,
                    "original_sha256": _hash(original), "index_sha256": _hash(index_text.encode("utf-8")),
                    "file_sha256": {name: _hash(text.encode("utf-8")) for name, text in files.items()}}
        private_write(backup / "transaction.json", json.dumps(manifest, indent=2) + "\n")
        written = []
        committed = False
        try:
            for filename, text in files.items():
                target = root / "profiles" / filename
                _plain_path(target)
                if target.exists():
                    raise SetupError("随机配置文件名发生冲突，未覆盖任何文件。")
                private_write(target, text)
                written.append(target)
            # All referenced files exist before the only index commit. Crashes
            # before this point leave harmless unreferenced files plus journal.
            if clash_running() or any(_hash(_read(root / name)) != fingerprint for name, fingerprint in plan.snapshots.items()):
                raise SetupError("Clash 已启动或配置已变化，导入已取消。")
            private_write(root / "profiles.yaml", index_text)
            committed = True
            manifest["status"] = "committed"
            private_write(backup / "transaction.json", json.dumps(manifest, indent=2) + "\n")
        except BaseException:
            if not committed:
                for target in written:
                    target.unlink(missing_ok=True)
            # A successfully replaced index is already a complete transaction.
            # Keep referenced files if only the journal update failed.
            raise
        return ImportResult(uid, backup, activate,
                            "导入完成。启动 Clash Verge Rev 后检查运行配置与规则下载状态；系统代理/TUN 需在 Clash 中自行开启。")
    except SetupError:
        raise
    except Exception:
        raise SetupError("导入未能完成，请检查所选目录权限与备份中的 transaction.json 状态；现有订阅文件未覆盖。") from None
    finally:
        lock.unlink(missing_ok=True)


def rollback_import(backup_dir: str | Path, *, consent: bool = False) -> None:
    """Undo exactly one transaction if neither the index nor its files changed.

    Also handles an interrupted transaction whose index replacement completed
    before its journal could be marked committed. Never overwrite later edits.
    """
    if consent is not True:
        raise SetupError("回滚需要确认；请先查看备份中的 transaction.json。")
    backup = Path(backup_dir).expanduser().absolute()
    _plain_path(backup)
    if not re.fullmatch(r"vps-proxy-backup-[0-9]{8}-[0-9]{6}-[a-f0-9]{8}", backup.name):
        raise SetupError("所选目录不是此工具创建的事务备份。")
    root = backup.parent
    if clash_running():
        raise SetupError("回滚前请完全退出 Clash/Mihomo。")
    try:
        manifest = json.loads((_read(backup / "transaction.json") or b"").decode("utf-8"))
        original = _read(backup / "profiles.yaml")
        files = manifest["files"]
        if (manifest.get("status") not in ("prepared", "committed") or not isinstance(files, list) or len(files) != 2
                or not all(isinstance(name, str) and re.fullmatch(r"[RLs][a-f0-9]{12}\.(?:yaml|js)", name) for name in files)
                or original is None or _hash(original) != manifest.get("original_sha256")):
            raise ValueError()
        _yaml(original)
        index_hash = _hash(_read(root / "profiles.yaml"))
        if index_hash not in (manifest.get("index_sha256"), manifest.get("original_sha256")):
            raise SetupError("Clash 配置在导入后已变化，自动回滚已停止；请在 Clash 中管理或手动核对备份。")
        for name in files:
            data = _read(root / "profiles" / name)
            if data is not None and _hash(data) != manifest["file_sha256"].get(name):
                raise SetupError("导入的配置文件已变化，自动回滚已停止。")
        lock = root / ".vps-proxy-setup.lock"
        _plain_path(lock)
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise SetupError("存在导入事务锁，请先检查未完成的事务。") from None
        try:
            os.close(fd)
            if clash_running() or _hash(_read(root / "profiles.yaml")) != index_hash:
                raise SetupError("Clash 已启动或配置已变化，未执行回滚。")
            # Commit restored index first; only then remove no-longer-referenced
            # files. A crash between these steps leaves harmless orphan files.
            private_write(root / "profiles.yaml", original.decode("utf-8"))
            for name in files:
                (root / "profiles" / name).unlink(missing_ok=True)
            manifest["status"] = "rolled-back"
            private_write(backup / "transaction.json", json.dumps(manifest, indent=2) + "\n")
        finally:
            lock.unlink(missing_ok=True)
    except SetupError:
        raise
    except Exception:
        raise SetupError("无法验证或回滚此备份，未覆盖后续配置。") from None
