"""Pure, dependency-free client profile rendering. Never log returned contents.

The caller supplies validated, full mainland-China lists. Domain entries retain
their exact / suffix / wildcard meanings; network entries are CIDRs. JSON output
is valid YAML and can be imported by current Mihomo-based Clash clients.
"""

from __future__ import annotations

import html
import ipaddress
import json
import re
from urllib.parse import quote, urlencode, urlsplit


PRIVATE_CIDRS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)
DOMESTIC_DNS = ("223.5.5.5#DIRECT", "119.29.29.29#DIRECT")
TEST_URL = "https://www.gstatic.com/generate_204"
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{24,256}\Z", re.ASCII)


def _text(value: object, field: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError(f"Invalid {field}")
    return value


def _ini(value: object, field: str) -> str:
    value = _text(value, field)
    if any(char.isspace() or char in ",;#=\"'[]\\" for char in value):
        raise ValueError(f"Unsupported delimiter in {field}")
    return value


def _hostname(value: object, field: str, *, single_label: bool = False) -> str:
    value = _text(value, field).lower().rstrip(".")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"Invalid {field}") from None
    labels = value.split(".")
    if (len(value) > 253 or (not single_label and len(labels) < 2)
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                   for part in labels)):
        raise ValueError(f"Invalid {field}")
    return value


def _address(value: object, field: str) -> str:
    value = _text(value, field)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", value):
            raise ValueError(f"Invalid {field}") from None
        return _hostname(value, field)
    if address.version != 4:
        raise ValueError("Version 1 requires an IPv4 address or DNS hostname")
    return str(address)


def _port(value: object, field: str) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError(f"Invalid {field}")
    return value


def validate_token(value: object) -> str:
    if not isinstance(value, str) or not TOKEN_PATTERN.fullmatch(value):
        raise ValueError("Invalid subscription token")
    return value


def normalize_domains(values: list[str]) -> list[str]:
    """Validate provider entries without silently changing matching semantics."""
    if not isinstance(values, list):
        raise ValueError("CN domains must be a list")
    result, seen = [], set()
    for value in values:
        value = _text(value, "CN domain")
        if value != value.strip():
            raise ValueError("Invalid CN domain")
        if value.startswith(("+.", "*.")):
            prefix, hostname = value[:2], value[2:]
        elif value.startswith("."):
            prefix, hostname = "+.", value[1:]
        else:
            prefix, hostname = "", value
        value = prefix + _hostname(hostname, "CN domain", single_label=True)
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def normalize_networks(values: list[str]) -> list[str]:
    if not isinstance(values, list):
        raise ValueError("CN networks must be a list")
    result, seen = [], set()
    for value in values:
        try:
            if not isinstance(value, str) or "/" not in value:
                raise ValueError
            network = ipaddress.ip_network(value, strict=True)
            if network.prefixlen == 0:
                raise ValueError
        except ValueError:
            raise ValueError("Invalid CN network") from None
        value = str(network)
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def _settings(settings: dict) -> dict:
    """Validate only the fields used here; errors never contain their values."""
    try:
        if type(settings.get("schema_version")) is not int or settings["schema_version"] != 1:
            raise ValueError("Unsupported settings schema")
        label = settings["label"]
        if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", label):
            raise ValueError("Invalid label")
        address = _address(settings["address"], "address")
        tls_name = _address(settings["tls_name"], "tls_name")
        if address != tls_name:
            raise ValueError("Version 1 requires matching address and TLS name")
        token = validate_token(settings["token"])
        ports = settings["ports"]
        https_port = _port(ports["https"], "HTTPS port")
        hy2_port = _port(settings["hy2_port"], "HY2 port")
        trojan_port = _port(settings["trojan_port"], "Trojan port")
        if ports["hy2"] != hy2_port or ports["trojan"] != trojan_port:
            raise ValueError("Inconsistent transport ports")
        base = _text(settings["base_url"], "base_url")
        parsed = urlsplit(base)
        if (parsed.scheme != "https" or parsed.hostname != address
                or (parsed.port or 443) != https_port or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path != f"/s/{token}"):
            raise ValueError("Invalid subscription base URL")
        clients = {}
        for platform in ("windows", "iphone"):
            client = settings["clients"][platform]
            clients[platform] = {
                key: _ini(client[key], f"{platform} {key}")
                for key in ("hy2_auth", "trojan_password")
            }
        return dict(label=label, address=address, tls_name=tls_name, base_url=base,
                    hy2_port=hy2_port, trojan_port=trojan_port, clients=clients,
                    hy2_obfs=_ini(settings["hy2_obfs"], "HY2 obfuscation"))
    except (KeyError, TypeError, AttributeError):
        raise ValueError("Incomplete subscription settings") from None


def _ip_rule(cidr: str, *, no_resolve: bool = False) -> str:
    kind = "IP-CIDR6" if ":" in cidr else "IP-CIDR"
    return f"{kind},{cidr},DIRECT" + (",no-resolve" if no_resolve else "")


def _local_rules(address: str) -> list[str]:
    rules = ["DOMAIN,localhost,DIRECT", "DOMAIN-SUFFIX,local,DIRECT",
             "DOMAIN-SUFFIX,lan,DIRECT", "DOMAIN-SUFFIX,ts.net,DIRECT",
             "DOMAIN-SUFFIX,tailscale.com,DIRECT"]
    try:
        network = str(ipaddress.ip_network(address))
    except ValueError:
        rules.append(f"DOMAIN,{address},DIRECT")
    else:
        rules.append(_ip_rule(network, no_resolve=True))
    return rules + [_ip_rule(cidr, no_resolve=True) for cidr in PRIVATE_CIDRS]


def _clash(settings: dict, domains: list[str], networks: list[str]) -> str:
    address, tls_name = settings["address"], settings["tls_name"]
    client = settings["clients"]["windows"]
    names = [settings["label"] + "-HY2", settings["label"] + "-Trojan"]
    dns_policy = {
        "+.ts.net": ["100.100.100.100#DIRECT"],
        "+.tailscale.com": list(DOMESTIC_DNS),
        "+.local": ["system"], "+.lan": ["system"], "localhost": ["system"],
        "+.cn": list(DOMESTIC_DNS), "rule-set:cn-domain": list(DOMESTIC_DNS),
        address: list(DOMESTIC_DNS),
    }
    config = {
        "mixed-port": 7897, "allow-lan": False, "bind-address": "127.0.0.1",
        "mode": "rule", "log-level": "warning", "ipv6": False,
        "tcp-concurrent": True, "unified-delay": True,
        "profile": {"store-selected": True, "store-fake-ip": True},
        "dns": {
            "enable": True, "ipv6": False, "prefer-h3": False,
            "use-hosts": True, "use-system-hosts": True,
            "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter": ["*.lan", "*.local", "+.ts.net", "localhost", address],
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "proxy-server-nameserver": list(DOMESTIC_DNS),
            "direct-nameserver": list(DOMESTIC_DNS),
            "direct-nameserver-follow-policy": True,
            "nameserver": ["https://1.1.1.1/dns-query#PROXY", "https://8.8.8.8/dns-query#PROXY"],
            "nameserver-policy": dns_policy,
        },
        "proxies": [
            {"name": names[0], "type": "hysteria2", "server": address,
             "port": settings["hy2_port"], "password": client["hy2_auth"],
             "sni": tls_name, "skip-cert-verify": False, "udp": True,
             "obfs": "salamander", "obfs-password": settings["hy2_obfs"], "alpn": ["h3"]},
            {"name": names[1], "type": "trojan", "server": address,
             "port": settings["trojan_port"], "password": client["trojan_password"],
             "sni": tls_name, "skip-cert-verify": False, "udp": True},
        ],
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO", *names]},
            {"name": "AUTO", "type": "fallback", "proxies": names, "url": TEST_URL,
             "interval": 300, "timeout": 5000, "max-failed-times": 3, "lazy": False},
        ],
        "rule-providers": {
            "cn-domain": {"type": "inline", "behavior": "domain", "payload": domains},
            "cn-ip": {"type": "inline", "behavior": "ipcidr", "payload": networks},
        },
        "rules": [*_local_rules(address), "DOMAIN-SUFFIX,cn,DIRECT",
                  "RULE-SET,cn-domain,DIRECT", "RULE-SET,cn-ip,DIRECT", "MATCH,PROXY"],
    }
    return json.dumps(config, ensure_ascii=False, indent=2) + "\n"


def _shadowrocket(settings: dict, domains: list[str], networks: list[str]) -> str:
    address, tls_name = settings["address"], settings["tls_name"]
    client = settings["clients"]["iphone"]
    first, second = settings["label"] + "-HY2", settings["label"] + "-Trojan"
    lines = [
        "# Complete profile: activate this file and use Config routing mode.",
        "[General]", f"update-url = {settings['base_url']}/shadowrocket.conf",
        "dns-server = 223.5.5.5,119.29.29.29", "direct-dns-server = 223.5.5.5,119.29.29.29",
        "fallback-dns-server = system", "dns-direct-system = false",
        "dns-direct-fallback-proxy = false", "private-ip-answer = true",
        "ipv6 = false", "prefer-ipv6 = false", "udp-policy-not-supported-behaviour = REJECT",
        "", "[Proxy]",
        f"{first} = hysteria2,{address},{settings['hy2_port']},auth={client['hy2_auth']},"
        f"obfsParam={settings['hy2_obfs']},udp=1,peer={tls_name},alpn=h3,allowInsecure=0",
        f"{second} = trojan,{address},{settings['trojan_port']},password={client['trojan_password']},"
        f"peer={tls_name},udp=1,allowInsecure=0,skip-cert-verify=false",
        "", "[Proxy Group]", f"PROXY = select,AUTO,{first},{second},select=0",
        f"AUTO = fallback,{first},{second},interval=300,timeout=5,url={TEST_URL}",
        "", "[Rule]", *_local_rules(address), "DOMAIN-SUFFIX,cn,DIRECT",
    ]
    for domain in domains:
        if domain.startswith("+."):
            lines.append(f"DOMAIN-SUFFIX,{domain[2:]},DIRECT")
        elif domain.startswith("*."):
            lines.append(f"DOMAIN-WILDCARD,{domain},DIRECT")
        else:
            lines.append(f"DOMAIN,{domain},DIRECT")
    lines.extend(_ip_rule(network) for network in networks)
    lines.extend(("FINAL,PROXY", ""))
    return "\n".join(lines)


def _landing(settings: dict) -> str:
    base = settings["base_url"]
    clash_url, sr_url = base + "/clash.yaml", base + "/shadowrocket.conf"
    values = {
        "LABEL": settings["label"], "BASE": base, "CLASH": clash_url, "SR": sr_url,
        "CLASH_IMPORT": "clash://install-config?" + urlencode(
            {"url": clash_url, "name": settings["label"]}, quote_via=quote),
        "SR_IMPORT": "shadowrocket://config/add/" + sr_url,
    }
    page = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<title>__LABEL__ · 连接配置</title><style>
:root{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#183026;background:#f4f6f2;color-scheme:light}*{box-sizing:border-box}
body{margin:0;padding:48px 20px}main{max-width:760px;margin:auto}.eyebrow{font-size:13px;font-weight:650;letter-spacing:.12em;color:#527461}
h1{font-size:clamp(30px,6vw,43px);line-height:1.2;margin:16px 0}.intro{font-size:17px;color:#486052}.cards{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:30px 0}
article{background:white;border:1px solid #dce4dc;border-radius:14px;padding:24px}h2{margin:0 0 8px;font-size:21px}p,li{line-height:1.7}
article p{color:#526659;font-size:14px;min-height:72px}.button{display:block;text-align:center;background:#19633e;color:white;text-decoration:none;padding:14px;border-radius:8px;font-weight:650;margin:18px 0}
button:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid #b17b00;outline-offset:3px}label{display:block;font-size:12px;color:#526659;margin:14px 0 6px}
input{width:100%;font:12px ui-monospace,monospace;border:1px solid #ccd7cd;border-radius:6px;padding:12px;color:#314939;background:#fafbf8}
.actions{display:flex;gap:18px;align-items:center;font-size:14px}button{font:inherit;color:#19633e;border:0;background:transparent;cursor:pointer;padding:14px 0}a{color:#19633e}
.notes{padding:0 4px}.notes h2{font-size:18px}.notes ol{padding-left:22px;color:#435a49}.small{font-size:13px;color:#526659}#copy-status{min-height:24px;color:#19633e;font-size:14px}
@media(max-width:620px){body{padding:30px 16px}.cards{grid-template-columns:1fr}article p{min-height:0}}
</style></head><body><main><div class="eyebrow">__LABEL__ / PRIVATE CONNECTION</div>
<h1>节点和规则，一次导入。</h1><p class="intro">国内域名与中国大陆 IP 直连，其他流量通过代理。优先使用 Hysteria 2，连接异常时自动尝试 Trojan。</p>
<div class="cards"><article><h2>Windows · Clash Verge</h2><p>适用于使用 Mihomo 内核的 Clash 客户端。配置包含两个节点、自动回退和完整国内直连规则。</p>
<a class="button" href="__CLASH_IMPORT__" rel="noreferrer">导入 Clash</a>
<label for="clash-url">完整订阅 URL</label><input id="clash-url" readonly value="__CLASH__" autocomplete="off" spellcheck="false">
<div class="actions"><button type="button" data-copy="clash-url">复制 URL</button><a href="__CLASH__" download="proxy-profile.yaml">下载配置</a></div></article>
<article><h2>iPhone · 小火箭</h2><p>导入完整配置后，在“配置”页选中并启用。首页只添加节点，不会启用这份国内直连规则。</p>
<a class="button" href="__SR_IMPORT__" rel="noreferrer">导入小火箭</a>
<label for="sr-url">完整配置 URL</label><input id="sr-url" readonly value="__SR__" autocomplete="off" spellcheck="false">
<div class="actions"><button type="button" data-copy="sr-url">复制 URL</button><a href="__SR__" download="proxy-profile.conf">下载配置</a></div></article></div>
<p id="copy-status" role="status" aria-live="polite"></p><section class="notes"><h2>导入后这样用</h2><ol>
<li><strong>Clash：</strong>启用新订阅，选择“规则”模式；PROXY 分组选择 AUTO，并打开系统代理或客户端的 TUN。</li>
<li><strong>小火箭：</strong>在“配置”页选中导入的文件，将“全局路由”设置为“配置”；PROXY 分组选择 AUTO，然后开启连接。</li>
<li><strong>检查连接：</strong>分别打开国内与海外网站。自动回退用于新连接，已有连接可能需要重连。</li></ol>
<p class="small">按钮未打开应用时，可复制对应 URL，在客户端手动添加远程订阅 / 配置。Tailscale 与局域网地址保持直连；访问它们仍需要本机已有网络连接。</p>
<label for="entry-url">保存入口，之后可重新导入</label><input id="entry-url" readonly value="__BASE__" autocomplete="off" spellcheck="false">
<div class="actions"><button type="button" data-copy="entry-url">复制入口 URL</button></div>
<p class="small">这些 URL 是私人访问凭据。请仅在自己的设备上保存和使用。</p></section></main><script>
document.querySelectorAll('[data-copy]').forEach(function(button){button.addEventListener('click',async function(){
const input=document.getElementById(button.dataset.copy),status=document.getElementById('copy-status');
try{await navigator.clipboard.writeText(input.value);status.textContent='已复制完整 URL。';}
catch(error){input.focus();input.select();input.setSelectionRange(0,input.value.length);status.textContent='已选中完整 URL，请长按或按 Ctrl+C 复制。';}
});});</script></body></html>
"""
    return re.sub(r"__(LABEL|BASE|CLASH|SR|CLASH_IMPORT|SR_IMPORT)__",
                  lambda match: html.escape(values[match[1]], quote=True), page)


def render(settings: dict, domains: list[str], networks: list[str]) -> dict[str, str]:
    """Return the three private artifacts; never write files or fetch rules."""
    validated = _settings(settings)
    domains, networks = normalize_domains(domains), normalize_networks(networks)
    return {"index.html": _landing(validated), "clash.yaml": _clash(validated, domains, networks),
            "shadowrocket.conf": _shadowrocket(validated, domains, networks)}
