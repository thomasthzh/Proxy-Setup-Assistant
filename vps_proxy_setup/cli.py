"""Interactive launcher. OpenSSH owns password and host-key prompts."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from . import __version__


class SetupError(Exception):
    """An actionable failure without credentials in its message."""


def hostname(value: str, *, public: bool = False) -> str:
    value = str(value).strip().rstrip(".")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", value):
            raise SetupError("IPv4 地址格式无效。") from None
        try:
            value = value.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise SetupError("地址必须是 IPv4 或有效域名。") from None
        if (len(value) > 253 or not re.fullmatch(r"[a-z0-9.-]+", value)
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
                       for p in value.split("."))):
            raise SetupError("地址格式无效，不能包含端口、URL 或命令。")
        if public and "." not in value:
            raise SetupError("代理公网地址请填写公网 IPv4 或完整域名。")
        return value
    if address.version != 4:
        raise SetupError("此版本的入口仅支持 IPv4 或指向 IPv4 的域名。")
    if public and not address.is_global:
        raise SetupError("代理入口必须是公网地址；Tailscale 地址可以用作 SSH 地址。")
    return str(address)


def port(value, *, service=False) -> int:
    if isinstance(value, bool) or not str(value).isdigit():
        raise SetupError("端口必须是整数。")
    value = int(value)
    if not (1024 if service else 1) <= value <= 65535:
        raise SetupError("代理/订阅端口需为 1024–65535；SSH 端口需为 1–65535。")
    return value


def validate_document(document: dict) -> dict:
    if not isinstance(document, dict) or set(document) != {"ssh", "server"}:
        raise SetupError("配置顶层必须且只能包含 ssh 和 server。")
    ssh = dict(document["ssh"])
    server = dict(document["server"])
    if set(ssh) - {"host", "port", "user", "alias", "identity_file"}:
        raise SetupError("ssh 中包含未知字段；请勿填写密码或私钥内容。")
    ssh["host"] = hostname(ssh.get("host", ""))
    ssh["port"] = port(ssh.get("port", 22))
    ssh["user"] = ssh.get("user", "root")
    if ssh["user"] != "root":
        raise SetupError("首版需要 root SSH 账号；不会自动修改服务器 sudo 或 SSH 登录策略。")
    ssh["alias"] = ssh.get("alias", "MyVPS")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", ssh["alias"]):
        raise SetupError("SSH 别名需以字母开头，仅含字母、数字、下划线或连字符，最长 32 位。")
    identity = ssh.get("identity_file") or str(Path.home() / ".ssh" / "vps-proxy-setup" / (ssh["alias"] + "_ed25519"))
    if any(c in str(identity) for c in '\r\n\x00"%'):
        raise SetupError("密钥路径不能包含换行、引号或 %。")
    # absolute() preserves symlinks so ensure_key can reject them explicitly.
    ssh["identity_file"] = str(Path(identity).expanduser().absolute())
    allowed = {"schema_version", "label", "address", "tls_name", "email", "acme_accept_terms", "ports", "tailscale", "tune"}
    if set(server) - allowed:
        raise SetupError("server 中包含未知字段；所有代理凭据由服务器自动生成。")
    if server.get("schema_version", 1) != 1:
        raise SetupError("不支持的配置版本。")
    server["schema_version"] = 1
    server["address"] = hostname(server.get("address", ""), public=True)
    server["tls_name"] = hostname(server.get("tls_name", server["address"]), public=True)
    if server["tls_name"] != server["address"]:
        raise SetupError("此版本的 tls_name 必须与 address 相同。")
    server["label"] = server.get("label", ssh["alias"])
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", server["label"]):
        raise SetupError("节点名称格式与 SSH 别名相同。")
    server["email"] = server.get("email", "")
    if server["email"] and not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", server["email"]):
        raise SetupError("证书联系邮箱格式无效。")
    values = server.get("ports", {})
    if not isinstance(values, dict) or set(values) - {"https", "hy2", "trojan"}:
        raise SetupError("ports 只能包含 https、hy2、trojan。")
    server["ports"] = {name: port(values.get(name, default), service=True)
                       for name, default in (("https", 8443), ("hy2", 8443), ("trojan", 9443))}
    if server["ports"]["https"] == server["ports"]["trojan"]:
        raise SetupError("订阅 HTTPS 和 Trojan 不能使用同一个 TCP 端口。")
    if 18081 in server["ports"].values() or ssh["port"] in (server["ports"]["https"], server["ports"]["trojan"], 80):
        raise SetupError("代理端口不能占用内部服务端口 18081；TCP 服务不能与 SSH/ACME 端口冲突。")
    for name, default in (("tailscale", False), ("tune", True), ("acme_accept_terms", False)):
        server[name] = server.get(name, default)
        if type(server[name]) is not bool:
            raise SetupError(name + " 必须为 true 或 false。")
    if not server["acme_accept_terms"]:
        raise SetupError("申请 HTTPS 证书需要接受 Let's Encrypt 服务条款；请在向导中确认或将 acme_accept_terms 设为 true。")
    return {"ssh": ssh, "server": server}


def ask(text: str, default="") -> str:
    suffix = f" [{default}]" if default != "" else ""
    return input(text + suffix + ": ").strip() or str(default)


def yes(text: str, default=False) -> bool:
    while True:
        answer = ask(text + (" (Y/n)" if default else " (y/N)"), "y" if default else "n").lower()
        if answer in ("y", "yes", "是"):
            return True
        if answer in ("n", "no", "否"):
            return False
        print("请输入 y 或 n。")


def questionnaire() -> dict:
    print("\nVPS-Proxy-SetUP — SSH + HTTPS 代理安装向导")
    print("适用于全新 Debian 12/13、Ubuntu 22.04/24.04，需 root 和 systemd。")
    print("请在商家防火墙开放 TCP 80、8443、9443 和 UDP 8443（可自定义代理端口）。")
    print("密码只由 OpenSSH 直接询问，不写入配置；首次连接须核对主机指纹。\n")
    host = ask("SSH 地址（可填公网 IP、域名或 Tailscale IP）")
    ssh_port = ask("SSH 端口", 22)
    alias = ask("本地 SSH 别名，以后可执行 ssh 别名", "MyVPS")
    address = ask("代理公网 IPv4 或指向本机的域名", host)
    print("域名必须直接指向 VPS（关闭 CDN 代理）；申请和续期都要求公网 TCP 80 可达。")
    identity = ask("已有 SSH 私钥路径（留空会创建专用 Ed25519 密钥）")
    https = ask("订阅页面 TCP 端口", 8443)
    hy2 = ask("Hysteria 2 UDP 端口", 8443)
    trojan = ask("Trojan 备用 TCP 端口", 9443)
    email = ask("Let's Encrypt 联系邮箱（可留空）")
    print("证书服务条款：https://letsencrypt.org/repository/")
    accepted = yes("是否接受 Let's Encrypt 服务条款并申请证书")
    tailscale = yes("是否安装 Tailscale（最后仍需在浏览器登录授权）")
    return validate_document({"ssh": {"host": host, "port": ssh_port, "user": "root", "alias": alias,
                                      "identity_file": identity},
                              "server": {"address": address, "label": alias, "email": email,
                                         "ports": {"https": https, "hy2": hy2, "trojan": trojan},
                                         "acme_accept_terms": accepted, "tailscale": tailscale, "tune": True}})


def run(args: list[str], *, capture=False, timeout=None, check=True):
    # Never shell=True: host names, file paths and arguments stay separate.
    result = subprocess.run(args, text=True, encoding="utf-8", errors="replace",
                            capture_output=capture, timeout=timeout,
                            **({"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" and capture else {}))
    if check and result.returncode:
        # Do not echo the command: future commands may carry private material.
        raise SetupError(f"{Path(args[0]).name} 执行失败（退出码 {result.returncode}）。请查看上方提示后重试。")
    return result


def protect(path: Path, *, directory=False):
    if os.name == "nt":
        who = run(["whoami"], capture=True).stdout.strip()
        permissions = "(OI)(CI)F" if directory else "F"
        run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{who}:{permissions}",
             f"*S-1-5-18:{permissions}"], capture=True)
    else:
        path.chmod(0o700 if directory else 0o600)


def state_root() -> Path:
    if os.name == "nt":
        parent = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        parent = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return parent / "vps-proxy-setup"


def private_write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=path.parent,
                                     prefix=".vps-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            protect(temporary)
            stream.write(text)
        except BaseException:
            stream.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def ssh_block(ssh: dict, *, managed=False) -> str:
    key = Path(ssh["identity_file"]).as_posix()
    block = (f'Host {ssh["alias"]}\n'
             f'    HostName {ssh["host"]}\n'
             f'    User {ssh["user"]}\n'
             f'    Port {ssh["port"]}\n'
             f'    IdentityFile "{key}"\n'
             '    IdentitiesOnly yes\n'
             '    StrictHostKeyChecking ask\n'
             '    ServerAliveInterval 30\n'
             '    ServerAliveCountMax 3\n'
             '    ConnectTimeout 15\n')
    if managed:
        return (f'# BEGIN VPS-PROXY-SETUP {ssh["alias"]}\n' + block
                + f'# END VPS-PROXY-SETUP {ssh["alias"]}\nHost *\n')
    return block


def merge_ssh_config(original: str, ssh: dict) -> str:
    alias = ssh["alias"]
    pattern = re.compile(r"(?m)^# BEGIN VPS-PROXY-SETUP " + re.escape(alias)
                         + r"\r?\n.*?^# END VPS-PROXY-SETUP " + re.escape(alias)
                         + r"\r?\n(?:Host \*\r?\n)?", re.DOTALL)
    match = pattern.search(original)
    remaining = pattern.sub("", original)
    if (re.search(r"(?m)^# BEGIN VPS-PROXY-SETUP " + re.escape(alias) + r"\r?$", original) and not match):
        raise SetupError("现有 SSH 管理块不完整，请先修复或改用新别名。")
    for line in remaining.splitlines():
        parts = re.split(r"[\s=]+", line.strip())
        if parts and parts[0].lower() == "host" and alias.lower() in [p.lower() for p in parts[1:]]:
            raise SetupError(f"SSH 别名 {alias} 已存在且不由本工具管理。请换一个别名。")
    # Prepend so global Host * defaults cannot override this explicit host.
    # Host * at the end restores scope for any global directives in original.
    return ssh_block(ssh, managed=True) + "\n" + remaining.lstrip("\r\n")


def configure_alias(ssh: dict, state: Path):
    config = Path.home() / ".ssh" / "config"
    if config.is_symlink():
        raise SetupError("~/.ssh/config 是符号链接；为保护原配置，请手动合并生成的 connection.conf。")
    original = config.read_text(encoding="utf-8-sig") if config.exists() else ""
    updated = merge_ssh_config(original, ssh)
    if original == updated:
        return
    if original:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        private_write(state / ("ssh-config-backup-" + stamp + ".txt"), original)
    private_write(config, updated)


class SSH:
    def __init__(self, ssh: dict, connection_file: Path):
        self.settings = ssh
        self.connection_file = connection_file

    def command(self, command: str, *, key_only=True, capture=False, check=True):
        args = ["ssh", "-F", str(self.connection_file)]
        if key_only:
            args += ["-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                     "-o", "KbdInteractiveAuthentication=no"]
        args += [self.settings["alias"], command]
        return run(args, capture=capture, check=check)

    def upload(self, source: Path, target: str):
        # The remote path is generated from a fixed prefix and random hex, not user input.
        run(["scp", "-F", str(self.connection_file), "-o", "PreferredAuthentications=publickey",
             "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
             str(source), self.settings["alias"] + ":" + target])


def ensure_key(ssh: dict):
    key = Path(ssh["identity_file"])
    parent_existed = key.parent.exists()
    key.parent.mkdir(parents=True, exist_ok=True)
    if key.is_symlink():
        raise SetupError("请提供真实密钥路径，不要使用符号链接。")
    if not key.exists():
        managed_parent = Path.home() / ".ssh" / "vps-proxy-setup"
        if not parent_existed or key.parent == managed_parent:
            protect(key.parent, directory=True)
        print("创建本地专用 SSH 密钥。ssh-keygen 会询问保护口令；留空可免口令连接。")
        run(["ssh-keygen", "-t", "ed25519", "-a", "64", "-f", str(key),
             "-C", "vps-proxy-setup:" + ssh["alias"]])
    protect(key)
    pub = key.with_name(key.name + ".pub")
    if pub.is_symlink():
        raise SetupError("公钥文件是符号链接，请提供真实文件。")
    if not pub.exists():
        result = run(["ssh-keygen", "-y", "-f", str(key)], capture=True)
        private_write(pub, result.stdout.strip() + "\n")
    content = pub.read_text(encoding="utf-8").strip()
    parts = content.split()
    if len(parts) < 2 or parts[0] not in ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"):
        raise SetupError("无法识别 SSH 公钥；请检查 .pub 文件。")
    try:
        base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise SetupError("SSH 公钥格式错误。") from None
    # Drop arbitrary comments, only the actual public key is sent.
    return " ".join(parts[:2])


def authorize_key(session: SSH, public_key: str):
    script = ("set -eu\n"
              '[ "$(id -u)" = 0 ] || { echo "Root SSH login is required" >&2; exit 1; }\n'
              'umask 077\nmkdir -p "$HOME/.ssh"\nchmod 700 "$HOME/.ssh"\n'
              'touch "$HOME/.ssh/authorized_keys"\nchmod 600 "$HOME/.ssh/authorized_keys"\n'
              + "key=" + shlex.quote(public_key) + "\n"
              + 'grep -qxF "$key" "$HOME/.ssh/authorized_keys" || printf "\\n%s\\n" "$key" >> "$HOME/.ssh/authorized_keys"\n')
    print("现在由 OpenSSH 连接服务器。首次请核对指纹；如提示 password，请输入 VPS 密码。")
    session.command("sh -c " + shlex.quote(script), key_only=False)
    print("验证刚配置的 SSH 密钥（服务器密码认证已从本次验证中排除）…")
    session.command("test \"$(id -u)\" = 0 && printf 'SSH_KEY_OK\\n'")


def build_payload(target: Path, server_config: dict, source: Path | None = None):
    source = source or Path(__file__).parent / "server"
    files = sorted(p for p in source.rglob("*") if p.is_file() and (p.suffix == ".py" or p == source / "assets.json")
                   and "__pycache__" not in p.parts)
    if not (source / "installer.py").exists():
        raise SetupError("发行包缺少 server/installer.py，请重新下载完整源码。")
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in files:
            if file.is_symlink() or source.resolve() not in file.resolve().parents:
                raise SetupError("发行包包含符号链接或越界文件，拒绝上传。")
            archive.write(file, "server/" + file.relative_to(source).as_posix())
        archive.writestr("input.json", json.dumps(server_config, ensure_ascii=False, indent=2))
    protect(target)


def deploy(session: SSH, config: dict, state: Path) -> dict:
    suffix = secrets.token_hex(12)
    remote = "/root/.cache/vps-proxy-setup/run-" + suffix
    session.command("umask 077; mkdir -p " + shlex.quote(remote))
    try:
        with tempfile.TemporaryDirectory(prefix="payload-", dir=state) as directory:
            payload = Path(directory) / "payload.zip"
            build_payload(payload, config)
            session.upload(payload, remote + "/payload.zip")
        script = """set -eu
. /etc/os-release
case "$ID:$VERSION_ID" in debian:12|debian:13|ubuntu:22.04|ubuntu:24.04) ;; *) echo 'Unsupported operating system' >&2; exit 1;; esac
if ! command -v python3 >/dev/null 2>&1; then
    apt-get update -o Acquire::Retries=2
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3
fi
cd REMOTE
python3 -m zipfile -e payload.zip .
python3 -m server.installer --config input.json
""".replace("REMOTE", shlex.quote(remote))
        session.command("sh -c " + shlex.quote(script))
        raw = session.command("cat /etc/vps-proxy-setup/result.json", capture=True).stdout
        try:
            result = json.loads(raw)
        except (ValueError, TypeError):
            raise SetupError("服务器未返回有效结果；请查看服务器服务状态后重试。") from None
        if (not isinstance(result, dict) or result.get("status") != "ready"
                or not isinstance(result.get("base_url"), str)):
            raise SetupError("服务器未确认部署就绪，或缺少 HTTPS 导入地址。")
        private_write(state / "result.json", json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        return result
    finally:
        # Exact path generated above; no recursive delete of user-provided paths.
        session.command("rm -rf -- " + shlex.quote(remote), check=False)


def verify_entry(result: dict) -> bool:
    url = result["base_url"]
    if not url.startswith("https://"):
        raise SetupError("结果不是 HTTPS 地址，拒绝访问。")
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request(url, headers={"User-Agent": "VPS-Proxy-SetUP/" + __version__})
        with opener.open(request, timeout=20) as response:
            page = response.read(2_000_000)
        return b"clash://install-config" in page and b"shadowrocket://config/add/" in page
    except Exception:
        # URL is a bearer credential: never print exception/traceback containing it.
        return False


def print_plan(document: dict):
    ssh, server = document["ssh"], document["server"]
    print(f"SSH: {ssh['user']}@{ssh['host']}:{ssh['port']} -> ssh {ssh['alias']}")
    print("本地密钥: " + ssh["identity_file"])
    print("公网入口: " + server["address"])
    print("端口: TCP 80 / HTTPS {https} / Trojan {trojan}; UDP HY2 {hy2}".format(**server["ports"]))
    print("部署: Hysteria 2 + Trojan + HTTPS 导入页面 + 国内直连规则 + 自动证书续期")
    print("Tailscale: " + ("安装，最后需浏览器授权" if server["tailscale"] else "不安装"))


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="引导配置本地 SSH，并部署 VPS 私人代理与一键导入页面。")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path, help="读取本地 JSON 配置（仅非秘密参数，密码仍由 SSH 询问）")
    parser.add_argument("--plan", "--dry-run", action="store_true", help="只显示计划，不更改本地或服务器")
    parser.add_argument("--ssh-only", action="store_true", help="只配置 SSH，不部署代理")
    args = parser.parse_args(argv)
    try:
        if args.config:
            document = validate_document(json.loads(args.config.read_text(encoding="utf-8-sig")))
        else:
            document = questionnaire()
        print_plan(document)
        if args.plan:
            print("计划检查通过；未生成密钥、连接服务器或写入配置。")
            return 0
        for executable in ("ssh", "ssh-keygen", "scp"):
            if not shutil.which(executable):
                raise SetupError(f"缺少 {executable}。请先安装系统 OpenSSH 客户端，再重试。")
        if not args.config and not yes("按上述信息开始配置", True):
            print("已取消，未修改配置。")
            return 0
        ssh = document["ssh"]
        state = state_root() / ssh["alias"]
        state.mkdir(parents=True, exist_ok=True)
        protect(state, directory=True)
        # Detect alias collisions before connecting or generating credentials.
        existing = Path.home() / ".ssh" / "config"
        if existing.is_symlink():
            raise SetupError("~/.ssh/config 是符号链接，请先改用普通文件或手动配置 SSH。")
        merge_ssh_config(existing.read_text(encoding="utf-8-sig") if existing.exists() else "", ssh)
        public_key = ensure_key(ssh)
        connection_file = state / "connection.conf"
        private_write(connection_file, ssh_block(ssh))
        session = SSH(ssh, connection_file)
        authorize_key(session, public_key)
        configure_alias(ssh, state)
        private_write(state / "input.json", json.dumps(document, ensure_ascii=False, indent=2) + "\n")
        print("本地 SSH 已就绪：ssh " + ssh["alias"])
        if args.ssh_only:
            return 0
        result = deploy(session, document["server"], state)
        verified = verify_entry(result)
        print("\n服务器已完成部署。" + ("当前网络 HTTPS 导入页面验证通过。" if verified else
                                          "当前网络尚未验证入口可达；请检查云防火墙、端口映射和本地网络。"))
        print("私人导入入口（请勿公开）：" + result["base_url"])
        print("Clash Verge：导入完整配置 → 启用 → 规则模式。")
        print("Shadowrocket：导入并启用配置 → 全局路由选择“配置”。")
        if result.get("tailscale_auth_url"):
            print("Tailscale 仍需浏览器登录授权：" + result["tailscale_auth_url"])
        print("本地结果保存在：" + str(state / "result.json"))
        print("规则通过订阅更新下发；请在客户端启用每日配置更新。")
        return 0 if verified else 2
    except (SetupError, OSError, ValueError, KeyError, TypeError) as error:
        if isinstance(error, SetupError):
            print("错误：" + str(error), file=sys.stderr)
        else:
            print("错误：无法读取配置或执行操作（" + type(error).__name__ + "）。请核对配置和运行环境。", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n已中断。已有 SSH 密钥和服务器凭据保留，可使用相同配置重试。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
