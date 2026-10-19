"""Exercise real pinned transports on ephemeral loopback ports in Linux CI.

Does not run the installer, change system services, request a public certificate,
or use any production host. The temporary test CA is trusted only by the child
Mihomo process. All credentials and test files disappear when the process ends.
"""
from __future__ import annotations

from contextlib import ExitStack
import gzip
import io
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vps_proxy_setup.server import installer
from vps_proxy_setup.server.subscription.renderer import render

MIHOMO_URL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-v1.19.32.gz"
MIHOMO_SHA256 = "8451100836c9eda194331c2babfad490b2faf30cebc1a04b0e76fd8ac2d35d10"


def command(args):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError(Path(args[0]).name + " check failed")
    return result


def free_port(udp=False):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port, process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("Test process exited before becoming ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("Test process did not become ready")


def spawn(stack, args, log_path, **kwargs):
    log = stack.enter_context(log_path.open("wb"))
    process = subprocess.Popen([str(arg) for arg in args], stdout=log, stderr=subprocess.STDOUT, **kwargs)

    def stop():
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    stack.callback(stop)
    return process


def diagnostics(root, settings):
    """Only temporary test logs; scrub every generated credential before output."""
    hidden = [settings["token"], settings["hy2_obfs"]]
    for client in settings["clients"].values():
        hidden.extend(client.values())
        hidden.append(client["hy2_auth"].split(":", 1)[1])
    for name in ("hy.log", "xray.log", "client.log"):
        path = root / name
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace")[-12000:]
            for value in hidden:
                content = content.replace(value, "[REDACTED]")
            print(name + " (temporary, redacted):\n" + content, flush=True)


def main():
    if sys.platform != "linux" or installer.architecture() != "amd64":
        raise SystemExit("This smoke check requires Linux amd64.")
    with tempfile.TemporaryDirectory(prefix="vps-proxy-smoke-") as temporary, ExitStack() as stack:
        root = Path(temporary)
        assets = installer.read_json(Path(installer.__file__).with_name("assets.json"))
        for product in ("hysteria", "xray"):
            item = assets[product]["amd64"]
            binary = installer.download(item["url"], sha256=item["sha256"])
            if product == "xray":
                with zipfile.ZipFile(io.BytesIO(binary)) as archive:
                    binary = archive.read("xray")
            (root / product).write_bytes(binary)
            (root / product).chmod(0o700)
        mihomo = root / "mihomo"
        mihomo.write_bytes(gzip.decompress(installer.download(MIHOMO_URL, sha256=MIHOMO_SHA256)))
        mihomo.chmod(0o700)
        print("Pinned upstream binary hashes verified.", flush=True)

        certificate, key = root / "test-ca.pem", root / "test-key.pem"
        command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-keyout", key, "-out", certificate, "-subj", "/CN=localhost",
                 "-addext", "subjectAltName=IP:127.0.0.1",
                 "-addext", "basicConstraints=critical,CA:TRUE"])
        key.chmod(0o600)
        ca_bundle = root / "ca-bundle.pem"
        ca_bundle.write_bytes(Path("/etc/ssl/certs/ca-certificates.crt").read_bytes() + b"\n" + certificate.read_bytes())
        document = json.loads((Path(__file__).resolve().parents[1] / "examples/setup.example.json").read_text())
        settings = installer.build_settings(document["server"])
        hy_port, trojan_port = free_port(udp=True), free_port()
        settings.update(address="127.0.0.1", tls_name="127.0.0.1", hy2_port=hy_port, trojan_port=trojan_port)
        settings["ports"].update(hy2=hy_port, trojan=trojan_port)
        settings["base_url"] = f'https://127.0.0.1:{settings["ports"]["https"]}/s/{settings["token"]}'
        transports = installer.transport_configs(settings)
        hy = transports["hysteria.json"]
        hy["listen"] = f"127.0.0.1:{hy_port}"
        hy["tls"].update(cert=str(certificate), key=str(key))
        xray = transports["xray.json"]
        inbound = xray["inbounds"][0]
        inbound["listen"] = "127.0.0.1"
        pair = inbound["streamSettings"]["tlsSettings"]["certificates"][0]
        pair.update(certificateFile=str(certificate), keyFile=str(key))
        for name, cfg in transports.items():
            (root / name).write_text(json.dumps(cfg), encoding="utf-8")
        command([root / "xray", "run", "-test", "-config", root / "xray.json"])
        hy_process = spawn(stack, [root / "hysteria", "server", "-c", root / "hysteria.json"], root / "hy.log")
        xray_process = spawn(stack, [root / "xray", "run", "-config", root / "xray.json"], root / "xray.log")
        wait_port(trojan_port, xray_process)
        time.sleep(0.2)
        if hy_process.poll() is not None:
            raise RuntimeError("Hysteria rejected the generated config")

        cfg = json.loads(render(settings, ["+.baidu.com", "+.qq.com"], ["1.0.1.0/24"])["clash.yaml"])
        mixed, control = free_port(), free_port()
        while control == mixed:
            control = free_port()
        cfg.update({"mixed-port": mixed, "external-controller": f"127.0.0.1:{control}",
                    "secret": secrets.token_urlsafe(32), "dns": {"enable": False},
                    "rules": ["MATCH,PROXY"], "profile": {"store-selected": False}})
        client_dir = root / "client"
        client_dir.mkdir()
        client_path = client_dir / "config.json"
        client_path.write_text(json.dumps(cfg), encoding="utf-8")
        command([mihomo, "-t", "-d", client_dir, "-f", client_path])
        child_env = {**os.environ, "SSL_CERT_FILE": str(ca_bundle)}
        client = spawn(stack, [mihomo, "-d", client_dir, "-f", client_path], root / "client.log", env=child_env)
        wait_port(control, client)
        wait_port(mixed, client)
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        proxied = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{mixed}",
                                                                        "https": f"http://127.0.0.1:{mixed}"}))
        for node in cfg["proxies"]:
            request = urllib.request.Request(f"http://127.0.0.1:{control}/proxies/PROXY",
                       data=json.dumps({"name": node["name"]}).encode(), method="PUT",
                       headers={"Authorization": "Bearer " + cfg["secret"], "Content-Type": "application/json"})
            with direct.open(request, timeout=5) as response:
                assert response.status == 204
            try:
                with proxied.open("https://example.com/", timeout=30) as response:
                    if response.status != 200 or b"Example Domain" not in response.read(100_000):
                        raise RuntimeError("Proxy egress did not return expected content")
            except Exception:
                diagnostics(root, settings)
                raise
            print(node["type"] + ": generated config, CA-verified handshake and HTTPS egress passed.", flush=True)
        print("Real transport smoke check passed; temporary processes and credentials cleaned up.", flush=True)


if __name__ == "__main__":
    main()
