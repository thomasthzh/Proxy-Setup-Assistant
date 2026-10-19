import copy
import json
import io
import os
import http.server
import socket
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import yaml

from vps_proxy_setup.cli import SetupError
from vps_proxy_setup.desktop import profiles as p


def sample():
    return {"proxies": [{"name": "测试节点", "type": "trojan", "server": "proxy.example.com",
                         "port": 443, "password": "TEST_ONLY_PRIVATE_PASSWORD", "sni": "proxy.example.com"}]}


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "Clash"
        self.root.mkdir()
        (self.root / "profiles").mkdir()
        (self.root / "verge.yaml").write_text("enable_tun_mode: false\n", encoding="utf-8")
        (self.root / "clash.yaml").write_text("allow-lan: false\nmode: rule\n", encoding="utf-8")
        self.existing = {"uid": "Lold", "type": "local", "file": "old.yaml", "name": "Existing"}
        self.index = {"current": "Lold", "items": [self.existing]}
        (self.root / "profiles.yaml").write_text(yaml.safe_dump(self.index), encoding="utf-8")
        (self.root / "profiles" / "old.yaml").write_text("# Original bytes\n", encoding="utf-8")
        self.input = Path(self.temp.name) / "subscription.yaml"
        self.input.write_text(yaml.safe_dump(sample(), allow_unicode=True), encoding="utf-8")
        self.subscription = p.load_subscription(self.input)
        self.real_running = p.clash_running
        self.running = patch.object(p, "clash_running", return_value=False)
        self.running.start()
        self.addCleanup(self.running.stop)

    def plan(self, **kw):
        return p.preview_import(self.subscription, self.root, **kw)

    def test_preview_is_read_only_and_redacted(self):
        before = sorted(str(x.relative_to(self.root)) for x in self.root.rglob("*"))
        plan = self.plan()
        self.assertEqual(before, sorted(str(x.relative_to(self.root)) for x in self.root.rglob("*")))
        self.assertEqual(plan.existing_profile_count, 1)
        self.assertEqual(plan.subscription.proxy_count, 1)
        self.assertIn("规则依赖", plan.summary)
        self.assertNotIn("TEST_ONLY_PRIVATE_PASSWORD", repr(plan))
        self.assertNotIn(str(self.input), plan.summary)

    def test_safe_parse_limits_and_errors_hide_secrets(self):
        for raw in (b"a: &x [1]\nb: *x", b"!!python/object/apply:os.system ['echo SECRET']",
                    b"proxies: []\nproxies: []", b"a: [" * 50, b"secret-URI-only"):
            with self.subTest(raw=raw), self.assertRaises(SetupError) as caught:
                p._yaml(raw)
            self.assertNotIn("SECRET", str(caught.exception))
        with self.assertRaises(SetupError):
            p._yaml(b"x" * (p.MAX_BYTES + 1))

    def test_reject_unsafe_or_unsupported_nodes(self):
        for change in ({"skip-cert-verify": True}, {"plugin": "evil"}, {"network": "h2"},
                       {"port": True}, {"server": "bad/path"}, {"name": "DIRECT"}, {"password": {}},
                       {"type": "direct"}):
            doc = sample()
            doc["proxies"][0].update(change)
            with self.subTest(change=change), self.assertRaises(SetupError):
                p._proxies(doc)
        with self.assertRaises(SetupError):
            p._proxies({"proxy-providers": {"x": {}}, **sample()})

    def test_https_only_and_redaction(self):
        for url in ("http://example.com/SECRET", "https://user:SECRET@example.com", "https://example.com/#SECRET",
                    "https://example.com:bad/SECRET", "https://example.com/\nSECRET"):
            with self.subTest(url=url), self.assertRaises(SetupError) as caught:
                p.load_subscription(url)
            self.assertNotIn("SECRET", str(caught.exception))
        with patch.object(p, "_fetch", return_value=json.dumps(sample()).encode()):
            subscription = p.load_subscription("https://example.com/private/SECRET?token=SECRET")
        self.assertNotIn("SECRET", repr(subscription))
        self.assertEqual(subscription.source_kind, "remote")
        handler = p._HTTPSRedirect()
        with self.assertRaises(SetupError):
            handler.redirect_request(None, None, 302, "", {}, "http://example.com/SECRET")

    def test_remote_preserves_url_and_update_script(self):
        with patch.object(p, "_fetch", return_value=json.dumps(sample()).encode()):
            sub = p.load_subscription("https://example.com/SECRET")
        with self.assertRaises(SetupError):
            p.preview_import(sub, self.root)
        plan = p.preview_import(sub, self.root, mihomo_version="1.19.32")
        result = p.apply_import(plan, consent=True)
        index = yaml.safe_load((self.root / "profiles.yaml").read_text(encoding="utf-8"))
        item = next(i for i in index["items"] if i["uid"] == result.profile_uid)
        self.assertEqual(item["url"], sub.source)
        self.assertFalse(item["option"]["allow_auto_update"])
        self.assertEqual(item["type"], "local")
        self.assertFalse(item["option"]["danger_accept_invalid_certs"])
        self.assertEqual(index["current"], "Lold")
        self.assertIn(self.existing, index["items"])
        self.assertEqual((self.root / "profiles" / "old.yaml").read_text(), "# Original bytes\n")
        self.assertTrue((result.backup_dir / "profiles.yaml").is_file())
        doc = json.loads((self.root / "profiles" / item["file"]).read_text(encoding="utf-8"))
        provider = doc["proxy-providers"]["vps-upstream"]
        self.assertEqual(provider["url"], sub.source)
        self.assertEqual(provider["interval"], 86400)
        self.assertEqual(provider["size-limit"], p.MAX_BYTES)
        self.assertFalse(provider["override"]["skip-cert-verify"])
        self.assertIn("with_entries", provider["override"]["override-expr"][0])
        self.assertEqual(doc["proxies"], [])
        self.assertEqual(doc["proxy-groups"][1]["use"], ["vps-upstream"])
        self.assertTrue((self.root / ".vps-proxy-setup-providers").is_dir())

    def test_activation_requires_apply_and_explicit_option(self):
        plan = self.plan()
        with self.assertRaises(SetupError):
            p.apply_import(plan)
        result = p.apply_import(plan, consent=True, activate=True)
        index = yaml.safe_load((self.root / "profiles.yaml").read_text(encoding="utf-8"))
        self.assertEqual(index["current"], result.profile_uid)

    def test_conflicts_and_versions(self):
        plan = self.plan(profile_name="Existing")
        self.assertTrue(plan.conflicts)
        with self.assertRaises(SetupError):
            p.apply_import(plan, consent=True)
        for version in ("", "2.6.0", "2.5.7"):
            with self.assertRaises(SetupError):
                self.plan(clash_version=version)
        (self.root / "clash.yaml").write_text("allow-lan: true\nexternal-controller: 0.0.0.0:9090\nmode: global\n", encoding="utf-8")
        self.assertEqual(len(self.plan().conflicts), 3)

    def test_live_process_or_changed_state_never_written(self):
        plan = self.plan()
        with patch.object(p, "clash_running", return_value=True), self.assertRaises(SetupError):
            p.apply_import(plan, consent=True)
        (self.root / "verge.yaml").write_text("# changed\n", encoding="utf-8")
        with self.assertRaises(SetupError):
            p.apply_import(plan, consent=True)
        self.assertEqual(len(list((self.root / "profiles").iterdir())), 1)

    def test_precommit_failure_rolls_back_additions(self):
        plan = self.plan()
        original = (self.root / "profiles.yaml").read_bytes()
        write = p.private_write

        def fail_index(path, text):
            if path == self.root / "profiles.yaml":
                raise OSError("private failure should not surface")
            return write(path, text)

        with patch.object(p, "private_write", side_effect=fail_index), self.assertRaises(SetupError) as caught:
            p.apply_import(plan, consent=True)
        self.assertNotIn("private failure", str(caught.exception))
        self.assertEqual((self.root / "profiles.yaml").read_bytes(), original)
        self.assertEqual(len(list((self.root / "profiles").iterdir())), 1)
        self.assertFalse((self.root / ".vps-proxy-setup.lock").exists())

    def test_existing_lock_is_not_deleted(self):
        (self.root / ".vps-proxy-setup.lock").write_text("other operation")
        with self.assertRaises(SetupError):
            p.apply_import(self.plan(), consent=True)
        self.assertEqual((self.root / ".vps-proxy-setup.lock").read_text(), "other operation")

    def test_rollback_restores_exact_original_and_refuses_later_edits(self):
        original = b"\xef\xbb\xbf# keep this comment\n" + (self.root / "profiles.yaml").read_bytes()
        (self.root / "profiles.yaml").write_bytes(original)
        result = p.apply_import(self.plan(), consent=True, activate=True)
        p.rollback_import(result.backup_dir, consent=True)
        self.assertEqual((self.root / "profiles.yaml").read_bytes(), original)
        self.assertEqual(len(list((self.root / "profiles").iterdir())), 1)
        result = p.apply_import(self.plan(), consent=True)
        later = (self.root / "profiles.yaml").read_bytes() + b"\n# user edit\n"
        (self.root / "profiles.yaml").write_bytes(later)
        with self.assertRaises(SetupError):
            p.rollback_import(result.backup_dir, consent=True)
        self.assertEqual((self.root / "profiles.yaml").read_bytes(), later)

    def test_fetch_is_bounded_and_network_errors_do_not_leak_url(self):
        def response(payload, encoding="identity"):
            item = MagicMock()
            item.__enter__.return_value = item
            item.headers = {"Content-Encoding": encoding}
            item.geturl.return_value = "https://example.com/SECRET"
            item.read1.side_effect = io.BytesIO(payload).read1
            return item

        opener = MagicMock()
        with patch.object(p.urllib.request, "build_opener", return_value=opener):
            opener.open.return_value = response(b"good")
            self.assertEqual(p._fetch("https://example.com/SECRET"), b"good")
            self.assertEqual(opener.open.call_args.kwargs["timeout"], 15)
            opener.open.return_value = response(b"x" * (p.MAX_BYTES + 1))
            with self.assertRaises(SetupError):
                p._fetch("https://example.com/SECRET")
            opener.open.side_effect = RuntimeError("https://example.com/SECRET")
            with self.assertRaises(SetupError) as caught:
                p._fetch("https://example.com/SECRET")
            self.assertNotIn("SECRET", str(caught.exception))

    def test_process_enumeration_is_fail_closed(self):
        # Override setUp's test fixture, without touching actual machine state.
        with patch.object(p.subprocess, "run", side_effect=OSError("failed")), self.assertRaises(SetupError):
            self.real_running()

    @unittest.skipUnless(os.name == "nt", "Windows tasklist format")
    def test_service_helper_alone_does_not_block_import(self):
        for process, expected in (("clash-verge-service.exe", False), ("clash-verge.exe", True),
                                  ("verge-mihomo.exe", True), ("verge-mihomo-alpha.exe", True)):
            result = MagicMock(returncode=0, stdout=('"' + process + '","123","Console"').encode())
            with self.subTest(process=process), patch.object(p.subprocess, "run", return_value=result):
                self.assertEqual(bool(self.real_running()), expected)

    def test_global_dns_override_is_reported_as_conflict(self):
        (self.root / "verge.yaml").write_text("enable_dns_settings: true\n", encoding="utf-8")
        (self.root / "dns_config.yaml").write_text("dns:\n  listen: 0.0.0.0:53\n", encoding="utf-8")
        self.assertEqual(len(self.plan().conflicts), 2)

    def test_rules_are_ordered_and_local_only(self):
        doc = p.render_profile(self.subscription)
        self.assertFalse(doc["allow-lan"])
        self.assertEqual(doc["external-controller"], "")
        self.assertIn("IP-CIDR,100.64.0.0/10,DIRECT,no-resolve", doc["rules"])
        self.assertLess(doc["rules"].index("DOMAIN-SUFFIX,ts.net,DIRECT"), doc["rules"].index("RULE-SET,vps-cn-domain,DIRECT"))
        self.assertEqual(doc["rules"][-1], "MATCH,VPS-PROXY")
        self.assertNotIn("DIRECT", doc["proxy-groups"][0]["proxies"])
        for name, provider in doc["rule-providers"].items():
            self.assertEqual(provider["path"], "./ruleset/" + name + ".mrs")
            self.assertTrue(provider["url"].startswith("https://raw.githubusercontent.com/MetaCubeX/"))
            self.assertNotIn("TEST_ONLY_PRIVATE_PASSWORD", provider["url"])

    def test_export_is_standalone_and_refuses_overwrite(self):
        target = Path(self.temp.name) / "standalone.yaml"
        before = (self.root / "profiles.yaml").read_bytes()
        self.assertEqual(p.export_profile(self.subscription, target), target)
        doc = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(doc["rules"][-1], "MATCH,VPS-PROXY")
        self.assertNotIn("url", doc)
        self.assertEqual((self.root / "profiles.yaml").read_bytes(), before)
        with self.assertRaises(SetupError):
            p.export_profile(self.subscription, target)

    @unittest.skipUnless(os.environ.get("MIHOMO_BINARY") and shutil.which("node"),
                         "Set MIHOMO_BINARY to the pinned core to validate final extension output offline")
    def test_final_profile_with_real_mihomo_offline(self):
        # Exercise the exact JS extension against the initial complete import
        # AND against a changed upstream subscription. Replace only network
        # providers with small inline CN fixtures; no user files or networking.
        remote = p.Subscription("remote", "private test", 1, ("trojan",), (), "https://example.com/private", sample())
        for sub, document in ((self.subscription, p.render_profile(self.subscription)),
                              (self.subscription, sample()), (remote, p.render_profile(remote))):
            code = p.profile_script(sub) + "\nconsole.log(JSON.stringify(main(" + json.dumps(document) + ")));"
            node = subprocess.run([shutil.which("node"), "-e", code], capture_output=True,
                                  text=True, encoding="utf-8", check=True, timeout=10)
            config = json.loads(node.stdout)
            config["rule-providers"] = {
                "vps-cn-domain": {"type": "inline", "behavior": "domain", "payload": ["+.cn", "+.baidu.com"]},
                "vps-cn-ip": {"type": "inline", "behavior": "ipcidr", "payload": ["1.0.1.0/24"]}}
            if config.get("proxy-providers"):
                config["proxy-providers"]["vps-upstream"]["url"] = "http://127.0.0.1:9"
            workdir = Path(self.temp.name) / ("core-" + str(len(list(Path(self.temp.name).glob("core-*")))))
            workdir.mkdir()
            config_file = workdir / "config.yaml"
            config_file.write_text(json.dumps(config), encoding="utf-8")
            result = subprocess.run([os.environ["MIHOMO_BINARY"], "-t", "-d", str(workdir), "-f", str(config_file)],
                                    capture_output=True, text=True, encoding="utf-8", timeout=30)
            self.assertEqual(result.returncode, 0, "Mihomo rejected the offline final desktop profile fixture")

    @unittest.skipUnless(os.environ.get("MIHOMO_BINARY") and os.name != "nt",
                         "Native controller integration runs in Linux CI; this Windows host blocks Python-to-core loopback")
    def test_native_provider_updates_cannot_change_routing_or_load_local_fields(self):
        fixture = sample()
        node = fixture["proxies"][0]
        node.update({"name": "updated-provider", "server": "127.0.0.1", "skip-cert-verify": True,
                     "certificate": "/missing-private-certificate", "client-key": "/missing-private-key",
                     "plugin": "forbidden-plugin", "network": "ws",
                     "ws-opts": {"path": "/secure", "client-key": "/missing-private-key"}})
        fixture.update({"allow-lan": True, "external-controller": "0.0.0.0:9999", "rules": ["MATCH,DIRECT"],
                        "listeners": [{"name": "evil", "type": "http", "port": 9998}]})

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                data = json.dumps(fixture).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            controller_port = reservation.getsockname()[1]
        sub = p.Subscription("remote", "private test", 1, ("trojan",), (), "https://example.com/private", sample())
        config = p.render_profile(sub)
        provider = config["proxy-providers"]["vps-upstream"]
        # HTTP is restricted to this isolated local fixture. Production accepts
        # HTTPS inputs only, and these addresses are never written to user state.
        provider["url"] = "http://127.0.0.1:" + str(server.server_port)
        provider["health-check"]["enable"] = False
        provider["override"]["override-expr"] += [
            'select((has("certificate") == false) and (has("client-key") == false) and (has("plugin") == false))',
            'select((.["ws-opts"] | has("client-key")) == false)',
            'select(.["skip-cert-verify"] == false)']
        config["mixed-port"] = 0
        config["log-level"] = "info"
        config["external-controller"] = "127.0.0.1:" + str(controller_port)
        config["dns"]["enable"] = False
        config["rule-providers"] = {
            "vps-cn-domain": {"type": "inline", "behavior": "domain", "payload": ["+.cn"]},
            "vps-cn-ip": {"type": "inline", "behavior": "ipcidr", "payload": ["1.0.1.0/24"]}}
        workdir = Path(self.temp.name) / "native-provider-core"
        workdir.mkdir()
        config_file = workdir / "config.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")
        process = subprocess.Popen([os.environ["MIHOMO_BINARY"], "-d", str(workdir), "-f", str(config_file),
                                    "-ext-ctl", "127.0.0.1:" + str(controller_port)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        base = "http://127.0.0.1:" + str(controller_port)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def api(path, method="GET"):
            with opener.open(urllib.request.Request(base + path, method=method), timeout=2) as response:
                payload = response.read()
                return json.loads(payload) if payload else None

        try:
            deadline = time.monotonic() + 15
            state = None
            last_error = ""
            while time.monotonic() < deadline:
                try:
                    state = api("/providers/proxies/vps-upstream")
                    if any(n["name"] == "VPS | updated-provider" for n in state["proxies"]):
                        break
                except (OSError, ValueError) as error:
                    last_error = type(error).__name__ + ":" + str(getattr(error, "code", "")) + ":" + str(getattr(error, "reason", ""))
                if process.poll() is not None:
                    output = process.stdout.read().decode("utf-8", errors="replace").replace("TEST_ONLY_PRIVATE_PASSWORD", "[redacted]")
                    self.fail("isolated Mihomo core exited before provider validation: " + output[-1500:])
                time.sleep(0.1)
            if state is None:
                process.terminate()
                output = process.communicate(timeout=10)[0].decode("utf-8", errors="replace").replace("TEST_ONLY_PRIVATE_PASSWORD", "[redacted]")
                self.fail("isolated Mihomo controller unavailable (" + last_error + "): " + output[-2500:])
            self.assertIn("VPS | updated-provider", [n["name"] for n in state["proxies"]],
                          "native whitelist/TLS overrides did not accept the sanitized update")
            self.assertFalse(api("/configs")["allow-lan"])
            rules = api("/rules")["rules"]
            self.assertEqual(rules[-1]["proxy"], "VPS-PROXY")
            self.assertIn("DIRECT", [rule["proxy"] for rule in rules])
            fixture["proxies"][0]["type"] = "ssh"
            try:
                api("/providers/proxies/vps-upstream", "PUT")
            except urllib.error.HTTPError:
                pass  # Rejected updates must retain the last valid safe set.
            after = api("/providers/proxies/vps-upstream")
            self.assertEqual([n["name"] for n in after["proxies"]], [n["name"] for n in state["proxies"]])
            self.assertEqual(api("/rules")["rules"][-1]["proxy"], "VPS-PROXY")
        finally:
            process.terminate()
            process.wait(timeout=10)

    def test_common_transports_preserved_as_bounded_data(self):
        for network, key, options in (("ws", "ws-opts", {"path": "/secure", "headers": {"Host": "cdn.example.com"}, "max-early-data": 2048}),
                                       ("grpc", "grpc-opts", {"grpc-service-name": "proxy-service"}),
                                       ("http", "http-opts", {"method": "GET", "path": ["/"], "headers": {"Host": ["cdn.example.com"]}})):
            doc = sample()
            doc["proxies"][0].update({"network": network, key: options})
            self.assertEqual(p._proxies(doc)[0][key], options)
        for options in ({"headers": {"Host": "bad\r\nInjection"}}, {"path": {"local": "/secret"}},
                        {"plugin": "evil"}, {"max-early-data": 999999}):
            with self.assertRaises(SetupError):
                p._transport("ws-opts", options)

    @unittest.skipUnless(shutil.which("node"), "Node required to execute extension contract")
    def test_script_rebuilds_after_update_and_rejects_unsafe_update(self):
        def run(doc):
            code = p.profile_script() + "\nconsole.log(JSON.stringify(main(" + json.dumps(doc) + ")));"
            result = subprocess.run([shutil.which("node"), "-e", code], capture_output=True, text=True,
                                    encoding="utf-8", check=True, timeout=10)
            return json.loads(result.stdout)

        doc = sample()
        doc["proxies"][0]["name"] = 'new"\\name'
        doc["proxies"][0].update({"network": "ws", "ws-opts": {"path": "/secure", "headers": {"Host": "cdn.example.com"}}})
        doc.update({"allow-lan": True, "external-controller": "0.0.0.0:9090", "listeners": [{"port": 9}],
                    "rules": ["MATCH,DIRECT"], "proxy-providers": {"evil": {"path": "../../secret"}}})
        out = run(doc)
        self.assertEqual(out["proxies"][0]["name"], 'new"\\name')
        self.assertEqual(out["proxies"][0]["ws-opts"], doc["proxies"][0]["ws-opts"])
        self.assertFalse(out["allow-lan"])
        self.assertNotIn("listeners", out)
        self.assertNotIn("proxy-providers", out)
        self.assertEqual(out["rules"][-1], "MATCH,VPS-PROXY")
        doc["proxies"][0]["skip-cert-verify"] = True
        rejected = run(doc)
        self.assertEqual(rejected["rules"], ["MATCH,REJECT"])
        self.assertEqual(rejected["proxies"], [])


if __name__ == "__main__":
    unittest.main()
