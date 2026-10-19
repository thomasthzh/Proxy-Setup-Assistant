"""Offline subscription tests. Every test credential is generated at runtime."""

from copy import deepcopy
from contextlib import redirect_stderr
import http.client
from io import StringIO
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import unittest
from unittest.mock import patch

from vps_proxy_setup.server.subscription.http_server import SubscriptionServer, choose_artifact
from vps_proxy_setup.server.subscription.renderer import normalize_domains, normalize_networks, render
from vps_proxy_setup.server.subscription import refresh as refresher


DOMAINS = ["+.baidu.com", "+.qq.com", "exact.example.cn", "*.wild.example.cn"]
NETWORKS = ["1.0.1.0/24", "240e::/16"]


def settings(address="proxy.example.invalid"):
    token = secrets.token_urlsafe(32)
    return {
        "schema_version": 1, "label": "Test-VPS", "address": address, "tls_name": address,
        "ports": {"https": 8443, "hy2": 8443, "trojan": 9443}, "token": token,
        "base_url": f"https://{address}:8443/s/{token}", "hy2_port": 8443, "trojan_port": 9443,
        "hy2_obfs": secrets.token_urlsafe(24),
        "clients": {kind: {"hy2_auth": kind + ":" + secrets.token_urlsafe(24),
                           "trojan_password": secrets.token_urlsafe(24)}
                    for kind in ("windows", "iphone")},
    }


def fixture_download(url):
    values = DOMAINS if url == refresher.SOURCES["cn-domain"] else NETWORKS
    return ("\n".join(values) + "\n").encode()


def no_network(url):
    raise OSError("offline")


class RendererTests(unittest.TestCase):
    def setUp(self):
        self.settings = settings()
        self.artifacts = render(self.settings, DOMAINS, NETWORKS)
        self.clash = json.loads(self.artifacts["clash.yaml"])
        self.sr = self.artifacts["shadowrocket.conf"]

    def test_complete_profiles_use_two_ca_verified_nodes_and_ordered_fallback(self):
        self.assertEqual(set(self.artifacts), {"index.html", "clash.yaml", "shadowrocket.conf"})
        proxies = self.clash["proxies"]
        self.assertEqual([p["type"] for p in proxies], ["hysteria2", "trojan"])
        for proxy in proxies:
            self.assertIs(proxy["skip-cert-verify"], False)
            self.assertEqual(proxy["sni"], self.settings["tls_name"])
        automatic = self.clash["proxy-groups"][1]
        self.assertEqual(automatic["type"], "fallback")
        self.assertEqual(automatic["proxies"], [p["name"] for p in proxies])
        self.assertEqual(self.sr.count("allowInsecure=0"), 2)
        self.assertIn("skip-cert-verify=false", self.sr)
        self.assertIn("AUTO = fallback,Test-VPS-HY2,Test-VPS-Trojan,", self.sr)

    def test_domestic_dns_stays_direct_if_all_proxy_nodes_fail(self):
        dns = self.clash["dns"]
        self.assertTrue(all(value.endswith("#DIRECT") for value in dns["direct-nameserver"]))
        self.assertTrue(all(value.endswith("#DIRECT") for value in dns["proxy-server-nameserver"]))
        for key in ("+.cn", "rule-set:cn-domain", self.settings["address"]):
            self.assertTrue(all(value.endswith("#DIRECT") for value in dns["nameserver-policy"][key]))
        self.assertTrue(all(value.endswith("#PROXY") for value in dns["nameserver"]))
        self.assertNotIn("fallback", dns)
        self.assertIn(self.settings["address"], dns["fake-ip-filter"])
        self.assertIn("dns-direct-fallback-proxy = false", self.sr)
        self.assertIn("direct-dns-server = 223.5.5.5,119.29.29.29", self.sr)

    def test_rules_are_embedded_with_lan_tailscale_and_server_direct_first(self):
        self.assertEqual(self.clash["mode"], "rule")
        self.assertEqual(self.clash["rules"][-1], "MATCH,PROXY")
        for rule in ("IP-CIDR,100.64.0.0/10,DIRECT,no-resolve", "DOMAIN-SUFFIX,ts.net,DIRECT",
                     "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
                     f"DOMAIN,{self.settings['address']},DIRECT"):
            self.assertIn(rule, self.clash["rules"])
            self.assertIn(rule, self.sr)
        providers = self.clash["rule-providers"]
        self.assertEqual(providers["cn-domain"]["payload"], DOMAINS)
        self.assertEqual(providers["cn-ip"]["payload"], NETWORKS)
        self.assertTrue(all(p["type"] == "inline" and "url" not in p for p in providers.values()))
        self.assertIn("DOMAIN,exact.example.cn,DIRECT", self.sr)
        self.assertIn("DOMAIN-WILDCARD,*.wild.example.cn,DIRECT", self.sr)
        self.assertIn("IP-CIDR6,240e::/16,DIRECT", self.sr)

    def test_ipv4_server_bypass(self):
        config = json.loads(render(settings("203.0.113.10"), DOMAINS, NETWORKS)["clash.yaml"])
        self.assertIn("IP-CIDR,203.0.113.10/32,DIRECT,no-resolve", config["rules"])

    def test_landing_has_private_urls_but_no_transport_credentials(self):
        page = self.artifacts["index.html"]
        self.assertIn("clash://install-config?", page)
        self.assertIn("shadowrocket://config/add/", page)
        self.assertIn("规则", page)
        self.assertIn("全局路由", page)
        self.assertIn("data-copy", page)
        self.assertNotIn(self.settings["hy2_obfs"], page)
        for client in self.settings["clients"].values():
            for secret in client.values():
                self.assertNotIn(secret, page)
        self.assertNotIn('<script src=', page)
        self.assertNotIn('<link ', page)

    def test_domain_validation_keeps_patterns_and_rejects_injection(self):
        self.assertEqual(normalize_domains(["+.EXAMPLE.CN", ".example.cn", "a.example.cn", "*.example.cn"]),
                         ["+.example.cn", "a.example.cn", "*.example.cn"])
        self.assertEqual(normalize_domains(["+.中国"]), ["+.xn--fiqs8s"])
        for bad in ("a..cn", "-bad.cn", "bad-.cn", "*.a.*.cn", "+.", "example.cn,MATCH,DIRECT",
                    "example.cn\nMATCH,DIRECT", "https://example.cn", "example.cn/#x", " example.cn",
                    "a" * 64 + ".cn", "example.cn:443", "example.cn?x", "_bad.cn"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_domains([bad])
        with self.assertRaises(ValueError):
            normalize_domains("example.cn")

    def test_network_validation_rejects_default_routes_and_noncanonical_inputs(self):
        for bad in ("0.0.0.0/0", "::/0", "1.0.1.5/24", "1.0.1.0", "1.0.1.0/24,DIRECT"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_networks([bad])

    def test_rejects_mismatched_urls_ports_and_unsafe_credentials(self):
        candidates = []
        for field, value in (("label", "bad,profile"), ("tls_name", "other.example.invalid"),
                             ("base_url", self.settings["base_url"] + "?x=1"), ("hy2_port", True)):
            invalid = deepcopy(self.settings)
            invalid[field] = value
            candidates.append(invalid)
        invalid = deepcopy(self.settings)
        invalid["clients"]["iphone"]["trojan_password"] += ",allowInsecure=1"
        candidates.append(invalid)
        for invalid in candidates:
            with self.assertRaises(ValueError):
                render(invalid, DOMAINS, NETWORKS)


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "data"
        self.settings = settings()
        self.minimums = patch.dict(refresher.MIN_ENTRIES, {"cn-domain": 4, "cn-ip": 2})
        self.minimums.start()
        self.addCleanup(self.minimums.stop)

    def publish(self, **kwargs):
        return refresher.refresh(self.settings, self.root, group=None, fetcher=fixture_download, **kwargs)

    @unittest.skipUnless(os.name == "posix", "Atomic publication uses Linux symlinks")
    def test_validated_cache_keeps_working_offline_and_releases_are_bounded(self):
        report = self.publish()
        self.assertFalse(report["cached_rules"])
        original = (self.root / "current").resolve()
        for _ in range(4):
            report = refresher.refresh(self.settings, self.root, group=None, fetcher=no_network)
            self.assertTrue(report["cached_rules"])
        self.assertFalse(original.exists())
        self.assertEqual(len(list((self.root / "releases").iterdir())), 3)
        self.assertEqual(set(p.name for p in (self.root / "current").iterdir()),
                         {"index.html", "clash.yaml", "shadowrocket.conf"})

    def test_offline_without_cache_fails_closed(self):
        with self.assertRaises(refresher.RuleError):
            refresher.refresh(self.settings, self.root, group=None, fetcher=no_network)
        self.assertFalse((self.root / "current").exists())

    @unittest.skipUnless(os.name == "posix", "Atomic publication uses Linux symlinks")
    def test_invalid_response_cannot_replace_valid_cache(self):
        self.publish()
        cache = (self.root / "rules" / "cn-domain.json").read_bytes()
        report = refresher.refresh(self.settings, self.root, group=None, fetcher=lambda _: b"<html>error</html>")
        self.assertTrue(report["cached_rules"])
        self.assertEqual(cache, (self.root / "rules" / "cn-domain.json").read_bytes())

    @unittest.skipUnless(os.name == "posix", "Atomic publication uses Linux symlinks")
    def test_invalid_settings_cannot_replace_current(self):
        self.publish()
        original = (self.root / "current").resolve()
        broken = deepcopy(self.settings)
        del broken["clients"]
        with self.assertRaises(ValueError):
            refresher.refresh(broken, self.root, group=None, fetcher=fixture_download)
        self.assertEqual(original, (self.root / "current").resolve())

    @unittest.skipUnless(os.name == "posix", "Atomic publication uses Linux symlinks")
    def test_interrupted_publish_preserves_current(self):
        self.publish()
        original = (self.root / "current").resolve()
        replace = os.replace

        def fail_link(source, target):
            if Path(target).name == "current":
                raise OSError("simulated publication failure")
            return replace(source, target)

        with patch.object(refresher.os, "replace", side_effect=fail_link), self.assertRaises(OSError):
            self.publish()
        self.assertEqual(original, (self.root / "current").resolve())
        self.assertEqual(len(list((self.root / "releases").iterdir())), 1)
        self.assertFalse((self.root / ".current-new").is_symlink())

    @unittest.skipUnless(os.name == "posix", "Atomic publication uses Linux symlinks")
    def test_cached_mode_never_fetches_and_revalidates_disk(self):
        self.publish()
        refresher.refresh(self.settings, self.root, group=None, cached=True,
                          fetcher=lambda _: self.fail("Cached mode must not fetch"))
        (self.root / "rules" / "cn-domain.json").write_text('["unsafe.cn,MATCH,DIRECT"]')
        with self.assertRaises(refresher.RuleError):
            self.publish(cached=True)

    def test_rule_limits_and_sentinels_reject_truncation_and_duplicate_padding(self):
        for data in (b"+.baidu.com\n+.qq.com\n", b"+.baidu.com\n" * 20,
                     b"+.a.cn\n+.b.cn\n+.c.cn\n+.d.cn\n", b"\xff"):
            with self.assertRaises(refresher.RuleError):
                refresher.parse_rules("cn-domain", data)
        with self.assertRaises(refresher.RuleError):
            refresher.download("http://example.invalid/rules")

    def test_incomplete_http_response_uses_validated_cache(self):
        self.root.mkdir()
        cache = self.root / "rules"
        cache.mkdir()
        (cache / "cn-domain.json").write_text(json.dumps(DOMAINS))

        def incomplete(_):
            raise http.client.IncompleteRead(b"partial")

        domains, used_cache = refresher._load_rules(cache, "cn-domain", incomplete, False)
        self.assertEqual(domains, DOMAINS)
        self.assertTrue(used_cache)

    @unittest.skipUnless(os.name == "posix", "POSIX file modes")
    def test_publication_permissions(self):
        self.publish()
        for directory in (self.root, self.root / "releases", self.root / "rules", self.root / "current"):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o750)
        for artifact in (self.root / "current").iterdir():
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o640)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = settings()
        self.token = self.settings["token"]
        release = self.root / "releases" / "test-release"
        release.mkdir(parents=True)
        self.artifacts = render(self.settings, DOMAINS, NETWORKS)
        for name, content in self.artifacts.items():
            (release / name).write_bytes(content.encode("utf-8"))
        self.current = self.root / "current"
        if os.name == "posix":
            self.current.symlink_to(release, target_is_directory=True)
        else:
            # Windows runners may lack symlink permission. Only emulate resolving
            # the publication pointer; real file reads and HTTP requests still run.
            self.current.touch()
            resolve = Path.resolve

            def resolve_current(path, strict=False):
                if path == self.current and path.exists():
                    return release
                return resolve(path, strict=strict)

            resolver = patch.object(Path, "resolve", resolve_current)
            resolver.start()
            self.addCleanup(resolver.stop)
        self.server = SubscriptionServer(self.root, self.token, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, path=None, *, ua="Mozilla/5.0", method="GET", headers=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        try:
            connection.request(method, path or f"/s/{self.token}", headers={"User-Agent": ua, **(headers or {})})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_loopback_and_user_agent_negotiation(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        for agent, expected in (("Mozilla/5.0", "index.html"), ("Clash Verge", "clash.yaml"),
                                ("mihomo/1", "clash.yaml"), ("Shadowrocket/1", "shadowrocket.conf")):
            status, headers, body = self.request(ua=agent)
            self.assertEqual(status, 200)
            self.assertEqual(body.decode(), self.artifacts[expected])
            self.assertIn("no-store", headers["Cache-Control"])
            self.assertEqual(headers["Referrer-Policy"], "no-referrer")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(choose_artifact(f"/s/{self.token}/index.html", "Clash", self.token), "index.html")

    def test_invalid_tokens_and_paths_are_indistinguishable_empty_404(self):
        base = f"/s/{self.token}"
        paths = ["/", "/settings.json", "/s/short", "/s/" + secrets.token_urlsafe(32),
                 base + "/../settings.json", base + "/%2e%2e/settings.json", base + "%2Fclash.yaml",
                 base + "/clash.yaml/", base + "/clash.yaml?x=1", base + "/unknown", "/" + base,
                 base + "//clash.yaml", base + "?x=1", base + "/%63lash.yaml", base + "/clash.yaml#x"]
        for path in paths:
            with self.subTest(path=path):
                status, headers, body = self.request(path)
                self.assertEqual(status, 404)
                self.assertEqual(body, b"")

    def test_get_has_no_body_input_and_head_has_no_body_output(self):
        status, headers, body = self.request(headers={"Content-Length": "999999999"})
        self.assertEqual((status, body), (413, b""))
        status, headers, body = self.request(method="HEAD")
        self.assertEqual((status, body), (200, b""))
        self.assertEqual(int(headers["Content-Length"]), len(self.artifacts["index.html"].encode()))
        self.assertEqual(self.request(method="POST")[0], 404)

    def test_no_request_logging_and_missing_release_is_safe(self):
        output = StringIO()
        with redirect_stderr(output):
            self.request()
            self.request("/s/" + secrets.token_urlsafe(32))
            (self.root / "current").unlink()
            status, _, body = self.request()
        self.assertEqual((status, body), (503, b""))
        self.assertEqual(output.getvalue(), "")

    @unittest.skipUnless(os.name == "posix", "Filesystem symlink security test")
    def test_file_symlink_cannot_escape_release(self):
        artifact = self.root / "current" / "index.html"
        artifact.unlink()
        target = self.root / "outside.html"
        target.write_text("private")
        artifact.symlink_to(target)
        self.assertEqual(self.request()[0], 503)


if __name__ == "__main__":
    unittest.main()
