"""Offline launcher regression tests. No real keys, SSH sessions or VPS writes."""

import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

from vps_proxy_setup import cli


def document():
    return {"ssh": {"host": "192.0.2.10", "alias": "ExampleVPS"},
            "server": {"address": "vps.example.com", "acme_accept_terms": True}}


class ValidationTests(unittest.TestCase):
    def test_defaults_and_input_not_mutated(self):
        original = document()
        before = copy.deepcopy(original)
        result = cli.validate_document(original)
        self.assertEqual(original, before)
        self.assertEqual(result["server"]["tls_name"], "vps.example.com")
        self.assertEqual(result["server"]["ports"], {"https": 8443, "hy2": 8443, "trojan": 9443})
        self.assertTrue(Path(result["ssh"]["identity_file"]).is_absolute())

    def test_hostname_rejects_injection_and_non_ipv4(self):
        for value in ("-oProxyCommand=id", "vps.example.com\nHost *", "example.com;id",
                      "example.com$(id)", "https://example.com", "example.com:22",
                      "user@example.com", "::1", "a..example", "bad_name.example"):
            with self.subTest(value=value), self.assertRaises(cli.SetupError):
                cli.hostname(value)

    def test_private_ssh_address_is_allowed_but_public_proxy_required(self):
        self.assertEqual(cli.hostname("100.64.0.10"), "100.64.0.10")
        for value in ("192.0.2.10", "127.0.0.1", "10.1.2.3", "100.64.0.10", "localhost"):
            with self.subTest(value=value), self.assertRaises(cli.SetupError):
                cli.hostname(value, public=True)

    def test_ports_are_strict_and_transport_aware(self):
        self.assertEqual(cli.port("22"), 22)
        self.assertEqual(cli.port(65535, service=True), 65535)
        for value in (True, False, 0, -1, 65536, 22.0, "22;id", " 22"):
            with self.subTest(value=value), self.assertRaises(cli.SetupError):
                cli.port(value)
        with self.assertRaises(cli.SetupError):
            cli.port(443, service=True)
        for ports, ssh_port in (({"https": 9443, "trojan": 9443}, 22),
                                ({"https": 18081}, 22), ({"hy2": 18081}, 22),
                                ({}, 8443), ({}, 80)):
            value = document()
            value["server"]["ports"] = ports
            value["ssh"]["port"] = ssh_port
            with self.subTest(ports=ports, ssh_port=ssh_port), self.assertRaises(cli.SetupError):
                cli.validate_document(value)

    def test_unsafe_paths_aliases_and_secret_fields_rejected(self):
        for field, value in (("identity_file", 'key"\nProxyCommand id'),
                             ("identity_file", "key%h"), ("identity_file", "key\x00"),
                             ("alias", "-oProxyCommand"), ("alias", "vps\nHost *"),
                             ("password", "TEST_ONLY_NOT_A_REAL_PASSWORD")):
            candidate = document()
            candidate["ssh"][field] = value
            with self.subTest(field=field), self.assertRaises(cli.SetupError):
                cli.validate_document(candidate)
        candidate = document()
        candidate["server"]["token"] = "TEST_ONLY_NOT_A_REAL_TOKEN"
        with self.assertRaises(cli.SetupError):
            cli.validate_document(candidate)

    def test_no_terms_and_non_boolean_flags_rejected(self):
        for field, value in (("acme_accept_terms", False), ("acme_accept_terms", 1),
                             ("tailscale", "false"), ("tune", "true"),
                             ("tls_name", "other.example.com")):
            candidate = document()
            candidate["server"][field] = value
            with self.subTest(field=field), self.assertRaises(cli.SetupError):
                cli.validate_document(candidate)

    def test_plan_does_not_write_or_connect(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.json"
            path.write_text(json.dumps(document()), encoding="utf-8")
            with patch.object(cli, "ensure_key") as key, patch.object(cli, "deploy") as deploy, \
                    patch.object(cli, "private_write") as write, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--plan", "--config", str(path)]), 0)
            key.assert_not_called()
            deploy.assert_not_called()
            write.assert_not_called()


class SSHConfigTests(unittest.TestCase):
    def setUp(self):
        self.settings = cli.validate_document(document())["ssh"]

    def test_idempotent_merge_preserves_original_context(self):
        original = ("ServerAliveInterval 12\nHost other\n  HostName other.example.com\n"
                    "  Port 2222\nHost *\n  User original-user\n")
        once = cli.merge_ssh_config(original, self.settings)
        twice = cli.merge_ssh_config(once, self.settings)
        self.assertEqual(once, twice)
        self.assertTrue(once.endswith(original))
        self.assertIn("# END VPS-PROXY-SETUP ExampleVPS\nHost *\n\nServerAliveInterval", once)
        self.assertEqual(once.count("# BEGIN VPS-PROXY-SETUP ExampleVPS"), 1)

    def test_unmanaged_conflicts_include_case_and_multiple_patterns(self):
        for original in ("Host ExampleVPS\n", "host = other EXAMPLEVPS\n", "Host other ExampleVPS extra\n"):
            with self.subTest(original=original), self.assertRaises(cli.SetupError):
                cli.merge_ssh_config(original, self.settings)

    def test_incomplete_lf_and_crlf_blocks_rejected(self):
        for newline in ("\n", "\r\n"):
            original = "# BEGIN VPS-PROXY-SETUP ExampleVPS" + newline + "Host ExampleVPS" + newline
            with self.subTest(newline=newline), self.assertRaises(cli.SetupError):
                cli.merge_ssh_config(original, self.settings)

    def test_replaces_managed_values_without_duplicates(self):
        previous = cli.merge_ssh_config("Host other\n  Port 2222\n", self.settings)
        changed = dict(self.settings, host="other-vps.example.com", port=2200)
        updated = cli.merge_ssh_config(previous, changed)
        self.assertNotIn("HostName 192.0.2.10", updated)
        self.assertIn("HostName other-vps.example.com", updated)
        self.assertEqual(updated.count("Host ExampleVPS"), 1)

    @unittest.skipUnless(shutil.which("ssh"), "OpenSSH not installed")
    def test_openssh_resolves_wildcards_and_existing_hosts_without_network(self):
        original = "ServerAliveInterval 12\nHost other\n  Port 2222\nHost *\n  User original-user\n"
        merged = cli.merge_ssh_config(original, self.settings)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config"
            path.write_text(merged, encoding="utf-8")
            for alias, expected in (("ExampleVPS", {"hostname": "192.0.2.10", "port": "22", "user": "root", "serveraliveinterval": "30"}),
                                    ("other", {"port": "2222", "user": "original-user", "serveraliveinterval": "12"})):
                result = subprocess.run(["ssh", "-G", "-F", str(path), alias], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                values = dict(line.split(" ", 1) for line in result.stdout.splitlines() if " " in line)
                for name, value in expected.items():
                    self.assertEqual(values[name], value)

    def test_key_only_commands_disable_password_fallback(self):
        session = cli.SSH(self.settings, Path("connection.conf"))
        with patch.object(cli, "run") as run:
            session.command("true")
            argv = run.call_args.args[0]
            self.assertIn("PasswordAuthentication=no", argv)
            self.assertIn("KbdInteractiveAuthentication=no", argv)
            self.assertEqual(argv[-2:], ["ExampleVPS", "true"])


class PrivateFilesTests(unittest.TestCase):
    def test_existing_key_reused_and_public_comment_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "fixture"
            key.write_text("TEST_ONLY_FAKE_PRIVATE_FILE", encoding="utf-8")
            key.with_suffix(".pub").write_text("ssh-ed25519 dGVzdA== arbitrary-comment\n", encoding="utf-8")
            with patch.object(cli, "run") as run, patch.object(cli, "protect") as protect:
                public = cli.ensure_key({"identity_file": str(key), "alias": "ExampleVPS"})
            self.assertEqual(public, "ssh-ed25519 dGVzdA==")
            run.assert_not_called()
            protect.assert_called_once_with(key)
            self.assertEqual(key.read_text(), "TEST_ONLY_FAKE_PRIVATE_FILE")

    def test_new_key_does_not_change_existing_arbitrary_parent_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "fixture"
            def keygen(args, **kwargs):
                key.write_text("TEST_ONLY_FAKE_PRIVATE_FILE", encoding="utf-8")
                key.with_suffix(".pub").write_text("ssh-ed25519 dGVzdA==", encoding="utf-8")
            with patch.object(cli, "run", side_effect=keygen), patch.object(cli, "protect") as protect, \
                    contextlib.redirect_stdout(io.StringIO()):
                cli.ensure_key({"identity_file": str(key), "alias": "ExampleVPS"})
            protect.assert_called_once_with(key)

    def test_key_symlink_survives_validation_and_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("TEST_ONLY_FAKE_PRIVATE_FILE", encoding="utf-8")
            link = Path(directory) / "link"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("Creating symlinks is not allowed on this platform")
            value = document()
            value["ssh"]["identity_file"] = str(link)
            validated = cli.validate_document(value)["ssh"]
            self.assertEqual(Path(validated["identity_file"]), link)
            with self.assertRaises(cli.SetupError), patch.object(cli, "protect") as protect:
                cli.ensure_key(validated)
            protect.assert_not_called()

    def test_failed_atomic_write_preserves_old_content_and_cleans_temp_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "saved.txt"
            path.write_text("previous", encoding="utf-8")
            with patch.object(cli, "protect"), patch.object(cli.os, "replace", side_effect=OSError("test")), \
                    self.assertRaises(OSError):
                cli.private_write(path, "replacement")
            self.assertEqual(path.read_text(), "previous")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_process_error_does_not_expose_command(self):
        value = "TEST_ONLY_PRIVATE_ARGUMENT"
        with patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaises(cli.SetupError) as error:
                cli.run(["ssh", value])
        self.assertNotIn(value, str(error.exception))


class PayloadTests(unittest.TestCase):
    def test_contains_only_python_package_explicit_assets_and_config(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "server"
            (source / "subscription").mkdir(parents=True)
            (source / "__pycache__").mkdir()
            for name in ("__init__.py", "installer.py", "subscription/__init__.py", "subscription/renderer.py",
                         "assets.json", "settings.json", "result.json", "subscription/stray.json",
                         "private.key", "debug.log", "__pycache__/secret.py", "installer.pyc"):
                (source / name).write_text("{}" if name.endswith("json") else "# TEST_ONLY_FIXTURE\n", encoding="utf-8")
            target = Path(directory) / "payload.zip"
            config = {"address": "vps.example.com"}
            with patch.object(cli, "protect"):
                cli.build_payload(target, config, source)
            with zipfile.ZipFile(target) as archive:
                self.assertEqual(set(archive.namelist()), {"server/__init__.py", "server/installer.py",
                    "server/subscription/__init__.py", "server/subscription/renderer.py", "server/assets.json", "input.json"})
                self.assertEqual(json.loads(archive.read("input.json")), config)

    def test_missing_installer_fails_before_writing_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "server"
            source.mkdir()
            target = Path(directory) / "payload.zip"
            with self.assertRaises(cli.SetupError):
                cli.build_payload(target, {}, source)
            self.assertFalse(target.exists())

    def test_symlinked_python_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "server"
            source.mkdir()
            outside = Path(directory) / "outside.py"
            outside.write_text("# TEST_ONLY_FIXTURE\n", encoding="utf-8")
            try:
                (source / "installer.py").symlink_to(outside)
            except OSError:
                self.skipTest("Creating symlinks is not allowed on this platform")
            with patch.object(cli, "protect"), self.assertRaises(cli.SetupError):
                cli.build_payload(Path(directory) / "payload.zip", {}, source)


if __name__ == "__main__":
    unittest.main()
