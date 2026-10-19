"""Desktop discovery uses mocked registry/processes; no machine changes."""
import json
import unittest
from unittest.mock import MagicMock, Mock, patch
import types
import tempfile
from pathlib import Path
import subprocess
import urllib.error

from vps_proxy_setup.desktop import environment as env


class EnvironmentTests(unittest.TestCase):
    def test_architecture_normalization(self):
        for value in ("AMD64", "x86_64", "x64"):
            self.assertEqual(env.normalize_architecture(value), "x64")
        self.assertEqual(env.normalize_architecture("aarch64"), "arm64")
        self.assertEqual(env.normalize_architecture("i686"), "unsupported")

    @patch.object(env.platform, "system", return_value="Windows")
    @patch.object(env.platform, "machine", return_value="AMD64")
    @patch.object(env.shutil, "which", return_value="C:/Windows/System32/OpenSSH/ssh.exe")
    @patch.object(env, "_running_names", return_value=["clash-verge.exe", "v2rayN.exe", "mysteryproxy.exe", "notepad.exe"])
    @patch.object(env, "_registered_apps", return_value=[
        ("Clash Verge", "C:/Apps/clash-verge-rev", "clash-verge-rev"),
        ("Clash for Windows", "C:/Apps/CFW", ""),
        ("sing-box", "C:/Apps/sing-box", ""),
    ])
    def test_evidence_and_conservative_unknown(self, *_):
        report = env.detect_environment()
        apps = {app.key: app for app in report.proxy_apps}
        self.assertTrue(apps["clash_verge_rev"].registered)
        self.assertTrue(apps["clash_verge_rev"].running)
        self.assertTrue(apps["clash_for_windows"].registered)
        self.assertTrue(apps["v2rayn"].running)
        self.assertIn("unknown:mysteryproxy.exe", apps)
        self.assertNotIn("unknown:notepad.exe", apps)
        self.assertTrue(report.ssh_path)
        self.assertTrue(report.warnings)

    def test_verge_edition_is_not_guessed_from_shared_name(self):
        self.assertEqual(env._classify("Clash Verge")[1], "Clash Verge (edition unconfirmed)")

    @patch.object(env.platform, "system", return_value="Windows")
    @patch.object(env, "_running_names", return_value=[])
    @patch.object(env, "_registered_apps", return_value=[("Clash Verge Rev", '"C:/Apps/rev"', "", "v2.5.8")])
    def test_registry_version_normalized_for_profile_compatibility(self, *_):
        app, = env.detect_environment().proxy_apps
        self.assertEqual(app.version, "2.5.8")
        self.assertEqual(app.paths, ("C:/Apps/rev",))

    def test_registry_reads_display_version_without_uninstall_command(self):
        registry = types.SimpleNamespace(HKEY_CURRENT_USER=1, HKEY_LOCAL_MACHINE=2,
                                        KEY_WOW64_64KEY=4, KEY_WOW64_32KEY=8, KEY_READ=16)
        opened = MagicMock()
        registry.OpenKey = Mock(return_value=opened)
        registry.QueryInfoKey = Mock(return_value=(1,))
        registry.EnumKey = Mock(return_value="app")
        values = {"DisplayName": "Clash Verge Rev", "InstallLocation": "C:/Apps/rev",
                  "Publisher": "clash-verge-rev", "DisplayVersion": "2.5.8"}
        registry.QueryValueEx = Mock(side_effect=lambda key, field: (values[field], 1))
        with patch.dict("sys.modules", {"winreg": registry}):
            entries = env._registered_apps()
        self.assertEqual(entries[0], ("Clash Verge Rev", "C:/Apps/rev", "clash-verge-rev", "2.5.8"))
        self.assertTrue(all(call.args[1] != "UninstallString" for call in registry.QueryValueEx.call_args_list))

    def test_core_version_only_from_registered_rev_known_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "verge-mihomo.exe"
            executable.write_bytes(b"fixture only; never executed")
            app = env.ProxyApp("clash_verge_rev", "Clash Verge Rev", (directory,), registered=True)
            with patch.object(env.subprocess, "run", return_value=Mock(stdout=b"Mihomo Meta v1.19.32 windows amd64\n")) as run:
                self.assertEqual(env._installed_mihomo_version((app,)), "1.19.32")
                self.assertEqual(run.call_args.args[0], [str(executable), "-v"])
                self.assertEqual(run.call_args.kwargs["timeout"], 3)
            for key, registered in (("unknown", True), ("clash_verge", True), ("clash_verge_rev", False)):
                app = env.ProxyApp(key, "app", (directory,), registered=registered)
                with patch.object(env.subprocess, "run") as run:
                    self.assertIsNone(env._installed_mihomo_version((app,)))
                    run.assert_not_called()

    def test_core_version_failure_remains_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "verge-mihomo.exe").write_bytes(b"fixture")
            app = env.ProxyApp("clash_verge_rev", "Rev", (directory,), registered=True)
            with patch.object(env.subprocess, "run", side_effect=subprocess.TimeoutExpired("core", 3)):
                self.assertIsNone(env._installed_mihomo_version((app,)))

    @patch.object(env.platform, "system", return_value="Windows")
    @patch.object(env, "_registered_apps", side_effect=OSError)
    @patch.object(env, "_running_names", side_effect=OSError)
    def test_discovery_failure_is_not_no_apps_claim(self, *_):
        report = env.detect_environment()
        self.assertEqual(report.proxy_apps, ())
        self.assertTrue(any("incomplete" in warning for warning in report.warnings))

    @patch.dict(env.PROJECTS, {"example": "owner/repo"}, clear=True)
    @patch.object(env, "_github_json", side_effect=[
        {"archived": False, "license": {"spdx_id": "MIT"}},
        {"tag_name": "v1", "published_at": "2019-01-01T00:00:00Z"},
    ])
    def test_release_age_does_not_imply_abandoned(self, _):
        result, = env.assess_projects()
        self.assertEqual(result.status, "available")
        self.assertEqual(result.license_spdx, "MIT")
        self.assertEqual(result.latest_release, "v1")

    @patch.dict(env.PROJECTS, {"example": "owner/repo"}, clear=True)
    @patch.object(env, "_github_json", side_effect=OSError("offline"))
    def test_offline_is_explicit_unknown(self, _):
        result, = env.assess_projects()
        self.assertEqual(result.status, "unknown")
        self.assertIsNone(result.archived)
        self.assertIsNone(result.license_spdx)

    @patch.dict(env.PROJECTS, {"example": "owner/repo"}, clear=True)
    @patch.object(env, "_github_json", side_effect=[
        {"archived": True, "license": None},
        urllib.error.HTTPError("https://api.github.com", 404, "no release", {}, None),
    ])
    def test_archived_is_factual_even_without_release(self, _):
        result, = env.assess_projects()
        self.assertEqual(result.status, "archived")
        self.assertIsNone(result.latest_release)

    @patch.object(env.platform, "system", return_value="Windows")
    def test_uninstall_help_opens_settings_only(self, _):
        with patch.object(env.os, "startfile", create=True) as start:
            self.assertTrue(env.open_windows_apps_settings())
            start.assert_called_once_with("ms-settings:appsfeatures")

    @patch.object(env.platform, "system", return_value="Linux")
    def test_other_platform_does_not_open_uninstaller(self, _):
        self.assertFalse(env.open_windows_apps_settings())


if __name__ == "__main__":
    unittest.main()
