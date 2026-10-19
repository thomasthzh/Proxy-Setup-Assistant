"""Launcher build contract and isolated Windows BAT/PowerShell security checks."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile

from tools.build_launcher import build_launcher, validate_member


VERSION = "0.2.1"
ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell.exe")


class BuildLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="psa-launcher-build-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.archive = self.root / f"Proxy-Setup-Assistant-{VERSION}-windows-x64.zip"

    def archive_with(self, extra=()):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("Proxy-Setup-Assistant.exe", b"desktop fixture")
            archive.writestr("Proxy-Setup-Console.exe", b"console fixture")
            archive.writestr("docs/guide.md", b"guide")
            for name, payload in extra:
                archive.writestr(name, payload)

    def test_single_file_crlf_no_bom_with_pinned_integrity_and_checksum(self):
        self.archive_with()
        target = build_launcher(VERSION, self.archive, self.root / "Proxy-Setup-Assistant.bat")
        data = target.read_bytes()
        self.assertTrue(data.startswith(b"@echo off\r\n"))
        self.assertNotIn(b"\n", data.replace(b"\r\n", b""))
        text = data.decode("utf-8")
        self.assertNotIn("@@", text)
        self.assertIn(hashlib.sha256(self.archive.read_bytes()).hexdigest(), text)
        self.assertIn(hashlib.sha256(b"desktop fixture").hexdigest(), text)
        self.assertIn(hashlib.sha256(b"console fixture").hexdigest(), text)
        self.assertIn(f"releases/download/v{VERSION}/{self.archive.name}", text)
        self.assertNotIn("ServerCertificateValidationCallback", text)
        self.assertNotIn("Invoke-Expression", text)
        self.assertIn("Set-StrictMode", text)
        self.assertIn("DisableDelayedExpansion", text)
        self.assertIn('"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"', text)
        self.assertIn(hashlib.sha256(data).hexdigest(), target.with_suffix(".bat.sha256").read_text())
        self.assertFalse(list(self.root.glob("*.ps1")))

    def test_reject_paths_links_duplicates_and_missing_binary(self):
        for name in ("../escape", "/absolute", "C:/escape", "a\\evil", "a//evil", "AUX.txt", "a/COM1", "a:stream", "a. /x"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_member(name)
        with self.assertRaises(ValueError):
            validate_member("link", (stat.S_IFLNK | 0o777) << 16)
        with self.assertRaises(ValueError):
            validate_member("junction", 0x400)
        self.archive_with((("DOCS/GUIDE.md", b"duplicate"),))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            build_launcher(VERSION, self.archive, self.root / "out.bat")
        self.archive_with((("docs", b"collision"),))
        with self.assertRaisesRegex(ValueError, "collision"):
            build_launcher(VERSION, self.archive, self.root / "out.bat")
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("Proxy-Setup-Assistant.exe", b"single")
        with self.assertRaisesRegex(ValueError, "Both"):
            build_launcher(VERSION, self.archive, self.root / "out.bat")

    def test_version_and_archive_name_are_fixed_not_runtime_overrides(self):
        self.archive_with()
        for version in ("latest", "0.2.1';Write-Host x;#", "0.2.2"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                build_launcher(version, self.archive, self.root / "out.bat")


@unittest.skipUnless(os.name == "nt" and POWERSHELL, "Requires Windows PowerShell and cmd.exe")
class WindowsLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compile_directory = tempfile.TemporaryDirectory(prefix="psa-launcher-stub-")
        cls.stub_path = Path(cls.compile_directory.name) / "stub.exe"
        cls.run_ps_static("""
Add-Type -TypeDefinition @'
using System;
using System.IO;
public static class Stub {
    public static int Main(string[] args) {
        File.WriteAllText(Environment.GetEnvironmentVariable("PSA_TEST_MARKER"), args.Length == 0 ? "launch" : args[0]);
        return 0;
    }
}
'@ -OutputAssembly $env:PSA_TEST_STUB -OutputType ConsoleApplication
""", {"PSA_TEST_STUB": str(cls.stub_path)})

    @classmethod
    def tearDownClass(cls):
        cls.compile_directory.cleanup()

    @staticmethod
    def run_ps_static(script, env=None):
        encoded = base64.b64encode(("$ErrorActionPreference='Stop';\n" + script).encode("utf-16le")).decode("ascii")
        result = subprocess.run([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                env=dict(os.environ, **(env or {})), capture_output=True, timeout=40)
        if result.returncode:
            raise AssertionError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
        return result

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="psa-launcher-run-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "中文 路径 (&!) ' percent%"
        self.root.mkdir()
        self.local = self.root / "应用 缓存 (&!)"
        self.local.mkdir()
        self.cache = self.local / "Proxy-Setup-Assistant" / "launcher" / VERSION
        self.archive = self.root / f"Proxy-Setup-Assistant-{VERSION}-windows-x64.zip"
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.write(self.stub_path, "Proxy-Setup-Assistant.exe")
            archive.write(self.stub_path, "Proxy-Setup-Console.exe")
            archive.writestr("docs/guide.md", b"guide")
        self.bat = build_launcher(VERSION, self.archive, self.root / "启动 助手 (&!) ' percent%.bat")
        self.marker = self.root / "executed.txt"
        self.env = dict(os.environ, LOCALAPPDATA=str(self.local), PSA_TEST_BAT=str(self.bat),
                        PSA_TEST_ARCHIVE=str(self.archive), PSA_TEST_MARKER=str(self.marker),
                        PSA_TEST_CACHE=str(self.cache), PSA_LAUNCHER_MODE="--verify-only")

    def functions(self, script):
        return self.run_ps_static("""
$text = [IO.File]::ReadAllText($env:PSA_TEST_BAT, [Text.Encoding]::UTF8)
$body = $text.Substring($text.IndexOf('#<POWERSHELL>'+[Environment]::NewLine) + '#<POWERSHELL>'.Length)
. ([ScriptBlock]::Create($body.Substring(0, $body.LastIndexOf('# LAUNCHER_ENTRY_POINT'))))
""" + script, self.env)

    def seed_cache(self):
        self.cache.mkdir(parents=True)
        with zipfile.ZipFile(self.archive) as archive:
            archive.extractall(self.cache)

    def bat_command(self, mode):
        # cmd's /s /c quoting needs an outer pair around the complete command.
        command = f'""{self.bat}" {mode}"'
        return f'{os.environ.get("COMSPEC", "cmd.exe")} /d /s /c {command}'

    def run_bat(self, mode="--verify-only"):
        return subprocess.run(self.bat_command(mode), env=self.env, capture_output=True, timeout=30)

    def test_real_bat_cached_verify_then_launch_handles_unicode_spaces_and_shell_characters(self):
        self.seed_cache()
        result = self.run_bat()
        self.assertEqual(result.returncode, 0, repr(result.stdout) + repr(result.stderr))
        self.assertFalse(self.marker.exists())
        result = self.run_bat("--self-test")
        self.assertEqual(result.returncode, 0, repr(result.stdout) + repr(result.stderr))
        self.assertEqual(self.marker.read_text(), "--self-test")

    def test_real_bat_tampered_cache_fails_without_execution_or_pause(self):
        self.seed_cache()
        (self.cache / "Proxy-Setup-Assistant.exe").write_bytes(b"tampered")
        result = self.run_bat("--self-test")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"damaged or changed", result.stdout)
        self.assertFalse(self.marker.exists())

    def test_cache_rejects_extra_files_missing_files_and_reparse_points(self):
        self.seed_cache()
        (self.cache / "injected.dll").write_bytes(b"not part of release")
        result = self.run_bat()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"unexpected file", result.stdout)
        (self.cache / "injected.dll").unlink()
        (self.cache / "docs" / "guide.md").unlink()
        result = self.run_bat()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"incomplete", result.stdout)
        # A junction does not require Developer Mode or elevated privileges.
        target = self.root / "junction-target"
        target.mkdir()
        self.env["PSA_TEST_JUNCTION"] = str(self.cache / "docs")
        self.env["PSA_TEST_TARGET"] = str(target)
        (self.cache / "docs").rmdir()
        try:
            self.functions("New-Item -ItemType Junction -Path $env:PSA_TEST_JUNCTION -Target $env:PSA_TEST_TARGET | Out-Null")
            result = self.run_bat()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"link or junction", result.stdout)
        finally:
            if (self.cache / "docs").exists():
                os.rmdir(self.cache / "docs")

    def test_first_launch_extracts_verified_payload_and_next_launch_is_offline(self):
        self.functions("""
function Receive-Release([string] $Url, [string] $Destination, [long] $ExpectedBytes) {
    [IO.File]::Copy($env:PSA_TEST_ARCHIVE, $Destination)
}
Invoke-Launcher
if (-not [IO.File]::Exists([IO.Path]::Combine($env:PSA_TEST_CACHE, 'Proxy-Setup-Console.exe'))) { throw 'Missing helper' }
function Receive-Release { throw 'A cached launch must not download anything' }
Invoke-Launcher
""")
        self.assertTrue((self.cache / "Proxy-Setup-Assistant.exe").is_file())
        self.assertFalse(list(self.cache.parent.glob("staging-*")))
        self.assertFalse(self.marker.exists())

    def test_bad_download_hash_fails_closed_and_removes_temporary_stage(self):
        self.functions("""
function Receive-Release([string] $Url, [string] $Destination, [long] $ExpectedBytes) {
    [IO.File]::WriteAllText($Destination, 'corrupted download')
}
$failed = $false
try { Invoke-Launcher } catch { $failed = $_.Exception.Message.Contains('SHA-256') }
if (-not $failed) { throw 'Corrupted download was not rejected' }
""")
        self.assertFalse(self.cache.exists())
        self.assertFalse(list(self.cache.parent.glob("staging-*")))

    def test_extract_rejects_zip_slip_duplicate_and_symlink(self):
        fixtures = [("../escaped.txt", b"escape"), ("DOCS/GUIDE.md", b"duplicate")]
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        fixtures.append((link, b"../target"))
        for index, (name, payload) in enumerate(fixtures):
            malicious = self.root / f"malicious-{index}.zip"
            with zipfile.ZipFile(malicious, "w") as archive:
                archive.writestr("docs/guide.md", b"guide")
                archive.writestr(name, payload)
            self.env["PSA_TEST_MALICIOUS"] = str(malicious)
            self.env["PSA_TEST_DESTINATION"] = str(self.root / f"extract-{index}")
            self.functions("""
$failed = $false
try { Expand-VerifiedArchive $env:PSA_TEST_MALICIOUS $env:PSA_TEST_DESTINATION $ExpectedFiles } catch { $failed = $true }
if (-not $failed) { throw 'Unsafe ZIP was accepted' }
""")
            self.assertFalse((self.root / f"extract-{index}").exists())
        self.assertFalse((self.root / "escaped.txt").exists())

    def test_lock_excludes_second_launcher_and_unsafe_download_url_fails_before_network(self):
        self.functions("""
$path = [IO.Path]::Combine($env:LOCALAPPDATA, 'test.lock')
$held = Enter-CacheLock $path
try {
    $failed = $false
    try { $other = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None); $other.Dispose() } catch [IO.IOException] { $failed = $true }
    if (-not $failed) { throw 'Lock was not exclusive' }
} finally { $held.Dispose() }
foreach ($url in @('http://github.com/release.zip', 'https://example.com/evil.zip', 'https://github.com:8443/evil.zip')) {
    $failed = $false
    try { Receive-Release $url ([IO.Path]::Combine($env:LOCALAPPDATA, 'unexpected-download')) 10 } catch { $failed = $_.Exception.Message.Contains('allowed HTTPS hosts') }
    if (-not $failed) { throw 'Unsafe download source was accepted' }
}
""")


if __name__ == "__main__":
    unittest.main()
