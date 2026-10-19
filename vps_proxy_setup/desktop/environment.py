"""Read-only desktop discovery. Detection is evidence, never permission to remove apps."""
from __future__ import annotations

import csv
from dataclasses import dataclass
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import urllib.error
import urllib.request


@dataclass(frozen=True)
class ProxyApp:
    key: str
    name: str
    paths: tuple[str, ...] = ()
    running: bool = False
    registered: bool = False
    source: str = ""
    version: str | None = None


@dataclass(frozen=True)
class EnvironmentReport:
    os_name: str
    architecture: str
    ssh_path: str | None
    proxy_apps: tuple[ProxyApp, ...]
    warnings: tuple[str, ...] = ()
    mihomo_version: str | None = None


@dataclass(frozen=True)
class ProjectAssessment:
    key: str
    repository: str
    license_spdx: str | None = None
    archived: bool | None = None
    latest_release: str | None = None
    published_at: str | None = None
    status: str = "unknown"
    error: str | None = None


PROJECTS = {
    "clash_verge_rev": "clash-verge-rev/clash-verge-rev",
    "clash_verge": "zzzgydi/clash-verge",
    "clash_for_windows": "Fndroid/clash_for_windows_pkg",
    "v2rayn": "2dust/v2rayN",
    "sing_box": "SagerNet/sing-box",
}


def normalize_architecture(machine: str) -> str:
    value = machine.casefold()
    if value in ("amd64", "x86_64", "x64"):
        return "x64"
    if value in ("arm64", "aarch64"):
        return "arm64"
    return "unsupported"


def _classify(name: str, evidence: str = "") -> tuple[str, str] | None:
    value = (name + " " + evidence).casefold()
    if "clash verge rev" in value or "clash-verge-rev" in value:
        return "clash_verge_rev", "Clash Verge Rev"
    if "clash verge" in value or "clash-verge" in value or "clash_verge" in value:
        return "clash_verge", "Clash Verge (edition unconfirmed)"
    if "clash for windows" in value or re.search(r"\bcfw(?:\.exe)?\b", value):
        return "clash_for_windows", "Clash for Windows"
    if "v2rayn" in value:
        return "v2rayn", "v2rayN"
    if "sing-box" in value or "sing_box" in value:
        return "sing_box", "sing-box"
    if re.search(r"clash|v2ray|xray|mihomo|shadowsocks|nekoray|hiddify|proxy", name, re.I):
        return "unknown:" + name.casefold(), name + " (possible proxy app; unconfirmed)"
    return None


def _registered_apps() -> list[tuple[str, str, str, str]]:
    import winreg
    results = []
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view) as root:
                    for index in range(winreg.QueryInfoKey(root)[0]):
                        try:
                            with winreg.OpenKey(root, winreg.EnumKey(root, index)) as entry:
                                def value(field: str) -> str:
                                    try:
                                        return str(winreg.QueryValueEx(entry, field)[0])
                                    except OSError:
                                        return ""
                                results.append((value("DisplayName"), value("InstallLocation"), value("Publisher"), value("DisplayVersion")))
                        except OSError:
                            continue
            except OSError:
                continue
    return results


def _running_names() -> list[str]:
    result = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True,
                            text=True, timeout=8, check=True,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return [row[0] for row in csv.reader(io.StringIO(result.stdout)) if row]


def _installed_mihomo_version(apps: tuple[ProxyApp, ...]) -> str | None:
    """Query only the stable core beside a registry-identified Rev installation."""
    filenames = ("verge-mihomo.exe", "verge-mihomo-x86_64-pc-windows-msvc.exe",
                 "verge-mihomo-aarch64-pc-windows-msvc.exe")
    for app in apps:
        if app.key != "clash_verge_rev" or not app.registered:
            continue
        for location in app.paths:
            installation = Path(location)
            if not installation.is_absolute():
                continue
            for parent in (installation, installation / "resources"):
                for filename in filenames:
                    executable = parent / filename
                    try:
                        if not executable.is_file() or executable.is_symlink():
                            continue
                        result = subprocess.run([str(executable), "-v"], capture_output=True,
                                                timeout=3, check=True,
                                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                        output = result.stdout[:4096].decode("utf-8", errors="replace")
                        match = re.search(r"\bmihomo\b[^\r\n]*?\bv?(\d+\.\d+\.\d+)\b", output, re.I)
                        if match:
                            return match.group(1)
                    except (OSError, subprocess.SubprocessError):
                        continue
    return None


def detect_environment() -> EnvironmentReport:
    system = platform.system()
    machine = os.environ.get("PROCESSOR_ARCHITEW6432") or platform.machine()
    warnings: list[str] = []
    apps: dict[str, ProxyApp] = {}
    if system == "Windows":
        try:
            entries = _registered_apps()
        except (ImportError, OSError):
            entries = []
            warnings.append("Installed app registry could not be read; detection is incomplete.")
        for entry in entries:
            name, path, publisher, *versions = entry
            path = path.strip()
            if path.startswith('"') and path.endswith('"'):
                path = path[1:-1]
            path = os.path.expandvars(path)
            version = versions[0].removeprefix("v") if versions and re.fullmatch(r"v?\d+\.\d+\.\d+", versions[0]) else None
            match = _classify(name, path + " " + publisher)
            if match:
                key, label = match
                existing = apps.get(key)
                paths = set(existing.paths if existing else ())
                if path:
                    paths.add(path)
                if existing and existing.version != version:
                    version = None  # Multiple registered versions require explicit selection.
                apps[key] = ProxyApp(key, label, tuple(sorted(paths)), False, True, "Windows uninstall registry", version)
        try:
            for name in _running_names():
                match = _classify(name)
                if match:
                    key, label = match
                    # Both Verge generations use the same executable name.
                    if key == "clash_verge" and "clash_verge_rev" in apps and key not in apps:
                        key, label = "clash_verge_rev", "Clash Verge Rev"
                    elif key == "clash_verge" and "clash_verge_rev" in apps:
                        key, label = "clash_verge_process", "Clash Verge process (edition unconfirmed)"
                    old = apps.get(key)
                    apps[key] = ProxyApp(key, label, old.paths if old else (), True,
                                         bool(old and old.registered), "process list" + (" + registry" if old else ""),
                                         old.version if old else None)
        except (OSError, subprocess.SubprocessError):
            warnings.append("Running process list unavailable; detection is incomplete.")
    else:
        warnings.append("Automatic proxy app discovery is currently supported on Windows only.")
    warnings.append("Portable, renamed, inaccessible or stopped unregistered apps may be missed. Confirm apps manually.")
    found = tuple(apps.values())
    core_version = _installed_mihomo_version(found) if system == "Windows" else None
    return EnvironmentReport(system, normalize_architecture(machine), shutil.which("ssh"),
                             found, tuple(warnings), core_version)


def _github_json(url: str, timeout: float) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "VPS-Proxy-SetUP"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if not response.geturl().startswith("https://api.github.com/"):
            raise ValueError("Unexpected metadata origin")
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("Metadata too large")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Invalid metadata")
    return data


def assess_projects(timeout: float = 8) -> tuple[ProjectAssessment, ...]:
    """Report factual upstream state. Release age alone does not imply abandonment."""
    results = []
    for key, repository in PROJECTS.items():
        license_spdx = None
        archived = None
        try:
            data = _github_json("https://api.github.com/repos/" + repository, timeout)
            archived = data.get("archived") if isinstance(data.get("archived"), bool) else None
            license_data = data.get("license")
            license_spdx = license_data.get("spdx_id") if isinstance(license_data, dict) else None
            if license_spdx in ("NOASSERTION", ""):
                license_spdx = None
            try:
                release = _github_json("https://api.github.com/repos/" + repository + "/releases/latest", timeout)
            except urllib.error.HTTPError as exc:
                if exc.code != 404:
                    raise
                release = {}
            results.append(ProjectAssessment(key, repository, license_spdx, archived,
                                              release.get("tag_name"), release.get("published_at"),
                                              "archived" if archived else "available" if archived is False else "unknown"))
        except (OSError, ValueError, TypeError):
            results.append(ProjectAssessment(key, repository, license_spdx, archived,
                                              status="unknown", error="GitHub metadata unavailable; maintenance and release status are unknown."))
    return tuple(results)


def open_windows_apps_settings() -> bool:
    """Open the user's uninstall UI; never execute app-provided uninstall commands."""
    if platform.system() != "Windows":
        return False
    try:
        os.startfile("ms-settings:appsfeatures")
        return True
    except OSError:
        return False
