#!/usr/bin/env python3
"""Check only this repository's Git-tracked files before public release.

This is a conservative release guard, not a general secret-detection product.
It prints finding categories and locations, never matched credential values.
Tests must visibly mark fake credentials with the TEST_ONLY_ prefix. Examples
should use reserved example domains and documentation IP ranges.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    category: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.category}"


PRIVATE_KEY = re.compile(r"-{4,5}BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-{4,5}")
PROVIDER_TOKENS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b"),
    re.compile(r"\btskey-(?:auth|api)-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{20,}\b"),
)
SECRET_ASSIGNMENT = re.compile(
    r'''(?ix)(?<![\w-])["']?
    (?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|
       auth[_-]?key|hy2[_-]auth|hy2[_-]obfs|trojan[_-]password|obfs[_-]password)
    ["']?\s*[:=]\s*(["'])([^\r\n"']{12,})\1'''
)
UNQUOTED_SECRET = re.compile(
    r"(?im)^\s*(?:password|passwd|token|secret|api[_-]?key|access[_-]?token|"
    r"hy2[_-]auth|hy2[_-]obfs|trojan[_-]password|obfs[_-]password)\s*[:=]\s*"
    r"([A-Za-z0-9_./+@!:$=-]{12,})\s*(?:#.*)?$"
)
BEARER_URL = re.compile(r"https?://[^\s\"'<>]+/s/([A-Za-z0-9_-]{24,})(?=[/\s\"'<>?#]|$)")
EMBEDDED_PASSWORD = re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:@]+:([^\s/@]{8,})@", re.I)
DEPLOYMENT_IP = re.compile(
    r'''(?ix)(?<![\w-])["']?\b(?:address|hostname|host|server|tls_name|vps_ip)["']?\s*[:=]\s*
    ["']?((?:\d{1,3}\.){3}\d{1,3})(?=["'\s,;}]|$)'''
)
SENSITIVE_NAMES = {
    "settings.json", "result.json", "input.json", "connection.conf", "subscription.json",
    "authorized_keys", "known_hosts", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "hysteria.yaml", "hysteria.yml", "trojan.json",
}
SENSITIVE_DIRECTORIES = {".ssh", "private", "secrets", "outputs", "deployed", "state"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".pub", ".p12", ".pfx", ".ppk", ".pyc", ".pyo", ".log"}


def _test_fixture(path: str, value: str) -> bool:
    return "tests" in PurePosixPath(path).parts and value.startswith("TEST_ONLY_")


def _placeholder(value: str) -> bool:
    lowered = value.lower()
    return (value.startswith(("<", "${", "{{")) or "{" in value or "}" in value
            or lowered in {"changeme", "change_me", "replace_me", "your_password", "your_token"}
            or lowered.startswith(("replace-with-", "replace_with_", "example-", "example_")))


def scan_text(path: str, content: str) -> list[Finding]:
    findings: set[Finding] = set()

    def flag(match: re.Match, category: str):
        findings.add(Finding(path, content.count("\n", 0, match.start()) + 1, category))

    for match in PRIVATE_KEY.finditer(content):
        flag(match, "private-key block")
    for pattern in PROVIDER_TOKENS:
        for match in pattern.finditer(content):
            flag(match, "provider credential")
    for pattern, group in ((SECRET_ASSIGNMENT, 2), (UNQUOTED_SECRET, 1),
                           (BEARER_URL, 1), (EMBEDDED_PASSWORD, 1)):
        for match in pattern.finditer(content):
            value = match.group(group)
            if _test_fixture(path, value) or _placeholder(value):
                continue
            # Literal source-code expressions are not saved credentials.
            if any(char.isspace() for char in value) or value.startswith(("settings[", "client[")):
                continue
            flag(match, "literal credential or private subscription URL")
    for match in DEPLOYMENT_IP.finditer(content):
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        if address.is_global:
            flag(match, "literal public deployment IP; use a reserved example address")
    return sorted(findings, key=lambda finding: (finding.path, finding.line, finding.category))


def scan_paths(root: Path, names: list[str]) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    for name in sorted(set(names)):
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            findings.append(Finding(name, 1, "unsafe tracked path"))
            continue
        path = root.joinpath(*relative.parts)
        if path.is_symlink() or root not in path.resolve().parents:
            findings.append(Finding(name, 1, "tracked symlink or path outside repository"))
            continue
        basename = relative.name.lower()
        if (basename in SENSITIVE_NAMES or relative.suffix.lower() in SENSITIVE_SUFFIXES
                or any(part.lower() in SENSITIVE_DIRECTORIES for part in relative.parts[:-1])
                or basename.endswith(".local.json")
                or (basename.startswith(".env") and basename not in (".env.example", ".env.template"))
                or (basename.startswith("payload") and basename.endswith(".zip"))
                or basename.startswith("ssh-config-backup-")):
            findings.append(Finding(name, 1, "possible deployed state or private artifact"))
        if not path.is_file():
            findings.append(Finding(name, 1, "tracked file is missing or is not a regular file"))
            continue
        if path.stat().st_size > 5_000_000:
            findings.append(Finding(name, 1, "large artifact requires manual release review"))
            continue
        data = path.read_bytes()
        try:
            content = data.decode("utf-8-sig")
        except UnicodeError:
            findings.append(Finding(name, 1, "non-UTF-8 artifact requires manual release review"))
            continue
        if "\x00" in content:
            findings.append(Finding(name, 1, "binary artifact requires manual release review"))
            continue
        findings.extend(scan_text(name, content))
    return findings


def tracked_files(root: Path) -> list[str]:
    """Refuse a parent checkout, so a mistaken path cannot scan private siblings."""
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                            check=True, capture_output=True, text=True, encoding="utf-8")
    if Path(result.stdout.strip()).resolve() != root.resolve():
        raise ValueError("--root must be the exact repository top-level")
    result = subprocess.run(["git", "-C", str(root), "ls-files", "--cached", "-z"],
                            check=True, capture_output=True)
    names = [name.decode("utf-8") for name in result.stdout.split(b"\x00") if name]
    if not names:
        raise ValueError("No Git-tracked files; stage the intended public release first")
    # The index is what will be committed. Refuse a different working copy so a
    # cleaned file cannot conceal a credential still staged in an older version.
    subprocess.run(["git", "-C", str(root), "diff", "--quiet", "--ignore-submodules", "--"],
                   check=True, capture_output=True)
    return names


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--tracked", action="store_true", help="scan Git-tracked files only (the default)")
    args = parser.parse_args(argv)
    try:
        names = tracked_files(args.root)
        findings = scan_paths(args.root, names)
    except (OSError, ValueError, subprocess.CalledProcessError):
        print("Public-tree check failed: use the exact repository root and stage final tracked changes first.", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding)
    if findings:
        print(f"Public-tree check failed: {len(findings)} finding(s). No matched values were printed.")
        return 1
    print(f"Public-tree check passed: {len(names)} tracked files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
