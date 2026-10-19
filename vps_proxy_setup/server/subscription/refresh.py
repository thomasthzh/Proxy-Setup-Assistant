"""Validate official CN rules and atomically publish private subscriptions.

No partial release becomes current. A failed fetch may use a previously validated
cache; a first installation fails if complete rules are unavailable. Only counts
and timestamps are printed, never settings, credentials, URLs, or fetch errors.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .renderer import normalize_domains, normalize_networks, render


SOURCES = {
    "cn-domain": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list",
    "cn-ip": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.list",
}
MIN_ENTRIES = {"cn-domain": 50_000, "cn-ip": 5_000}
MAX_ENTRIES = {"cn-domain": 500_000, "cn-ip": 100_000}
MAX_DOWNLOAD_BYTES = 20_000_000
RELEASE_NAME = re.compile(r"\d{8}T\d{12}Z-[a-z0-9_]+\Z")


class RuleError(ValueError):
    """A rule set is unavailable or unsafe; messages contain no source data."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuleError("Rule-source redirects are not accepted")


def download(url: str) -> bytes:
    """Fetch only fixed official HTTPS sources with normal CA verification."""
    if url not in SOURCES.values():
        raise RuleError("Unexpected rule source")
    request = Request(url, headers={"User-Agent": "vps-proxy-setup-rule-refresh/1"})
    with build_opener(_NoRedirect()).open(request, timeout=30) as response:
        if response.status != 200 or response.geturl() != url:
            raise RuleError("Unexpected rule-source response")
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise RuleError("Rule-source response is too large")
    return data


def validate_rules(kind: str, values: list[str]) -> list[str]:
    if kind not in SOURCES:
        raise RuleError("Unknown rule kind")
    try:
        result = normalize_domains(values) if kind == "cn-domain" else normalize_networks(values)
    except (ValueError, TypeError):
        raise RuleError("Rule-source entries are invalid") from None
    if not MIN_ENTRIES[kind] <= len(result) <= MAX_ENTRIES[kind]:
        raise RuleError("Rule-source entry count is outside expected bounds")
    if kind == "cn-domain" and not {"+.baidu.com", "+.qq.com"}.issubset(result):
        raise RuleError("Rule source is missing expected domains")
    return result


def parse_rules(kind: str, data: bytes) -> list[str]:
    if not isinstance(data, bytes) or len(data) > MAX_DOWNLOAD_BYTES:
        raise RuleError("Invalid rule-source response size")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        raise RuleError("Invalid rule-source encoding") from None
    lines = [line.strip() for line in text.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    return validate_rules(kind, lines)


def _permissions(path: Path, mode: int, group: str | None) -> None:
    path.chmod(mode)
    if group is not None:
        import grp  # Production is Linux; offline tests can pass group=None.
        os.chown(path, 0, grp.getgrnam(group).gr_gid)


def _directory(path: Path, group: str | None) -> None:
    if path.is_symlink():
        raise ValueError("Data directories must not be symbolic links")
    path.mkdir(parents=True, exist_ok=True, mode=0o750)
    _permissions(path, 0o750, group)


def _atomic_write(path: Path, data: str, group: str | None) -> None:
    descriptor, temp_name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _permissions(temp, 0o640, group)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


@contextmanager
def _refresh_lock(root: Path):
    descriptor = os.open(root / ".refresh.lock", os.O_CREAT | os.O_RDWR
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a+") as stream:
        if os.name == "posix":
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "posix":
                fcntl.flock(stream, fcntl.LOCK_UN)


def _cached_rules(path: Path, kind: str) -> list[str]:
    if path.is_symlink() or path.stat().st_size > MAX_DOWNLOAD_BYTES:
        raise RuleError("Invalid cached rule file")
    try:
        return validate_rules(kind, json.loads(path.read_text(encoding="utf-8")))
    except (ValueError, TypeError):
        raise RuleError("Cached rules did not pass validation") from None


def _load_rules(cache: Path, kind: str, fetcher, cached: bool) -> tuple[list[str], bool]:
    if not cached:
        try:
            return parse_rules(kind, fetcher(SOURCES[kind])), False
        except (OSError, ValueError, UnicodeError, HTTPException):
            pass  # Do not expose an upstream exception's URL or response body.
    try:
        return _cached_rules(cache / (kind + ".json"), kind), True
    except (OSError, ValueError):
        raise RuleError(f"No complete validated {kind} rules are available") from None


def prune_releases(root: Path, keep: int = 3) -> None:
    """Keep bounded generations, including current; never follow stray links."""
    if not 2 <= keep <= 10:
        raise ValueError("Release retention must be between 2 and 10")
    releases = (root / "releases").resolve(strict=True)
    current = (root / "current").resolve(strict=True)
    candidates = sorted(
        (path for path in releases.iterdir()
         if RELEASE_NAME.fullmatch(path.name) and path.is_dir() and not path.is_symlink()),
        key=lambda path: path.name, reverse=True,
    )
    retained = {current}
    for path in candidates:
        resolved = path.resolve(strict=True)
        if resolved.parent != releases:
            raise ValueError("Release path escaped the data directory")
        if resolved in retained:
            continue
        if len(retained) < keep:
            retained.add(resolved)
        else:
            shutil.rmtree(resolved)


def refresh(settings: dict, data_dir: str | Path, *, fetcher=download,
            cached: bool = False, group: str | None = "vpsproxy-sub", keep: int = 3) -> dict:
    """Publish a release. Inject fetcher/group only for local, offline tests."""
    if not 2 <= keep <= 10:
        raise ValueError("Release retention must be between 2 and 10")
    root = Path(data_dir).absolute()
    _directory(root, group)
    with _refresh_lock(root):
        cache, releases = root / "rules", root / "releases"
        _directory(cache, group)
        _directory(releases, group)
        domains, domains_cached = _load_rules(cache, "cn-domain", fetcher, cached)
        networks, networks_cached = _load_rules(cache, "cn-ip", fetcher, cached)
        artifacts = render(settings, domains, networks)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        release = Path(tempfile.mkdtemp(prefix=stamp + "-", dir=releases))
        link = root / ".current-new"
        published = False
        try:
            _permissions(release, 0o750, group)
            for name, content in artifacts.items():
                _atomic_write(release / name, content, group)
            # Cache complete validated lists, even when the server was offline.
            for kind, values in (("cn-domain", domains), ("cn-ip", networks)):
                _atomic_write(cache / (kind + ".json"), json.dumps(values), group)
            if link.is_symlink():
                link.unlink()
            elif link.exists():
                raise ValueError("Unexpected publication staging path")
            link.symlink_to(Path("releases") / release.name, target_is_directory=True)
            os.replace(link, root / "current")
            published = True
            prune_releases(root, keep)
        finally:
            if link.is_symlink():
                link.unlink()
            if not published and release.exists():
                # The release was created here and checked beneath our root.
                if release.resolve().parent != releases.resolve():
                    raise ValueError("Release path escaped the data directory")
                shutil.rmtree(release)
        return {"generated_utc": stamp, "cn_domains": len(domains), "cn_networks": len(networks),
                "cached_rules": domains_cached or networks_cached,
                "bytes": {name: len(value.encode("utf-8")) for name, value in artifacts.items()}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh private client profiles with validated CN rules")
    parser.add_argument("--settings", required=True, type=Path)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--cached", action="store_true", help="Use previously validated lists without network")
    args = parser.parse_args(argv)
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("The server refresh command must run as root on Linux")
    os.umask(0o077)
    try:
        settings = json.loads(args.settings.read_text(encoding="utf-8"))
        report = refresh(settings, args.data_dir, cached=args.cached)
    except (OSError, ValueError, KeyError, TypeError):
        print("Subscription refresh failed; any published release remains available.", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
