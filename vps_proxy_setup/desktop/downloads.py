"""Bounded HTTPS downloads verified against official release SHA-256 metadata."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import tempfile
import time
from typing import Callable
import urllib.parse
import urllib.request

REPOSITORY = "clash-verge-rev/clash-verge-rev"
API_URL = "https://api.github.com/repos/" + REPOSITORY + "/releases/latest"
MAX_INSTALLER_BYTES = 200 * 1024 * 1024
# Verified against official GitHub release asset digests on 2026-10-19.
PINNED_DIGESTS = {
    ("v2.5.8", "Clash.Verge_2.5.8_x64-setup.exe"): "821c0f5957f84c8f7d14532044840e8280d708af24a6a143db360b49bd1e7302",
    ("v2.5.8", "Clash.Verge_2.5.8_arm64-setup.exe"): "077efab7874a6be7c48630d19c941ef679fa265f79c243f9d20ce5878eb5a943",
}


class DownloadError(Exception):
    """A safe message suitable for desktop display."""


@dataclass(frozen=True)
class ReleaseInstaller:
    version: str
    architecture: str
    filename: str
    url: str
    sha256: str
    size: int


@dataclass(frozen=True)
class DownloadCandidate:
    url: str
    label: str
    third_party: bool = False
    bytes_per_second: float = 0
    error: str | None = None


def _safe_origin(url: str, third_party: bool = False) -> bool:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.username or parts.password or parts.port not in (None, 443):
        return False
    host = (parts.hostname or "").lower()
    official = host in {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
    mirror = host in {"sourceforge.net", "downloads.sourceforge.net"} or host.endswith(".dl.sourceforge.net")
    return official or (third_party and mirror)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, third_party: bool = False):
        self.third_party = third_party

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _safe_origin(newurl, self.third_party):
            raise DownloadError("Download redirected outside the approved HTTPS sources.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_asset(url: str, timeout: float, third_party: bool = False, probe: bool = False):
    if not _safe_origin(url, third_party):
        raise DownloadError("Unapproved download source.")
    headers = {"User-Agent": "VPS-Proxy-SetUP", "Accept-Encoding": "identity"}
    if probe:
        headers["Range"] = "bytes=0-262143"
    return urllib.request.build_opener(_SafeRedirect(third_party)).open(
        urllib.request.Request(url, headers=headers), timeout=timeout)


def _read_bounded(response, count: int, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DownloadError("Download time limit exceeded.")
    # HTTPResponse.read(n) can wait for many small receives indefinitely under a
    # trickling server. read1 does one receive; cap that receive by the deadline.
    try:
        response.fp.raw._sock.settimeout(min(remaining, 10))
    except AttributeError:
        pass
    reader = getattr(response, "read1", response.read)
    chunk = reader(count)
    if time.monotonic() > deadline:
        raise DownloadError("Download time limit exceeded.")
    return chunk


def get_latest_installer(architecture: str, timeout: float = 10) -> ReleaseInstaller:
    if architecture not in ("x64", "arm64"):
        raise DownloadError("Only Windows x64 and ARM64 installers are supported.")
    try:
        request = urllib.request.Request(API_URL, headers={"Accept": "application/vnd.github+json", "User-Agent": "VPS-Proxy-SetUP"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.geturl() != API_URL:
                raise DownloadError("Unexpected release metadata origin.")
            raw = response.read(4_000_001)
        if len(raw) > 4_000_000:
            raise DownloadError("Release metadata exceeded the size limit.")
        data = json.loads(raw)
        version = data["tag_name"]
        if not re.fullmatch(r"v\d+\.\d+\.\d+", version) or data.get("draft") or data.get("prerelease"):
            raise DownloadError("A stable official release could not be selected.")
        filename = "Clash.Verge_" + version[1:] + "_" + architecture + "-setup.exe"
        asset = next((item for item in data["assets"] if item.get("name") == filename), None)
        if not asset:
            raise DownloadError("The official release has no installer for this architecture.")
        url = "https://github.com/" + REPOSITORY + "/releases/download/" + version + "/" + filename
        if asset.get("browser_download_url") != url:
            raise DownloadError("The installer is not hosted in the official release.")
        digest = asset.get("digest")
        if isinstance(digest, str) and re.fullmatch(r"sha256:[a-fA-F0-9]{64}", digest):
            digest = digest.split(":")[1].lower()
        else:
            digest = PINNED_DIGESTS.get((version, filename))
        if not digest:
            raise DownloadError("No official SHA-256 digest is available for this installer.")
        size = asset.get("size")
        if type(size) is not int or not 0 < size <= MAX_INSTALLER_BYTES:
            raise DownloadError("Installer size is invalid or exceeds the download limit.")
        return ReleaseInstaller(version, architecture, filename, url, digest, size)
    except DownloadError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        raise DownloadError("Official GitHub release metadata is unavailable; check the network and try again.") from None


def get_pinned_installer(architecture: str) -> ReleaseInstaller:
    """Return the official v2.5.8 asset verified 2026-10-19, without a network call.

    This is an explicitly dated fallback, not a claim about the latest version.
    Mirrors remain opt-in through probe_candidates; all downloads must match the
    pinned official digest and exact asset size.
    """
    sizes = {"x64": 60_230_483, "arm64": 53_952_182}
    if architecture not in sizes:
        raise DownloadError("Only Windows x64 and ARM64 installers are supported.")
    version = "v2.5.8"
    filename = f"Clash.Verge_2.5.8_{architecture}-setup.exe"
    return ReleaseInstaller(version, architecture, filename,
                            f"https://github.com/{REPOSITORY}/releases/download/{version}/{filename}",
                            PINNED_DIGESTS[(version, filename)], sizes[architecture])


def _candidates(installer: ReleaseInstaller, allow_sourceforge: bool) -> list[DownloadCandidate]:
    _validate_installer(installer)
    result = [DownloadCandidate(installer.url, "GitHub official release")]
    if allow_sourceforge:
        url = ("https://sourceforge.net/projects/clash-verge-rev.mirror/files/" +
               installer.version + "/" + installer.filename + "/download")
        result.append(DownloadCandidate(url, "SourceForge third-party mirror (official SHA-256 required)", True))
    return result


def _validate_installer(installer: ReleaseInstaller) -> None:
    if installer.architecture not in ("x64", "arm64") or not re.fullmatch(r"v\d+\.\d+\.\d+", installer.version):
        raise DownloadError("Invalid installer architecture or release.")
    expected = f"Clash.Verge_{installer.version[1:]}_{installer.architecture}-setup.exe"
    if installer.filename != expected or installer.url != f"https://github.com/{REPOSITORY}/releases/download/{installer.version}/{expected}":
        raise DownloadError("Invalid official installer URL or filename.")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", installer.sha256):
        raise DownloadError("A valid official SHA-256 digest is required.")
    if type(installer.size) is not int or not 0 < installer.size <= MAX_INSTALLER_BYTES:
        raise DownloadError("Invalid installer size.")


def probe_candidates(installer: ReleaseInstaller, allow_sourceforge: bool = False,
                     timeout: float = 4, max_bytes: int = 262144) -> tuple[DownloadCandidate, ...]:
    """Measure a bounded sample of available routes, not a universal speed ranking."""
    if timeout <= 0 or not 0 < max_bytes <= 1024 * 1024:
        raise DownloadError("Invalid probe limits.")
    results = []
    for candidate in _candidates(installer, allow_sourceforge):
        started = time.monotonic()
        count = 0
        signature = b""
        try:
            with _open_asset(candidate.url, timeout, candidate.third_party, probe=True) as response:
                while count < max_bytes:
                    if time.monotonic() - started >= timeout:
                        break
                    chunk = _read_bounded(response, min(65536, max_bytes - count), started + timeout)
                    if not chunk:
                        break
                    if len(signature) < 2:
                        signature += chunk[:2 - len(signature)]
                    count += len(chunk)
            if not count:
                raise DownloadError("Empty probe response.")
            if signature != b"MZ":
                raise DownloadError("The route returned a web page or non-installer response.")
            results.append(DownloadCandidate(candidate.url, candidate.label, candidate.third_party,
                                             count / max(time.monotonic() - started, 0.001)))
        except (OSError, ValueError, DownloadError):
            results.append(DownloadCandidate(candidate.url, candidate.label, candidate.third_party,
                                             error="Route unavailable or HTTPS verification failed."))
    return tuple(sorted(results, key=lambda item: (item.error is not None, -item.bytes_per_second)))


def download_installer(installer: ReleaseInstaller, destination_dir: str | Path,
                       candidate: DownloadCandidate | None = None, timeout: float = 120,
                       max_bytes: int = MAX_INSTALLER_BYTES,
                       progress: Callable[[int, int], None] | None = None) -> Path:
    """Return an atomically saved verified installer. Never launch or install it."""
    options = _candidates(installer, allow_sourceforge=True)
    candidate = candidate or options[0]
    if not any(candidate.url == item.url and candidate.third_party == item.third_party for item in options):
        raise DownloadError("Unapproved installer route.")
    if timeout <= 0 or max_bytes <= 0 or installer.size > max_bytes:
        raise DownloadError("Installer exceeds the requested download limits.")
    directory = Path(destination_dir)
    directory.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    started = time.monotonic()
    try:
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".clash-download-", suffix=".part", delete=False) as output:
            temporary = Path(output.name)
            digest = hashlib.sha256()
            count = 0
            with _open_asset(candidate.url, min(timeout, 10), candidate.third_party) as response:
                while True:
                    if time.monotonic() - started > timeout:
                        raise DownloadError("Installer download timed out.")
                    chunk = _read_bounded(response, min(65536, max_bytes - count + 1), started + timeout)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > max_bytes or count > installer.size:
                        raise DownloadError("Installer exceeded the expected size.")
                    output.write(chunk)
                    digest.update(chunk)
                    if progress:
                        progress(count, installer.size)
            if count != installer.size or digest.hexdigest() != installer.sha256.lower():
                raise DownloadError("Installer SHA-256 or size verification failed; the file was discarded.")
        final = directory / installer.filename
        temporary.replace(final)
        temporary = None
        return final
    except DownloadError:
        raise
    except (OSError, ValueError):
        raise DownloadError("Installer download failed or HTTPS verification failed; try another measured route.") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
