#!/usr/bin/env python3
"""Build a self-contained Windows BAT with an immutable, verified release payload."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import stat
import zipfile


ROOT = Path(__file__).resolve().parents[1]
BINARIES = {"Proxy-Setup-Assistant.exe", "Proxy-Setup-Console.exe"}
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_EXPANDED_BYTES = 300 * 1024 * 1024
MAX_ENTRIES = 512


def validate_member(name: str, attributes: int = 0) -> str:
    """Require canonical, ordinary Windows relative paths; no links or devices."""
    if not name or "\\" in name or name.startswith("/"):
        raise ValueError("Unsafe ZIP member path")
    trimmed = name.rstrip("/")
    for part in trimmed.split("/"):
        if (not part or part in {".", ".."} or part.endswith((".", " "))
                or re.search(r'[<>:"|?*\x00-\x1f]', part)
                or re.match(r"(?i)^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", part)):
            raise ValueError("Unsafe ZIP member path")
    mode = (attributes >> 16) & 0o170000
    if mode not in {0, stat.S_IFREG, stat.S_IFDIR} or attributes & 0x400:
        raise ValueError("ZIP links and reparse points are forbidden")
    return trimmed


def build_launcher(version: str, zip_path: Path, output_path: Path) -> Path:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Expected a stable numeric release version")
    zip_path, output_path = Path(zip_path), Path(output_path)
    expected_name = f"Proxy-Setup-Assistant-{version}-windows-x64.zip"
    if zip_path.name != expected_name:
        raise ValueError("Archive filename must match the pinned release version")
    if not 0 < zip_path.stat().st_size <= MAX_ARCHIVE_BYTES:
        raise ValueError("Release archive exceeds the size limit")
    manifest: dict[str, str] = {}
    occupied: set[str] = set()
    with zipfile.ZipFile(zip_path) as archive:
        members = archive.infolist()
        if len(members) > MAX_ENTRIES or sum(item.file_size for item in members) > MAX_EXPANDED_BYTES:
            raise ValueError("Release archive exceeds extraction limits")
        for member in members:
            name = validate_member(member.filename, member.external_attr)
            if name.casefold() in occupied:
                raise ValueError("Duplicate ZIP member")
            occupied.add(name.casefold())
            if member.flag_bits & 1:
                raise ValueError("Encrypted ZIP members are forbidden")
            if not member.is_dir():
                manifest[name] = hashlib.sha256(archive.read(member)).hexdigest()
    if not BINARIES.issubset(manifest):
        raise ValueError("Both desktop and console executables are required")
    file_names = {name.casefold() for name in manifest}
    for name in manifest:
        if any(str(parent).replace("\\", "/").casefold() in file_names
               for parent in Path(name).parents if str(parent) != "."):
            raise ValueError("ZIP file/directory collision")
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    template = (ROOT / "tools" / "windows-launcher.bat.in").read_text(encoding="utf-8")
    manifest_ps = "\n".join("    '" + name.replace("'", "''") + "' = '" + value + "'"
                            for name, value in sorted(manifest.items()))
    replacements = {"@@VERSION@@": version, "@@ZIP_SHA256@@": digest,
                    "@@ZIP_BYTES@@": str(zip_path.stat().st_size), "@@FILE_MANIFEST@@": manifest_ps}
    for marker, value in replacements.items():
        template = template.replace(marker, value)
    if re.search(r"@@[A-Z_0-9]+@@", template):
        raise ValueError("Unresolved launcher template marker")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(template.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
    output_path.with_suffix(".bat.sha256").write_text(
        hashlib.sha256(output_path.read_bytes()).hexdigest() + "  " + output_path.name + "\n", encoding="utf-8")
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "Proxy-Setup-Assistant.bat")
    args = parser.parse_args()
    print(build_launcher(args.version, args.archive, args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
