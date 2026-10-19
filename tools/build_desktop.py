#!/usr/bin/env python3
"""Build and verify the Windows x64 desktop/console release; never deploy a VPS."""

from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import distribution
import os
from pathlib import Path
import platform
import runpy
import struct
import subprocess
import sys
import tempfile
import zipfile

from build_launcher import build_launcher


ROOT = Path(__file__).resolve().parents[1]
VERSION = runpy.run_path(str(ROOT / "vps_proxy_setup" / "__init__.py"))["__version__"]
BINARIES = ("Proxy-Setup-Assistant.exe", "Proxy-Setup-Console.exe")


def run(command: list[str], *, env=None):
    subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=600)


def build(output: Path):
    server = ROOT / "vps_proxy_setup" / "server"
    data_args = []
    # build_payload() needs real Python sources at the frozen package path.
    # Include only release inputs, never __pycache__, logs or local state.
    for source in sorted(server.rglob("*")):
        if source.is_file() and (source.suffix == ".py" or source == server / "assets.json") and "__pycache__" not in source.parts:
            if source.is_symlink():
                raise RuntimeError("Server payload must not contain symlinks")
            destination = "vps_proxy_setup/server/" + source.parent.relative_to(server).as_posix()
            data_args.extend(("--add-data", str(source) + os.pathsep + destination))
    for name, launcher, mode in (
        ("Proxy-Setup-Assistant", "launch-desktop.pyw", "--windowed"),
        ("Proxy-Setup-Console", "launch-console.py", "--console"),
    ):
        run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", mode,
             "--name", name, "--distpath", str(output),
             "--workpath", str(ROOT / "build" / "desktop" / "work"),
             "--specpath", str(ROOT / "build" / "desktop"),
             "--paths", str(ROOT), *data_args, str(ROOT / launcher)])


def verify(output: Path):
    with tempfile.TemporaryDirectory(prefix="vps-proxy-package-check-") as temporary:
        env = dict(os.environ)
        # Verification must never write a real user's SSH or application state.
        env.update({"LOCALAPPDATA": temporary, "APPDATA": temporary, "USERPROFILE": temporary,
                    "HOME": temporary, "XDG_STATE_HOME": temporary, "PYTHONUTF8": "1"})
        for name in BINARIES:
            run([str(output / name), "--self-test"], env=env)
        run([str(output / "Proxy-Setup-Console.exe"), "--config",
             str(ROOT / "examples" / "setup.example.json"), "--plan", "--no-pause"], env=env)
        if (Path(temporary) / ".ssh").exists() or (Path(temporary) / "vps-proxy-setup").exists():
            raise RuntimeError("Package self-test unexpectedly created persistent user state")


def package(output: Path) -> Path:
    archive_path = ROOT / "dist" / f"Proxy-Setup-Assistant-{VERSION}-windows-x64.zip"
    files = {name: output / name for name in BINARIES}
    files.update({"README.md": ROOT / "README.md", "LICENSE": ROOT / "LICENSE",
                  "docs/desktop.md": ROOT / "docs" / "desktop.md",
                  "docs/operations.md": ROOT / "docs" / "operations.md",
                  "examples/setup.example.json": ROOT / "examples" / "setup.example.json"})
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, path in files.items():
            archive.write(path, name)
        notices = ["Third-party components and build tools", "", "Python " + platform.python_version()]
        python_license = Path(sys.base_prefix) / "LICENSE.txt"
        if not python_license.is_file():
            raise RuntimeError("Python distribution license file is missing")
        archive.write(python_license, "licenses/Python-LICENSE.txt")
        for component in ("tcl", "tk"):
            for terms in (Path(sys.base_prefix) / "tcl").glob(component + "*/license.terms"):
                archive.write(terms, "licenses/" + terms.parent.name + "-license.terms")
                notices.append(terms.parent.name + " (terms supplied by the Python distribution)")
        for name in ("PyYAML", "PyInstaller", "pyinstaller-hooks-contrib"):
            metadata = distribution(name)
            notices.append(name + " " + metadata.version)
            licenses = [entry for entry in metadata.files or () if entry.name.lower().startswith(("license", "copying", "notice"))]
            if not licenses:
                raise RuntimeError(name + " license files are missing")
            for index, entry in enumerate(licenses):
                archive.write(metadata.locate_file(entry), f"licenses/{name}-{index}-{entry.name}")
        notices.extend(("", "License texts from the installed distributions are included in licenses/.",
                        "PyInstaller and hooks are build tools; consult their supplied licensing exception text.",
                        "Upstream VPS programs are downloaded separately and retain their own licenses."))
        archive.writestr("THIRD-PARTY-NOTICES.txt", "\n".join(notices) + "\n")
        checksums = "".join(hashlib.sha256((output / name).read_bytes()).hexdigest() + "  " + name + "\n" for name in BINARIES)
        archive.writestr("SHA256SUMS.txt", checksums)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    archive_path.with_suffix(".zip.sha256").write_text(digest + "  " + archive_path.name + "\n", encoding="ascii")
    return archive_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true", help="Recheck and package existing dist/desktop executables")
    args = parser.parse_args()
    if sys.platform != "win32" or struct.calcsize("P") != 8 or platform.machine().lower() not in {"amd64", "x86_64"}:
        parser.error("Build on Windows x64 using 64-bit Python 3.10+ with Tkinter")
    output = ROOT / "dist" / "desktop"
    output.mkdir(parents=True, exist_ok=True)
    if not args.skip_build:
        build(output)
    verify(output)
    archive = package(output)
    print("Verified release archive: " + str(archive))
    print("Single-file launcher: " + str(build_launcher(VERSION, archive, ROOT / "dist" / "Proxy-Setup-Assistant.bat")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
