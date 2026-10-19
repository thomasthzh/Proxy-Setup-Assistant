"""Interactive OpenSSH helper for the desktop wizard and standalone CLI use."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import zipfile

from .. import __version__
from ..cli import build_payload, main as cli_main


def self_test() -> int:
    """Exercise frozen payload resources without connecting or writing user state."""
    import yaml

    assert yaml.safe_load("enabled: true")["enabled"] is True
    with tempfile.TemporaryDirectory(prefix="vps-proxy-self-test-") as directory:
        payload = Path(directory) / "payload.zip"
        build_payload(payload, {})
        with zipfile.ZipFile(payload) as archive:
            names = set(archive.namelist())
            required = {"server/installer.py", "server/assets.json", "input.json"}
            if not required <= names or not any(name.startswith("server/subscription/") and name.endswith(".py") for name in names):
                raise RuntimeError("Packaged server payload is incomplete")
            json.loads(archive.read("server/assets.json"))
    print("Proxy-Setup-Console " + __version__ + " self-test passed")
    return 0


def main(argv=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--self-test"]:
        return self_test()
    pause = not any(arg in arguments for arg in ("--no-pause", "--version", "--help", "-h"))
    arguments = [arg for arg in arguments if arg != "--no-pause"]
    try:
        try:
            return cli_main(arguments)
        except SystemExit as error:
            return error.code if isinstance(error.code, int) else 1
        except Exception as error:
            # Unexpected failures must be visible before the final pause too.
            # Exception text may contain a private URL, so show only its type.
            print("错误：控制台遇到未预期故障（" + type(error).__name__ + "）。请保留现有配置并检查环境。", file=sys.stderr)
            return 1
    finally:
        if pause:
            try:
                input("\n运行已结束。请查看上方结果；按 Enter 关闭窗口。")
            except (EOFError, KeyboardInterrupt):
                pass


if __name__ == "__main__":
    raise SystemExit(main())
