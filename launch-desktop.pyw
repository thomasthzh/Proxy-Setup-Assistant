"""Windowed entry point; keep its console helper beside the packaged executable."""

from vps_proxy_setup.desktop.app import main

if __name__ == "__main__":
    raise SystemExit(main())
