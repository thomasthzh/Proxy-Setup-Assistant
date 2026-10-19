"""Thin frozen-console entry point; implementation also runs as an installed module."""

from vps_proxy_setup.desktop.console import main


if __name__ == "__main__":
    raise SystemExit(main())
