#!/usr/bin/env python3
"""Entry point — parsing + orchestration live in core.cli_parser (Tahap 2).

Re-exports every name the test-suite imports via `from verd import ...`
and keeps the `verd:main` console entry (pyproject.toml) working.
"""
import asyncio
import sys

if sys.version_info < (3, 12):
    sys.stderr.write(
        f"\033[91m[!] Verdamt-Snipe requires Python 3.12 or newer. "
        f"Detected Python {sys.version.split()[0]}.\033[0m\n"
    )
    sys.exit(1)

from core.cli_parser import (  # noqa: F401  (re-export for tests/legacy)
    parse_target, parse_mode, parse_scan_args, parse_cli_headers,
    parse_scan_policy_options, _flag_value,
    _VALUE_FLAGS, _SHORT_ALIASES,
    seed_session_headers, phase_verify_report,
    main_cli, _execute_mode,
)
from core.ui import R, N  # noqa: F401


def main():
    try:
        asyncio.run(main_cli())
    except KeyboardInterrupt:
        print(f"\n{R}[!] Interrupted by user. Exiting.{N}")
        sys.exit(0)


if __name__ == "__main__":
    main()
