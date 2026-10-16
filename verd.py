#!/usr/bin/env python3
"""Entry point — parsing lives in core.cli_parser, orchestration in
core/orchestrator.py, mode runners in core/modes.py.

Re-exports every name the test-suite imports via `from verd import ...`
and keeps the `verd:main` console entry (pyproject.toml) working.
"""
import asyncio
import sys

from core.cli_parser import (  # noqa: F401  (re-export for tests/legacy)
    _SHORT_ALIASES,
    _VALUE_FLAGS,
    _flag_value,
    parse_cli_headers,
    parse_mode,
    parse_scan_args,
    parse_scan_policy_options,
    parse_target,
    seed_session_headers,
)
from core.modes import _execute_mode, phase_verify_report  # noqa: F401
from core.orchestrator import main_cli
from core.ui import N, R


def main():
    try:
        asyncio.run(main_cli())
    except KeyboardInterrupt:
        print(f"\n{R}[!] Interrupted by user. Exiting.{N}")
        sys.exit(0)


if __name__ == "__main__":
    main()
