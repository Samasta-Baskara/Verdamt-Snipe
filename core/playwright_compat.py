"""Optional Playwright dependency gate.

One import site for every module that gates browser features on
Playwright being installed (11 modules used to carry an identical
try/except copy).
"""

try:
    from playwright.async_api import Request, async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised on playwright-less installs
    # Keep annotations resolvable (request: Request) when absent.
    from typing import Any as _Any
    async_playwright = Request = _Any
    PLAYWRIGHT_AVAILABLE = False

__all__ = ["PLAYWRIGHT_AVAILABLE", "Request", "async_playwright"]
