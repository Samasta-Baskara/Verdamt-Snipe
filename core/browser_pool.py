"""Singleton Shared Playwright Browser Instance Pool.

Prevents browser startup/teardown bottleneck by reusing a single Chromium process
across all Playwright security modules (CSRF, PostMessage, Clickjacking, WS, Proto, etc).
"""

import asyncio
from typing import Any, Optional

from core.playwright_compat import PLAYWRIGHT_AVAILABLE, async_playwright
from core.ua import CHROME_WIN


class SharedBrowserPool:
    """Thread-safe & Async-safe Playwright Browser Singleton Pool."""

    _instance: Optional["SharedBrowserPool"] = None
    _lock = asyncio.Lock()

    def __init__(self):
        self._pw: Any | None = None
        self._browser: Any | None = None

    @classmethod
    async def get_browser(cls) -> Any | None:
        """Get or initialize shared browser instance."""
        if not PLAYWRIGHT_AVAILABLE:
            return None

        if cls._instance is None:
            async with cls._lock:
                if cls._instance is None:
                    pool = cls()
                    await pool._init_browser()
                    cls._instance = pool

        return cls._instance._browser

    async def _init_browser(self):
        try:
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--blink-settings=imagesEnabled=false",
                ]
            )
        except Exception:
            self._browser = None

    @classmethod
    async def new_context(cls, proxy: str | None = None) -> Any | None:
        """Create an isolated lightweight BrowserContext from the shared browser pool."""
        browser = await cls.get_browser()
        if not browser:
            return None

        kwargs: dict[str, Any] = {
            "viewport": {"width": 1280, "height": 720},
            "user_agent": CHROME_WIN,
            "ignore_https_errors": True,
        }
        if proxy:
            kwargs["proxy"] = {"server": proxy}

        context = await browser.new_context(**kwargs)
        # Block non-essential media & CSS assets globally across all Playwright modules
        await context.route(
            "**/*.{png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,ico,mp4,webm,pdf}",
            lambda route: route.abort()
        )
        return context

    @classmethod
    async def shutdown(cls):
        """Clean shutdown of the shared browser process."""
        if cls._instance and cls._instance._browser:
            async with cls._lock:
                if cls._instance and cls._instance._browser:
                    try:
                        await cls._instance._browser.close()
                        if cls._instance._pw:
                            await cls._instance._pw.stop()
                    except Exception:
                        pass
                    cls._instance = None
