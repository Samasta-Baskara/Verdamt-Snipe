"""Single source of truth for User-Agent strings.

The tool used to hardcode UA lists in 5+ places with mutually
inconsistent browser versions (Chrome 118/119/120/122 in the same
scan) — a trivial tell for any WAF correlating TLS fingerprint,
Client-Hints and UA generation. Every consumer draws from these pools
so the fingerprint family stays coherent per run.
"""
import random

# Coherent browser generation (late-2024 era builds). Keep versions in
# sync across engines when bumping — one generation, one story.
CHROME_VERSION = "131.0.0.0"
FIREFOX_VERSION = "133.0"
SAFARI_VERSION = "18.1"

CHROME_WIN = (
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    f"(KHTML, like Gecko) Chrome/{CHROME_VERSION} Safari/537.36"
)
CHROME_MAC = (
    f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    f"(KHTML, like Gecko) Chrome/{CHROME_VERSION} Safari/537.36"
)
CHROME_LINUX = (
    f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    f"(KHTML, like Gecko) Chrome/{CHROME_VERSION} Safari/537.36"
)
FIREFOX_LINUX = (
    f"Mozilla/5.0 (X11; Linux x86_64; rv:{FIREFOX_VERSION}) "
    f"Gecko/20100101 Firefox/{FIREFOX_VERSION}"
)
SAFARI_MAC = (
    f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    f"(KHTML, like Gecko) Version/{SAFARI_VERSION} Safari/605.1.15"
)
SAFARI_IOS = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
)

# Generic fallback (noisier than a full string; used for raw paths).
DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
BARE_UA = "Mozilla/5.0"

# Bot UAs — only for WAF header spoofing (some WAFs whitelist crawlers).
BOT_UAS = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
)

# Pools — every rotation in the codebase picks from these.
STEALTH_UAS = (CHROME_WIN, CHROME_MAC, FIREFOX_LINUX)
SEARCH_UAS = (CHROME_WIN, SAFARI_MAC, FIREFOX_LINUX)
BYPASS_UAS = (CHROME_WIN, SAFARI_MAC, FIREFOX_LINUX, SAFARI_IOS) + BOT_UAS


def pick(pool=STEALTH_UAS) -> str:
    """Random UA from a pool (default: stealth pool)."""
    return random.choice(pool)
