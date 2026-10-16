"""wave — verbatim split from poison.py (no logic changes)."""
from urllib.parse import urlparse

from core.ui import w


def _hold_for_backoff(state, what: str) -> bool:
    """True while the target host sits inside a 429 backoff window.

    AsyncNetworkEngine already refuses its own requests during backoff, but
    ffuf and the raw-socket modules bypass the engine — without this check,
    'backoff' only throttles half the traffic while the other half keeps
    hammering a host that just said no. Logs once per wave.
    """
    if not state.services:
        return False
    limiter = getattr(state.async_engine, "host_limiter", None)
    checker = getattr(limiter, "is_backing_off", None)
    if not callable(checker):
        return False
    host = urlparse(state.services[0]["url"]).hostname or ""
    try:
        held = checker(host) is True
    except Exception:
        return False
    if held and state._backoff_notice_wave != state.wave:
        state._backoff_notice_wave = state.wave
        w(f"Host in 429 backoff — holding {what}")
    return held
