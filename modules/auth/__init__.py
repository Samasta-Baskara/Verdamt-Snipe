# Re-export for backward compatibility
from .tester import AuthTester
from .bypass import WAFBypass, RateLimiter

__all__ = ["AuthTester", "WAFBypass", "RateLimiter"]
