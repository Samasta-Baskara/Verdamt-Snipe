# Re-export for backward compatibility
from .client_side.dom_xss import DOMXSSScanner
from .recon_crawlers.api_profiler import APIProfiler
from .recon_crawlers.browser_recon import BrowserRecon
from .recon_crawlers.crawler import DeepCrawler

__all__ = ["APIProfiler", "BrowserRecon", "DOMXSSScanner", "DeepCrawler"]
