"""
Pidanos Core Module
~~~~~~~~~~~~~~~~~~~

This module contains the core functionality for DNS filtering and blocking.
"""

__version__ = "1.0.0"
__author__ = "Pidanos Team"

from .blocker import DNSBlocker
from .modules import CoreModules
from .dns_parser import DNSParser
from .cache_manager import CacheManager
from .filter_engine import FilterEngine
from .statistics import StatisticsCollector

__all__ = [
    "DNSBlocker",
    "CoreModules",
    "DNSParser",
    "CacheManager",
    "FilterEngine",
    "StatisticsCollector"
]