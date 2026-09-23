"""Highly concurrent, encrypted in-memory name/value cache for HkdfGuard. Python port of
HkdfGuard.Cache.
"""

from .protected_cache import ProtectedCache
from .protected_cache_collection import ProtectedCacheCollection

__all__ = [
    "ProtectedCache",
    "ProtectedCacheCollection",
]
