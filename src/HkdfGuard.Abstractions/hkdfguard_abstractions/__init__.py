"""Shared interfaces and cross-cutting types for HkdfGuard components. Partial Python port of
HkdfGuard.Abstractions - only the members needed by ported dependents exist so far.
"""

from .crypto_provider import ICryptoProvider
from .data_protection_key import IDataProtectionKey
from .data_protector import IDataProtector
from .encrypted_format_provider import IEncryptedFormatProvider
from .errors import HkdfGuardCryptographicError
from .key_tracking_value import KeyTrackingValue
from .key_wrapper import IKeyWrapper
from .protected_cache import IProtectedCache
from .protected_cache_base import ProtectedCacheBase
from .protected_read_only_cache import IProtectedReadOnlyCache

__all__ = [
    "HkdfGuardCryptographicError",
    "ICryptoProvider",
    "IDataProtectionKey",
    "IDataProtector",
    "IEncryptedFormatProvider",
    "IKeyWrapper",
    "IProtectedCache",
    "IProtectedReadOnlyCache",
    "KeyTrackingValue",
    "ProtectedCacheBase",
]
