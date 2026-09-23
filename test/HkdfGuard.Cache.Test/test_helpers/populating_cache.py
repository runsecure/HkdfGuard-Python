"""Python port of test/HkdfGuard.Cache.Test/TestHelpers/PopulatingCache.cs."""

from collections.abc import Callable

from hkdfguard_abstractions import IDataProtectionKey, ProtectedCacheBase


class PopulatingCache(ProtectedCacheBase):
    """A minimal ProtectedCacheBase subclass whose _try_populate is driven directly by the test -
    lets tests exercise the base class's cache-miss-then-populate path without depending on any
    real external source.
    """

    def __init__(self, data_protection_key: IDataProtectionKey) -> None:
        super().__init__(data_protection_key)
        self.try_populate_call_count = 0
        self.on_try_populate: Callable[[str], bool] | None = None

    def seed(self, name: str, plaintext: str) -> None:
        self._set_encrypted(name, self._encrypt_str(plaintext))

    def _try_populate(self, name: str) -> bool:
        self.try_populate_call_count += 1
        return self.on_try_populate(name) if self.on_try_populate is not None else False
