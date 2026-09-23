"""Python port of test/HkdfGuard.Cache.Test/TestHelpers/ThrowingReadOnlyCache.cs."""

from hkdfguard_abstractions import IProtectedReadOnlyCache


class ThrowingReadOnlyCache(IProtectedReadOnlyCache):
    """An IProtectedReadOnlyCache whose every member raises - exercises
    ProtectedCacheCollection's except blocks without depending on a specific real failure mode.
    """

    def __init__(self, exception: BaseException) -> None:
        self._exception = exception

    def decrypt(self, name: str, result: bytearray) -> int:
        raise self._exception

    def decrypt_str(self, name: str) -> str | None:
        raise self._exception

    def try_get_max_decrypted_length(self, name: str) -> int | None:
        raise self._exception
