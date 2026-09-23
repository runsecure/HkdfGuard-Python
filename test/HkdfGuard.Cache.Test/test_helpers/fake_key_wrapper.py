"""Python port of test/HkdfGuard.Cache.Test/TestHelpers/FakeKeyWrapper.cs."""

from hkdfguard_abstractions import IKeyWrapper


class FakeKeyWrapper(IKeyWrapper):
    """An IKeyWrapper that always reveals the same fixed key - isolates ProtectedCache tests from
    the real blob/file/OS-storage machinery (already covered elsewhere) while still exercising
    real AES-GCM via a real ICryptoProvider.
    """

    def __init__(self, key: bytes) -> None:
        self._key = key

    def encrypt(self, plaintext: bytes, result: bytearray) -> int:
        raise NotImplementedError("FakeKeyWrapper only supports decrypt.")

    def decrypt(self, wrapped: bytes, result: bytearray) -> int:
        result[: len(self._key)] = self._key
        return len(self._key)

    def generate_and_wrap(self, result: bytearray) -> int:
        raise NotImplementedError("FakeKeyWrapper only supports decrypt.")
