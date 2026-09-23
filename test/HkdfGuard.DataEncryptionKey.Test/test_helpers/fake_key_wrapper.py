"""Python port of test/HkdfGuard.DataEncryptionKey.Test/TestHelpers/FakeKeyWrapper.cs."""

from hkdfguard_abstractions import IKeyWrapper


class FakeKeyWrapper(IKeyWrapper):
    """An IKeyWrapper that always reveals/generates the same fixed key, tracking how many times
    decrypt/generate_and_wrap were called - isolates KeyWrappedDataEncryptionKey/
    EphemeralDataEncryptionKey/KeyRing tests from the real native KMS machinery while still
    exercising real AES-GCM via a real ICryptoProvider.
    """

    def __init__(self, key: bytes) -> None:
        self._key = key
        self.decrypt_call_count = 0
        self.generate_and_wrap_call_count = 0

        #: When set, decrypt raises this instead of revealing the key - lets tests exercise a
        #: KeyWrappedDataEncryptionKey encrypt/decrypt except block without depending on the real
        #: cipher failing.
        self.throw_on_decrypt: BaseException | None = None

    def encrypt(self, plaintext: bytes, result: bytearray) -> int:
        raise NotImplementedError("FakeKeyWrapper only supports decrypt.")

    def decrypt(self, wrapped: bytes, result: bytearray) -> int:
        self.decrypt_call_count += 1
        if self.throw_on_decrypt is not None:
            raise self.throw_on_decrypt

        result[: len(self._key)] = self._key
        return len(self._key)

    def generate_and_wrap(self, result: bytearray) -> int:
        self.generate_and_wrap_call_count += 1
        result[: len(self._key)] = self._key
        return len(self._key)
