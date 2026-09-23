"""Python port of test/HkdfGuard.CryptoSession.AesGcm256.Test/TestHelpers/FakeKeyWrapper.cs."""

import secrets

from hkdfguard_abstractions import IKeyWrapper


class FakeKeyWrapper(IKeyWrapper):
    """An IKeyWrapper that always reveals a fresh random key, tracking how many times decrypt was
    called - isolates AesGcmCryptoProvider tests from any real native KMS machinery.
    """

    def __init__(self) -> None:
        self.decrypt_call_count = 0

        #: When set, decrypt raises this instead of revealing a key.
        self.throw_on_decrypt: BaseException | None = None

    def encrypt(self, plaintext: bytes, result: bytearray) -> int:
        raise NotImplementedError

    def decrypt(self, wrapped: bytes, result: bytearray) -> int:
        self.decrypt_call_count += 1
        if self.throw_on_decrypt is not None:
            raise self.throw_on_decrypt

        result[:] = secrets.token_bytes(len(result))
        return len(result)

    def generate_and_wrap(self, result: bytearray) -> int:
        raise NotImplementedError
