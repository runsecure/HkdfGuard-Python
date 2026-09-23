"""Python port of HkdfGuard.DataEncryptionKey/DummyKeyWrapper.cs.

Stands in for the IKeyWrapper the pipeline flow's ICryptoProviderFactory.create_for_pipeline
requires but never actually calls (the DEK is used as-is, never wrapped) - every member is an
inert no-op.
"""

from hkdfguard_abstractions import IKeyWrapper


class DummyKeyWrapper(IKeyWrapper):
    def encrypt(self, plaintext: bytes, result: bytearray) -> int:
        return 0

    def decrypt(self, wrapped: bytes, result: bytearray) -> int:
        return 0

    def generate_and_wrap(self, result: bytearray) -> int:
        return 0
