"""Python port of HkdfGuard.DataEncryptionKey/PipelineDataEncryptionKey.cs."""

from typing import Self

from hkdfguard_abstractions import ICryptoProvider
from hkdfguard_abstractions.array_utility import zero_memory

from .encryption_key_base import EncryptionKeyBase


class PipelineDataEncryptionKey(EncryptionKeyBase):
    """An IDataEncryptionKey backed by a plain 32-byte DEK, used directly - never wrapped, never
    unwrapped. Meant for a pipeline that needs to encrypt secrets in-flight before a durable KEK
    exists yet: build one via PipelineKeyFactory, encrypt whatever needs protecting during the
    pipeline, then read the same plaintext DEK back via as_bytearray() at the end of the chain to
    hand off to the platform's native "initialize" CLI utility, which independently wraps/
    registers it against a real KEK. close() zeroes the DEK.
    """

    def __init__(self, provider: ICryptoProvider, dek: bytearray) -> None:
        super().__init__(provider)
        self._provider = provider
        self._dek = dek

    def as_bytearray(self) -> bytearray:
        """The plain, plaintext DEK this instance protects with - e.g. to hand off to the
        platform's native "initialize" CLI utility once the pipeline finishes. Returns the live
        buffer, not a copy - it reflects close()'s zeroing.
        """
        return self._dek

    def close(self) -> None:
        """Closes the underlying provider, and zeroes the plaintext DEK."""
        self._provider.close()
        zero_memory(self._dek)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()
