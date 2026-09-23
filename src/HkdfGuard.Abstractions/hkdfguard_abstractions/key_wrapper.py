"""Python port of HkdfGuard.Abstractions/IKeyWrapper.cs."""

from abc import ABC, abstractmethod


class IKeyWrapper(ABC):
    """Protects (encrypt) and reveals (decrypt) an encryption key against a single, implicitly
    identified KEK (e.g. a native KMS-backed key, identified by service name at construction).
    decrypt takes the wrapped payload as an explicit argument on every call, so one instance can
    reveal any number of different wrapped keys sharing the same KEK - it holds no wrapped payload
    of its own.
    """

    @abstractmethod
    def encrypt(self, plaintext: bytes, result: bytearray) -> int:
        """Protects an encryption key. Returns the number of bytes written to result."""

    @abstractmethod
    def decrypt(self, wrapped: bytes, result: bytearray) -> int:
        """Reveals a previously-wrapped key. Returns the number of bytes written to result."""

    @abstractmethod
    def generate_and_wrap(self, result: bytearray) -> int:
        """Generates a fresh key and immediately protects it against the same KEK this instance
        wraps/reveals against - the plaintext key never crosses this call's return value. Returns
        the number of bytes written to result.
        """
