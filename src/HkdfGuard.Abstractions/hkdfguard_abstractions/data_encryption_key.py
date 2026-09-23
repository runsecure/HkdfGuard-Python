"""Python port of HkdfGuard.Abstractions/IDataEncryptionKey.cs."""

from abc import ABC, abstractmethod


class IDataEncryptionKey(ABC):
    @abstractmethod
    def encrypt(self, plaintext: bytearray, aad: bytes = b"") -> bytes:
        """Protects an encryption key. Returns the encrypted key, ready to be stored. plaintext
        must be mutable: an implementation may zero it in place once encryption completes -
        callers should not read plaintext again afterward.
        """

    @abstractmethod
    def decrypt(self, ciphertext: bytes, result: bytearray, aad: bytes = b"") -> int:
        """Reveals an encryption key. Returns the number of bytes written to result."""
