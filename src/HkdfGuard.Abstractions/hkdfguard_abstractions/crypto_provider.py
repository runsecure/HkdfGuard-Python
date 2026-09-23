"""Python port of HkdfGuard.Abstractions/ICryptoProvider.cs.

C#'s two Encrypt/Decrypt overloads (with and without an aad parameter) collapse into a single
method with aad defaulting to b"" - Python has no method overloading, and a default parameter is
the direct, idiomatic equivalent (the same substitution already made for IKeyWrapper's callers).
IDisposable becomes the context-manager protocol (__enter__/__exit__ calling close()), Python's
standard analogue for a type that owns a resource which must be released deterministically.
"""

from abc import ABC, abstractmethod
from typing import Self


class ICryptoProvider(ABC):
    """Tracks a single cached crypto session, refreshing it (from a fresh key reveal/unwrap) once
    it expires, and closing the outgoing session as it does. Callers should call encrypt/decrypt
    on every operation rather than caching results themselves, so they always see a non-expired
    session.
    """

    @abstractmethod
    def encrypt(self, plaintext: bytearray, result: bytearray, aad: bytes = b"") -> int:
        """Encrypts plaintext, authenticating aad alongside it if given. Returns the number of
        bytes written to result. plaintext must be mutable: an implementation may zero it in
        place once encryption completes, as HkdfGuard.CryptoSession.AesGcm256's does - callers
        should not read plaintext again afterward.
        """

    @abstractmethod
    def decrypt(self, ciphertext: bytes, result: bytearray, aad: bytes = b"") -> int:
        """Decrypts ciphertext, verifying it (and aad, if given) was produced by a matching
        encrypt call. Returns the number of bytes written to result.
        """

    @abstractmethod
    def close(self) -> None:
        """Releases the underlying cryptographic session."""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()
