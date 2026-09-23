"""Python port of HkdfGuard.Abstractions/IProtectedReadOnlyCache.cs.

C#'s byte-span and char-span overloads (Decrypt(name, Span<byte>) / Decrypt(name, Span<char>))
become two differently-named methods here rather than one method overloaded on type: decrypt
(writes into a caller-supplied bytearray, mirroring Span<byte>) and decrypt_str (returns a new
str directly, since Python strings can't be decrypted into in place the same way - the same
simplification already made for IDataProtector.decrypt). try_get_max_decrypted_length returns
Optional[int] instead of a bool-plus-out-parameter pair, the same substitution already made for
IKeyWrapper.decrypt's caller-facing helpers elsewhere in this port.
"""

from abc import ABC, abstractmethod


class IProtectedReadOnlyCache(ABC):
    """Read surface of a highly concurrent name -> encrypted-value cache backed by a single
    IDataEncryptionKey. Names are compared case-insensitively. decrypt/decrypt_str reveal a
    stored value, returning 0/None for a missing name rather than raising. Nothing here ever
    holds plaintext beyond the duration of a single call - only the encrypted bytes are retained
    internally.
    """

    @abstractmethod
    def decrypt(self, name: str, result: bytearray) -> int:
        """Decrypts the value stored under name into result. Returns the number of bytes
        written, or 0 if no value is stored under name.
        """

    @abstractmethod
    def decrypt_str(self, name: str) -> str | None:
        """Decrypts the value stored under name as a UTF-8-decoded string. Returns None if no
        value is stored under name.
        """

    @abstractmethod
    def try_get_max_decrypted_length(self, name: str) -> int | None:
        """Computes an upper bound on how many bytes or chars decrypt/decrypt_str will produce
        for the value stored under name, so a result buffer can be sized without decrypting
        first. Returns None if no value is stored under name.
        """
