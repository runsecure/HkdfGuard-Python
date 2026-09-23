"""Python port of HkdfGuard.Abstractions/IDataProtector.cs.

C#'s Decrypt writes into a caller-supplied Span<char> result, sized ahead of time via
GetMaxDecryptedLength, purely to avoid an extra string allocation holding decrypted plaintext.
Python strings are always immutable - there is no in-place char buffer to decrypt into - so
decrypt here just returns a new str, the same way encrypt already does on both sides.
get_max_decrypted_length stays, since IEncryptedFormatProvider still needs it and it is otherwise
unused.
"""

from abc import ABC, abstractmethod


class IDataProtector(ABC):
    """A named, string-level data protector: the name given at construction is used as the
    Additional Auth Data for every encrypt/decrypt, binding a protected value to the purpose it
    was protected for so it can't be reused under a different one. encrypt/decrypt resolve the
    actual IDataProtectionKey to use from a KeyRing, rather than holding one key permanently.
    """

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """Encrypts a plaintext string and formats the result via the configured
        IEncryptedFormatProvider.
        """

    @abstractmethod
    def decrypt(self, encrypted: str) -> str:
        """Parses a formatted encrypted string via the configured IEncryptedFormatProvider and
        decrypts it.
        """

    @abstractmethod
    def get_max_decrypted_length(self, encrypted: str) -> int:
        """Computes an upper bound on how long decrypt's result will be for the given formatted
        string, without decrypting it.
        """
