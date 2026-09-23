"""Python port of HkdfGuard.Abstractions/IEncryptedFormatProvider.cs."""

from abc import ABC, abstractmethod

from .key_tracking_value import KeyTrackingValue


class IEncryptedFormatProvider(ABC):
    @abstractmethod
    def format(self, value: KeyTrackingValue) -> str: ...

    @abstractmethod
    def parse(self, encrypted: str) -> KeyTrackingValue: ...

    @abstractmethod
    def get_max_decrypted_length(self, encrypted: str) -> int:
        """Computes an upper bound on the decrypted plaintext's length (bytes or chars - safe for
        either, since UTF-8-decoded char count never exceeds byte count) from the Base64
        payload's length alone, without decoding it. AEAD ciphertext is always at least as long
        as the plaintext it encloses, so the actual decrypted length is this value or less -
        always safe to size a result buffer to what this returns.
        """
