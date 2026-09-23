"""Python port of test/HkdfGuard.DataEncryptionKey.Test/TestHelpers/RecordingFormatProvider.cs."""

from hkdfguard_abstractions import IEncryptedFormatProvider, KeyTrackingValue
from hkdfguard_dataencryptionkey import DefaultFormatProvider


class RecordingFormatProvider(IEncryptedFormatProvider):
    """A real DefaultFormatProvider wrapped with call tracking, so a test can prove a component
    (e.g. KeyRing/KeyRingBuilder) actually uses the specific IEncryptedFormatProvider instance it
    was given, rather than some other one.
    """

    def __init__(self) -> None:
        self._inner = DefaultFormatProvider()
        self.format_called = False
        self.parse_called = False

    def format(self, value: KeyTrackingValue) -> str:
        self.format_called = True
        return self._inner.format(value)

    def parse(self, encrypted: str) -> KeyTrackingValue:
        self.parse_called = True
        return self._inner.parse(encrypted)

    def get_max_decrypted_length(self, encrypted: str) -> int:
        return self._inner.get_max_decrypted_length(encrypted)
