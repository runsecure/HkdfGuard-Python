"""Python port of test/HkdfGuard.DataEncryptionKey.Test/TestHelpers/RecordingCryptoProviderFactory.cs."""

from hkdfguard_abstractions import ICryptoProvider, ICryptoProviderFactory, IKeyWrapper
from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProviderFactory


class RecordingCryptoProviderFactory(ICryptoProviderFactory):
    """An ICryptoProviderFactory that delegates to a real AesGcmCryptoProviderFactory (so callers
    get a genuinely working ICryptoProvider back) while recording the arguments each method was
    called with - lets KeyRingBuilder tests assert exactly what it passes through without
    depending on AesGcmCryptoProvider exposing its own configuration for inspection.
    """

    def __init__(self) -> None:
        self._inner = AesGcmCryptoProviderFactory()
        self.create_expiry_seconds_calls: list[int] = []
        self.create_ephemeral_expiry_seconds_calls: list[int] = []

    def create(self, wrapper: IKeyWrapper, wrapped: bytes, expiry_seconds: int) -> ICryptoProvider:
        self.create_expiry_seconds_calls.append(expiry_seconds)
        return self._inner.create(wrapper, wrapped, expiry_seconds)

    def create_ephemeral(self, wrapper: IKeyWrapper, expiry_seconds: int) -> ICryptoProvider:
        self.create_ephemeral_expiry_seconds_calls.append(expiry_seconds)
        return self._inner.create_ephemeral(wrapper, expiry_seconds)

    def create_for_pipeline(self, wrapper: IKeyWrapper, not_wrapped: bytes) -> ICryptoProvider:
        return self._inner.create_for_pipeline(wrapper, not_wrapped)
