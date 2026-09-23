"""Python port of HkdfGuard.CryptoSession.AesGcm256/AesGcmCryptoProviderFactory.cs."""

from hkdfguard_abstractions import ICryptoProvider, ICryptoProviderFactory, IKeyWrapper

from .provider import AesGcmCryptoProvider

# IKeyWrapper.generate_and_wrap is implementation-agnostic about its own wrapped-payload
# format/size (a native KMS library's is a small fixed size, at most a few hundred bytes) -
# over-allocate generously and trim to what it actually wrote.
_GENERATE_AND_WRAP_BUFFER_LENGTH = 512


class AesGcmCryptoProviderFactory(ICryptoProviderFactory):
    """Builds AesGcmCryptoProvider instances."""

    def create(self, wrapper: IKeyWrapper, wrapped: bytes, expiry_seconds: int) -> ICryptoProvider:
        return AesGcmCryptoProvider(wrapper, wrapped, expiry_seconds)

    def create_ephemeral(self, wrapper: IKeyWrapper, expiry_seconds: int) -> ICryptoProvider:
        buffer = bytearray(_GENERATE_AND_WRAP_BUFFER_LENGTH)
        written = wrapper.generate_and_wrap(buffer)
        return AesGcmCryptoProvider(wrapper, bytes(buffer[:written]), expiry_seconds)

    def create_for_pipeline(self, wrapper: IKeyWrapper, not_wrapped: bytes) -> ICryptoProvider:
        # Same-package access to a leading-underscore member - the Python analogue of a
        # package-private constructor.
        return AesGcmCryptoProvider._for_pipeline(wrapper, not_wrapped)
