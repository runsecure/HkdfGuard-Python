"""Python port of HkdfGuard.DataEncryptionKey/EphemeralDataEncryptionKey.cs."""

from collections.abc import Callable

from hkdfguard_abstractions import ICryptoProvider, IDataProtectionKey, IKeyWrapper
from hkdfguard_diagnostics import ActivityNames, ComponentTelemetry, HkdfGuardTelemetry

from .key_wrapped_data_encryption_key import KeyWrappedDataEncryptionKey

# IKeyWrapper.generate_and_wrap is implementation-agnostic about its own wrapped-payload
# format/size (a native KMS library's is a small fixed size, at most a few hundred bytes) -
# over-allocate generously and trim to what it actually wrote, the same as
# KeyWrappedDataEncryptionKey's _MAX_CIPHER_OVERHEAD does for cipher output.
_MAX_WRAPPED_LENGTH = 512

_TELEMETRY = HkdfGuardTelemetry.DATA_PROTECTION


class EphemeralDataEncryptionKey(IDataProtectionKey):
    """An IDataProtectionKey whose own DEK is never read from a file on disk - key_wrapper
    generates and immediately wraps a fresh one in the constructor (see
    IKeyWrapper.generate_and_wrap); the plaintext DEK itself never crosses that call's return
    value. session_provider_factory then binds an ICryptoProvider to that wrapped payload (this
    class can't construct one directly - a concrete provider lives in whichever cipher package
    the caller chose, not here). Every encrypt/decrypt delegates to an inner
    KeyWrappedDataEncryptionKey built from that provider, the same as a durable, file-backed key
    would use.
    """

    def __init__(
        self,
        key_wrapper: IKeyWrapper,
        session_provider_factory: Callable[[IKeyWrapper, bytes], ICryptoProvider],
    ) -> None:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.DataProtection.EPHEMERAL_KEY_INITIALIZE) as span:
            try:
                buffer = bytearray(_MAX_WRAPPED_LENGTH)
                written = key_wrapper.generate_and_wrap(buffer)
                wrapped = bytes(buffer[:written])

                session_provider = session_provider_factory(key_wrapper, wrapped)
                self._inner = KeyWrappedDataEncryptionKey(session_provider)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def encrypt(self, plaintext: bytearray, aad: bytes = b"") -> bytes:
        return self._inner.encrypt(plaintext, aad)

    def decrypt(self, ciphertext: bytes, result: bytearray, aad: bytes = b"") -> int:
        return self._inner.decrypt(ciphertext, result, aad)
