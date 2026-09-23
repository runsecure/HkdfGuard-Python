"""Python port of HkdfGuard.DataEncryptionKey/KeyWrappedDataEncryptionKey.cs."""

from hkdfguard_abstractions import ICryptoProvider, IDataProtectionKey
from hkdfguard_diagnostics import ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry

_MAX_CIPHER_OVERHEAD = 64

_TELEMETRY = HkdfGuardTelemetry.DATA_PROTECTION


class KeyWrappedDataEncryptionKey(IDataProtectionKey):
    """An IDataProtectionKey backed by one wrapped DEK payload. provider owns revealing that
    payload's key (from a fresh unwrap, once its cached session expires) and performing the
    actual data encrypt/decrypt with it - see ICryptoProvider. Every operation resolves the
    provider's current session fresh rather than caching it, so it always uses a non-expired one.
    """

    def __init__(self, provider: ICryptoProvider) -> None:
        self._provider = provider

    def encrypt(self, plaintext: bytearray, aad: bytes = b"") -> bytes:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.DataProtection.KEY_WRAPPED_KEY_ENCRYPT) as span:
            _TELEMETRY.log_sensitive_operation(
                span,
                ActivityNames.DataProtection.KEY_WRAPPED_KEY_ENCRYPT,
                (AttributeNames.PLAINTEXT_LENGTH, len(plaintext)),
                (AttributeNames.AAD_LENGTH, len(aad)),
            )
            try:
                # ICryptoProvider is cipher-agnostic, so its exact ciphertext overhead (nonce/tag
                # for AES-GCM, potentially something else for a swapped-in cipher) isn't known
                # here - over-allocate generously and trim to what it actually wrote.
                buffer = bytearray(len(plaintext) + _MAX_CIPHER_OVERHEAD)
                written = self._provider.encrypt(plaintext, buffer, aad)
                return bytes(buffer[:written])
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def decrypt(self, ciphertext: bytes, result: bytearray, aad: bytes = b"") -> int:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.DataProtection.KEY_WRAPPED_KEY_DECRYPT) as span:
            _TELEMETRY.log_sensitive_operation(
                span,
                ActivityNames.DataProtection.KEY_WRAPPED_KEY_DECRYPT,
                (AttributeNames.CIPHERTEXT_LENGTH, len(ciphertext)),
                (AttributeNames.AAD_LENGTH, len(aad)),
            )
            try:
                return self._provider.decrypt(ciphertext, result, aad)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise
