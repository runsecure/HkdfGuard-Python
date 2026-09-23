"""Python port of HkdfGuard.DataEncryptionKey/EncryptionKeyBase.cs.

A DataEncryptionKey backed by one ICryptoProvider. Every operation calls straight through to
provider, which owns revealing/refreshing its own key material - EncryptionKeyBase adds only the
allocation sizing (via provider.get_encrypted_allocation_length) and telemetry every concrete key
in this package needs.
"""

from hkdfguard_abstractions import ICryptoProvider, IDataEncryptionKey
from hkdfguard_diagnostics import ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry

_TELEMETRY = HkdfGuardTelemetry.DATA_PROTECTION


class EncryptionKeyBase(IDataEncryptionKey):
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
                buffer = bytearray(self._provider.get_encrypted_allocation_length(len(plaintext)))
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
