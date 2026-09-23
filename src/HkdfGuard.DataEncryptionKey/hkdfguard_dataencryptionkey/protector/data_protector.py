"""Python port of HkdfGuard.DataEncryptionKey/Protector/DataProtector.cs.

DataProtector is an internal implementation detail: like the .NET original (`internal sealed
class DataProtector`, constructible only via KeyRing.CreateProtector), it is not re-exported from
this package's __init__ - callers only ever see it as an IDataProtector. name is UTF-8-encoded
once into _aad and used for every encrypt/decrypt, so a value protected under one name/purpose
fails to decrypt under another. encrypt resolves key_ring.get_current() fresh on every call rather
than capturing a version once at construction, so it always protects new data with whatever the
ring's latest rotation is; decrypt instead resolves whichever version the formatted ciphertext
itself names, so old versions stay readable regardless.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hkdfguard_abstractions import IDataProtector, IEncryptedFormatProvider, KeyTrackingValue
from hkdfguard_abstractions.array_utility import zero_memory
from hkdfguard_diagnostics import ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry

if TYPE_CHECKING:
    from ..key_ring import KeyRing

_TELEMETRY = HkdfGuardTelemetry.DATA_PROTECTION


class DataProtector(IDataProtector):
    def __init__(self, name: str, key_ring: KeyRing, format_provider: IEncryptedFormatProvider) -> None:
        self._name = name
        self._key_ring = key_ring
        self._format_provider = format_provider
        self._aad = name.encode("utf-8")

    def encrypt(self, plaintext: str) -> str:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.DataProtection.PROTECTOR_ENCRYPT) as span:
            _TELEMETRY.log_sensitive_operation(
                span,
                ActivityNames.DataProtection.PROTECTOR_ENCRYPT,
                (AttributeNames.NAME, self._name),
                (AttributeNames.PLAINTEXT_LENGTH, len(plaintext)),
            )
            try:
                version, key = self._key_ring.get_current()

                # plaintext_bytes is zeroed as a side effect of the encrypt call it's passed to.
                plaintext_bytes = bytearray(plaintext.encode("utf-8"))
                encrypted_bytes = key.encrypt(plaintext_bytes, self._aad)

                return self._format_provider.format(KeyTrackingValue(key_version=version, value=encrypted_bytes))
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def decrypt(self, encrypted: str) -> str:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.DataProtection.PROTECTOR_DECRYPT) as span:
            _TELEMETRY.log_sensitive_operation(
                span,
                ActivityNames.DataProtection.PROTECTOR_DECRYPT,
                (AttributeNames.NAME, self._name),
                (AttributeNames.ENCRYPTED_LENGTH, len(encrypted)),
            )
            try:
                value = self._format_provider.parse(encrypted)
                key = self._key_ring.get(value.key_version)

                # AEAD ciphertext is always at least as long as the plaintext it encloses, so
                # len(value.value) is a safe upper bound for the decrypted UTF-8 byte count.
                plaintext_bytes = bytearray(len(value.value))
                try:
                    bytes_written = key.decrypt(value.value, plaintext_bytes, self._aad)
                    return bytes(plaintext_bytes[:bytes_written]).decode("utf-8")
                finally:
                    zero_memory(plaintext_bytes)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def get_max_decrypted_length(self, encrypted: str) -> int:
        return self._format_provider.get_max_decrypted_length(encrypted)
