"""Python port of HkdfGuard.DataEncryptionKey/FormatProvider/DefaultFormatProvider.cs."""

from hkdfguard_abstractions import IEncryptedFormatProvider, KeyTrackingValue
from hkdfguard_diagnostics import ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry

from ..utilities.base64_conversion_utility import from_base64, get_binary_length, is_base64, to_base64_string

_ENC_PREFIX = "enc"
_DELIMITER = "::"
_VERSION_PREFIX = "v"

_TELEMETRY = HkdfGuardTelemetry.DATA_PROTECTION


class DefaultFormatProvider(IEncryptedFormatProvider):
    def format(self, value: KeyTrackingValue) -> str:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.DataProtection.FORMAT_PROVIDER_FORMAT) as span:
            _TELEMETRY.log_sensitive_operation(
                span,
                ActivityNames.DataProtection.FORMAT_PROVIDER_FORMAT,
                (AttributeNames.KEY_VERSION, value.key_version),
                (AttributeNames.VALUE_LENGTH, len(value.value)),
            )
            try:
                encoded = to_base64_string(value.value)
                return f"{_ENC_PREFIX}{_DELIMITER}{_VERSION_PREFIX}{value.key_version}{_DELIMITER}{encoded}"
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def parse(self, encrypted: str) -> KeyTrackingValue:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.DataProtection.FORMAT_PROVIDER_PARSE) as span:
            _TELEMETRY.log_sensitive_operation(
                span,
                ActivityNames.DataProtection.FORMAT_PROVIDER_PARSE,
                (AttributeNames.ENCRYPTED_LENGTH, len(encrypted)),
            )
            try:
                segments = _try_parse_segments(encrypted)
                if segments is None:
                    raise ValueError(_malformed_message())
                version, encoded = segments

                if not is_base64(encoded):
                    raise ValueError("Encrypted value is not valid base64.")

                value = bytearray(get_binary_length(encoded))
                from_base64(encoded, value)

                return KeyTrackingValue(key_version=version, value=bytes(value))
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def get_max_decrypted_length(self, encrypted: str) -> int:
        with _TELEMETRY.tracer.start_as_current_span(
            ActivityNames.DataProtection.FORMAT_PROVIDER_GET_MAX_DECRYPTED_LENGTH
        ) as span:
            _TELEMETRY.log_sensitive_operation(
                span,
                ActivityNames.DataProtection.FORMAT_PROVIDER_GET_MAX_DECRYPTED_LENGTH,
                (AttributeNames.ENCRYPTED_LENGTH, len(encrypted)),
            )
            try:
                segments = _try_parse_segments(encrypted)
                if segments is None:
                    raise ValueError(_malformed_message())
                _, encoded = segments

                if not is_base64(encoded):
                    raise ValueError("Encrypted value is not valid base64.")
                return get_binary_length(encoded)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise


def _malformed_message() -> str:
    return f"Invalid encrypted format. Expected '{_ENC_PREFIX}{_DELIMITER}{_VERSION_PREFIX}<version>{_DELIMITER}<base64>'."


# Shared by parse and get_max_decrypted_length so both agree on exactly what counts as
# well-formed - only get_max_decrypted_length skips the actual Base64 decode/allocation.
def _try_parse_segments(encrypted: str) -> tuple[int, str] | None:
    first = encrypted.find(_DELIMITER)
    if first < 0:
        return None

    after_prefix = encrypted[first + len(_DELIMITER) :]
    second = after_prefix.find(_DELIMITER)
    if second < 0:
        return None

    prefix = encrypted[:first]
    version_segment = after_prefix[:second]
    base64_segment = after_prefix[second + len(_DELIMITER) :]

    if prefix != _ENC_PREFIX or not version_segment.startswith(_VERSION_PREFIX):
        return None

    try:
        version = int(version_segment[len(_VERSION_PREFIX) :])
    except ValueError:
        return None

    return version, base64_segment
