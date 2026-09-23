"""Python port of test/HkdfGuard.DataEncryptionKey.Test/DefaultFormatProviderTests.cs."""

import secrets

import pytest
from hkdfguard_abstractions import KeyTrackingValue
from hkdfguard_dataencryptionkey import DefaultFormatProvider
from test_helpers.sensitive_logging_scope import sensitive_logging_scope


@pytest.fixture
def provider() -> DefaultFormatProvider:
    return DefaultFormatProvider()


def test_format_parse_get_max_decrypted_length_with_sensitive_logging_enabled_still_work_correctly(
    provider: DefaultFormatProvider,
) -> None:
    with sensitive_logging_scope(True):
        value = KeyTrackingValue(key_version=2, value=b"abc")
        formatted = provider.format(value)
        parsed = provider.parse(formatted)
        max_length = provider.get_max_decrypted_length(formatted)

        assert parsed.value == value.value
        assert max_length == len(parsed.value)


def test_format_then_parse_round_trips(provider: DefaultFormatProvider) -> None:
    value = KeyTrackingValue(key_version=7, value=b"hello")

    formatted = provider.format(value)
    assert formatted.startswith("enc::v7::")

    parsed = provider.parse(formatted)
    assert parsed.key_version == 7
    assert parsed.value == value.value


def test_format_with_empty_value_round_trips(provider: DefaultFormatProvider) -> None:
    value = KeyTrackingValue(key_version=1, value=b"")

    formatted = provider.format(value)
    parsed = provider.parse(formatted)

    assert parsed.key_version == 1
    assert parsed.value == b""


@pytest.mark.parametrize(
    "text",
    ["", "no-delimiters-at-all", "enc::onlyonepart", "wrong::v1::AAAA", "enc::1::AAAA", "enc::vNotANumber::AAAA"],
)
def test_parse_with_malformed_input_raises(provider: DefaultFormatProvider, text: str) -> None:
    with pytest.raises(ValueError):
        provider.parse(text)


def test_parse_with_invalid_base64_raises(provider: DefaultFormatProvider) -> None:
    with pytest.raises(ValueError):
        provider.parse("enc::v1::not-valid-base64!!!")


def test_get_max_decrypted_length_matches_parsed_value_length(provider: DefaultFormatProvider) -> None:
    value = KeyTrackingValue(key_version=3, value=secrets.token_bytes(40))
    formatted = provider.format(value)

    max_length = provider.get_max_decrypted_length(formatted)
    parsed = provider.parse(formatted)

    assert max_length == len(parsed.value)


@pytest.mark.parametrize("text", ["", "enc::onlyonepart", "enc::1::AAAA"])
def test_get_max_decrypted_length_with_malformed_input_raises(provider: DefaultFormatProvider, text: str) -> None:
    with pytest.raises(ValueError):
        provider.get_max_decrypted_length(text)


def test_get_max_decrypted_length_with_invalid_base64_raises(provider: DefaultFormatProvider) -> None:
    with pytest.raises(ValueError):
        provider.get_max_decrypted_length("enc::v1::not-valid-base64!!!")
