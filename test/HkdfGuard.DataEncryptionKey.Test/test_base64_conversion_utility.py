"""Python port of test/HkdfGuard.DataEncryptionKey.Test/Base64ConversionUtilityTests.cs."""

import secrets

import pytest
from hkdfguard_dataencryptionkey.utilities.base64_conversion_utility import (
    from_base64,
    get_base64_length,
    get_binary_length,
    is_base64,
    is_base64_bytes,
    to_base64_chars,
    to_base64_string,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [("AAAA", True), ("AAA=", True), ("", True), ("not valid base64!!!", False)],
)
def test_is_base64_str_validates_correctly(text: str, expected: bool) -> None:
    assert is_base64(text) == expected


def test_is_base64_bytes_validates_correctly() -> None:
    assert is_base64_bytes(b"AAAA") is True
    assert is_base64_bytes(b"!!!!") is False


def test_get_binary_length_empty_input_returns_zero() -> None:
    assert get_binary_length("") == 0


@pytest.mark.parametrize(("base64_text", "expected_length"), [("QQ==", 1), ("QUI=", 2), ("QUJD", 3)])
def test_get_binary_length_computes_correct_length(base64_text: str, expected_length: int) -> None:
    assert get_binary_length(base64_text) == expected_length


def test_get_binary_length_not_multiple_of_four_raises() -> None:
    with pytest.raises(ValueError, match="multiple of 4"):
        get_binary_length("AAA")


def test_get_base64_length_empty_input_returns_zero() -> None:
    assert get_base64_length(b"") == 0


@pytest.mark.parametrize(
    ("byte_length", "expected_char_length"),
    [(1, 4), (2, 4), (3, 4), (4, 8)],
)
def test_get_base64_length_computes_correct_length(byte_length: int, expected_char_length: int) -> None:
    assert get_base64_length(bytes(byte_length)) == expected_char_length


def test_to_base64_string_then_from_base64_round_trips() -> None:
    data = b"hello world"
    encoded = to_base64_string(data)
    destination = bytearray(get_binary_length(encoded))

    written = from_base64(encoded, destination)

    assert written == len(data)
    assert bytes(destination) == data


def test_from_base64_with_invalid_input_raises() -> None:
    destination = bytearray(16)
    with pytest.raises(ValueError):
        from_base64("not valid base64!!!", destination)


def test_from_base64_with_too_small_destination_raises() -> None:
    destination = bytearray(1)
    with pytest.raises(ValueError):
        from_base64("QUJD", destination)


def test_to_base64_chars_then_from_base64_round_trips() -> None:
    data = b"round trip"
    destination = bytearray(get_base64_length(data))

    written = to_base64_chars(data, destination)

    assert written == len(destination)

    decoded = bytearray(get_binary_length(destination[:written].decode("ascii")))
    from_base64(destination[:written].decode("ascii"), decoded)
    assert bytes(decoded) == data


def test_to_base64_chars_with_too_small_destination_raises() -> None:
    data = secrets.token_bytes(5)
    destination = bytearray(1)

    with pytest.raises(ValueError):
        to_base64_chars(data, destination)
