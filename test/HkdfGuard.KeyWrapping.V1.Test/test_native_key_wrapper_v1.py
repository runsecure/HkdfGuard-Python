"""Python port of test/HkdfGuard.KeyWrapping.V1.Test/NativeHkdfKeyWrapperV1Tests.cs."""

import pytest
from hkdfguard_abstractions import HkdfGuardCryptographicError
from hkdfguard_keywrapping_v1 import NativeHkdfKeyWrapperV1
from test_helpers.fake_kms_library import FakeHkdfGuardKmsLibrary


def test_constructor_with_service_name_instantiates_successfully() -> None:
    wrapper = NativeHkdfKeyWrapperV1("test-service")

    assert wrapper is not None


def test_encrypt_delegates_to_library() -> None:
    fake_library = FakeHkdfGuardKmsLibrary()
    fake_library.wrap_payload_to_emit = bytes([10, 20, 30, 40])
    wrapper = NativeHkdfKeyWrapperV1("service-a", fake_library)

    plaintext = bytes([1, 2, 3, 4, 5])
    result_buffer = bytearray(16)

    bytes_written = wrapper.encrypt(plaintext, result_buffer)

    assert bytes_written == 4
    assert fake_library.wrap_call_count == 1
    assert fake_library.last_service == "service-a"
    assert fake_library.last_wrap_plaintext == plaintext
    assert bytes(result_buffer[:4]) == bytes([10, 20, 30, 40])


@pytest.mark.parametrize("error_code", [-1, -2, -7])
def test_encrypt_when_library_fails_raises_cryptographic_error(error_code: int) -> None:
    fake_library = FakeHkdfGuardKmsLibrary()
    fake_library.wrap_dek_status = error_code
    wrapper = NativeHkdfKeyWrapperV1("service-d", fake_library)

    plaintext = bytes([1, 2, 3])
    result_buffer = bytearray(8)

    with pytest.raises(HkdfGuardCryptographicError, match=rf"^Native KMS wrap failed with status {error_code}\.$"):
        wrapper.encrypt(plaintext, result_buffer)

    assert fake_library.wrap_call_count == 1


def test_decrypt_delegates_to_library() -> None:
    fake_library = FakeHkdfGuardKmsLibrary()
    fake_library.unwrap_payload_to_emit = bytes([1, 2, 3, 4, 5])
    wrapper = NativeHkdfKeyWrapperV1("service-a", fake_library)

    wrapped = bytes([10, 20, 30, 40])
    result_buffer = bytearray(16)

    bytes_written = wrapper.decrypt(wrapped, result_buffer)

    assert bytes_written == 5
    assert fake_library.unwrap_call_count == 1
    assert fake_library.last_service == "service-a"
    assert fake_library.last_unwrap_wrapped == wrapped
    assert bytes(result_buffer[:5]) == bytes([1, 2, 3, 4, 5])


@pytest.mark.parametrize("error_code", [-1, -2, -6])
def test_decrypt_when_library_fails_raises_cryptographic_error(error_code: int) -> None:
    fake_library = FakeHkdfGuardKmsLibrary()
    fake_library.unwrap_dek_status = error_code
    wrapper = NativeHkdfKeyWrapperV1("service-d", fake_library)

    wrapped = bytes([10, 20, 30])
    result_buffer = bytearray(8)

    with pytest.raises(HkdfGuardCryptographicError, match=rf"^Native KMS unwrap failed with status {error_code}\.$"):
        wrapper.decrypt(wrapped, result_buffer)

    assert fake_library.unwrap_call_count == 1


def test_generate_and_wrap_delegates_to_library() -> None:
    fake_library = FakeHkdfGuardKmsLibrary()
    fake_library.generate_and_wrap_payload_to_emit = bytes([11, 22, 33, 44, 55])
    wrapper = NativeHkdfKeyWrapperV1("service-e", fake_library)

    result_buffer = bytearray(16)

    bytes_written = wrapper.generate_and_wrap(result_buffer)

    assert bytes_written == 5
    assert fake_library.generate_and_wrap_call_count == 1
    assert fake_library.last_service == "service-e"
    assert bytes(result_buffer[:5]) == bytes([11, 22, 33, 44, 55])


@pytest.mark.parametrize("error_code", [-1, -3, -7])
def test_generate_and_wrap_when_library_fails_raises_cryptographic_error(error_code: int) -> None:
    fake_library = FakeHkdfGuardKmsLibrary()
    fake_library.generate_and_wrap_dek_status = error_code
    wrapper = NativeHkdfKeyWrapperV1("service-f", fake_library)

    result_buffer = bytearray(16)

    with pytest.raises(
        HkdfGuardCryptographicError, match=rf"^Native KMS generate-and-wrap failed with status {error_code}\.$"
    ):
        wrapper.generate_and_wrap(result_buffer)

    assert fake_library.generate_and_wrap_call_count == 1
