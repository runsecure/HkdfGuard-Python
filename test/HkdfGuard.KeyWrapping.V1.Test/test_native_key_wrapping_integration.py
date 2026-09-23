"""Python port of test/HkdfGuard.KeyWrapping.V1.Test/NativeKeyWrappingIntegrationTests.cs.

Integration tests verifying real key wrapping and unwrapping against the platform's native KMS
library (Windows Platform Crypto Provider / TPM, Linux TPM2/keyring/OpenSSL, macOS Secure
Enclave). When the native shared library isn't available on the execution host, the whole module
is skipped rather than silently passing - pytest surfaces that as "skipped" in the run summary,
where the .NET originals' "return early" would just look like a passing (but empty) test.
"""

import secrets
import uuid

import pytest
from hkdfguard_abstractions import HkdfGuardCryptographicError
from hkdfguard_keywrapping_v1 import NativeHkdfKeyWrapperV1
from hkdfguard_keywrapping_v1.interop import AbstractHkdfGuardKmsLibrary
from hkdfguard_keywrapping_v1.native_host import get_library


def _native_library_available() -> bool:
    try:
        library = get_library()
        library.wrap_dek("hkdfguard-probe-service", bytes(32), bytearray(512))
        return True
    except (OSError, AttributeError, NotImplementedError):
        return False
    except Exception:  # noqa: BLE001 - any other exception means the native binary loaded and executed
        return True


pytestmark = pytest.mark.skipif(
    not _native_library_available(), reason="native HkdfGuard KMS library not available on this host"
)


def _service_name(label: str) -> str:
    return f"hkdfguard-{label}-{uuid.uuid4().hex}"


def test_encrypt_and_decrypt_round_trips_32_byte_dek() -> None:
    wrapper = NativeHkdfKeyWrapperV1(_service_name("test"))

    original_dek = secrets.token_bytes(32)
    wrapped = bytearray(512)
    wrapped_bytes_written = wrapper.encrypt(original_dek, wrapped)

    assert wrapped_bytes_written > 0
    assert bytes(wrapped[:wrapped_bytes_written]) != original_dek

    unwrapped_dek = bytearray(32)
    unwrapped_bytes_written = wrapper.decrypt(bytes(wrapped[:wrapped_bytes_written]), unwrapped_dek)

    assert unwrapped_bytes_written == 32
    assert bytes(unwrapped_dek) == original_dek


def test_generate_and_wrap_and_decrypt_produces_valid_32_byte_dek() -> None:
    wrapper = NativeHkdfKeyWrapperV1(_service_name("test"))

    wrapped = bytearray(512)
    wrapped_bytes_written = wrapper.generate_and_wrap(wrapped)

    assert wrapped_bytes_written > 0

    recovered_dek_1 = bytearray(32)
    unwrapped_bytes_1 = wrapper.decrypt(bytes(wrapped[:wrapped_bytes_written]), recovered_dek_1)

    assert unwrapped_bytes_1 == 32
    assert any(b != 0 for b in recovered_dek_1)

    recovered_dek_2 = bytearray(32)
    unwrapped_bytes_2 = wrapper.decrypt(bytes(wrapped[:wrapped_bytes_written]), recovered_dek_2)

    assert unwrapped_bytes_2 == 32
    assert recovered_dek_1 == recovered_dek_2


def test_service_isolation_cannot_decrypt_payload_from_different_service() -> None:
    wrapper_a = NativeHkdfKeyWrapperV1(_service_name("service-a"))
    wrapper_b = NativeHkdfKeyWrapperV1(_service_name("service-b"))

    original_dek = secrets.token_bytes(32)
    wrapped = bytearray(512)
    wrapped_len = wrapper_a.encrypt(original_dek, wrapped)

    destination = bytearray(32)
    with pytest.raises(HkdfGuardCryptographicError):
        wrapper_b.decrypt(bytes(wrapped[:wrapped_len]), destination)


def test_multiple_keys_under_same_service_wrap_and_unwrap_independently() -> None:
    wrapper = NativeHkdfKeyWrapperV1(_service_name("multi"))

    dek1 = secrets.token_bytes(32)
    dek2 = secrets.token_bytes(32)

    wrapped1 = bytearray(512)
    wrapped2 = bytearray(512)

    len1 = wrapper.encrypt(dek1, wrapped1)
    len2 = wrapper.encrypt(dek2, wrapped2)

    recovered1 = bytearray(32)
    recovered2 = bytearray(32)

    recovered_len1 = wrapper.decrypt(bytes(wrapped1[:len1]), recovered1)
    recovered_len2 = wrapper.decrypt(bytes(wrapped2[:len2]), recovered2)

    assert recovered_len1 == 32
    assert recovered_len2 == 32
    assert bytes(recovered1) == dek1
    assert bytes(recovered2) == dek2


def test_direct_wrap_and_unwrap_returns_ok_status_and_recovers_dek() -> None:
    library = get_library()
    service_name = _service_name("direct")
    dek = secrets.token_bytes(32)

    wrapped = bytearray(512)
    wrap_status, bytes_written = library.wrap_dek(service_name, dek, wrapped)

    assert wrap_status == AbstractHkdfGuardKmsLibrary.OK
    assert bytes_written > 0

    recovered = bytearray(32)
    unwrap_status, unwrap_bytes = library.unwrap_dek(service_name, bytes(wrapped[:bytes_written]), recovered)

    assert unwrap_status == AbstractHkdfGuardKmsLibrary.OK
    assert unwrap_bytes == 32
    assert bytes(recovered) == dek


def test_direct_generate_and_wrap_dek_returns_ok_status_and_produces_valid_payload() -> None:
    library = get_library()
    service_name = _service_name("direct-gen")

    wrapped = bytearray(512)
    gen_status, bytes_written = library.generate_and_wrap_dek(service_name, wrapped)

    assert gen_status == AbstractHkdfGuardKmsLibrary.OK
    assert bytes_written > 0

    recovered = bytearray(32)
    unwrap_status, unwrap_bytes = library.unwrap_dek(service_name, bytes(wrapped[:bytes_written]), recovered)

    assert unwrap_status == AbstractHkdfGuardKmsLibrary.OK
    assert unwrap_bytes == 32
    assert any(b != 0 for b in recovered)


def test_wrap_dek_with_insufficient_buffer_returns_error() -> None:
    library = get_library()
    service_name = _service_name("short-buf")
    dek = secrets.token_bytes(32)

    tiny_buffer = bytearray(1)
    status, required_bytes = library.wrap_dek(service_name, dek, tiny_buffer)

    assert status < 0
    assert required_bytes > 1


def test_unwrap_dek_with_insufficient_buffer_returns_error() -> None:
    library = get_library()
    service_name = _service_name("unwrap-short-buf")
    dek = secrets.token_bytes(32)

    wrapped = bytearray(512)
    wrap_status, bytes_written = library.wrap_dek(service_name, dek, wrapped)
    assert wrap_status == AbstractHkdfGuardKmsLibrary.OK

    tiny_destination = bytearray(1)
    status, _ = library.unwrap_dek(service_name, bytes(wrapped[:bytes_written]), tiny_destination)

    assert status < 0


def test_generate_and_wrap_dek_with_insufficient_buffer_returns_error() -> None:
    library = get_library()
    service_name = _service_name("gen-short-buf")

    tiny_buffer = bytearray(1)
    status, _ = library.generate_and_wrap_dek(service_name, tiny_buffer)

    assert status < 0


def test_unwrap_dek_with_corrupted_payload_returns_error() -> None:
    library = get_library()
    service_name = _service_name("corrupt")
    dek = secrets.token_bytes(32)

    wrapped = bytearray(512)
    wrap_status, bytes_written = library.wrap_dek(service_name, dek, wrapped)
    assert wrap_status == AbstractHkdfGuardKmsLibrary.OK

    # Corrupt the wrapped payload bytes.
    wrapped[0] ^= 0xFF
    wrapped[bytes_written // 2] ^= 0xFF

    recovered = bytearray(32)
    status, _ = library.unwrap_dek(service_name, bytes(wrapped[:bytes_written]), recovered)

    assert status < 0
