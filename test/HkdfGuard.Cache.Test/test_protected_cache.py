"""Python port of test/HkdfGuard.Cache.Test/ProtectedCacheTests.cs.

Byte-span vs char-span overloads (Add(name, Span<byte>) / Add(name, Span<char>)) become add/
add_str and add_or_update/add_or_update_str here - see IProtectedCache's module docstring.
FakeLogger<T> isn't ported as its own class: pytest's built-in caplog fixture already does exactly
what it exists for (capturing log records without a real logging provider), so the logger tests
use that directly instead of a bespoke recorder.
"""

import logging
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from hkdfguard_abstractions import IProtectedCache
from hkdfguard_cache import ProtectedCache
from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProvider
from hkdfguard_dataencryptionkey import KeyWrappedDataEncryptionKey
from hkdfguard_diagnostics import ActivityNames, AttributeNames, HkdfGuardTelemetry, MetricNames
from test_helpers.fake_key_wrapper import FakeKeyWrapper
from test_helpers.sensitive_logging_scope import sensitive_logging_scope


def _create_cache() -> IProtectedCache:
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))
    data_encryption_key = KeyWrappedDataEncryptionKey(AesGcmCryptoProvider(wrapper, b"wrapped", 60))
    return ProtectedCache(data_encryption_key)


def test_add_decrypt_bytes_round_trips() -> None:
    cache = _create_cache()
    plaintext = bytearray(b"top secret bytes")
    expected = bytes(plaintext)

    cache.add("item", plaintext)

    result = bytearray(len(expected))
    written = cache.decrypt("item", result)

    assert written > 0
    assert written == len(expected)
    assert bytes(result) == expected


def test_add_decrypt_str_round_trips() -> None:
    cache = _create_cache()
    plaintext = "top secret chars"

    cache.add_str("item", plaintext)

    assert cache.decrypt_str("item") == plaintext


def test_add_decrypt_str_handles_multi_byte_utf8() -> None:
    cache = _create_cache()
    plaintext = "héllo wörld 日本語"

    cache.add_str("item", plaintext)

    assert cache.decrypt_str("item") == plaintext


def test_add_bytes_called_twice_with_same_name_raises() -> None:
    cache = _create_cache()

    cache.add("item", bytearray(b"first"))

    with pytest.raises(ValueError):
        cache.add("item", bytearray(b"second"))


def test_add_str_called_twice_with_same_name_raises() -> None:
    cache = _create_cache()

    cache.add_str("item", "first")

    with pytest.raises(ValueError):
        cache.add_str("item", "second")


def test_add_bytes_called_twice_with_different_cased_name_raises() -> None:
    cache = _create_cache()

    cache.add("Item", bytearray(b"first"))

    with pytest.raises(ValueError):
        cache.add("ITEM", bytearray(b"second"))


def test_add_bytes_does_not_replace_previous_value_when_duplicate_name_rejected() -> None:
    cache = _create_cache()
    expected = b"original"

    cache.add("item", bytearray(expected))
    with pytest.raises(ValueError):
        cache.add("item", bytearray(b"attempted-overwrite"))

    result = bytearray(len(expected))
    written = cache.decrypt("item", result)
    assert bytes(result[:written]) == expected


def test_add_or_update_bytes_called_twice_with_same_name_replaces_previous_value() -> None:
    cache = _create_cache()

    cache.add_or_update("item", bytearray(b"first"))
    cache.add_or_update("item", bytearray(b"second-value"))

    max_length = cache.try_get_max_decrypted_length("item")
    assert max_length is not None
    result = bytearray(max_length)
    written = cache.decrypt("item", result)

    assert written > 0
    assert bytes(result[:written]).decode("utf-8") == "second-value"


def test_add_or_update_str_called_twice_with_same_name_replaces_previous_value() -> None:
    cache = _create_cache()

    cache.add_or_update_str("item", "first")
    cache.add_or_update_str("item", "second-value")

    assert cache.decrypt_str("item") == "second-value"


def test_add_or_update_after_add_replaces_previous_value_without_raising() -> None:
    cache = _create_cache()

    cache.add("item", bytearray(b"first"))
    cache.add_or_update("item", bytearray(b"second"))  # should not raise


def test_names_are_case_insensitive_across_add_and_decrypt() -> None:
    cache = _create_cache()
    expected = b"value"

    cache.add("Item-Name", bytearray(expected))

    result = bytearray(len(expected))
    written = cache.decrypt("ITEM-name", result)

    assert written > 0
    assert bytes(result[:written]) == expected


def test_names_are_case_insensitive_across_add_or_update() -> None:
    cache = _create_cache()

    cache.add_or_update("Item-Name", bytearray(b"first"))
    cache.add_or_update("ITEM-name", bytearray(b"second"))

    assert cache.decrypt_str("item-name") == "second"


def test_decrypt_bytes_with_unknown_name_returns_zero() -> None:
    cache = _create_cache()

    assert cache.decrypt("missing", bytearray(16)) == 0


def test_decrypt_str_with_unknown_name_returns_none() -> None:
    cache = _create_cache()

    assert cache.decrypt_str("missing") is None


def test_try_get_max_decrypted_length_with_unknown_name_returns_none() -> None:
    cache = _create_cache()

    assert cache.try_get_max_decrypted_length("missing") is None


def test_try_get_max_decrypted_length_is_safe_upper_bound_for_decrypt() -> None:
    cache = _create_cache()
    expected = b"some plaintext value"

    cache.add("item", bytearray(expected))

    max_length = cache.try_get_max_decrypted_length("item")
    assert max_length is not None

    result = bytearray(max_length)
    written = cache.decrypt("item", result)

    assert max_length >= written
    assert bytes(result[:written]) == expected


def test_add_decrypt_with_sensitive_logging_enabled_still_round_trips() -> None:
    with sensitive_logging_scope(True):
        cache = _create_cache()
        expected = b"top secret"

        cache.add("item", bytearray(expected))
        result = bytearray(len(expected))
        written = cache.decrypt("item", result)

        assert written > 0
        assert bytes(result[:written]) == expected


def test_add_or_update_decrypt_str_with_sensitive_logging_enabled_still_round_trips() -> None:
    with sensitive_logging_scope(True):
        cache = _create_cache()
        plaintext = "top secret chars"

        cache.add_or_update_str("item", plaintext)

        assert cache.decrypt_str("item") == plaintext


def test_add_str_with_sensitive_logging_enabled_still_round_trips() -> None:
    with sensitive_logging_scope(True):
        cache = _create_cache()
        plaintext = "top secret chars"

        cache.add_str("item", plaintext)

        assert cache.decrypt_str("item") == plaintext


def test_add_or_update_bytes_with_sensitive_logging_enabled_still_round_trips() -> None:
    with sensitive_logging_scope(True):
        cache = _create_cache()
        expected = b"top secret"

        cache.add_or_update("item", bytearray(expected))
        result = bytearray(len(expected))
        written = cache.decrypt("item", result)

        assert written > 0
        assert bytes(result[:written]) == expected


def test_decrypt_bytes_with_too_small_result_buffer_raises() -> None:
    cache = _create_cache()
    cache.add("item", bytearray(b"top secret"))

    with pytest.raises(ValueError):
        cache.decrypt("item", bytearray(1))


def test_decrypt_bytes_with_missing_name_and_sensitive_logging_enabled_still_returns_zero() -> None:
    with sensitive_logging_scope(True):
        cache = _create_cache()

        assert cache.decrypt("missing", bytearray(16)) == 0


def test_concurrent_add_and_decrypt_across_many_names_all_round_trip() -> None:
    cache = _create_cache()
    item_count = 200

    def add_item(i: int) -> None:
        cache.add(f"item-{i}", bytearray(f"value-{i}".encode()))

    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(add_item, range(item_count)))

    def check_item(i: int) -> None:
        max_length = cache.try_get_max_decrypted_length(f"item-{i}")
        assert max_length is not None
        result = bytearray(max_length)
        written = cache.decrypt(f"item-{i}", result)
        assert written > 0
        assert bytes(result[:written]).decode("utf-8") == f"value-{i}"

    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(check_item, range(item_count)))


def test_concurrent_add_with_same_name_exactly_one_succeeds() -> None:
    cache = _create_cache()
    attempt_count = 50
    succeeded = 0
    lock = threading.Lock()

    def attempt(i: int) -> None:
        nonlocal succeeded
        try:
            cache.add("shared-name", bytearray(f"value-{i}".encode()))
            with lock:
                succeeded += 1
        except ValueError:
            pass  # expected for every attempt but the winner

    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(attempt, range(attempt_count)))

    assert succeeded == 1


def test_add_with_null_logger_still_works() -> None:
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))
    data_encryption_key = KeyWrappedDataEncryptionKey(AesGcmCryptoProvider(wrapper, b"wrapped", 60))
    cache = ProtectedCache(data_encryption_key, logger=None)

    cache.add("item", bytearray(b"value"))  # should not raise


def test_add_with_logger_and_sensitive_logging_enabled_logs_sensitive_operation(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with sensitive_logging_scope(True):
        wrapper = FakeKeyWrapper(secrets.token_bytes(32))
        data_encryption_key = KeyWrappedDataEncryptionKey(AesGcmCryptoProvider(wrapper, b"wrapped", 60))
        logger = logging.getLogger("hkdfguard-cache-test.add-sensitive")
        logger.setLevel(logging.DEBUG)
        cache = ProtectedCache(data_encryption_key, logger)

        with caplog.at_level(logging.DEBUG, logger=logger.name):
            cache.add("item", bytearray(b"value"))

        records = [r for r in caplog.records if r.name == logger.name]
        assert len(records) == 1
        assert records[0].levelname == "DEBUG"
        assert "item" in records[0].getMessage()


def test_add_with_logger_when_duplicate_name_raises_logs_operation_failed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))
    data_encryption_key = KeyWrappedDataEncryptionKey(AesGcmCryptoProvider(wrapper, b"wrapped", 60))
    logger = logging.getLogger("hkdfguard-cache-test.add-duplicate")
    logger.setLevel(logging.DEBUG)
    cache = ProtectedCache(data_encryption_key, logger)
    cache.add("item", bytearray(b"first"))

    with caplog.at_level(logging.DEBUG, logger=logger.name), pytest.raises(ValueError):
        cache.add("item", bytearray(b"second"))

    error_records = [r for r in caplog.records if r.name == logger.name and r.levelname == "ERROR"]
    assert len(error_records) == 1
    assert error_records[0].exc_info is not None
    assert isinstance(error_records[0].exc_info[1], ValueError)


def test_add_increments_cache_operations_counter_on_success_and_failure(metric_reader) -> None:
    cache = _create_cache()
    cache.add("item", bytearray(b"value"))
    with pytest.raises(ValueError):
        cache.add("item", bytearray(b"value"))

    measurements = _cache_operation_measurements(metric_reader.get_metrics_data())

    assert (1, ActivityNames.Cache.ADD, "success") in measurements
    assert (1, ActivityNames.Cache.ADD, "error") in measurements


def _cache_operation_measurements(data) -> list[tuple[int, str | None, str | None]]:
    measurements = []
    for resource_metrics in data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            if scope_metrics.scope.name != HkdfGuardTelemetry.CACHE.source_name:
                continue
            for metric in scope_metrics.metrics:
                if metric.name != MetricNames.Cache.OPERATIONS:
                    continue
                for point in metric.data.data_points:
                    measurements.append(
                        (
                            point.value,
                            point.attributes.get(AttributeNames.OPERATION_NAME),
                            point.attributes.get(AttributeNames.RESULT),
                        )
                    )
    return measurements
