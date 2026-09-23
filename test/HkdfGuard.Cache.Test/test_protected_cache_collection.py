"""Python port of test/HkdfGuard.Cache.Test/ProtectedCacheCollectionTests.cs."""

import secrets

import pytest
from hkdfguard_cache import ProtectedCache, ProtectedCacheCollection
from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProvider
from hkdfguard_dataencryptionkey import KeyWrappedDataEncryptionKey
from test_helpers.fake_key_wrapper import FakeKeyWrapper
from test_helpers.sensitive_logging_scope import sensitive_logging_scope
from test_helpers.throwing_read_only_cache import ThrowingReadOnlyCache


def _create_cache() -> ProtectedCache:
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))
    data_encryption_key = KeyWrappedDataEncryptionKey(AesGcmCryptoProvider(wrapper, b"wrapped", 60))
    return ProtectedCache(data_encryption_key)


def test_add_returns_same_instance_for_fluent_chaining() -> None:
    collection = ProtectedCacheCollection()

    returned = collection.add(_create_cache())

    assert returned is collection


def test_decrypt_bytes_with_no_sources_returns_zero() -> None:
    collection = ProtectedCacheCollection()

    written = collection.decrypt("item", bytearray(16))

    assert written == 0


def test_decrypt_bytes_returns_from_first_source_that_has_it() -> None:
    first = _create_cache()
    second = _create_cache()
    first.add("item", bytearray(b"from-first"))
    second.add("item", bytearray(b"from-second"))

    collection = ProtectedCacheCollection().add(first).add(second)

    result = bytearray(32)
    written = collection.decrypt("item", result)

    assert written > 0
    assert bytes(result[:written]).decode("utf-8") == "from-first"


def test_decrypt_bytes_falls_through_to_later_source_when_earlier_ones_lack_the_name() -> None:
    first = _create_cache()
    second = _create_cache()
    second.add("item", bytearray(b"from-second"))

    collection = ProtectedCacheCollection().add(first).add(second)

    result = bytearray(32)
    written = collection.decrypt("item", result)

    assert written > 0
    assert bytes(result[:written]).decode("utf-8") == "from-second"


def test_decrypt_bytes_with_no_source_having_the_name_returns_zero() -> None:
    collection = ProtectedCacheCollection().add(_create_cache()).add(_create_cache())

    written = collection.decrypt("missing", bytearray(16))

    assert written == 0


def test_decrypt_str_returns_from_first_source_that_has_it() -> None:
    first = _create_cache()
    second = _create_cache()
    first.add_str("item", "from-first")
    second.add_str("item", "from-second")

    collection = ProtectedCacheCollection().add(first).add(second)

    assert collection.decrypt_str("item") == "from-first"


def test_decrypt_str_falls_through_to_later_source_when_earlier_ones_lack_the_name() -> None:
    first = _create_cache()
    second = _create_cache()
    second.add_str("item", "from-second")

    collection = ProtectedCacheCollection().add(first).add(second)

    assert collection.decrypt_str("item") == "from-second"


def test_decrypt_str_with_no_source_having_the_name_returns_none() -> None:
    collection = ProtectedCacheCollection().add(_create_cache()).add(_create_cache())

    assert collection.decrypt_str("missing") is None


def test_try_get_max_decrypted_length_with_no_sources_returns_none() -> None:
    collection = ProtectedCacheCollection()

    assert collection.try_get_max_decrypted_length("item") is None


def test_try_get_max_decrypted_length_returns_from_first_source_that_has_it() -> None:
    first = _create_cache()
    second = _create_cache()
    first.add("item", bytearray(b"abc"))
    second.add("item", bytearray(b"a much longer value than the first source has"))

    collection = ProtectedCacheCollection().add(first).add(second)

    expected_max_length = first.try_get_max_decrypted_length("item")
    max_length = collection.try_get_max_decrypted_length("item")

    assert max_length == expected_max_length


def test_try_get_max_decrypted_length_falls_through_to_later_source_when_earlier_ones_lack_the_name() -> None:
    first = _create_cache()
    second = _create_cache()
    second.add("item", bytearray(b"from-second"))

    collection = ProtectedCacheCollection().add(first).add(second)

    max_length = collection.try_get_max_decrypted_length("item")

    assert max_length is not None
    assert max_length > 0


def test_try_get_max_decrypted_length_with_no_source_having_the_name_returns_none() -> None:
    collection = ProtectedCacheCollection().add(_create_cache()).add(_create_cache())

    assert collection.try_get_max_decrypted_length("missing") is None


def test_decrypt_bytes_with_sensitive_logging_enabled_still_round_trips() -> None:
    with sensitive_logging_scope(True):
        source = _create_cache()
        source.add("item", bytearray(b"top secret"))
        collection = ProtectedCacheCollection().add(source)

        result = bytearray(32)
        written = collection.decrypt("item", result)

        assert written > 0
        assert bytes(result[:written]).decode("utf-8") == "top secret"


def test_decrypt_str_with_sensitive_logging_enabled_still_round_trips() -> None:
    with sensitive_logging_scope(True):
        source = _create_cache()
        source.add_str("item", "top secret")
        collection = ProtectedCacheCollection().add(source)

        assert collection.decrypt_str("item") == "top secret"


def test_decrypt_bytes_when_a_source_raises_records_exception_and_raises() -> None:
    collection = ProtectedCacheCollection().add(ThrowingReadOnlyCache(RuntimeError("boom")))

    with pytest.raises(RuntimeError, match="boom"):
        collection.decrypt("item", bytearray(16))


def test_decrypt_str_when_a_source_raises_records_exception_and_raises() -> None:
    collection = ProtectedCacheCollection().add(ThrowingReadOnlyCache(RuntimeError("boom")))

    with pytest.raises(RuntimeError, match="boom"):
        collection.decrypt_str("item")
