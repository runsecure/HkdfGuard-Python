"""Python port of test/HkdfGuard.Cache.Test/ProtectedCacheBaseTests.cs."""

import secrets

from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProvider
from hkdfguard_dataencryptionkey import KeyWrappedDataEncryptionKey
from test_helpers.fake_key_wrapper import FakeKeyWrapper
from test_helpers.populating_cache import PopulatingCache


def _create_cache() -> PopulatingCache:
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))
    data_protection_key = KeyWrappedDataEncryptionKey(AesGcmCryptoProvider(wrapper, b"wrapped", 60))
    return PopulatingCache(data_protection_key)


def test_decrypt_on_miss_calls_try_populate_and_returns_populated_value() -> None:
    cache = _create_cache()

    def on_try_populate(name: str) -> bool:
        cache.seed(name, "populated value")
        return True

    cache.on_try_populate = on_try_populate

    result = bytearray(32)
    written = cache.decrypt("item", result)

    assert written > 0
    assert cache.try_populate_call_count == 1
    assert bytes(result[:written]).decode("utf-8") == "populated value"


def test_decrypt_when_already_cached_does_not_call_try_populate() -> None:
    cache = _create_cache()
    cache.seed("item", "already cached")

    def on_try_populate(_: str) -> bool:
        raise RuntimeError("should not be called")

    cache.on_try_populate = on_try_populate

    result = bytearray(32)
    written = cache.decrypt("item", result)

    assert written > 0
    assert cache.try_populate_call_count == 0
    assert bytes(result[:written]).decode("utf-8") == "already cached"


def test_decrypt_when_try_populate_returns_false_returns_zero() -> None:
    cache = _create_cache()
    cache.on_try_populate = lambda _: False

    written = cache.decrypt("item", bytearray(32))

    assert written == 0
    assert cache.try_populate_call_count == 1


def test_decrypt_when_try_populate_returns_true_but_does_not_actually_populate_returns_zero() -> None:
    cache = _create_cache()
    cache.on_try_populate = lambda _: True  # lies - never calls seed

    written = cache.decrypt("item", bytearray(32))

    assert written == 0


def test_try_get_max_decrypted_length_on_miss_calls_try_populate() -> None:
    cache = _create_cache()

    def on_try_populate(name: str) -> bool:
        cache.seed(name, "populated value")
        return True

    cache.on_try_populate = on_try_populate

    max_length = cache.try_get_max_decrypted_length("item")

    assert max_length is not None
    assert max_length > 0
    assert cache.try_populate_call_count == 1


def test_default_try_populate_returns_false_without_override() -> None:
    cache = _create_cache()
    cache.on_try_populate = None

    written = cache.decrypt("item", bytearray(16))

    assert written == 0
