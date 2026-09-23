"""Python port of test/HkdfGuard.DataEncryptionKey.Test/EphemeralDataEncryptionKeyTests.cs."""

import secrets

import pytest
from cryptography.exceptions import InvalidTag
from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProvider
from hkdfguard_dataencryptionkey import EphemeralDataEncryptionKey
from test_helpers.fake_key_wrapper import FakeKeyWrapper


def _session_provider_factory(key_wrapper, wrapped):
    return AesGcmCryptoProvider(key_wrapper, wrapped, 60)


def test_constructor_generates_wrapped_dek_exactly_once() -> None:
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))

    EphemeralDataEncryptionKey(wrapper, _session_provider_factory)

    assert wrapper.generate_and_wrap_call_count == 1


def test_encrypt_decrypt_round_trips() -> None:
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))
    key = EphemeralDataEncryptionKey(wrapper, _session_provider_factory)
    plaintext = bytearray(b"top secret")
    expected = bytes(plaintext)

    encrypted = key.encrypt(plaintext)
    decrypted = bytearray(len(expected))
    written = key.decrypt(encrypted, decrypted)

    assert written == len(expected)
    assert bytes(decrypted) == expected


def test_encrypt_decrypt_with_aad_round_trips() -> None:
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))
    key = EphemeralDataEncryptionKey(wrapper, _session_provider_factory)
    plaintext = bytearray(b"top secret")
    expected = bytes(plaintext)
    aad = b"context"

    encrypted = key.encrypt(plaintext, aad)
    decrypted = bytearray(len(expected))
    written = key.decrypt(encrypted, decrypted, aad)

    assert bytes(decrypted[:written]) == expected


def test_decrypt_with_mismatched_aad_raises() -> None:
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))
    key = EphemeralDataEncryptionKey(wrapper, _session_provider_factory)
    encrypted = key.encrypt(bytearray(b"top secret"), b"context-a")

    with pytest.raises(InvalidTag):
        key.decrypt(encrypted, bytearray(16), b"context-b")


def test_encrypt_and_decrypt_reuse_the_same_generated_key_across_calls() -> None:
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))
    key = EphemeralDataEncryptionKey(wrapper, _session_provider_factory)

    encrypted1 = key.encrypt(bytearray(b"first"))
    encrypted2 = key.encrypt(bytearray(b"second"))

    result1 = bytearray(5)
    result2 = bytearray(6)
    key.decrypt(encrypted1, result1)
    key.decrypt(encrypted2, result2)

    assert bytes(result1).decode("utf-8") == "first"
    assert bytes(result2).decode("utf-8") == "second"
    assert wrapper.generate_and_wrap_call_count == 1


def test_encrypt_and_decrypt_reuse_the_cached_session_across_calls() -> None:
    # AesGcmCryptoProvider only calls back into the key wrapper when it has no cached session yet
    # or the cached one has expired - not on every operation - so the wrapper's key is revealed
    # once here, then reused for every subsequent encrypt/decrypt.
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))
    key = EphemeralDataEncryptionKey(wrapper, _session_provider_factory)
    encrypted = key.encrypt(bytearray(b"value"))

    key.decrypt(encrypted, bytearray(5))
    key.decrypt(encrypted, bytearray(5))

    assert wrapper.decrypt_call_count == 1
