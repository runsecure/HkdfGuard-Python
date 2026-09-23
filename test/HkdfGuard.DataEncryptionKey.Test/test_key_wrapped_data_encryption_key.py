"""Python port of test/HkdfGuard.DataEncryptionKey.Test/KeyWrappedDataEncryptionKeyTests.cs."""

import secrets

import pytest
from cryptography.exceptions import InvalidTag
from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProvider
from hkdfguard_dataencryptionkey import KeyWrappedDataEncryptionKey
from test_helpers.fake_key_wrapper import FakeKeyWrapper
from test_helpers.sensitive_logging_scope import sensitive_logging_scope


def _create_key() -> tuple[KeyWrappedDataEncryptionKey, FakeKeyWrapper]:
    wrapper = FakeKeyWrapper(secrets.token_bytes(32))
    return KeyWrappedDataEncryptionKey(AesGcmCryptoProvider(wrapper, b"wrapped", 60)), wrapper


def test_encrypt_decrypt_round_trips() -> None:
    data_protection_key, _ = _create_key()
    plaintext = bytearray(b"top secret")
    # encrypt() zeroes the plaintext bytearray it's given as a side effect.
    expected = bytes(plaintext)

    encrypted = data_protection_key.encrypt(plaintext)
    assert len(encrypted) == len(expected) + 12 + 16

    decrypted = bytearray(len(expected))
    decrypted_length = data_protection_key.decrypt(encrypted, decrypted)

    assert decrypted_length == len(expected)
    assert bytes(decrypted) == expected


def test_encrypt_decrypt_with_aad_round_trips() -> None:
    data_protection_key, _ = _create_key()
    plaintext = bytearray(b"top secret")
    expected = bytes(plaintext)
    aad = b"context"

    encrypted = data_protection_key.encrypt(plaintext, aad)

    decrypted = bytearray(len(expected))
    decrypted_length = data_protection_key.decrypt(encrypted, decrypted, aad)

    assert bytes(decrypted[:decrypted_length]) == expected


def test_decrypt_with_mismatched_aad_raises() -> None:
    data_protection_key, _ = _create_key()
    plaintext = bytearray(b"top secret")
    encrypted = data_protection_key.encrypt(plaintext, b"context-a")

    result = bytearray(len(plaintext))
    with pytest.raises(InvalidTag):
        data_protection_key.decrypt(encrypted, result, b"context-b")


def test_encrypt_decrypt_with_sensitive_logging_enabled_still_round_trips() -> None:
    with sensitive_logging_scope(True):
        data_protection_key, _ = _create_key()
        plaintext = bytearray(b"top secret")
        expected = bytes(plaintext)

        encrypted = data_protection_key.encrypt(plaintext)
        decrypted = bytearray(len(expected))
        decrypted_length = data_protection_key.decrypt(encrypted, decrypted)

        assert bytes(decrypted[:decrypted_length]) == expected


def test_encrypt_returns_exactly_sized_result() -> None:
    data_protection_key, _ = _create_key()
    plaintext = bytearray(b"a longer plaintext value to encrypt")
    expected_length = len(plaintext) + 12 + 16  # AES-GCM nonce + tag overhead

    encrypted = data_protection_key.encrypt(plaintext)

    assert len(encrypted) == expected_length


def test_encrypt_and_decrypt_reuse_the_cached_session_across_calls() -> None:
    # AesGcmCryptoProvider only calls back into the key wrapper when it has no cached session yet
    # or the cached one has expired - not on every operation - so a wrapper's key is revealed once
    # here, then reused for every subsequent encrypt/decrypt.
    data_protection_key, wrapper = _create_key()
    encrypted1 = data_protection_key.encrypt(bytearray(b"one"))
    encrypted2 = data_protection_key.encrypt(bytearray(b"two"))

    data_protection_key.decrypt(encrypted1, bytearray(3))
    data_protection_key.decrypt(encrypted2, bytearray(3))

    assert wrapper.decrypt_call_count == 1
