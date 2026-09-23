"""Python port of test/HkdfGuard.DataEncryptionKey.Test/PipelineDataEncryptionKeyTests.cs."""

import secrets

import pytest
from cryptography.exceptions import InvalidTag
from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProvider
from hkdfguard_dataencryptionkey import PipelineDataEncryptionKey


def _session_provider_factory(key_wrapper, wrapped):
    return AesGcmCryptoProvider(key_wrapper, wrapped, 60)


def test_constructor_with_no_dek_supplied_generates_a_random_32_byte_dek() -> None:
    with PipelineDataEncryptionKey(_session_provider_factory) as key:
        dek = key.as_bytearray()
        assert len(dek) == 32
        assert any(b != 0 for b in dek)


def test_constructor_with_no_dek_supplied_generates_a_different_dek_each_time() -> None:
    with (
        PipelineDataEncryptionKey(_session_provider_factory) as key1,
        PipelineDataEncryptionKey(_session_provider_factory) as key2,
    ):
        assert bytes(key1.as_bytearray()) != bytes(key2.as_bytearray())


def test_constructor_with_supplied_dek_uses_it_as_is() -> None:
    dek = bytearray(secrets.token_bytes(32))
    expected = bytes(dek)

    with PipelineDataEncryptionKey(_session_provider_factory, dek) as key:
        assert bytes(key.as_bytearray()) == expected


def test_constructor_with_empty_dek_raises() -> None:
    with pytest.raises(ValueError):
        PipelineDataEncryptionKey(_session_provider_factory, bytearray(32))


def test_constructor_with_wrong_size_dek_raises() -> None:
    with pytest.raises(ValueError):
        PipelineDataEncryptionKey(_session_provider_factory, bytearray(secrets.token_bytes(16)))


def test_encrypt_decrypt_round_trips() -> None:
    with PipelineDataEncryptionKey(_session_provider_factory) as key:
        plaintext = bytearray(b"top secret")
        expected = bytes(plaintext)

        encrypted = key.encrypt(plaintext)
        decrypted = bytearray(len(expected))
        written = key.decrypt(encrypted, decrypted)

        assert written == len(expected)
        assert bytes(decrypted) == expected


def test_encrypt_decrypt_with_aad_round_trips() -> None:
    with PipelineDataEncryptionKey(_session_provider_factory) as key:
        plaintext = bytearray(b"top secret")
        expected = bytes(plaintext)
        aad = b"context"

        encrypted = key.encrypt(plaintext, aad)
        decrypted = bytearray(len(expected))
        written = key.decrypt(encrypted, decrypted, aad)

        assert bytes(decrypted[:written]) == expected


def test_decrypt_with_mismatched_aad_raises() -> None:
    with PipelineDataEncryptionKey(_session_provider_factory) as key:
        encrypted = key.encrypt(bytearray(b"top secret"), b"context-a")

        with pytest.raises(InvalidTag):
            key.decrypt(encrypted, bytearray(16), b"context-b")


def test_two_instances_with_different_generated_deks_cannot_decrypt_each_others_ciphertext() -> None:
    with (
        PipelineDataEncryptionKey(_session_provider_factory) as key1,
        PipelineDataEncryptionKey(_session_provider_factory) as key2,
    ):
        encrypted = key1.encrypt(bytearray(b"top secret"))

        with pytest.raises(InvalidTag):
            key2.decrypt(encrypted, bytearray(16))


def test_close_zeroes_the_dek() -> None:
    key = PipelineDataEncryptionKey(_session_provider_factory)

    key.close()

    assert bytes(key.as_bytearray()) == bytes(32)
