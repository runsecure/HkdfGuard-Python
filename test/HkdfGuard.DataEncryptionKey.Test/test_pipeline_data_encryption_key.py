"""Python port of test/HkdfGuard.DataEncryptionKey.Test/PipelineDataEncryptionKeyTests.cs."""

import secrets

import pytest
from cryptography.exceptions import InvalidTag
from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard_dataencryptionkey import PipelineDataEncryptionKey
from test_helpers.fake_key_wrapper import FakeKeyWrapper

_CRYPTO_PROVIDER_FACTORY = AesGcmCryptoProviderFactory()


def _create_key(dek: bytearray | None = None) -> PipelineDataEncryptionKey:
    if dek is None:
        dek = bytearray(secrets.token_bytes(32))
    provider = _CRYPTO_PROVIDER_FACTORY.create_for_pipeline(FakeKeyWrapper(secrets.token_bytes(32)), dek)
    return PipelineDataEncryptionKey(provider, dek)


def test_as_bytearray_returns_the_supplied_dek() -> None:
    dek = bytearray(secrets.token_bytes(32))
    expected = bytes(dek)

    with _create_key(dek) as key:
        assert bytes(key.as_bytearray()) == expected


def test_encrypt_decrypt_round_trips() -> None:
    with _create_key() as key:
        plaintext = bytearray(b"top secret")
        expected = bytes(plaintext)

        encrypted = key.encrypt(plaintext)
        decrypted = bytearray(len(expected))
        written = key.decrypt(encrypted, decrypted)

        assert written == len(expected)
        assert bytes(decrypted) == expected


def test_encrypt_decrypt_with_aad_round_trips() -> None:
    with _create_key() as key:
        plaintext = bytearray(b"top secret")
        expected = bytes(plaintext)
        aad = b"context"

        encrypted = key.encrypt(plaintext, aad)
        decrypted = bytearray(len(expected))
        written = key.decrypt(encrypted, decrypted, aad)

        assert bytes(decrypted[:written]) == expected


def test_decrypt_with_mismatched_aad_raises() -> None:
    with _create_key() as key:
        encrypted = key.encrypt(bytearray(b"top secret"), b"context-a")

        with pytest.raises(InvalidTag):
            key.decrypt(encrypted, bytearray(16), b"context-b")


def test_two_instances_with_different_deks_cannot_decrypt_each_others_ciphertext() -> None:
    with _create_key() as key1, _create_key() as key2:
        encrypted = key1.encrypt(bytearray(b"top secret"))

        with pytest.raises(InvalidTag):
            key2.decrypt(encrypted, bytearray(16))


def test_close_zeroes_the_dek() -> None:
    dek = bytearray(secrets.token_bytes(32))
    key = _create_key(dek)

    key.close()

    assert bytes(dek) == bytes(32)


def test_close_does_not_raise() -> None:
    # Regression test: AesGcmCryptoProvider's pipeline-only constructor used to leave its
    # background-refresh-thread field unset, which crashed close once PipelineDataEncryptionKey
    # started closing its provider.
    key = _create_key()

    key.close()
