"""Python port of test/HkdfGuard.DataEncryptionKey.Test/PipelineKeyFactoryTests.cs."""

from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard_dataencryptionkey import PipelineKeyFactory

_CRYPTO_PROVIDER_FACTORY = AesGcmCryptoProviderFactory()


def test_create_generates_a_32_byte_dek() -> None:
    factory = PipelineKeyFactory()

    with factory.create(_CRYPTO_PROVIDER_FACTORY) as key:
        dek = key.as_bytearray()
        assert len(dek) == 32
        assert any(b != 0 for b in dek)


def test_create_generates_a_different_dek_each_time() -> None:
    factory = PipelineKeyFactory()

    with factory.create(_CRYPTO_PROVIDER_FACTORY) as key1, factory.create(_CRYPTO_PROVIDER_FACTORY) as key2:
        assert bytes(key1.as_bytearray()) != bytes(key2.as_bytearray())


def test_create_produces_a_working_key() -> None:
    factory = PipelineKeyFactory()

    with factory.create(_CRYPTO_PROVIDER_FACTORY) as key:
        plaintext = bytearray(b"top secret")
        expected = bytes(plaintext)

        encrypted = key.encrypt(plaintext)
        decrypted = bytearray(len(expected))
        written = key.decrypt(encrypted, decrypted)

        assert written == len(expected)
        assert bytes(decrypted) == expected


def test_create_key_can_be_closed_without_raising() -> None:
    factory = PipelineKeyFactory()
    key = factory.create(_CRYPTO_PROVIDER_FACTORY)

    key.close()
