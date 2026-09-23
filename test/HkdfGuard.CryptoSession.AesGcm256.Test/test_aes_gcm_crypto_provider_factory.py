"""Python port of test/HkdfGuard.CryptoSession.AesGcm256.Test/AesGcmCryptoProviderFactoryTests.cs."""

import secrets

from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProviderFactory
from test_helpers.fake_key_wrapper import FakeKeyWrapper

_FACTORY = AesGcmCryptoProviderFactory()


def test_create_produces_a_working_provider() -> None:
    wrapper = FakeKeyWrapper()
    with _FACTORY.create(wrapper, b"wrapped", 60) as provider:
        plaintext = bytearray(b"top secret")
        encrypted = bytearray(provider.get_encrypted_allocation_length(len(plaintext)))
        written = provider.encrypt(plaintext, encrypted)

        decrypted = bytearray(10)
        assert provider.decrypt(bytes(encrypted[:written]), decrypted) == 10


def test_create_ephemeral_calls_generate_and_wrap_exactly_once() -> None:
    wrapper = FakeKeyWrapper()
    with _FACTORY.create_ephemeral(wrapper, 60):
        assert wrapper.generate_and_wrap_call_count == 1


def test_create_ephemeral_produces_a_working_provider() -> None:
    wrapper = FakeKeyWrapper()
    with _FACTORY.create_ephemeral(wrapper, 60) as provider:
        plaintext = bytearray(b"top secret")
        expected = bytes(plaintext)
        encrypted = bytearray(provider.get_encrypted_allocation_length(len(plaintext)))
        written = provider.encrypt(plaintext, encrypted)

        decrypted = bytearray(len(expected))
        decrypted_length = provider.decrypt(bytes(encrypted[:written]), decrypted)

        assert decrypted_length == len(expected)
        assert bytes(decrypted) == expected


def test_create_for_pipeline_never_calls_the_key_wrapper() -> None:
    # create_for_pipeline uses the supplied bytes directly as the AES key - there is nothing to
    # wrap/unwrap, so the wrapper it's handed should never be invoked.
    wrapper = FakeKeyWrapper()
    wrapper.throw_on_decrypt = RuntimeError("should not be called")
    dek = bytearray(secrets.token_bytes(32))

    with _FACTORY.create_for_pipeline(wrapper, dek):
        assert wrapper.decrypt_call_count == 0
        assert wrapper.generate_and_wrap_call_count == 0


def test_create_for_pipeline_produces_a_working_provider() -> None:
    wrapper = FakeKeyWrapper()
    dek = bytearray(secrets.token_bytes(32))

    with _FACTORY.create_for_pipeline(wrapper, dek) as provider:
        plaintext = bytearray(b"top secret")
        expected = bytes(plaintext)
        encrypted = bytearray(provider.get_encrypted_allocation_length(len(plaintext)))
        written = provider.encrypt(plaintext, encrypted)

        decrypted = bytearray(len(expected))
        decrypted_length = provider.decrypt(bytes(encrypted[:written]), decrypted)

        assert decrypted_length == len(expected)
        assert bytes(decrypted) == expected


def test_create_for_pipeline_provider_close_does_not_raise() -> None:
    # Regression test: the pipeline-only AesGcmCryptoProvider constructor used to leave its
    # background-refresh-thread field unset, and close unconditionally joined it, raising.
    wrapper = FakeKeyWrapper()
    dek = bytearray(secrets.token_bytes(32))
    provider = _FACTORY.create_for_pipeline(wrapper, dek)

    provider.close()
