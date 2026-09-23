"""Python port of test/HkdfGuard.DataEncryptionKey.Test/DummyKeyWrapperTests.cs.

DummyKeyWrapper stands in for the IKeyWrapper the pipeline flow's
ICryptoProviderFactory.create_for_pipeline requires but never actually calls (the DEK is used
as-is, never wrapped) - every member is an inert no-op.
"""

from hkdfguard_dataencryptionkey.dummy_key_wrapper import DummyKeyWrapper


def test_encrypt_returns_zero() -> None:
    wrapper = DummyKeyWrapper()

    assert wrapper.encrypt(bytes(32), bytearray(64)) == 0


def test_decrypt_returns_zero() -> None:
    wrapper = DummyKeyWrapper()

    assert wrapper.decrypt(bytes(32), bytearray(32)) == 0


def test_generate_and_wrap_returns_zero() -> None:
    wrapper = DummyKeyWrapper()

    assert wrapper.generate_and_wrap(bytearray(32)) == 0
