"""Python port of test/HkdfGuard.DataEncryptionKey.Test/DataProtectorTests.cs.

Exercises IDataProtector's failure paths (protector.data_protector.DataProtector is not part of
this package's public API - reachable only through KeyRing.create_protector, matching how it's
actually used in practice).
"""

import secrets

import pytest
from cryptography.exceptions import InvalidTag
from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProvider
from hkdfguard_dataencryptionkey import DefaultFormatProvider, KeyRing, KeyWrappedDataEncryptionKey
from test_helpers.fake_key_wrapper import FakeKeyWrapper
from test_helpers.sensitive_logging_scope import sensitive_logging_scope


def _create_ring_with_one_key() -> KeyRing:
    ring = KeyRing(DefaultFormatProvider())
    ring.add(
        1,
        KeyWrappedDataEncryptionKey(AesGcmCryptoProvider(FakeKeyWrapper(secrets.token_bytes(32)), b"wrapped", 60)),
    )
    return ring


def test_encrypt_on_empty_ring_raises() -> None:
    ring = KeyRing(DefaultFormatProvider())
    protector = ring.create_protector("purpose")

    with pytest.raises(ValueError):
        protector.encrypt("hello")


def test_decrypt_with_malformed_input_raises() -> None:
    protector = _create_ring_with_one_key().create_protector("purpose")

    with pytest.raises(ValueError):
        protector.decrypt("not-a-valid-format")


def test_decrypt_for_unregistered_version_raises_key_error() -> None:
    protector = _create_ring_with_one_key().create_protector("purpose")
    formatted = protector.encrypt("hello")

    # Claim a version that was never registered in this ring.
    tampered = formatted.replace("::v1::", "::v99::")

    with pytest.raises(KeyError):
        protector.decrypt(tampered)


def test_encrypt_decrypt_with_sensitive_logging_enabled_still_round_trips() -> None:
    with sensitive_logging_scope(True):
        protector = _create_ring_with_one_key().create_protector("purpose")
        formatted = protector.encrypt("hello")

        assert protector.decrypt(formatted) == "hello"


def test_decrypt_with_different_protector_name_raises_due_to_aad_mismatch() -> None:
    ring = _create_ring_with_one_key()
    formatted = ring.create_protector("purpose-a").encrypt("hello")

    with pytest.raises(InvalidTag):
        ring.create_protector("purpose-b").decrypt(formatted)
