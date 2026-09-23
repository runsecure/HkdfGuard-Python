"""Python port of test/HkdfGuard.DataEncryptionKey.Test/KeyRingTests.cs."""

import secrets

import pytest
from hkdfguard_abstractions import IDataProtectionKey
from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProvider
from hkdfguard_dataencryptionkey import DefaultFormatProvider, KeyRing, KeyWrappedDataEncryptionKey
from test_helpers.fake_key_wrapper import FakeKeyWrapper
from test_helpers.recording_format_provider import RecordingFormatProvider
from test_helpers.sensitive_logging_scope import sensitive_logging_scope


def _create_fake_key() -> IDataProtectionKey:
    return KeyWrappedDataEncryptionKey(AesGcmCryptoProvider(FakeKeyWrapper(secrets.token_bytes(32)), b"wrapped", 60))


def test_current_version_before_any_add_raises() -> None:
    ring = KeyRing(DefaultFormatProvider())
    with pytest.raises(ValueError):
        _ = ring.current_version


def test_add_first_key_becomes_current_version() -> None:
    ring = KeyRing(DefaultFormatProvider())
    ring.add(1, _create_fake_key())

    assert ring.current_version == 1


def test_add_higher_version_becomes_new_current() -> None:
    ring = KeyRing(DefaultFormatProvider())
    ring.add(1, _create_fake_key())
    ring.add(5, _create_fake_key())

    assert ring.current_version == 5


def test_add_lower_version_after_higher_does_not_change_current() -> None:
    ring = KeyRing(DefaultFormatProvider())
    ring.add(5, _create_fake_key())
    ring.add(1, _create_fake_key())

    assert ring.current_version == 5


def test_add_with_sensitive_logging_enabled_still_works_correctly() -> None:
    with sensitive_logging_scope(True):
        ring = KeyRing(DefaultFormatProvider())
        ring.add(1, _create_fake_key())

        assert ring.current_version == 1


def test_add_duplicate_version_raises() -> None:
    ring = KeyRing(DefaultFormatProvider())
    ring.add(1, _create_fake_key())

    with pytest.raises(ValueError):
        ring.add(1, _create_fake_key())


def test_get_registered_version_returns_same_instance() -> None:
    ring = KeyRing(DefaultFormatProvider())
    key = _create_fake_key()
    ring.add(1, key)

    assert ring.get(1) is key


def test_get_unregistered_version_raises_key_error() -> None:
    ring = KeyRing(DefaultFormatProvider())
    with pytest.raises(KeyError):
        ring.get(999)


def test_try_get_registered_version_returns_key() -> None:
    ring = KeyRing(DefaultFormatProvider())
    key = _create_fake_key()
    ring.add(1, key)

    assert ring.try_get(1) is key


def test_try_get_unregistered_version_returns_none() -> None:
    ring = KeyRing(DefaultFormatProvider())

    assert ring.try_get(999) is None


def test_get_current_returns_current_version_and_key() -> None:
    ring = KeyRing(DefaultFormatProvider())
    key = _create_fake_key()
    ring.add(3, key)

    version, resolved_key = ring.get_current()

    assert version == 3
    assert resolved_key is key


def test_get_current_with_no_keys_added_raises() -> None:
    ring = KeyRing(DefaultFormatProvider())
    with pytest.raises(ValueError):
        ring.get_current()


def test_create_protector_produces_working_protector_bound_to_this_ring() -> None:
    ring = KeyRing(DefaultFormatProvider())
    ring.add(1, _create_fake_key())

    protector = ring.create_protector("purpose")
    formatted = protector.encrypt("hello")

    decrypted = protector.decrypt(formatted)

    assert decrypted == "hello"


def test_create_protector_uses_rings_configured_format_provider() -> None:
    recording_format_provider = RecordingFormatProvider()
    ring = KeyRing(recording_format_provider)
    ring.add(1, _create_fake_key())

    formatted = ring.create_protector("purpose").encrypt("hello")
    assert recording_format_provider.format_called

    ring.create_protector("purpose").decrypt(formatted)
    assert recording_format_provider.parse_called
