"""Python port of test/HkdfGuard.DataEncryptionKey.Test/KeyRingBuilderTests.cs."""

import secrets
import tempfile
from pathlib import Path

import pytest
from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard_dataencryptionkey import KeyRingBuilder
from test_helpers.fake_key_wrapper import FakeKeyWrapper
from test_helpers.recording_crypto_provider_factory import RecordingCryptoProviderFactory
from test_helpers.recording_format_provider import RecordingFormatProvider

_CRYPTO_PROVIDER_FACTORY = AesGcmCryptoProviderFactory()


def test_with_service_name_sets_service_name() -> None:
    builder = KeyRingBuilder().with_service_name("my-service")

    assert builder.service_name == "my-service"


@pytest.mark.parametrize("cached_key_expiry", [0, 300])
def test_with_cached_key_expiry_within_range_sets_cached_key_expiry(cached_key_expiry: int) -> None:
    builder = KeyRingBuilder().with_cached_key_expiry(cached_key_expiry)

    assert builder.cached_key_expiry == cached_key_expiry


@pytest.mark.parametrize("cached_key_expiry", [-1, 301])
def test_with_cached_key_expiry_out_of_range_raises(cached_key_expiry: int) -> None:
    with pytest.raises(ValueError):
        KeyRingBuilder().with_cached_key_expiry(cached_key_expiry)


@pytest.mark.parametrize("key_rotation_days", [1, 180])
def test_with_key_rotation_days_within_range_sets_key_rotation_days(key_rotation_days: int) -> None:
    builder = KeyRingBuilder().with_key_rotation_days(key_rotation_days)

    assert builder.key_rotation_days == key_rotation_days


@pytest.mark.parametrize("key_rotation_days", [0, 181])
def test_with_key_rotation_days_out_of_range_raises(key_rotation_days: int) -> None:
    with pytest.raises(ValueError):
        KeyRingBuilder().with_key_rotation_days(key_rotation_days)


def test_build_without_key_wrapper_raises() -> None:
    builder = (
        KeyRingBuilder()
        .with_crypto_provider_factory(_CRYPTO_PROVIDER_FACTORY)
        .with_cached_key_expiry(60)
        .with_ephemeral_key(1)
    )

    with pytest.raises(ValueError):
        builder.build()


def test_build_without_crypto_provider_factory_raises() -> None:
    builder = (
        KeyRingBuilder()
        .with_key_wrapper(FakeKeyWrapper(secrets.token_bytes(32)))
        .with_cached_key_expiry(60)
        .with_ephemeral_key(1)
    )

    with pytest.raises(ValueError):
        builder.build()


def test_build_without_key_files_or_ephemeral_keys_raises() -> None:
    builder = (
        KeyRingBuilder()
        .with_key_wrapper(FakeKeyWrapper(secrets.token_bytes(32)))
        .with_crypto_provider_factory(_CRYPTO_PROVIDER_FACTORY)
        .with_cached_key_expiry(60)
    )

    with pytest.raises(ValueError):
        builder.build()


def test_build_without_cached_key_expiry_raises() -> None:
    builder = (
        KeyRingBuilder()
        .with_key_wrapper(FakeKeyWrapper(secrets.token_bytes(32)))
        .with_crypto_provider_factory(_CRYPTO_PROVIDER_FACTORY)
        .with_ephemeral_key(1)
    )

    with pytest.raises(ValueError):
        builder.build()


def test_build_with_key_file_registers_version_from_file() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / "key.bin"
        path.write_bytes(b"wrapped")

        ring = (
            KeyRingBuilder()
            .with_key_wrapper(FakeKeyWrapper(secrets.token_bytes(32)))
            .with_crypto_provider_factory(_CRYPTO_PROVIDER_FACTORY)
            .with_cached_key_expiry(60)
            .with_key_file(1, str(path))
            .build()
        )

        assert ring.current_version == 1


def test_build_with_multiple_key_files_highest_version_becomes_current() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        path1 = Path(tmp_dir) / "key1.bin"
        path2 = Path(tmp_dir) / "key2.bin"
        path1.write_bytes(b"wrapped-v1")
        path2.write_bytes(b"wrapped-v2")

        ring = (
            KeyRingBuilder()
            .with_key_wrapper(FakeKeyWrapper(secrets.token_bytes(32)))
            .with_crypto_provider_factory(_CRYPTO_PROVIDER_FACTORY)
            .with_cached_key_expiry(60)
            .with_key_file(1, str(path1))
            .with_key_file(2, str(path2))
            .build()
        )

        assert ring.current_version == 2


def test_build_with_ephemeral_key_registers_version() -> None:
    ring = (
        KeyRingBuilder()
        .with_key_wrapper(FakeKeyWrapper(secrets.token_bytes(32)))
        .with_crypto_provider_factory(_CRYPTO_PROVIDER_FACTORY)
        .with_cached_key_expiry(60)
        .with_ephemeral_key(1)
        .build()
    )

    assert ring.current_version == 1


def test_build_with_ephemeral_key_produces_a_working_key() -> None:
    ring = (
        KeyRingBuilder()
        .with_key_wrapper(FakeKeyWrapper(secrets.token_bytes(32)))
        .with_crypto_provider_factory(_CRYPTO_PROVIDER_FACTORY)
        .with_cached_key_expiry(60)
        .with_ephemeral_key(1)
        .build()
    )

    key = ring.get(1)
    plaintext = bytearray(b"top secret")
    expected = bytes(plaintext)

    encrypted = key.encrypt(plaintext)
    decrypted = bytearray(len(expected))
    written = key.decrypt(encrypted, decrypted)

    assert written == len(expected)
    assert bytes(decrypted) == expected


def test_build_with_key_file_and_higher_version_ephemeral_key_ephemeral_becomes_current() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / "key.bin"
        path.write_bytes(b"wrapped")

        ring = (
            KeyRingBuilder()
            .with_key_wrapper(FakeKeyWrapper(secrets.token_bytes(32)))
            .with_crypto_provider_factory(_CRYPTO_PROVIDER_FACTORY)
            .with_cached_key_expiry(60)
            .with_key_file(1, str(path))
            .with_ephemeral_key(2)
            .build()
        )

        assert ring.current_version == 2


def test_build_uses_configured_format_provider() -> None:
    recording_format_provider = RecordingFormatProvider()

    ring = (
        KeyRingBuilder()
        .with_key_wrapper(FakeKeyWrapper(secrets.token_bytes(32)))
        .with_crypto_provider_factory(_CRYPTO_PROVIDER_FACTORY)
        .with_cached_key_expiry(60)
        .with_ephemeral_key(1)
        .with_format_provider(recording_format_provider)
        .build()
    )

    ring.create_protector("purpose").encrypt("hello")

    assert recording_format_provider.format_called


def test_build_with_key_file_passes_cached_key_expiry_to_the_crypto_provider_factory() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / "key.bin"
        path.write_bytes(b"wrapped")
        recording_factory = RecordingCryptoProviderFactory()

        (
            KeyRingBuilder()
            .with_key_wrapper(FakeKeyWrapper(secrets.token_bytes(32)))
            .with_crypto_provider_factory(recording_factory)
            .with_cached_key_expiry(123)
            .with_key_file(1, str(path))
            .build()
        )

        assert recording_factory.create_expiry_seconds_calls == [123]


def test_build_with_ephemeral_key_passes_cached_key_expiry_rather_than_version_to_the_crypto_provider_factory() -> (
    None
):
    # Regression test: create_ephemeral used to be called with the KeyRing version instead of
    # cached_key_expiry - a version of 1 would silently become a 1-second session lifetime.
    recording_factory = RecordingCryptoProviderFactory()

    (
        KeyRingBuilder()
        .with_key_wrapper(FakeKeyWrapper(secrets.token_bytes(32)))
        .with_crypto_provider_factory(recording_factory)
        .with_cached_key_expiry(123)
        .with_ephemeral_key(42)
        .build()
    )

    assert recording_factory.create_ephemeral_expiry_seconds_calls == [123]
