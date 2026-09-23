"""Python port of HkdfGuard.DataEncryptionKey/KeyRingBuilder.cs."""

from pathlib import Path
from typing import Self

from hkdfguard_abstractions import ICryptoProviderFactory, IEncryptedFormatProvider, IKeyWrapper

from .format_provider.default_format_provider import DefaultFormatProvider
from .key_ring import KeyRing
from .key_wrapped_data_encryption_key import KeyWrappedDataEncryptionKey


class KeyRingBuilder:
    """Builds a KeyRing from wrapped-DEK files on disk, suitable for registering as a singleton
    at startup. There is one IKeyWrapper shared by every registered file - it's bound only to a
    KEK (e.g. NativeHkdfKeyWrapperV1's service name), not to any one wrapped payload, so it can
    reveal any number of different files' DEKs (see IKeyWrapper). Each registered file gets its
    own ICryptoProvider (minted by the configured ICryptoProviderFactory, bound to that file's own
    wrapped bytes) and becomes its own KeyWrappedDataEncryptionKey. with_ephemeral_key registers a
    version whose own key material is instead generated fresh in memory on first use (via
    ICryptoProviderFactory.create_ephemeral) - it shares the same IKeyWrapper/ICryptoProviderFactory,
    so no extra configuration is needed for it.
    service_name/key_rotation_days describe this ring's key identity/policy - they're carried on
    the builder for callers to read back, but only cached_key_expiry is consumed by build itself
    (as every provider's refresh interval), since IKeyWrapper already knows what KEK it's bound to.
    """

    def __init__(self) -> None:
        self._key_files: dict[int, str] = {}
        self._ephemeral_versions: list[int] = []
        self._key_wrapper: IKeyWrapper | None = None
        self._crypto_provider_factory: ICryptoProviderFactory | None = None
        self._format_provider: IEncryptedFormatProvider = DefaultFormatProvider()
        self._service_name: str | None = None
        self._cached_key_expiry: int | None = None
        self._key_rotation_days: int | None = None

    @property
    def service_name(self) -> str | None:
        return self._service_name

    @property
    def cached_key_expiry(self) -> int | None:
        return self._cached_key_expiry

    @property
    def key_rotation_days(self) -> int | None:
        return self._key_rotation_days

    def with_service_name(self, service_name: str) -> Self:
        """The service name identifying this ring's KEK to the native KMS library."""
        self._service_name = service_name
        return self

    def with_cached_key_expiry(self, cached_key_expiry: int) -> Self:
        """How many seconds a revealed key may be cached in memory before it must be re-derived.

        Raises ValueError if cached_key_expiry is not between 0 and 300.
        """
        if not 0 <= cached_key_expiry <= 300:
            raise ValueError(f"cached_key_expiry must be between 0 and 300 seconds, got {cached_key_expiry}.")

        self._cached_key_expiry = cached_key_expiry
        return self

    def with_key_rotation_days(self, key_rotation_days: int) -> Self:
        """How many days may pass before this ring's key must be rotated.

        Raises ValueError if key_rotation_days is not between 1 and 180.
        """
        if not 1 <= key_rotation_days <= 180:
            raise ValueError(f"key_rotation_days must be between 1 and 180 days, got {key_rotation_days}.")

        self._key_rotation_days = key_rotation_days
        return self

    def with_key_wrapper(self, key_wrapper: IKeyWrapper) -> Self:
        """Supplies the IKeyWrapper shared by every registered key file when build runs."""
        self._key_wrapper = key_wrapper
        return self

    def with_crypto_provider_factory(self, crypto_provider_factory: ICryptoProviderFactory) -> Self:
        """Supplies the factory used to build each key file's own ICryptoProvider, called once
        per registered file with the shared IKeyWrapper and that file's own wrapped bytes.
        """
        self._crypto_provider_factory = crypto_provider_factory
        return self

    def with_format_provider(self, format_provider: IEncryptedFormatProvider) -> Self:
        """Overrides the IEncryptedFormatProvider the built KeyRing uses for create_protector.
        Defaults to DefaultFormatProvider.
        """
        self._format_provider = format_provider
        return self

    def with_key_file(self, version: int, path_to_file: str) -> Self:
        """Registers a version whose wrapped DEK will be read from path_to_file when build runs.
        The highest version registered across every with_key_file call intrinsically becomes the
        built KeyRing's current_version.

        Raises ValueError if version is already registered.
        """
        if version in self._key_files:
            raise ValueError(f"A key file for version {version} is already registered.")

        self._key_files[version] = path_to_file
        return self

    def with_ephemeral_key(self, version: int) -> Self:
        """Registers a version whose own key material is generated fresh in memory the first
        time it's used, and never written to or read from disk. The highest version registered
        across every with_key_file/with_ephemeral_key call intrinsically becomes the built
        KeyRing's current_version.
        """
        self._ephemeral_versions.append(version)
        return self

    def build(self) -> KeyRing:
        """Reads each registered key file's wrapped bytes, mints each registered ephemeral key,
        and returns a populated KeyRing.

        Raises ValueError if no key wrapper, no crypto provider factory, no key files/ephemeral
        keys, or no cached key expiry were configured.
        """
        if self._key_wrapper is None:
            raise ValueError("A key wrapper is required - call with_key_wrapper first.")

        if self._crypto_provider_factory is None:
            raise ValueError("A crypto provider factory is required - call with_crypto_provider_factory first.")

        if not self._key_files and not self._ephemeral_versions:
            raise ValueError(
                "At least one key file or ephemeral key is required - call with_key_file or with_ephemeral_key first."
            )

        if self._cached_key_expiry is None:
            raise ValueError("A cached key expiry is required - call with_cached_key_expiry first.")

        ring = KeyRing(self._format_provider)

        for version, path in sorted(self._key_files.items()):
            wrapped = Path(path).read_bytes()
            provider = self._crypto_provider_factory.create(self._key_wrapper, wrapped, self._cached_key_expiry)
            ring.add(version, KeyWrappedDataEncryptionKey(provider))

        for version in self._ephemeral_versions:
            provider = self._crypto_provider_factory.create_ephemeral(self._key_wrapper, self._cached_key_expiry)
            ring.add(version, KeyWrappedDataEncryptionKey(provider))

        return ring
