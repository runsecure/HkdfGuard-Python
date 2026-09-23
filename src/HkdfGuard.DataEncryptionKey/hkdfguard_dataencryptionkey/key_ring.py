"""Python port of HkdfGuard.DataEncryptionKey/KeyRing.cs.

Tracks IDataEncryptionKey instances by version for highly concurrent workloads. get is served
straight off a plain dict - CPython dict reads/writes are already atomic under the GIL, so the
hot read path never blocks and needs no separate lock (the direct analogue of the .NET original's
lock-free ConcurrentDictionary read) - no telemetry on that path either, only on a miss, since
that's the exceptional case. add is serialized through a threading.Lock (the .NET original uses a
SemaphoreSlim specifically so a future async Add could await it; nothing here is async, so a plain
Lock is the simpler, direct equivalent) - key registration only happens at startup/rotation, not
per-operation, so the gate (and its telemetry) costs nothing where it matters.

The ring tracks its own current version intrinsically: whichever registered version number is
highest becomes current_version, automatically, the moment it's added - there is no separate call
to designate one, so it can never fall out of sync with what's actually registered.
"""

import threading
from typing import Self

from hkdfguard_abstractions import IDataEncryptionKey, IDataProtector, IEncryptedFormatProvider
from hkdfguard_diagnostics import ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry

from .protector.data_protector import DataProtector

_TELEMETRY = HkdfGuardTelemetry.DATA_PROTECTION


class KeyRing:
    def __init__(self, format_provider: IEncryptedFormatProvider) -> None:
        self._format_provider = format_provider
        self._keys_by_version: dict[int, IDataEncryptionKey] = {}
        self._add_gate = threading.Lock()
        self._current_version: int | None = None

    @property
    def current_version(self) -> int:
        """The highest version registered so far - what encrypt-side operations (e.g.
        DataProtector.encrypt) protect new data with.

        Raises ValueError if no key has been added yet.
        """
        current = self._current_version
        if current is None:
            raise ValueError("No current version has been set. Add a key first.")
        return current

    def add(self, version: int, key: IDataEncryptionKey) -> None:
        """Registers a key for the given version. If version is higher than every version
        registered so far, it intrinsically becomes the new current_version.

        Raises ValueError if a key for this version is already registered.
        """
        with (
            _TELEMETRY.tracer.start_as_current_span(ActivityNames.DataProtection.KEY_RING_ADD) as span,
            self._add_gate,
        ):
            try:
                if version in self._keys_by_version:
                    raise ValueError(f"A key for version {version} is already registered.")
                self._keys_by_version[version] = key

                became_current = self._current_version is None or version > self._current_version
                if became_current:
                    self._current_version = version

                _TELEMETRY.log_sensitive_operation(
                    span,
                    ActivityNames.DataProtection.KEY_RING_ADD,
                    (AttributeNames.KEY_VERSION, version),
                    (AttributeNames.KEY_RING_BECAME_CURRENT, became_current),
                )
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def get(self, version: int) -> IDataEncryptionKey:
        """Retrieves the key registered for the given version.

        Raises KeyError if no key is registered for this version.
        """
        key = self._keys_by_version.get(version)
        if key is not None:
            return key

        not_found = KeyError(f"No key is registered for version {version}.")
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.DataProtection.KEY_RING_GET) as span:
            ComponentTelemetry.record_exception(span, not_found)
        raise not_found

    def try_get(self, version: int) -> IDataEncryptionKey | None:
        """Attempts to retrieve the key registered for the given version without raising - for
        the high-frequency hot path, where exception overhead (and telemetry) on a routine miss
        is unacceptable.
        """
        return self._keys_by_version.get(version)

    def get_current(self) -> tuple[int, IDataEncryptionKey]:
        """Retrieves current_version together with its IDataEncryptionKey atomically - what
        encrypt-side operations (e.g. DataProtector.encrypt) resolve fresh on every call, so they
        always reflect the latest rotation rather than a version captured once at construction.

        Raises ValueError if no key has been added yet.
        """
        try:
            version = self.current_version
            return version, self.get(version)
        except ValueError as exc:
            with _TELEMETRY.tracer.start_as_current_span(ActivityNames.DataProtection.KEY_RING_GET_CURRENT) as span:
                ComponentTelemetry.record_exception(span, exc)
            raise

    def create_protector(self, name: str) -> IDataProtector:
        """Creates an IDataProtector bound to this KeyRing - the only way to obtain one, since
        DataProtector is not part of this package's public API. encrypt resolves current_version
        fresh via get_current on every call (not a version captured once here), and
        formats/parses via the IEncryptedFormatProvider this ring was constructed with.

        name: used as this protector's Additional Auth Data on every encrypt/decrypt.
        """
        return DataProtector(name, self, self._format_provider)

    def close(self) -> None:
        # threading.Lock needs no explicit release/disposal, unlike the .NET original's
        # SemaphoreSlim - kept only so callers written against KeyRing as a context manager work.
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()
