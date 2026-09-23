"""Python port of HkdfGuard.Cache/ProtectedCacheCollection.cs.

Aggregates multiple IProtectedReadOnlyCache sources into a single read-only surface. add
registers a source and returns this same instance for fluent chaining (e.g.
ProtectedCacheCollection().add(a).add(b)). decrypt/decrypt_str/try_get_max_decrypted_length check
each registered source in the order it was added, returning the first match. This never owns or
writes any encrypted values of its own - add here only registers a source, it never protects or
stores a value - so mutation of actual cached values stays entirely a concern of whichever
underlying source(s) actually support it (e.g. a writable ProtectedCache mixed in as one of the
sources).
"""

from typing import Self

from hkdfguard_abstractions import IProtectedReadOnlyCache
from hkdfguard_diagnostics import ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry

_TELEMETRY = HkdfGuardTelemetry.CACHE


class ProtectedCacheCollection(IProtectedReadOnlyCache):
    def __init__(self) -> None:
        self._sources: list[IProtectedReadOnlyCache] = []

    def add(self, source: IProtectedReadOnlyCache) -> Self:
        """Registers source as an additional lookup source, checked after every source already
        added. Returns this same ProtectedCacheCollection, for fluent chaining.
        """
        self._sources.append(source)
        return self

    def decrypt(self, name: str, result: bytearray) -> int:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.Cache.DECRYPT) as span:
            _TELEMETRY.log_sensitive_operation(span, ActivityNames.Cache.DECRYPT, (AttributeNames.NAME, name))
            try:
                for source in self._sources:
                    written = source.decrypt(name, result)
                    if written > 0:
                        return written

                return 0
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def decrypt_str(self, name: str) -> str | None:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.Cache.DECRYPT) as span:
            _TELEMETRY.log_sensitive_operation(span, ActivityNames.Cache.DECRYPT, (AttributeNames.NAME, name))
            try:
                for source in self._sources:
                    value = source.decrypt_str(name)
                    if value is not None:
                        return value

                return None
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def try_get_max_decrypted_length(self, name: str) -> int | None:
        for source in self._sources:
            max_length = source.try_get_max_decrypted_length(name)
            if max_length is not None:
                return max_length

        return None
