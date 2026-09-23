"""Python port of HkdfGuard.Cache/ProtectedCache.cs.

Default IProtectedCache. Backed by a single, already-built IDataEncryptionKey - every add/
add_or_update encrypts through it (see ProtectedCacheBase), every decrypt reveals through it. add
uses _try_add_encrypted as its atomicity gate so a duplicate name is rejected even under
concurrent callers; add_or_update's upsert and decrypt's reads are otherwise lock-free, so this
holds up under highly concurrent access in every direction. Nothing here ever holds plaintext
beyond the duration of a single add/add_or_update/decrypt call.

The pattern class for HkdfGuard.Diagnostics's metrics/logging extension points: logger is
optional (defaults to None, so every existing call site keeps compiling unchanged) and, when
supplied, receives a debug log per sensitive operation and an error log per failure alongside the
existing span/CacheMetrics.OPERATIONS telemetry.
"""

import logging

from hkdfguard_abstractions import IDataEncryptionKey, IProtectedCache, ProtectedCacheBase
from hkdfguard_diagnostics import (
    ActivityNames,
    AttributeNames,
    CacheMetrics,
    ComponentTelemetry,
    HkdfGuardTelemetry,
    operation_failed,
    sensitive_operation_logged,
)

_TELEMETRY = HkdfGuardTelemetry.CACHE


class ProtectedCache(ProtectedCacheBase, IProtectedCache):
    def __init__(self, data_encryption_key: IDataEncryptionKey, logger: logging.Logger | None = None) -> None:
        super().__init__(data_encryption_key)
        self._logger = logger

    def add(self, name: str, plaintext: bytearray) -> None:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.Cache.ADD) as span:
            if _TELEMETRY.enable_sensitive_logging:
                _TELEMETRY.log_sensitive_operation(
                    span,
                    ActivityNames.Cache.ADD,
                    (AttributeNames.NAME, name),
                    (AttributeNames.PLAINTEXT_LENGTH, len(plaintext)),
                )
                if self._logger is not None:
                    sensitive_operation_logged(self._logger, ActivityNames.Cache.ADD, name)

            try:
                if not self._try_add_encrypted(name, self._encrypt(plaintext)):
                    raise ValueError(f"An item with the name '{name}' has already been added.")

                self._record_operation(ActivityNames.Cache.ADD, success=True)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                if self._logger is not None:
                    operation_failed(self._logger, ActivityNames.Cache.ADD, exc)
                self._record_operation(ActivityNames.Cache.ADD, success=False)
                raise

    def add_str(self, name: str, plaintext: str) -> None:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.Cache.ADD) as span:
            if _TELEMETRY.enable_sensitive_logging:
                _TELEMETRY.log_sensitive_operation(
                    span,
                    ActivityNames.Cache.ADD,
                    (AttributeNames.NAME, name),
                    (AttributeNames.PLAINTEXT_LENGTH, len(plaintext)),
                )
                if self._logger is not None:
                    sensitive_operation_logged(self._logger, ActivityNames.Cache.ADD, name)

            try:
                if not self._try_add_encrypted(name, self._encrypt_str(plaintext)):
                    raise ValueError(f"An item with the name '{name}' has already been added.")

                self._record_operation(ActivityNames.Cache.ADD, success=True)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                if self._logger is not None:
                    operation_failed(self._logger, ActivityNames.Cache.ADD, exc)
                self._record_operation(ActivityNames.Cache.ADD, success=False)
                raise

    def add_or_update(self, name: str, plaintext: bytearray) -> None:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.Cache.ADD_OR_UPDATE) as span:
            if _TELEMETRY.enable_sensitive_logging:
                _TELEMETRY.log_sensitive_operation(
                    span,
                    ActivityNames.Cache.ADD_OR_UPDATE,
                    (AttributeNames.NAME, name),
                    (AttributeNames.PLAINTEXT_LENGTH, len(plaintext)),
                )
                if self._logger is not None:
                    sensitive_operation_logged(self._logger, ActivityNames.Cache.ADD_OR_UPDATE, name)

            try:
                self._set_encrypted(name, self._encrypt(plaintext))
                self._record_operation(ActivityNames.Cache.ADD_OR_UPDATE, success=True)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                if self._logger is not None:
                    operation_failed(self._logger, ActivityNames.Cache.ADD_OR_UPDATE, exc)
                self._record_operation(ActivityNames.Cache.ADD_OR_UPDATE, success=False)
                raise

    def add_or_update_str(self, name: str, plaintext: str) -> None:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.Cache.ADD_OR_UPDATE) as span:
            if _TELEMETRY.enable_sensitive_logging:
                _TELEMETRY.log_sensitive_operation(
                    span,
                    ActivityNames.Cache.ADD_OR_UPDATE,
                    (AttributeNames.NAME, name),
                    (AttributeNames.PLAINTEXT_LENGTH, len(plaintext)),
                )
                if self._logger is not None:
                    sensitive_operation_logged(self._logger, ActivityNames.Cache.ADD_OR_UPDATE, name)

            try:
                self._set_encrypted(name, self._encrypt_str(plaintext))
                self._record_operation(ActivityNames.Cache.ADD_OR_UPDATE, success=True)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                if self._logger is not None:
                    operation_failed(self._logger, ActivityNames.Cache.ADD_OR_UPDATE, exc)
                self._record_operation(ActivityNames.Cache.ADD_OR_UPDATE, success=False)
                raise

    @staticmethod
    def _record_operation(operation_name: str, *, success: bool) -> None:
        CacheMetrics.OPERATIONS.add(
            1,
            {
                AttributeNames.OPERATION_NAME: operation_name,
                AttributeNames.RESULT: "success" if success else "error",
            },
        )
