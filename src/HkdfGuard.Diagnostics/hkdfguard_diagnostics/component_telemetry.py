"""One component's telemetry surface: a Tracer and Meter sharing that component's scope name, an
enable_sensitive_logging toggle, and the record_exception/log_sensitive_operation helpers every
operation across the library calls through. A single implementation shared by every component in
``HkdfGuardTelemetry`` - replacing what would otherwise be six near-identical, hand-duplicated
diagnostics modules.
"""

from __future__ import annotations

from opentelemetry import metrics, trace
from opentelemetry.trace import Span, Status, StatusCode

from .attribute_names import AttributeNames
from .event_names import EventNames


class ComponentTelemetry:
    """
    Parameters
    ----------
    source_name:
        This component's Tracer/Meter instrumentation scope name - e.g. ``"HkdfGuard.Cache"``.
    shared_flag_owner:
        When given, ``enable_sensitive_logging`` delegates to this component's own flag instead of
        keeping an independent one - e.g. Cache/DataProtection/EncryptedConfiguration all share
        Root's flag.
    """

    def __init__(self, source_name: str, shared_flag_owner: ComponentTelemetry | None = None) -> None:
        self.source_name = source_name
        self.tracer = trace.get_tracer(source_name)
        self.meter = metrics.get_meter(source_name)
        self._shared_flag_owner = shared_flag_owner
        self._enable_sensitive_logging = False

    @property
    def enable_sensitive_logging(self) -> bool:
        """
        When enabled, sensitive operations emit additional debug telemetry (operation metadata such
        as buffer lengths and identifiers). Raw key, plaintext, and ciphertext bytes are never
        logged, regardless of this setting. Components constructed with a shared_flag_owner read
        and write that owner's flag instead of keeping their own.
        """
        if self._shared_flag_owner is not None:
            return self._shared_flag_owner.enable_sensitive_logging
        return self._enable_sensitive_logging

    @enable_sensitive_logging.setter
    def enable_sensitive_logging(self, value: bool) -> None:
        if self._shared_flag_owner is not None:
            self._shared_flag_owner.enable_sensitive_logging = value
        else:
            self._enable_sensitive_logging = value

    @staticmethod
    def record_exception(span: Span | None, exception: BaseException) -> None:
        """Records an exception on the given span and marks it as errored."""
        if span is None:
            return
        span.record_exception(exception)
        span.set_status(Status(StatusCode.ERROR, str(exception)))

    def log_sensitive_operation(
        self,
        span: Span | None,
        operation_name: str,
        *details: tuple[str, object],
    ) -> None:
        """Emits a fixed-name (``EventNames.SENSITIVE_OPERATION``) debug event when
        ``enable_sensitive_logging`` is set, carrying operation_name and every detail as
        attributes. Only pass non-sensitive metadata (lengths, identifiers, timings) as details -
        never raw key, plaintext, or ciphertext bytes.
        """
        if not self.enable_sensitive_logging or span is None:
            return

        attributes: dict[str, object] = {AttributeNames.OPERATION_NAME: operation_name}
        for key, value in details:
            attributes[key] = value

        span.add_event(EventNames.SENSITIVE_OPERATION, attributes=attributes)
