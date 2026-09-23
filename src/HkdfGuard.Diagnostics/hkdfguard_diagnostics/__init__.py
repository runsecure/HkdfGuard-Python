"""Shared OpenTelemetry activity/metric/event naming and telemetry helpers for HkdfGuard
components. Python port of the HkdfGuard.Diagnostics .NET project.
"""

from .activity_names import ActivityNames
from .attribute_names import AttributeNames
from .cache_metrics import CacheMetrics
from .component_telemetry import ComponentTelemetry
from .event_names import EventNames
from .hkdfguard_telemetry import HkdfGuardTelemetry
from .logger_extensions import operation_failed, sensitive_operation_logged
from .metric_names import MetricNames

__all__ = [
    "ActivityNames",
    "AttributeNames",
    "CacheMetrics",
    "ComponentTelemetry",
    "EventNames",
    "HkdfGuardTelemetry",
    "MetricNames",
    "operation_failed",
    "sensitive_operation_logged",
]
