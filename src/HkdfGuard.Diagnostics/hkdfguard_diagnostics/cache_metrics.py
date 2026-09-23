"""Cache component instruments, built on HkdfGuardTelemetry.CACHE.meter. Operations counts every
ProtectedCache add/add_or_update call, tagged with AttributeNames.OPERATION_NAME (which
ActivityNames.Cache constant ran) and AttributeNames.RESULT ("success" or "error").
"""

from .hkdfguard_telemetry import HkdfGuardTelemetry
from .metric_names import MetricNames


class CacheMetrics:
    OPERATIONS = HkdfGuardTelemetry.CACHE.meter.create_counter(
        MetricNames.Cache.OPERATIONS,
        unit="{operation}",
        description="Number of ProtectedCache operations, tagged by operation and result.",
    )
