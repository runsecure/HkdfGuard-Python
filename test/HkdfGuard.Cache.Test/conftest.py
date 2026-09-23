"""Configures a real OTel SDK MeterProvider with a delta-temporality in-memory reader, so
test_add_increments_cache_operations_counter_on_success_and_failure can observe only the
measurements contributed during its own run, regardless of what earlier tests in this session
already added to the same process-wide CacheMetrics.OPERATIONS counter (a true global singleton,
same as the .NET original's static field). Delta temporality makes each get_metrics_data() call
return only the increments since the previous collection - the closest equivalent to .NET's
MeterListener, which only observes events raised while it's actively listening, rather than a
cumulative running total the way OTel's default (CUMULATIVE) temporality would.
"""

import pytest
from opentelemetry import metrics
from opentelemetry.sdk.metrics import Counter, MeterProvider
from opentelemetry.sdk.metrics.export import AggregationTemporality, InMemoryMetricReader

_reader = InMemoryMetricReader(preferred_temporality={Counter: AggregationTemporality.DELTA})


@pytest.fixture(scope="session", autouse=True)
def _configure_meter_provider() -> None:
    provider = MeterProvider(metric_readers=[_reader])
    metrics.set_meter_provider(provider)


@pytest.fixture
def metric_reader() -> InMemoryMetricReader:
    _reader.get_metrics_data()  # flush/reset accumulated state so this test sees only its own delta
    return _reader
