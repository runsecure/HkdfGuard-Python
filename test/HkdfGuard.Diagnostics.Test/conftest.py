"""Installs a real OTel SDK TracerProvider backed by an in-memory exporter for the whole test
session. ComponentTelemetry singletons are constructed at import time via ``trace.get_tracer``,
before any provider is configured; OTel's ProxyTracer resolves to the real tracer lazily once
``set_tracer_provider`` runs, so spans created afterwards are still captured - the same effect the
.NET tests get from installing a per-test ActivityListener.
"""

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

_exporter = InMemorySpanExporter()


@pytest.fixture(scope="session", autouse=True)
def _configure_tracer_provider() -> None:
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(_exporter))
    trace.set_tracer_provider(provider)


@pytest.fixture
def span_exporter() -> InMemorySpanExporter:
    _exporter.clear()
    return _exporter
