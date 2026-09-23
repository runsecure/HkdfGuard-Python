import pytest
from hkdfguard_diagnostics import AttributeNames, ComponentTelemetry, EventNames, HkdfGuardTelemetry
from opentelemetry.trace import StatusCode

ALL_COMPONENTS = [
    pytest.param(HkdfGuardTelemetry.ROOT, id="root"),
    pytest.param(HkdfGuardTelemetry.CACHE, id="cache"),
    pytest.param(HkdfGuardTelemetry.DATA_PROTECTION, id="data_protection"),
    pytest.param(HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION, id="encrypted_configuration"),
    pytest.param(HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256, id="crypto_session_aes_gcm256"),
    pytest.param(HkdfGuardTelemetry.KEY_WRAPPING, id="key_wrapping"),
]


@pytest.mark.parametrize("component", ALL_COMPONENTS)
def test_meter_name_matches_source_name(component: ComponentTelemetry) -> None:
    # OTel Python's Meter proxy exposes a public `.name`, but its Tracer proxy does not - so
    # unlike the .NET ActivitySource/Meter pair, only the meter side can be asserted here.
    assert component.meter.name == component.source_name


@pytest.mark.parametrize("component", ALL_COMPONENTS)
def test_record_exception_with_none_span_does_not_raise(component: ComponentTelemetry) -> None:
    ComponentTelemetry.record_exception(None, ValueError("boom"))


@pytest.mark.parametrize("component", ALL_COMPONENTS)
def test_record_exception_with_real_span_records_exception_and_error_status(
    component: ComponentTelemetry, span_exporter
) -> None:
    exception = ValueError("boom")

    with component.tracer.start_as_current_span("test-activity") as span:
        ComponentTelemetry.record_exception(span, exception)

    (finished_span,) = span_exporter.get_finished_spans()
    assert finished_span.status.status_code == StatusCode.ERROR
    assert any(event.name == "exception" for event in finished_span.events)


@pytest.mark.parametrize("component", ALL_COMPONENTS)
def test_log_sensitive_operation_with_none_span_does_not_raise(component: ComponentTelemetry) -> None:
    component.log_sensitive_operation(None, "test-op")


@pytest.mark.parametrize("component", ALL_COMPONENTS)
def test_log_sensitive_operation_when_disabled_does_not_add_event(
    component: ComponentTelemetry, span_exporter
) -> None:
    original = component.enable_sensitive_logging
    try:
        component.enable_sensitive_logging = False

        with component.tracer.start_as_current_span("test-activity") as span:
            component.log_sensitive_operation(span, "test-op", ("key", "value"))

        (finished_span,) = span_exporter.get_finished_spans()
        assert finished_span.events == ()
    finally:
        component.enable_sensitive_logging = original


@pytest.mark.parametrize("component", ALL_COMPONENTS)
def test_log_sensitive_operation_when_enabled_adds_fixed_name_event_with_operation_and_detail_tags(
    component: ComponentTelemetry, span_exporter
) -> None:
    original = component.enable_sensitive_logging
    try:
        component.enable_sensitive_logging = True

        with component.tracer.start_as_current_span("test-activity") as span:
            component.log_sensitive_operation(span, "test-op", ("hkdfguard.name", "item"))

        (finished_span,) = span_exporter.get_finished_spans()
        (logged_event,) = finished_span.events
        assert logged_event.name == EventNames.SENSITIVE_OPERATION
        assert logged_event.attributes[AttributeNames.OPERATION_NAME] == "test-op"
        assert logged_event.attributes["hkdfguard.name"] == "item"
    finally:
        component.enable_sensitive_logging = original


def test_enable_sensitive_logging_root_shares_flag_with_cache_data_protection_and_encrypted_configuration() -> None:
    original = HkdfGuardTelemetry.ROOT.enable_sensitive_logging
    try:
        HkdfGuardTelemetry.ROOT.enable_sensitive_logging = True
        assert HkdfGuardTelemetry.CACHE.enable_sensitive_logging is True
        assert HkdfGuardTelemetry.DATA_PROTECTION.enable_sensitive_logging is True
        assert HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION.enable_sensitive_logging is True

        HkdfGuardTelemetry.CACHE.enable_sensitive_logging = False
        assert HkdfGuardTelemetry.ROOT.enable_sensitive_logging is False
        assert HkdfGuardTelemetry.DATA_PROTECTION.enable_sensitive_logging is False
        assert HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION.enable_sensitive_logging is False
    finally:
        HkdfGuardTelemetry.ROOT.enable_sensitive_logging = original


def test_enable_sensitive_logging_crypto_session_aes_gcm256_and_key_wrapping_are_independent_from_root_and_each_other() -> (
    None
):
    original_root = HkdfGuardTelemetry.ROOT.enable_sensitive_logging
    original_crypto_session = HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256.enable_sensitive_logging
    original_key_wrapping = HkdfGuardTelemetry.KEY_WRAPPING.enable_sensitive_logging
    try:
        HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256.enable_sensitive_logging = False
        HkdfGuardTelemetry.KEY_WRAPPING.enable_sensitive_logging = False

        HkdfGuardTelemetry.ROOT.enable_sensitive_logging = True
        assert HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256.enable_sensitive_logging is False
        assert HkdfGuardTelemetry.KEY_WRAPPING.enable_sensitive_logging is False

        HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256.enable_sensitive_logging = True
        assert HkdfGuardTelemetry.KEY_WRAPPING.enable_sensitive_logging is False
    finally:
        HkdfGuardTelemetry.ROOT.enable_sensitive_logging = original_root
        HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256.enable_sensitive_logging = original_crypto_session
        HkdfGuardTelemetry.KEY_WRAPPING.enable_sensitive_logging = original_key_wrapping
