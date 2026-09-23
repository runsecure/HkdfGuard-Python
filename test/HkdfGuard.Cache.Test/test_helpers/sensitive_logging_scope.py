"""Temporarily sets HkdfGuardTelemetry.CACHE.enable_sensitive_logging, restoring the original
value on exit - so a test can exercise a production method's "if enabled, log" branch without
leaking that shared flag into other tests. CACHE shares its flag with ROOT (see
hkdfguard_diagnostics.HkdfGuardTelemetry), so this also covers ProtectedCacheBase, which reads
ROOT's flag directly. Safe only because pytest runs test functions within a module sequentially
by default (no parallel test execution) - enable_sensitive_logging has no synchronization of its
own.
"""

from collections.abc import Iterator
from contextlib import contextmanager

from hkdfguard_diagnostics import HkdfGuardTelemetry


@contextmanager
def sensitive_logging_scope(enabled: bool) -> Iterator[None]:
    original = HkdfGuardTelemetry.CACHE.enable_sensitive_logging
    HkdfGuardTelemetry.CACHE.enable_sensitive_logging = enabled
    try:
        yield
    finally:
        HkdfGuardTelemetry.CACHE.enable_sensitive_logging = original
