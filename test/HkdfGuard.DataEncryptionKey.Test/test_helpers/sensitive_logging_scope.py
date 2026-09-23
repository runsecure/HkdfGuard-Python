"""Python port of test/HkdfGuard.DataEncryptionKey.Test/TestHelpers/SensitiveLoggingScope.cs.

C#'s version is an IDisposable struct used with `using`; Python's equivalent for a scoped
set-then-restore is a @contextmanager generator function used with `with`.
"""

from collections.abc import Iterator
from contextlib import contextmanager

from hkdfguard_diagnostics import HkdfGuardTelemetry


@contextmanager
def sensitive_logging_scope(enabled: bool) -> Iterator[None]:
    """Temporarily sets HkdfGuardTelemetry.DATA_PROTECTION.enable_sensitive_logging, restoring
    the original value on exit - so a test can exercise a production method's "if enabled, log"
    branch without leaking that shared flag into other tests. Safe only because pytest runs test
    functions within a module sequentially by default (no parallel test execution) -
    enable_sensitive_logging has no synchronization of its own.
    """
    original = HkdfGuardTelemetry.DATA_PROTECTION.enable_sensitive_logging
    HkdfGuardTelemetry.DATA_PROTECTION.enable_sensitive_logging = enabled
    try:
        yield
    finally:
        HkdfGuardTelemetry.DATA_PROTECTION.enable_sensitive_logging = original
