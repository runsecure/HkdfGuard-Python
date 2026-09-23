"""Standard-library ``logging`` helpers, shared by every component that chooses to accept an
optional ``logging.Logger`` (e.g. ProtectedCache's constructor). Mirrors
ComponentTelemetry.log_sensitive_operation/record_exception's gating: sensitive_operation_logged
is only worth calling when ComponentTelemetry.enable_sensitive_logging is set, while
operation_failed is unconditional - failures are always worth logging. Both use %-style deferred
formatting, so the message is only built when the target level is enabled.
"""

from __future__ import annotations

import logging


def sensitive_operation_logged(logger: logging.Logger, operation_name: str, name: str | None) -> None:
    logger.debug("%s completed for %s.", operation_name, name)


def operation_failed(logger: logging.Logger, operation_name: str, exception: BaseException) -> None:
    logger.error("%s failed.", operation_name, exc_info=exception)
