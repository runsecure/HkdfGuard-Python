"""One ComponentTelemetry instance per component in the library - the single place every
component's Tracer/Meter/enable_sensitive_logging telemetry lives. Preserves the same
flag-sharing split used across the .NET port's original per-project Diagnostics classes: ROOT,
CACHE, DATA_PROTECTION, and ENCRYPTED_CONFIGURATION all share one enable_sensitive_logging flag
(set any of them, all four read the new value); CRYPTO_SESSION_AES_GCM256 and KEY_WRAPPING each
keep their own, independent flag.
"""

from .component_telemetry import ComponentTelemetry


class HkdfGuardTelemetry:
    ROOT = ComponentTelemetry("HkdfGuard")
    CACHE = ComponentTelemetry("HkdfGuard.Cache", ROOT)
    DATA_PROTECTION = ComponentTelemetry("HkdfGuard.DataEncryptionKey", ROOT)
    ENCRYPTED_CONFIGURATION = ComponentTelemetry("HkdfGuard.EncryptedConfiguration", ROOT)
    CRYPTO_SESSION_AES_GCM256 = ComponentTelemetry("HkdfGuard.CryptoSession.AesGcm256")
    KEY_WRAPPING = ComponentTelemetry("HkdfGuard.KeyWrapping.V1")
