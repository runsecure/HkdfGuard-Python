"""Python port of HkdfGuard.KeyWrapping.V1/Interop/WindowsHkdfGuardKmsLibrary.cs."""

from .native_kms_library import NativeCtypesKmsLibrary


class WindowsHkdfGuardKmsLibrary(NativeCtypesKmsLibrary):
    """Binds HkdfGuard.Kms.Windows.v1.dll (see hkdfguard.h), which holds the per-service KEK as a
    persistent, machine-wide-scoped, non-exportable P-256 key in the Microsoft Platform Crypto
    Provider (TPM/vTPM) when available, or the Microsoft Software Key Storage Provider otherwise.
    """

    LIBRARY_NAME = "HkdfGuard.Kms.Windows.v1.dll"

    ERR_INVALID_ARG = -1
    ERR_BUFFER_TOO_SMALL = -2
    ERR_PROVIDER = -3
    ERR_CRYPTO = -4
    ERR_AUTH_FAILED = -5
    ERR_MALFORMED = -6
    ERR_INTERNAL = -7
