"""Python port of HkdfGuard.KeyWrapping.V1/Interop/MacOsHkdfGuardKmsLibrary.cs."""

from .native_kms_library import NativeCtypesKmsLibrary


class MacOsHkdfGuardKmsLibrary(NativeCtypesKmsLibrary):
    """Binds HkdfGuard.Kms.MacOS.v1.dylib (see HkdfGuardKeyProtectionEnclave.h), which holds the
    per-service KEK as a Secure Enclave key. Each distinct service string gets its own,
    independent Secure Enclave key - wrapping under one service's identifier and unwrapping under
    a different one fails by design (ERR_DECRYPTION_FAILED).
    """

    LIBRARY_NAME = "HkdfGuard.Kms.MacOS.v1.dylib"

    ERR_INVALID_INPUT_LENGTH = -1
    ERR_OUTPUT_BUFFER_TOO_SMALL = -2
    ERR_KEY_UNAVAILABLE = -3
    ERR_PUBLIC_KEY_UNAVAILABLE = -4
    ERR_ENCRYPTION_FAILED = -5
    ERR_DECRYPTION_FAILED = -6
    ERR_UNEXPECTED_OUTPUT_LENGTH = -7
    ERR_MISSING_SERVICE_IDENTIFIER = -8
