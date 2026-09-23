"""Python port of HkdfGuard.KeyWrapping.V1/Interop/LinuxHkdfGuardKmsLibrary.cs."""

from .native_kms_library import NativeCtypesKmsLibrary


class LinuxHkdfGuardKmsLibrary(NativeCtypesKmsLibrary):
    """Binds libHkdfGuardKeyProtectionLinux.so (see hkdfguard.h), which picks the strongest
    available provider on the host - TPM2 > PKCS#11 > external secret > software > ephemeral - to
    hold the per-service KEK. No Rust type, TPM handle, or OpenSSL structure ever crosses this
    boundary, and no panic ever crosses it either: every native call returns a plain status code.
    """

    LIBRARY_NAME = "libHkdfGuardKeyProtectionLinux.so"

    ERR_INVALID_ARGUMENT = -1
    ERR_BUFFER_TOO_SMALL = -2
    ERR_PROVIDER_UNAVAILABLE = -3
    ERR_PROVIDER_ERROR = -4
    ERR_CRYPTO_ERROR = -5
    ERR_INTERNAL_ERROR = -6
    ERR_INVALID_UTF8 = -7
    ERR_MISSING_SERVICE_NAME = -8
