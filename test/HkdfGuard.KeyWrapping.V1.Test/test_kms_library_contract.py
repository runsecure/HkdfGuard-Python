"""Python port of test/HkdfGuard.KeyWrapping.V1.Test/KmsLibraryContractTests.cs.

These only read class-level constants, so - like the .NET originals - none of them touch the
native library.
"""

from hkdfguard_keywrapping_v1.interop import (
    AbstractHkdfGuardKmsLibrary,
    LinuxHkdfGuardKmsLibrary,
    MacOsHkdfGuardKmsLibrary,
    WindowsHkdfGuardKmsLibrary,
)


def test_abstract_hkdfguard_kms_library_constants_match_expected() -> None:
    assert AbstractHkdfGuardKmsLibrary.DEK_LENGTH == 32
    assert AbstractHkdfGuardKmsLibrary.OK == 0


def test_windows_hkdfguard_kms_library_error_constants_match_expected() -> None:
    assert WindowsHkdfGuardKmsLibrary.ERR_INVALID_ARG == -1
    assert WindowsHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL == -2
    assert WindowsHkdfGuardKmsLibrary.ERR_PROVIDER == -3
    assert WindowsHkdfGuardKmsLibrary.ERR_CRYPTO == -4
    assert WindowsHkdfGuardKmsLibrary.ERR_AUTH_FAILED == -5
    assert WindowsHkdfGuardKmsLibrary.ERR_MALFORMED == -6
    assert WindowsHkdfGuardKmsLibrary.ERR_INTERNAL == -7


def test_linux_hkdfguard_kms_library_error_constants_match_expected() -> None:
    assert LinuxHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT == -1
    assert LinuxHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL == -2
    assert LinuxHkdfGuardKmsLibrary.ERR_PROVIDER_UNAVAILABLE == -3
    assert LinuxHkdfGuardKmsLibrary.ERR_PROVIDER_ERROR == -4
    assert LinuxHkdfGuardKmsLibrary.ERR_CRYPTO_ERROR == -5
    assert LinuxHkdfGuardKmsLibrary.ERR_INTERNAL_ERROR == -6
    assert LinuxHkdfGuardKmsLibrary.ERR_INVALID_UTF8 == -7
    assert LinuxHkdfGuardKmsLibrary.ERR_MISSING_SERVICE_NAME == -8


def test_macos_hkdfguard_kms_library_error_constants_match_expected() -> None:
    assert MacOsHkdfGuardKmsLibrary.ERR_INVALID_INPUT_LENGTH == -1
    assert MacOsHkdfGuardKmsLibrary.ERR_OUTPUT_BUFFER_TOO_SMALL == -2
    assert MacOsHkdfGuardKmsLibrary.ERR_KEY_UNAVAILABLE == -3
    assert MacOsHkdfGuardKmsLibrary.ERR_PUBLIC_KEY_UNAVAILABLE == -4
    assert MacOsHkdfGuardKmsLibrary.ERR_ENCRYPTION_FAILED == -5
    assert MacOsHkdfGuardKmsLibrary.ERR_DECRYPTION_FAILED == -6
    assert MacOsHkdfGuardKmsLibrary.ERR_UNEXPECTED_OUTPUT_LENGTH == -7
    assert MacOsHkdfGuardKmsLibrary.ERR_MISSING_SERVICE_IDENTIFIER == -8
