"""Python port of test/HkdfGuard.KeyWrapping.V1.Test/NativeHostTests.cs.

get_library() only resolves *which* platform class to construct - it never dlopens the native
binary (see native_kms_library.NativeCtypesKmsLibrary), so these pass on any host regardless of
whether the native library is actually installed.
"""

import platform

from hkdfguard_keywrapping_v1.interop import (
    LinuxHkdfGuardKmsLibrary,
    MacOsHkdfGuardKmsLibrary,
    WindowsHkdfGuardKmsLibrary,
)
from hkdfguard_keywrapping_v1.native_host import get_library


def test_library_returns_non_none_instance() -> None:
    library = get_library()

    assert library is not None


def test_library_returns_same_instance_across_calls() -> None:
    first = get_library()
    second = get_library()

    assert first is second


def test_library_returns_matching_platform_implementation() -> None:
    library = get_library()
    system = platform.system()

    if system == "Windows":
        assert isinstance(library, WindowsHkdfGuardKmsLibrary)
    elif system == "Linux":
        assert isinstance(library, LinuxHkdfGuardKmsLibrary)
    elif system == "Darwin":
        assert isinstance(library, MacOsHkdfGuardKmsLibrary)
