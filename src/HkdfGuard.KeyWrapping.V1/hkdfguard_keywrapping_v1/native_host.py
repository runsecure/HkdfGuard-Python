"""Python port of HkdfGuard.KeyWrapping.V1/NativeHost.cs.

Resolves the current OS's native HkdfGuard KMS library exactly once per process (binding the
wrong platform's library would fail on first native call anyway, so there's nothing to gain by
re-resolving per instance). get_library() itself never touches the native binary - constructing a
platform library object is cheap; dlopen only happens lazily on the first wrap/unwrap/generate
call (see NativeCtypesKmsLibrary) - so this stays safe to call even on a host where the native
library isn't installed.
"""

import functools
import platform

from .interop.abstract_kms_library import AbstractHkdfGuardKmsLibrary
from .interop.linux_kms_library import LinuxHkdfGuardKmsLibrary
from .interop.macos_kms_library import MacOsHkdfGuardKmsLibrary
from .interop.windows_kms_library import WindowsHkdfGuardKmsLibrary


@functools.lru_cache(maxsize=1)
def get_library() -> AbstractHkdfGuardKmsLibrary:
    system = platform.system()

    if system == "Windows":
        return WindowsHkdfGuardKmsLibrary()

    if system == "Linux":
        return LinuxHkdfGuardKmsLibrary()

    if system == "Darwin":
        return MacOsHkdfGuardKmsLibrary()

    raise NotImplementedError(f"HkdfGuard.KeyWrapping.V1 has no native KMS library for '{system}'.")
