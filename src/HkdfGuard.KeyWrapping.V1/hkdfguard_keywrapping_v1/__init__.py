"""Native KMS-backed key wrapping for HkdfGuard. Python port of HkdfGuard.KeyWrapping.V1."""

from .native_host import get_library
from .native_key_wrapper_v1 import NativeHkdfKeyWrapperV1

__all__ = [
    "NativeHkdfKeyWrapperV1",
    "get_library",
]
