"""Shared ctypes binding for every platform's native HkdfGuard KMS library.

Binding approach: ctypes (standard library) over cffi or a compiled extension. It ships with
CPython on every platform this needs to run on, needs no build step or C toolchain at install
time, and its explicit argtypes/restype declarations are the most direct Python analogue of the
.NET side's source-generated [LibraryImport] marshalling - both describe the same fixed C ABI up
front rather than inferring it at call time.

All three platform libraries export an identical
``int hkdfguard_<op>_dek(const char* service, const uint8_t* data, int32_t data_len,
uint8_t* output, int32_t* out_len)``-shaped C ABI (see hkdfguard.h), differing only in filename
and the meaning of their negative status codes - so, like ComponentTelemetry consolidated the
Diagnostics port's six duplicated per-component classes into one, this one implementation is
shared by every platform class in this package instead of being hand-duplicated per platform.

Two marshalling details worth calling out:

- ``destination: bytearray`` is wrapped with ``(c_char * len).from_buffer(destination)`` rather
  than copied into a separate ctypes buffer - the native call writes straight into the caller's
  own bytearray, the same zero-copy shape as the .NET side's ``Span<byte> destination``.
- The native library is not dlopen'd until the first wrap/unwrap/generate call, not at
  construction - mirroring .NET's [LibraryImport], which only resolves the native library on the
  first P/Invoke call through it, not when the wrapping C# object is constructed. This matters
  for parity: code that only constructs a platform library instance (e.g. NativeHost resolution)
  must not fail on a host where the native binary isn't installed - only an actual wrap/unwrap/
  generate call should.
"""

import ctypes

from .abstract_kms_library import AbstractHkdfGuardKmsLibrary

_c_len = ctypes.c_int32
_ARGTYPES_4 = [ctypes.c_char_p, ctypes.c_char_p, _c_len, ctypes.c_char_p, ctypes.POINTER(_c_len)]
_ARGTYPES_3 = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(_c_len)]


class NativeCtypesKmsLibrary(AbstractHkdfGuardKmsLibrary):
    """Base class for the platform-specific KMS library bindings. Subclasses set LIBRARY_NAME
    (and their own error-code constants) and inherit this ctypes marshalling as-is.
    """

    LIBRARY_NAME: str

    def __init__(self) -> None:
        self._lib: ctypes.CDLL | None = None

    def wrap_dek(self, service: str, dek: bytes, destination: bytearray) -> tuple[int, int]:
        return self._call4(self._handle().hkdfguard_wrap_dek, service, dek, destination)

    def unwrap_dek(self, service: str, wrapped: bytes, destination: bytearray) -> tuple[int, int]:
        return self._call4(self._handle().hkdfguard_unwrap_dek, service, wrapped, destination)

    def generate_and_wrap_dek(self, service: str, destination: bytearray) -> tuple[int, int]:
        out_len = _c_len(len(destination))
        dest_view = (ctypes.c_char * len(destination)).from_buffer(destination)
        status = self._handle().hkdfguard_generate_and_wrap_dek(
            service.encode("utf-8"), dest_view, ctypes.byref(out_len)
        )
        return status, out_len.value

    @staticmethod
    def _call4(native_fn, service: str, data: bytes, destination: bytearray) -> tuple[int, int]:
        out_len = _c_len(len(destination))
        dest_view = (ctypes.c_char * len(destination)).from_buffer(destination)
        status = native_fn(service.encode("utf-8"), bytes(data), len(data), dest_view, ctypes.byref(out_len))
        return status, out_len.value

    def _handle(self) -> ctypes.CDLL:
        if self._lib is None:
            lib = ctypes.CDLL(self.LIBRARY_NAME)

            lib.hkdfguard_wrap_dek.restype = ctypes.c_int
            lib.hkdfguard_wrap_dek.argtypes = _ARGTYPES_4

            lib.hkdfguard_unwrap_dek.restype = ctypes.c_int
            lib.hkdfguard_unwrap_dek.argtypes = _ARGTYPES_4

            lib.hkdfguard_generate_and_wrap_dek.restype = ctypes.c_int
            lib.hkdfguard_generate_and_wrap_dek.argtypes = _ARGTYPES_3

            self._lib = lib
        return self._lib
