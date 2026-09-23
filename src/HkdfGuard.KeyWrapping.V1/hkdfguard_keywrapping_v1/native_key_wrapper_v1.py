"""Python port of HkdfGuard.KeyWrapping.V1/NativeHkdfKeyWrapperV1.cs.

Protects (encrypt) a fresh DEK, or reveals (decrypt) a previously-wrapped one, via the current
OS's native HkdfGuard KMS library (see native_host) - a TPM2, Secure Enclave, or Platform Crypto
Provider key held entirely outside this process, identified only by a service name. No
salt/blob machinery is involved: the native library owns the KEK, the wrapped payload's format,
and its own key derivation. Since decrypt takes its wrapped payload as an explicit argument
rather than one bound at construction, a single instance freely handles both directions, and any
number of different wrapped payloads sharing the same service name.
"""

from hkdfguard_abstractions import HkdfGuardCryptographicError, IKeyWrapper

from .interop.abstract_kms_library import AbstractHkdfGuardKmsLibrary
from .native_host import get_library


class NativeHkdfKeyWrapperV1(IKeyWrapper):
    def __init__(self, service_name: str, library: AbstractHkdfGuardKmsLibrary | None = None) -> None:
        self._service_name = service_name
        self._library = library if library is not None else get_library()

    def encrypt(self, plaintext: bytes, result: bytearray) -> int:
        status, bytes_written = self._library.wrap_dek(self._service_name, plaintext, result)
        if status != AbstractHkdfGuardKmsLibrary.OK:
            raise HkdfGuardCryptographicError(f"Native KMS wrap failed with status {status}.")
        return bytes_written

    def decrypt(self, wrapped: bytes, result: bytearray) -> int:
        status, bytes_written = self._library.unwrap_dek(self._service_name, wrapped, result)
        if status != AbstractHkdfGuardKmsLibrary.OK:
            raise HkdfGuardCryptographicError(f"Native KMS unwrap failed with status {status}.")
        return bytes_written

    def generate_and_wrap(self, result: bytearray) -> int:
        status, bytes_written = self._library.generate_and_wrap_dek(self._service_name, result)
        if status != AbstractHkdfGuardKmsLibrary.OK:
            raise HkdfGuardCryptographicError(f"Native KMS generate-and-wrap failed with status {status}.")
        return bytes_written
