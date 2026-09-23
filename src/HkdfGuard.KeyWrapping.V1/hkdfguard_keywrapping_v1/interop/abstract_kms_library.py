"""Python port of HkdfGuard.KeyWrapping.V1/Interop/AbstractHkdfGuardKmsLibrary.cs."""

from abc import ABC, abstractmethod


class AbstractHkdfGuardKmsLibrary(ABC):
    """Shared surface over a platform's native HkdfGuard KMS library. Every implementation wraps
    and unwraps a fixed-length DEK under a persistent, per-service KEK held outside this process
    (a TPM2 key, a Secure Enclave key, etc.) via that platform's hkdfguard_wrap_dek /
    hkdfguard_unwrap_dek / hkdfguard_generate_and_wrap_dek native functions - identical in shape
    across platforms, but each library's negative status codes mean different things, so callers
    must consult the concrete implementation they're using to interpret a non-OK result.
    """

    DEK_LENGTH = 32

    #: Status code common to every platform's native library: the call succeeded.
    OK = 0

    @abstractmethod
    def wrap_dek(self, service: str, dek: bytes, destination: bytearray) -> tuple[int, int]:
        """Wraps dek under the persistent KEK identified by service.

        service: Non-empty, cross-platform identity of the KEK.
        dek: The plaintext DEK to wrap (must be exactly DEK_LENGTH bytes).
        destination: Buffer to receive the wrapped payload.

        Returns (status, bytes_written): status is OK on success, or a negative,
        implementation-specific error code. On success, bytes_written is the number of bytes
        written to destination; on a buffer-too-small failure, the required capacity instead.
        """

    @abstractmethod
    def unwrap_dek(self, service: str, wrapped: bytes, destination: bytearray) -> tuple[int, int]:
        """Unwraps a payload previously produced by wrap_dek for the same service, recovering the
        original DEK.

        service: Must match the value used when the payload was wrapped.
        wrapped: The wrapped payload bytes.
        destination: Buffer to receive the recovered DEK.

        Returns (status, bytes_written): status is OK on success, or a negative,
        implementation-specific error code. On success, bytes_written is always DEK_LENGTH; on a
        buffer-too-small failure, the required capacity instead.
        """

    @abstractmethod
    def generate_and_wrap_dek(self, service: str, destination: bytearray) -> tuple[int, int]:
        """Generates a fresh, cryptographically random DEK and immediately wraps it under the
        persistent KEK identified by service. The plaintext DEK never crosses this boundary -
        recover it later via unwrap_dek with the same service.

        service: Service name to use with KMS operations.
        destination: Buffer to receive the wrapped payload.

        Returns (status, bytes_written): status is OK on success, or a negative,
        implementation-specific error code. On success, bytes_written is the number of bytes
        written to destination; on a buffer-too-small failure, the required capacity instead.
        """
