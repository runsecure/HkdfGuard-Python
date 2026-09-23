"""Python port of HkdfGuard.DataEncryptionKey/PipelineDataEncryptionKey.cs.

The .NET original has two constructor overloads (one generating a random DEK, one taking a
supplied DEK); Python collapses them into one constructor with dek defaulting to None ("generate
a fresh one"), the session_provider_factory moving first since it's the one argument every caller
must supply.
"""

import secrets
from collections.abc import Callable
from typing import Self

from hkdfguard_abstractions import ICryptoProvider, IDataProtectionKey, IKeyWrapper
from hkdfguard_abstractions.array_utility import is_null_or_empty, zero_memory
from hkdfguard_diagnostics import ActivityNames, ComponentTelemetry, HkdfGuardTelemetry

from .key_wrapped_data_encryption_key import KeyWrappedDataEncryptionKey

_DEK_LENGTH = 32

_TELEMETRY = HkdfGuardTelemetry.DATA_PROTECTION


class PipelineDataEncryptionKey(IDataProtectionKey):
    """An IDataProtectionKey backed by a plain 32-byte DEK, used directly - never wrapped, never
    unwrapped. Meant for a pipeline that needs to encrypt secrets in-flight before a durable KEK
    exists yet: construct one (generating a fresh random DEK, or supplying an existing one),
    encrypt whatever needs protecting during the pipeline, then read the same plaintext DEK back
    via as_bytearray() at the end of the chain to hand off to the platform's native "initialize"
    CLI utility, which independently wraps/registers it against a real KEK. close() zeroes the
    DEK.
    """

    def __init__(
        self,
        session_provider_factory: Callable[[IKeyWrapper, bytes], ICryptoProvider],
        dek: bytearray | None = None,
    ) -> None:
        """session_provider_factory: builds the ICryptoProvider this instance encrypts/decrypts
        through (this class can't construct one directly - a concrete provider lives in
        whichever cipher package the caller chose, not here) - e.g.
        ``lambda kw, wrapped: AesGcmCryptoProvider(kw, wrapped, 60)``. Since dek needs no
        unwrapping, it's handed to that factory as both the key wrapper (an identity wrapper
        that reveals whatever "wrapped" bytes it's given, unchanged) and the wrapped payload
        itself.
        dek: the plain 32-byte DEK to use as-is - ownership transfers to this instance (the exact
        object given, not a copy), which zeroes it on close(). Defaults to a fresh,
        cryptographically random 32-byte DEK.

        Raises ValueError if dek is empty/all-zero, or not exactly 32 bytes.
        """
        if dek is None:
            dek = bytearray(secrets.token_bytes(_DEK_LENGTH))

        if is_null_or_empty(dek):
            raise ValueError("DEK must not be empty or all zero.")
        if len(dek) != _DEK_LENGTH:
            raise ValueError(f"DEK must be exactly {_DEK_LENGTH} bytes.")

        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.DataProtection.PIPELINE_KEY_INITIALIZE) as span:
            try:
                self._dek = dek
                self._provider = session_provider_factory(_IdentityKeyWrapper(), bytes(dek))
                self._inner = KeyWrappedDataEncryptionKey(self._provider)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def as_bytearray(self) -> bytearray:
        """The plain, plaintext DEK this instance protects with - e.g. to hand off to the
        platform's native "initialize" CLI utility once the pipeline finishes. Returns the live
        buffer, not a copy - it reflects close()'s zeroing.
        """
        return self._dek

    def encrypt(self, plaintext: bytearray, aad: bytes = b"") -> bytes:
        return self._inner.encrypt(plaintext, aad)

    def decrypt(self, ciphertext: bytes, result: bytearray, aad: bytes = b"") -> int:
        return self._inner.decrypt(ciphertext, result, aad)

    def close(self) -> None:
        """Closes the underlying session provider/session, and zeroes the plaintext DEK."""
        self._provider.close()
        zero_memory(self._dek)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()


class _IdentityKeyWrapper(IKeyWrapper):
    """Treats the "wrapped" payload it's handed as already being the plaintext key - there is
    nothing to unwrap, since this whole class's point is using a plain key as-is.
    """

    def encrypt(self, plaintext: bytes, result: bytearray) -> int:
        raise NotImplementedError("_IdentityKeyWrapper only supports decrypt.")

    def decrypt(self, wrapped: bytes, result: bytearray) -> int:
        result[: len(wrapped)] = wrapped
        return len(wrapped)

    def generate_and_wrap(self, result: bytearray) -> int:
        raise NotImplementedError("_IdentityKeyWrapper only supports decrypt.")
