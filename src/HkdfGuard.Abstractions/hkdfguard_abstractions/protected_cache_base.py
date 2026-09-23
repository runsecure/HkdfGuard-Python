"""Python port of HkdfGuard.Abstractions/ProtectedCacheBase.cs.

Case-insensitive keying: C#'s ConcurrentDictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
becomes a plain dict keyed by name.casefold() - Python's documented, canonical technique for
case-insensitive string keys (OrdinalIgnoreCase is simple, non-locale-aware case folding; casefold
is more aggressive for a handful of exotic Unicode characters, but identically for every name this
library actually sees). Thread safety: individual dict reads/writes are already atomic under
CPython's GIL, matching the .NET original's lock-free AddOrUpdate/decrypt paths; _try_add_encrypted
additionally needs its own check-and-insert to be atomic, achieved via dict.setdefault (itself one
atomic operation) rather than a separate lock - the direct analogue of ConcurrentDictionary.TryAdd.
"""

from abc import ABC

from hkdfguard_diagnostics import ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry

from .array_utility import zero_memory
from .data_encryption_key import IDataEncryptionKey
from .protected_read_only_cache import IProtectedReadOnlyCache

_TELEMETRY = HkdfGuardTelemetry.ROOT


class ProtectedCacheBase(IProtectedReadOnlyCache, ABC):
    """Shared IProtectedReadOnlyCache plumbing for every cache in this library: a single
    IDataEncryptionKey, a dict[str, bytes] of encrypted bytes keyed case-insensitively, and the
    encrypt/decrypt/telemetry logic every concrete cache needs. decrypt/decrypt_str/
    try_get_max_decrypted_length fall back to _try_populate on a miss before giving up - the
    default implementation here just returns False (nothing to pull from), but a subclass backed
    by an external source (e.g. a remote secret store) overrides it to fetch the plaintext value
    and encrypt it into this cache on demand, so nothing here ever holds plaintext beyond the
    duration of a single call.
    """

    def __init__(self, data_encryption_key: IDataEncryptionKey) -> None:
        self._data_encryption_key = data_encryption_key
        self._encrypted: dict[str, bytes] = {}

    def _try_populate(self, name: str) -> bool:
        """Called when name isn't already cached, before decrypt/decrypt_str/
        try_get_max_decrypted_length give up and return a miss. The default implementation does
        nothing - override to pull a value in from an external source and populate this cache
        (via _try_add_encrypted/_set_encrypted) before returning True.
        """
        return False

    def decrypt(self, name: str, result: bytearray) -> int:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.Cache.DECRYPT) as span:
            _TELEMETRY.log_sensitive_operation(span, ActivityNames.Cache.DECRYPT, (AttributeNames.NAME, name))
            try:
                encrypted = self._try_get_encrypted(name)
                if encrypted is None:
                    return 0

                return self._data_encryption_key.decrypt(encrypted, result)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def decrypt_str(self, name: str) -> str | None:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.Cache.DECRYPT) as span:
            _TELEMETRY.log_sensitive_operation(span, ActivityNames.Cache.DECRYPT, (AttributeNames.NAME, name))
            try:
                encrypted = self._try_get_encrypted(name)
                if encrypted is None:
                    return None

                # AEAD ciphertext is always at least as long as the plaintext it encloses, so
                # len(encrypted) is a safe upper bound for the decrypted UTF-8 byte count.
                plaintext_bytes = bytearray(len(encrypted))
                try:
                    decrypted_length = self._data_encryption_key.decrypt(encrypted, plaintext_bytes)
                    return bytes(plaintext_bytes[:decrypted_length]).decode("utf-8")
                finally:
                    zero_memory(plaintext_bytes)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def try_get_max_decrypted_length(self, name: str) -> int | None:
        encrypted = self._try_get_encrypted(name)
        return len(encrypted) if encrypted is not None else None

    def _try_get_encrypted(self, name: str) -> bytes | None:
        key = name.casefold()
        encrypted = self._encrypted.get(key)
        if encrypted is not None:
            return encrypted

        if self._try_populate(name):
            encrypted = self._encrypted.get(key)
            if encrypted is not None:
                return encrypted

        return None

    def _try_add_encrypted(self, name: str, encrypted: bytes) -> bool:
        """Inserts encrypted under name unless a value is already stored there. Returns True if
        it was inserted.
        """
        key = name.casefold()
        return self._encrypted.setdefault(key, encrypted) is encrypted

    def _set_encrypted(self, name: str, encrypted: bytes) -> None:
        """Inserts encrypted under name, replacing any value already stored there."""
        self._encrypted[name.casefold()] = encrypted

    def _encrypt(self, plaintext: bytearray) -> bytes:
        """Encrypts plaintext through this cache's IDataEncryptionKey."""
        return self._data_encryption_key.encrypt(plaintext)

    def _encrypt_str(self, plaintext: str) -> bytes:
        """Encrypts plaintext (as UTF-8 bytes) through this cache's IDataEncryptionKey."""
        plaintext_bytes = bytearray(plaintext.encode("utf-8"))
        return self._data_encryption_key.encrypt(plaintext_bytes)
