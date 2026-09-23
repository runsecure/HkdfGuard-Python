"""Python port of HkdfGuard.CryptoSession.AesGcm256/AesGcmCryptoSession.cs.

Uses pyca/cryptography - Python's de facto standard cryptography library, wrapping OpenSSL and
maintained by the Python Cryptographic Authority - for AES-256-GCM, via
cryptography.hazmat.primitives.ciphers.aead.AESGCM. Its encrypt() already returns
ciphertext + tag concatenated, and decrypt() expects that same concatenation and raises
cryptography.exceptions.InvalidTag on an authentication failure - both line up exactly with this
session's [nonce | ciphertext | tag] wire layout and with .NET AesGcm's Encrypt/Decrypt shape, so
no reshaping is needed beyond splitting the nonce off the front.

AesGcmCryptoSession is an internal implementation detail of AesGcmCryptoProvider - like the .NET
original (`internal class AesGcmCryptoSession`), it is not re-exported from this package's
__init__ and isn't part of the public API, even though nothing stops importing it directly (the
same relationship the .NET project has with its test assembly via InternalsVisibleTo).
"""

import secrets
from typing import Self

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hkdfguard_abstractions.array_utility import is_null_or_empty, zero_memory
from hkdfguard_diagnostics import ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry

_TAG_SIZE = 16
_NONCE_SIZE = 12
_KEY_LENGTH = 32

_TELEMETRY = HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256


class AesGcmCryptoSession:
    """An encrypt/decrypt session backed by a single 32-byte AES-256 key, supplied once at
    construction. The underlying AESGCM instance is built once here too (not per encrypt/decrypt
    call), so this instance is meant to be held for a while - see AesGcmCryptoProvider - and
    closed (releasing the AESGCM instance and zeroing the key) once no longer needed rather than
    rebuilt on every operation.
    """

    def __init__(self, key: bytearray) -> None:
        """key: the 32-byte AES-256 key this session encrypts/decrypts with - ownership transfers
        to this instance (the exact object given, not a copy - matching the .NET original taking
        a byte[] reference), which zeroes it in place on close().

        Raises ValueError if key is empty/all-zero, or not exactly 32 bytes.
        """
        if is_null_or_empty(key):
            raise ValueError("AES key must not be empty or all zero.")
        if len(key) != _KEY_LENGTH:
            raise ValueError(f"AES key must be exactly {_KEY_LENGTH} bytes.")

        self._key = key
        self._aes: AESGCM | None = AESGCM(bytes(key))

    def encrypt(self, plaintext: bytearray, result: bytearray, aad: bytes = b"") -> int:
        """plaintext is zeroed in place once encryption completes (success or failure) - the
        Python analogue of the .NET original's mutable Span<byte> plaintext parameter, which it
        also zeroes as a side effect. Callers (e.g. DataProtector) rely on this rather than
        zeroing their own plaintext buffer afterward - hence plaintext must be a bytearray, not
        immutable bytes.
        """
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.CryptoSessionAesGcm256.ENCRYPT) as span:
            _TELEMETRY.log_sensitive_operation(
                span,
                ActivityNames.CryptoSessionAesGcm256.ENCRYPT,
                (AttributeNames.PLAINTEXT_LENGTH, len(plaintext)),
                (AttributeNames.AAD_LENGTH, len(aad)),
            )
            try:
                return self._core_encrypt(plaintext, aad, result)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise
            finally:
                zero_memory(plaintext)

    def _core_encrypt(self, plaintext: bytearray, aad: bytes, result: bytearray) -> int:
        if self._aes is None:
            raise ValueError("Operation on a closed AesGcmCryptoSession.")
        if is_null_or_empty(plaintext):
            raise ValueError("Plaintext must not be empty or all zero.")

        total_length = _NONCE_SIZE + len(plaintext) + _TAG_SIZE
        if len(result) < total_length:
            raise ValueError("Result buffer too small.")

        # Layout: [nonce | ciphertext | tag]
        nonce = secrets.token_bytes(_NONCE_SIZE)
        ciphertext_and_tag = self._aes.encrypt(nonce, bytes(plaintext), aad)

        result[:_NONCE_SIZE] = nonce
        result[_NONCE_SIZE:total_length] = ciphertext_and_tag

        return total_length

    def decrypt(self, ciphertext: bytes, result: bytearray, aad: bytes = b"") -> int:
        with _TELEMETRY.tracer.start_as_current_span(ActivityNames.CryptoSessionAesGcm256.DECRYPT) as span:
            _TELEMETRY.log_sensitive_operation(
                span,
                ActivityNames.CryptoSessionAesGcm256.DECRYPT,
                (AttributeNames.CIPHERTEXT_LENGTH, len(ciphertext)),
                (AttributeNames.AAD_LENGTH, len(aad)),
            )
            try:
                return self._core_decrypt(ciphertext, aad, result)
            except Exception as exc:
                ComponentTelemetry.record_exception(span, exc)
                raise

    def _core_decrypt(self, ciphertext: bytes, aad: bytes, result: bytearray) -> int:
        if self._aes is None:
            raise ValueError("Operation on a closed AesGcmCryptoSession.")
        if is_null_or_empty(ciphertext):
            raise ValueError("Ciphertext must not be empty or all zero.")
        if len(ciphertext) < _NONCE_SIZE + _TAG_SIZE:
            raise ValueError("Ciphertext too short.")

        result_length = len(ciphertext) - _NONCE_SIZE - _TAG_SIZE
        if len(result) < result_length:
            raise ValueError("Result buffer too small.")

        nonce = ciphertext[:_NONCE_SIZE]
        ciphertext_and_tag = ciphertext[_NONCE_SIZE:]

        # Raises cryptography.exceptions.InvalidTag on a tampered ciphertext or mismatched aad -
        # the Python analogue of .NET's AuthenticationTagMismatchException.
        plaintext = self._aes.decrypt(nonce, ciphertext_and_tag, aad)

        result[:result_length] = plaintext
        return result_length

    def close(self) -> None:
        # Zeroes our own key copy, same as .NET's CryptographicOperations.ZeroMemory(_key). Unlike
        # .NET's AesGcm.Dispose(), which also tells its native/CNG provider to release and clear
        # its own internal copy, pyca/cryptography's AESGCM exposes no equivalent call - its
        # OpenSSL-held copy is freed (not necessarily zeroed) whenever this object is garbage
        # collected. Dropping the reference here lets that happen as early as possible.
        self._aes = None
        zero_memory(self._key)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()
