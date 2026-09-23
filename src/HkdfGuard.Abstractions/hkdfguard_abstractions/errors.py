"""Python analogue of System.Security.Cryptography.CryptographicException from the .NET BCL -
used across HkdfGuard components so callers can catch one exception type regardless of which
component's cryptographic operation failed, without depending on a specific implementation.
"""


class HkdfGuardCryptographicError(Exception):
    """Raised when a cryptographic operation (wrap/unwrap, encrypt/decrypt, key derivation, ...)
    fails.
    """
