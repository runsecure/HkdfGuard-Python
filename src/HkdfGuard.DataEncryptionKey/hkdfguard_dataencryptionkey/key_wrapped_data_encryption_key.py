"""Python port of HkdfGuard.DataEncryptionKey/KeyWrappedDataEncryptionKey.cs."""

from .encryption_key_base import EncryptionKeyBase


class KeyWrappedDataEncryptionKey(EncryptionKeyBase):
    """An IDataEncryptionKey backed by one wrapped DEK payload. provider owns revealing that
    payload's key (from a fresh unwrap, on its own internal refresh schedule) and performing the
    actual data encrypt/decrypt with it - see ICryptoProvider.
    """
