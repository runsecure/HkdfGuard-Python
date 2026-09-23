"""Python port of HkdfGuard.DataEncryptionKey/PipelineKeyFactory.cs.

Builds fresh PipelineDataEncryptionKey instances, each around a newly generated random 32-byte
DEK.

The .NET original's Create also accepts a format-provider argument and an optional key version,
neither of which its own implementation ever reads (a pipeline key isn't registered in a KeyRing,
so it has no format or version to speak of) - this port drops both rather than carrying two
parameters that do nothing.
"""

import secrets

from hkdfguard_abstractions import ICryptoProviderFactory

from .dummy_key_wrapper import DummyKeyWrapper
from .pipeline_data_encryption_key import PipelineDataEncryptionKey

_DEK_LENGTH = 32


class PipelineKeyFactory:
    def create(self, factory: ICryptoProviderFactory) -> PipelineDataEncryptionKey:
        """Generates a fresh, cryptographically random 32-byte DEK and builds a
        PipelineDataEncryptionKey around it via factory.create_for_pipeline.
        """
        dek = bytearray(secrets.token_bytes(_DEK_LENGTH))
        provider = factory.create_for_pipeline(DummyKeyWrapper(), dek)
        return PipelineDataEncryptionKey(provider, dek)
