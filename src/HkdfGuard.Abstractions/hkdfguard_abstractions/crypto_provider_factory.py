"""Python port of HkdfGuard.Abstractions/ICryptoProviderFactory.cs."""

from abc import ABC, abstractmethod

from .crypto_provider import ICryptoProvider
from .key_wrapper import IKeyWrapper


class ICryptoProviderFactory(ABC):
    """Builds ICryptoProvider instances bound to an IKeyWrapper, for each of the three ways this
    library reveals a DEK.
    """

    @abstractmethod
    def create(self, wrapper: IKeyWrapper, wrapped: bytes, expiry_seconds: int) -> ICryptoProvider:
        """Builds an ICryptoProvider that reveals wrapped through wrapper, refreshing every
        expiry_seconds.
        """

    @abstractmethod
    def create_ephemeral(self, wrapper: IKeyWrapper, expiry_seconds: int) -> ICryptoProvider:
        """Generates a fresh DEK via wrapper.generate_and_wrap and builds an ICryptoProvider
        around it, refreshing every expiry_seconds.
        """

    @abstractmethod
    def create_for_pipeline(self, wrapper: IKeyWrapper, not_wrapped: bytes) -> ICryptoProvider:
        """Builds an ICryptoProvider around not_wrapped directly - not_wrapped is already a
        plaintext DEK, never wrapped or unwrapped through wrapper.
        """
