"""Python port of HkdfGuard.Abstractions/IProtectedCache.cs."""

from abc import abstractmethod

from .protected_read_only_cache import IProtectedReadOnlyCache


class IProtectedCache(IProtectedReadOnlyCache):
    """Read/write surface of a highly concurrent name -> encrypted-value cache backed by a
    single IDataProtectionKey. add/add_or_update protect and store plaintext under a name; the
    read surface (decrypt/decrypt_str/try_get_max_decrypted_length) is inherited from
    IProtectedReadOnlyCache. Nothing here ever holds plaintext beyond the duration of a single
    add/add_or_update call - only the encrypted bytes are retained internally.
    """

    @abstractmethod
    def add(self, name: str, plaintext: bytearray) -> None:
        """Encrypts plaintext and stores it under name. plaintext is zeroed as a side effect of
        encrypting it.

        Raises ValueError if a value is already stored under this name.
        """

    @abstractmethod
    def add_str(self, name: str, plaintext: str) -> None:
        """Encrypts plaintext (as UTF-8 bytes) and stores it under name.

        Raises ValueError if a value is already stored under this name.
        """

    @abstractmethod
    def add_or_update(self, name: str, plaintext: bytearray) -> None:
        """Encrypts plaintext and stores it under name, replacing any value already stored under
        that name. plaintext is zeroed as a side effect of encrypting it.
        """

    @abstractmethod
    def add_or_update_str(self, name: str, plaintext: str) -> None:
        """Encrypts plaintext (as UTF-8 bytes) and stores it under name, replacing any value
        already stored under that name.
        """
