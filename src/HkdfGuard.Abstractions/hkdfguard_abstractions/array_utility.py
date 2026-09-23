"""Python port of HkdfGuard.Abstractions/ArrayUtility.cs (the byte-buffer members only - no
str/char port is needed here, unlike the .NET version's char overloads).
"""


def is_null_or_empty(data: bytes) -> bool:
    """True if data is empty, or every byte in it is zero."""
    return all(b == 0 for b in data)


def zero_memory(data: bytearray) -> None:
    """Overwrites every byte of data with zero, in place."""
    data[:] = bytes(len(data))
