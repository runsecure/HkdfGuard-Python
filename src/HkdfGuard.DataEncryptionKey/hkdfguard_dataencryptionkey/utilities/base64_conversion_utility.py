"""Python port of HkdfGuard.DataEncryptionKey/Utilities/Base64ConversionUtility.cs.

C#'s FormatException and ArgumentException both map to ValueError here - the same substitution
already used throughout this port for .NET's more finely-typed exceptions (binascii.Error, raised
by base64.b64decode, is itself a ValueError subclass, so it needs no separate translation).
"""

import base64
import re

# Matches System.Buffers.Text.Base64.IsValid's definition of well-formed base64: zero or more
# full 4-char groups, optionally followed by one partial group with 1 or 2 '=' padding chars.
_BASE64_STR_RE = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
_BASE64_BYTES_RE = re.compile(rb"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")


def is_base64(base64_text: str) -> bool:
    """Checks whether a string is valid base64 text."""
    return _BASE64_STR_RE.fullmatch(base64_text) is not None


def is_base64_bytes(base64_bytes: bytes) -> bool:
    """Checks whether a bytes value holds base64 text encoded as ASCII/UTF-8 bytes."""
    return _BASE64_BYTES_RE.fullmatch(base64_bytes) is not None


def get_binary_length(base64_text: str) -> int:
    """Computes the decoded binary length for a base64-encoded string."""
    if not base64_text:
        return 0

    if len(base64_text) % 4 != 0:
        raise ValueError("Base64 input length must be a multiple of 4.")

    padding = 0
    if base64_text[-1] == "=":
        padding += 1
    if base64_text[-2] == "=":
        padding += 1

    return len(base64_text) // 4 * 3 - padding


def get_base64_length(data: bytes) -> int:
    """Computes the base64-encoded string length for a bytes value."""
    if not data:
        return 0
    return (len(data) + 2) // 3 * 4


def from_base64(base64_text: str, destination: bytearray) -> int:
    """Decodes base64 text into destination. Returns the number of bytes written."""
    try:
        decoded = base64.b64decode(base64_text, validate=True)
    except ValueError as exc:
        raise ValueError("Input is not valid base64, or the destination buffer is too small.") from exc

    if len(decoded) > len(destination):
        raise ValueError("Input is not valid base64, or the destination buffer is too small.")

    destination[: len(decoded)] = decoded
    return len(decoded)


def to_base64_string(data: bytes) -> str:
    """Encodes binary data as a base64 string."""
    return base64.b64encode(data).decode("ascii")


def to_base64_chars(data: bytes, destination: bytearray) -> int:
    """Encodes binary data as base64 ASCII bytes into destination. Returns the number of bytes
    written.
    """
    encoded = base64.b64encode(data)
    if len(encoded) > len(destination):
        raise ValueError("Destination buffer too small.")

    destination[: len(encoded)] = encoded
    return len(encoded)
