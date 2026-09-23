"""Python port of HkdfGuard.Abstractions/KeyTrackingValue.cs."""

from dataclasses import dataclass


@dataclass(frozen=True)
class KeyTrackingValue:
    key_version: int
    value: bytes
