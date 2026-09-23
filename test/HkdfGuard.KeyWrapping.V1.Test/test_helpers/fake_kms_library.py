"""Python port of test/HkdfGuard.KeyWrapping.V1.Test/TestHelpers/FakeHkdfGuardKmsLibrary.cs."""

from hkdfguard_keywrapping_v1.interop import AbstractHkdfGuardKmsLibrary


class FakeHkdfGuardKmsLibrary(AbstractHkdfGuardKmsLibrary):
    def __init__(self) -> None:
        self.wrap_dek_status = self.OK
        self.unwrap_dek_status = self.OK
        self.generate_and_wrap_dek_status = self.OK

        self.wrap_dek_bytes_written_override: int | None = None
        self.unwrap_dek_bytes_written_override: int | None = None
        self.generate_and_wrap_dek_bytes_written_override: int | None = None

        self.wrap_payload_to_emit: bytes | None = None
        self.unwrap_payload_to_emit: bytes | None = None
        self.generate_and_wrap_payload_to_emit: bytes | None = None

        self.last_service: str | None = None
        self.last_wrap_plaintext: bytes | None = None
        self.last_unwrap_wrapped: bytes | None = None

        self.wrap_call_count = 0
        self.unwrap_call_count = 0
        self.generate_and_wrap_call_count = 0

    def wrap_dek(self, service: str, dek: bytes, destination: bytearray) -> tuple[int, int]:
        self.wrap_call_count += 1
        self.last_service = service
        self.last_wrap_plaintext = bytes(dek)

        if self.wrap_dek_status != self.OK:
            written = self.wrap_dek_bytes_written_override if self.wrap_dek_bytes_written_override is not None else 0
            return self.wrap_dek_status, written

        payload = self.wrap_payload_to_emit if self.wrap_payload_to_emit is not None else bytes(dek)
        _copy_into(destination, payload)
        written = (
            self.wrap_dek_bytes_written_override if self.wrap_dek_bytes_written_override is not None else len(payload)
        )
        return self.OK, written

    def unwrap_dek(self, service: str, wrapped: bytes, destination: bytearray) -> tuple[int, int]:
        self.unwrap_call_count += 1
        self.last_service = service
        self.last_unwrap_wrapped = bytes(wrapped)

        if self.unwrap_dek_status != self.OK:
            written = (
                self.unwrap_dek_bytes_written_override if self.unwrap_dek_bytes_written_override is not None else 0
            )
            return self.unwrap_dek_status, written

        payload = self.unwrap_payload_to_emit if self.unwrap_payload_to_emit is not None else bytes(wrapped)
        _copy_into(destination, payload)
        written = (
            self.unwrap_dek_bytes_written_override
            if self.unwrap_dek_bytes_written_override is not None
            else len(payload)
        )
        return self.OK, written

    def generate_and_wrap_dek(self, service: str, destination: bytearray) -> tuple[int, int]:
        self.generate_and_wrap_call_count += 1
        self.last_service = service

        if self.generate_and_wrap_dek_status != self.OK:
            written = (
                self.generate_and_wrap_dek_bytes_written_override
                if self.generate_and_wrap_dek_bytes_written_override is not None
                else 0
            )
            return self.generate_and_wrap_dek_status, written

        payload = (
            self.generate_and_wrap_payload_to_emit
            if self.generate_and_wrap_payload_to_emit is not None
            else bytes(64)
        )
        _copy_into(destination, payload)
        written = (
            self.generate_and_wrap_dek_bytes_written_override
            if self.generate_and_wrap_dek_bytes_written_override is not None
            else len(payload)
        )
        return self.OK, written


def _copy_into(destination: bytearray, payload: bytes) -> None:
    if len(payload) > len(destination):
        raise BufferError(f"destination has capacity {len(destination)}, payload needs {len(payload)}")
    destination[: len(payload)] = payload
