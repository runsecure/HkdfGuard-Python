"""Python port of HkdfGuard.CryptoSession.AesGcm256/AesGcmCryptoProvider.cs.

Tracks one cached AesGcmCryptoSession, bound to a single wrapped DEK. A background thread, waking
every expiry_seconds, proactively reveals the DEK fresh (via key_wrapper.decrypt(wrapped, ...))
and builds the next AesGcmCryptoSession before the current one expires, then swaps it in and
closes the outgoing one (zeroing its key) - so encrypt/decrypt themselves almost never pay the
unwrap cost. Thread-safe: concurrent refreshes never race to unwrap/swap the same session twice.

The background loop is a daemon threading.Thread instead of .NET's PeriodicTimer + async Task -
this library is otherwise fully synchronous (ICryptoProvider has no async members), so a thread is
the direct equivalent of "spawn a background worker from a synchronous constructor" without
forcing an event loop onto every caller. threading.Event.wait(timeout) stands in for
PeriodicTimer.WaitForNextTickAsync(cancellationToken): it returns False on a plain timeout (tick)
and True the instant the event is set (cancellation/close), so `while not stop_event.wait(...)`
is an interruptible sleep-and-tick loop, exactly mirroring the .NET side's cancellable timer.
"""

import threading

from hkdfguard_abstractions import ICryptoProvider, IKeyWrapper
from hkdfguard_diagnostics import ActivityNames, ComponentTelemetry, HkdfGuardTelemetry

from .session import AesGcmCryptoSession

_KEY_LENGTH = 32

_TELEMETRY = HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256


class AesGcmCryptoProvider(ICryptoProvider):
    def __init__(self, key_wrapper: IKeyWrapper, wrapped: bytes, expiry_seconds: int) -> None:
        """key_wrapper: reveals wrapped's DEK - see IKeyWrapper.decrypt.
        wrapped: the wrapped DEK payload this provider's sessions decrypt.
        expiry_seconds: how long each refreshed session stays valid for, in the range 1-300. Also
        the background refresh interval: a fresh session is unwrapped this often, ahead of the
        current one's expiry. This provider holds only one active session at a time, so this is
        the sole place that range is enforced - AesGcmCryptoSession itself doesn't validate it.

        Raises ValueError if expiry_seconds is not between 1 and 300, or if the initial key
        reveal/session build fails.
        """
        if not 1 <= expiry_seconds <= 300:
            raise ValueError(f"expiry_seconds must be between 1 and 300, got {expiry_seconds}.")

        self._key_wrapper = key_wrapper
        self._wrapped = wrapped
        self._expiry_seconds = expiry_seconds
        self._gate = threading.Lock()
        self._stop_event = threading.Event()
        self._current: AesGcmCryptoSession | None = None

        self._refresh()

        self._refresh_thread = threading.Thread(target=self._run_refresh_loop, daemon=True)
        self._refresh_thread.start()

    def encrypt(self, plaintext: bytearray, result: bytearray, aad: bytes = b"") -> int:
        session = self._current
        if session is None:
            raise ValueError("Operation on a closed AesGcmCryptoProvider.")
        return session.encrypt(plaintext, result, aad)

    def decrypt(self, ciphertext: bytes, result: bytearray, aad: bytes = b"") -> int:
        session = self._current
        if session is None:
            raise ValueError("Operation on a closed AesGcmCryptoProvider.")
        return session.decrypt(ciphertext, result, aad)

    def _refresh(self) -> None:
        with self._gate:
            key = bytearray(_KEY_LENGTH)
            self._key_wrapper.decrypt(self._wrapped, key)
            fresh = AesGcmCryptoSession(key)

            outgoing = self._current
            self._current = fresh
            if outgoing is not None:
                outgoing.close()

    def _run_refresh_loop(self) -> None:
        while not self._stop_event.wait(self._expiry_seconds):
            with _TELEMETRY.tracer.start_as_current_span(
                ActivityNames.CryptoSessionAesGcm256.BACKGROUND_REFRESH
            ) as span:
                try:
                    self._refresh()
                except Exception as exc:  # noqa: BLE001 - a bad refresh must not kill the background loop
                    ComponentTelemetry.record_exception(span, exc)

    def close(self) -> None:
        self._stop_event.set()
        self._refresh_thread.join()

        with self._gate:
            outgoing = self._current
            self._current = None
            if outgoing is not None:
                outgoing.close()
