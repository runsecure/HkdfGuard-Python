"""Python port of test/HkdfGuard.CryptoSession.AesGcm256.Test/AesGcmCryptoProviderTests.cs.

The background-refresh tests are inherently timing-based (real time.sleep waits around a 1-second
refresh interval), same as the .NET originals' Thread.Sleep waits - a deliberate, accepted
trade-off for testing a real background thread rather than mocking the clock.
"""

import time

import pytest
from hkdfguard_cryptosession_aesgcm256 import AesGcmCryptoProvider
from test_helpers.fake_key_wrapper import FakeKeyWrapper


def test_constructor_builds_initial_session_eagerly() -> None:
    wrapper = FakeKeyWrapper()

    with AesGcmCryptoProvider(wrapper, b"wrapped", 60):
        assert wrapper.decrypt_call_count == 1


def test_constructor_when_key_wrapper_fails_raises() -> None:
    wrapper = FakeKeyWrapper()
    wrapper.throw_on_decrypt = RuntimeError("reveal failed")

    with pytest.raises(RuntimeError, match="reveal failed"):
        AesGcmCryptoProvider(wrapper, b"wrapped", 60)


@pytest.mark.parametrize("expiry_seconds", [0, -1, 301])
def test_constructor_with_expiry_seconds_out_of_range_raises(expiry_seconds: int) -> None:
    wrapper = FakeKeyWrapper()

    with pytest.raises(ValueError, match="expiry_seconds"):
        AesGcmCryptoProvider(wrapper, b"wrapped", expiry_seconds)


def test_background_timer_proactively_refreshes_the_session_without_any_call() -> None:
    wrapper = FakeKeyWrapper()
    with AesGcmCryptoProvider(wrapper, b"wrapped", 1):
        # No encrypt/decrypt call at all - only the constructor's eager build
        # (decrypt_call_count == 1) and the background thread, waking every expiry_seconds,
        # should have run by now.
        time.sleep(1.5)

        assert wrapper.decrypt_call_count == 2


def test_close_closes_the_current_session_and_stops_the_background_thread() -> None:
    wrapper = FakeKeyWrapper()
    provider = AesGcmCryptoProvider(wrapper, b"wrapped", 1)

    provider.close()
    time.sleep(1.5)

    # Only the constructor's eager build - the background thread must not have ticked after close.
    assert wrapper.decrypt_call_count == 1
