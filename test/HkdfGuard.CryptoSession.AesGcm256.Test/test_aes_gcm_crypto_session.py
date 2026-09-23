"""Python port of test/HkdfGuard.CryptoSession.AesGcm256.Test/AesGcmCryptoSessionTests.cs.

AesGcmCryptoSession is an internal implementation detail (see session.py's module docstring), so -
like the .NET test assembly's InternalsVisibleTo - this imports it directly from its module rather
than through the package's public __init__.

encrypt() zeroes its plaintext argument in place once it returns (the .NET original does the same
to its mutable Span<byte> plaintext) - every test below that needs the original plaintext bytes
afterward, for an assertion, clones them first, exactly like the .NET original's
`expectedPlaintext = (byte[])plaintext.Clone()`.
"""

import secrets

import pytest
from cryptography.exceptions import InvalidTag
from hkdfguard_cryptosession_aesgcm256.session import AesGcmCryptoSession


def _random_key() -> bytearray:
    return bytearray(secrets.token_bytes(32))


def test_encrypt_decrypt_round_trips() -> None:
    with AesGcmCryptoSession(_random_key()) as cipher:
        plaintext = bytearray(b"hello world")
        expected_plaintext = bytes(plaintext)
        encrypted = bytearray(len(plaintext) + 28)

        written = cipher.encrypt(plaintext, encrypted)
        assert written == len(encrypted)
        assert plaintext == bytearray(len(expected_plaintext))  # zeroed as a side effect

        decrypted = bytearray(len(expected_plaintext))
        decrypted_length = cipher.decrypt(bytes(encrypted), decrypted)

        assert decrypted_length == len(expected_plaintext)
        assert bytes(decrypted) == expected_plaintext


def test_encrypt_decrypt_round_trips_with_aad() -> None:
    with AesGcmCryptoSession(_random_key()) as cipher:
        plaintext = bytearray(b"hello world")
        expected_plaintext = bytes(plaintext)
        aad = b"context"
        encrypted = bytearray(len(plaintext) + 28)

        cipher.encrypt(plaintext, encrypted, aad)

        decrypted = bytearray(len(expected_plaintext))
        cipher.decrypt(bytes(encrypted), decrypted, aad)

        assert bytes(decrypted) == expected_plaintext


def test_decrypt_with_wrong_aad_raises_invalid_tag() -> None:
    with AesGcmCryptoSession(_random_key()) as cipher:
        plaintext = bytearray(b"hello world")
        encrypted = bytearray(len(plaintext) + 28)
        cipher.encrypt(plaintext, encrypted, b"correct-aad")

        decrypted = bytearray(11)
        with pytest.raises(InvalidTag):
            cipher.decrypt(bytes(encrypted), decrypted, b"wrong-aad")


def test_decrypt_with_tampered_ciphertext_raises_invalid_tag() -> None:
    with AesGcmCryptoSession(_random_key()) as cipher:
        plaintext = bytearray(b"hello world")
        encrypted = bytearray(len(plaintext) + 28)
        cipher.encrypt(plaintext, encrypted)
        encrypted[15] ^= 0xFF

        decrypted = bytearray(11)
        with pytest.raises(InvalidTag):
            cipher.decrypt(bytes(encrypted), decrypted)


def test_encrypt_with_too_small_result_buffer_raises() -> None:
    with AesGcmCryptoSession(_random_key()) as cipher:
        plaintext = bytearray(b"hello world")
        too_small = bytearray(len(plaintext))

        with pytest.raises(ValueError, match="too small"):
            cipher.encrypt(plaintext, too_small)


def test_decrypt_with_too_short_ciphertext_raises() -> None:
    with AesGcmCryptoSession(_random_key()) as cipher:
        too_short = bytes(10)
        result = bytearray(4)

        with pytest.raises(ValueError):
            cipher.decrypt(too_short, result)


def test_constructor_with_invalid_key_size_raises() -> None:
    invalid_key = bytearray(secrets.token_bytes(10))

    with pytest.raises(ValueError):
        AesGcmCryptoSession(invalid_key)


def test_constructor_with_all_zero_key_raises() -> None:
    zero_key = bytearray(32)

    with pytest.raises(ValueError):
        AesGcmCryptoSession(zero_key)


def test_encrypt_with_all_zero_plaintext_raises() -> None:
    with AesGcmCryptoSession(_random_key()) as cipher:
        zero_plaintext = bytearray(11)
        encrypted = bytearray(len(zero_plaintext) + 28)

        with pytest.raises(ValueError, match="Plaintext"):
            cipher.encrypt(zero_plaintext, encrypted)


def test_decrypt_with_non_zero_but_too_short_ciphertext_raises() -> None:
    with AesGcmCryptoSession(_random_key()) as cipher:
        too_short = secrets.token_bytes(10)  # non-zero, but shorter than nonce + tag
        result = bytearray(4)

        with pytest.raises(ValueError, match="too short"):
            cipher.decrypt(too_short, result)


def test_decrypt_with_too_small_result_buffer_raises() -> None:
    with AesGcmCryptoSession(_random_key()) as cipher:
        plaintext = bytearray(b"hello world")
        encrypted = bytearray(len(plaintext) + 28)
        cipher.encrypt(plaintext, encrypted)

        too_small = bytearray(len(plaintext) - 1)  # len is unaffected by encrypt()'s zeroing
        with pytest.raises(ValueError, match="too small"):
            cipher.decrypt(bytes(encrypted), too_small)


def test_close_zeroes_the_key() -> None:
    key = _random_key()
    key_clone = bytes(key)
    cipher = AesGcmCryptoSession(key)  # ownership transfers - close() zeroes this same object

    cipher.close()

    assert key == bytearray(32)
    assert key != key_clone


def test_close_then_encrypt_raises() -> None:
    cipher = AesGcmCryptoSession(_random_key())
    cipher.close()

    with pytest.raises(ValueError, match="closed"):
        cipher.encrypt(bytearray(b"hello"), bytearray(33))
