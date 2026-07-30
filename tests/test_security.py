from __future__ import annotations

from wallpilot.security import PasswordHasher, generate_totp_secret, totp_code, verify_totp


def test_password_hash_and_verify() -> None:
    hasher = PasswordHasher()
    encoded = hasher.hash("Correct-Horse-42!")
    assert hasher.verify(encoded, "Correct-Horse-42!")
    assert not hasher.verify(encoded, "wrong-password")
    assert "Correct-Horse" not in encoded


def test_totp_matches_adjacent_time_window() -> None:
    secret = generate_totp_secret()
    code = totp_code(secret, timestamp=1_800_000_000)
    assert verify_totp(secret, code, timestamp=1_800_000_000)
    assert verify_totp(secret, code, timestamp=1_800_000_029)
    assert not verify_totp(secret, "000000", timestamp=1_800_000_000)

