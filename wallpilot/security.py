from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from dataclasses import dataclass


class PasswordHasher:
    """Argon2id in production with a stdlib scrypt fallback for constrained hosts."""

    def __init__(self) -> None:
        try:
            from argon2 import PasswordHasher as Argon2Hasher

            self._argon = Argon2Hasher(
                time_cost=3,
                memory_cost=65536,
                parallelism=2,
                hash_len=32,
                salt_len=16,
            )
        except ImportError:
            self._argon = None

    def hash(self, password: str) -> str:
        self._validate_password(password)
        if self._argon is not None:
            return self._argon.hash(password)
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
        )
        return "scrypt$16384$8$1$" + base64.urlsafe_b64encode(salt + digest).decode()

    def verify(self, encoded: str, password: str) -> bool:
        if encoded.startswith("$argon2"):
            if self._argon is None:
                return False
            try:
                return bool(self._argon.verify(encoded, password))
            except Exception:
                return False
        try:
            scheme, n, r, p, payload = encoded.split("$", 4)
            if scheme != "scrypt":
                return False
            raw = base64.urlsafe_b64decode(payload.encode())
            salt, expected = raw[:16], raw[16:]
            actual = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=int(n),
                r=int(r),
                p=int(p),
                dklen=len(expected),
            )
            return hmac.compare_digest(actual, expected)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < 12:
            raise ValueError("密码至少需要 12 个字符")
        if len(password) > 512:
            raise ValueError("密码过长")
        categories = sum(
            (
                any(ch.islower() for ch in password),
                any(ch.isupper() for ch in password),
                any(ch.isdigit() for ch in password),
                any(not ch.isalnum() for ch in password),
            )
        )
        if categories < 3:
            raise ValueError("密码需要包含大小写字母、数字或符号中的至少三类")


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret: str, *, timestamp: int | None = None, step: int = 30) -> str:
    timestamp = int(time.time()) if timestamp is None else timestamp
    counter = timestamp // step
    padding = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode((secret + padding).upper())
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{number:06d}"


def verify_totp(secret: str, code: str, *, timestamp: int | None = None) -> bool:
    if not code.isdigit() or len(code) not in {6, 8}:
        return False
    now = int(time.time()) if timestamp is None else timestamp
    return any(
        hmac.compare_digest(totp_code(secret, timestamp=now + offset), code[-6:])
        for offset in (-30, 0, 30)
    )


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class SessionToken:
    raw: str
    digest: str
    csrf: str


def new_session_token() -> SessionToken:
    raw = secrets.token_urlsafe(32)
    return SessionToken(raw=raw, digest=token_hash(raw), csrf=secrets.token_urlsafe(24))


def secure_file_mode(path: os.PathLike[str]) -> None:
    if os.name == "posix":
        os.chmod(path, 0o600)

