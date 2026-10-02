from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timezone


PBKDF2_ITERATIONS = 260_000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def epoch_now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def normalize_totp_secret(value: str) -> str:
    secret = "".join(value.upper().split()).rstrip("=")
    if not 16 <= len(secret) <= 128:
        raise ValueError("TOTP secret must contain 16-128 Base32 characters")
    try:
        base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("TOTP secret must be valid Base32") from exc
    return secret


def verify_totp(code: str, secret: str, *, at_epoch: int | None = None) -> bool:
    normalized_code = "".join(code.split())
    if len(normalized_code) != 6 or not normalized_code.isdigit():
        return False
    try:
        normalized_secret = normalize_totp_secret(secret)
        key = base64.b32decode(
            normalized_secret + "=" * (-len(normalized_secret) % 8), casefold=True
        )
    except ValueError:
        return False
    current_step = int(time.time() if at_epoch is None else at_epoch) // 30
    for offset in (-1, 0, 1):
        digest = hmac.new(key, struct.pack(">Q", current_step + offset), hashlib.sha1).digest()
        start = digest[-1] & 0x0F
        value = (struct.unpack(">I", digest[start : start + 4])[0] & 0x7FFFFFFF) % 1_000_000
        if hmac.compare_digest(f"{value:06d}", normalized_code):
            return True
    return False
