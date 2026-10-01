from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterable
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Encrypted image self-reports contain Base64 image text inside the encrypted
# JSON envelope, so their ciphertext is larger than the decoded image.
MAX_LEGACY_CIPHERTEXT_BYTES = 6 * 1024 * 1024

STATUS_KEYS = {
    "battery",
    "battery_percent",
    "charging",
    "netstate",
    "network",
    "network_type",
    "network_quality",
    "network_latency_ms",
    "lock",
    "lock_state_code",
    "screen_state",
    "locked",
    "acc",
    "acc_status",
    "accessibility_enabled",
    "battery_whitelist",
    "ignoring_battery_opt",
    "battery_whitelist_enabled",
    "device_admin_enabled",
    "screen_permission_enabled",
    "camera_permission_enabled",
    "uninstall_protection_enabled",
    "launcher_icon_visible",
    "reported_at",
    "diag",
    "diagnostic",
    "type",
    "name",
    "event",
    "category",
    "status",
    "state",
    "value",
    "message",
}

DEVICE_ID_KEYS = {
    "deviceid",
    "xdeviceid",
    "installationid",
    "androidid",
    "uniqueid",
    "uuid",
    "uid",
}

DEVICE_TOKEN_KEYS = {
    "devicetoken",
    "xdevicetoken",
    "token",
    "authtoken",
}


class LegacyProtocolError(ValueError):
    pass


def _normalized_key(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def _walk_objects(value: Any) -> Iterable[dict[str, Any]]:
    pending = [value]
    visited = 0
    while pending and visited < 100:
        current = pending.pop(0)
        visited += 1
        if isinstance(current, dict):
            yield current
            pending.extend(current.values())
        elif isinstance(current, (list, tuple)):
            pending.extend(current)


def _extract_ciphertext(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise LegacyProtocolError("encrypted payload must be Base64 text") from exc
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        for item in value:
            try:
                return _extract_ciphertext(item)
            except LegacyProtocolError:
                continue
    if isinstance(value, dict):
        for key in ("data", "msg", "message", "payload", "enc", "ciphertext"):
            if key not in value:
                continue
            try:
                return _extract_ciphertext(value[key])
            except LegacyProtocolError:
                continue
    raise LegacyProtocolError("Socket.IO event does not contain a Base64 ciphertext")


def decrypt_legacy_payload(value: Any, key: str) -> Any:
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 16:
        raise LegacyProtocolError("legacy AES key must be exactly 16 UTF-8 bytes")

    encoded = "".join(_extract_ciphertext(value).split())
    if len(encoded) > MAX_LEGACY_CIPHERTEXT_BYTES * 2:
        raise LegacyProtocolError("encrypted payload is too large")
    try:
        ciphertext = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise LegacyProtocolError("encrypted payload is not valid Base64") from exc
    if not ciphertext or len(ciphertext) > MAX_LEGACY_CIPHERTEXT_BYTES:
        raise LegacyProtocolError("encrypted payload size is invalid")
    if len(ciphertext) % 16:
        raise LegacyProtocolError("AES-ECB ciphertext length must be a multiple of 16")

    decryptor = Cipher(algorithms.AES(key_bytes), modes.ECB()).decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        decoded: Any = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LegacyProtocolError("decrypted payload is not valid padded UTF-8 JSON") from exc

    # Some Socket.IO clients JSON-encode the message twice.
    if isinstance(decoded, str):
        try:
            decoded = json.loads(decoded)
        except json.JSONDecodeError:
            pass
    return decoded


def encrypt_legacy_payload(value: Any, key: str) -> str:
    """Encode a JSON value with the legacy APK's AES/Base64 envelope."""
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 16:
        raise LegacyProtocolError("legacy AES key must be exactly 16 UTF-8 bytes")
    try:
        plaintext = json.dumps(
            value, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LegacyProtocolError("legacy payload must be JSON serializable") from exc
    if not plaintext or len(plaintext) > MAX_LEGACY_CIPHERTEXT_BYTES:
        raise LegacyProtocolError("legacy plaintext size is invalid")
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key_bytes), modes.ECB()).encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("ascii")


def collect_status_payload(value: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in _walk_objects(value):
        for key, field_value in item.items():
            if key in STATUS_KEYS and key not in result:
                result[key] = field_value
    return result


def find_device_identity(*values: Any) -> tuple[list[str], list[str]]:
    identifiers: list[str] = []
    tokens: list[str] = []
    for value in values:
        for item in _walk_objects(value):
            for key, field_value in item.items():
                if not isinstance(field_value, (str, int)):
                    continue
                normalized = _normalized_key(key)
                text = str(field_value).strip()
                if not text:
                    continue
                if normalized in DEVICE_ID_KEYS and text not in identifiers:
                    identifiers.append(text)
                elif normalized in DEVICE_TOKEN_KEYS and text not in tokens:
                    tokens.append(text)
    return identifiers, tokens
