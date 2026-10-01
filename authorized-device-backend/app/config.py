from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_path: Path
    bootstrap_admin_username: str
    bootstrap_admin_password: str
    session_ttl_seconds: int
    reauth_ttl_seconds: int
    ws_ticket_ttl_seconds: int
    device_offline_after_seconds: int
    enable_device_lock: bool
    legacy_device_aes_key: str = "0623U25KTT3YO8P9"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            database_path=Path(os.getenv("ADB_DB_PATH", "data/backend.sqlite3")).resolve(),
            bootstrap_admin_username=os.getenv("ADB_ADMIN_USERNAME", "admin"),
            bootstrap_admin_password=os.getenv("ADB_ADMIN_PASSWORD", ""),
            session_ttl_seconds=int(os.getenv("ADB_SESSION_TTL_SECONDS", "28800")),
            reauth_ttl_seconds=int(os.getenv("ADB_REAUTH_TTL_SECONDS", "300")),
            ws_ticket_ttl_seconds=int(os.getenv("ADB_WS_TICKET_TTL_SECONDS", "45")),
            device_offline_after_seconds=int(os.getenv("ADB_DEVICE_OFFLINE_SECONDS", "90")),
            enable_device_lock=_bool_env("ADB_ENABLE_DEVICE_LOCK", False),
            legacy_device_aes_key=os.getenv(
                "ADB_LEGACY_DEVICE_AES_KEY", "0623U25KTT3YO8P9"
            ),
        )
