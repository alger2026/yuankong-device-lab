from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .security import epoch_now, hash_password, token_hash, utc_now


SCHEMA = """
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')),
    status TEXT NOT NULL CHECK(status IN ('active','disabled')),
    created_at TEXT NOT NULL,
    ip_whitelist TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    totp_secret TEXT,
    deleted_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    created_at_epoch INTEGER NOT NULL,
    expires_at_epoch INTEGER NOT NULL,
    reauth_at_epoch INTEGER,
    revoked_at_epoch INTEGER
);

CREATE TABLE IF NOT EXISTS device_groups (
    id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(owner_user_id, name)
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL UNIQUE,
    owner_user_id TEXT NOT NULL REFERENCES users(id),
    group_id TEXT REFERENCES device_groups(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    brand TEXT NOT NULL,
    model TEXT NOT NULL,
    android_version TEXT NOT NULL,
    sdk_int INTEGER NOT NULL,
    package_name TEXT NOT NULL,
    app_version TEXT NOT NULL,
    locale TEXT,
    timezone TEXT,
    ip_address TEXT,
    socket_id TEXT,
    last_online_at TEXT,
    last_heartbeat_at TEXT,
    last_heartbeat_epoch INTEGER,
    fcm_token TEXT,
    fcm_token_updated_at TEXT,
    device_token_hash TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_status (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    online INTEGER NOT NULL DEFAULT 0,
    battery_percent INTEGER,
    charging INTEGER,
    network_type TEXT,
    network_quality TEXT,
    network_latency_ms INTEGER,
    screen_state TEXT,
    locked INTEGER,
    lock_state_code INTEGER,
    accessibility_enabled INTEGER,
    battery_whitelist_enabled INTEGER,
    device_admin_enabled INTEGER,
    screen_permission_enabled INTEGER,
    camera_permission_enabled INTEGER,
    uninstall_protection_enabled INTEGER,
    launcher_icon_visible INTEGER,
    screen_interactive INTEGER,
    idle_mode INTEGER,
    memory_available_mb INTEGER,
    memory_total_mb INTEGER,
    memory_low INTEGER,
    last_acc_event TEXT,
    last_acc_event_at TEXT,
    battery_stage TEXT,
    battery_message TEXT,
    battery_status_at TEXT,
    device_admin_status TEXT,
    device_admin_message TEXT,
    device_admin_updated_at TEXT,
    reported_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_sessions (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    socket_id TEXT NOT NULL,
    connected_at TEXT NOT NULL,
    last_heartbeat_at TEXT NOT NULL,
    disconnected_at TEXT,
    disconnect_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_device_sessions_device ON device_sessions(device_id, connected_at);

CREATE TABLE IF NOT EXISTS commands (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    operator_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    queued_at TEXT NOT NULL,
    sent_at TEXT,
    acknowledged_at TEXT,
    completed_at TEXT,
    error_code TEXT,
    error_message TEXT,
    result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_commands_device ON commands(device_id, queued_at);

CREATE TABLE IF NOT EXISTS battery_guides (
    id TEXT PRIMARY KEY,
    brand TEXT NOT NULL,
    model_pattern TEXT NOT NULL DEFAULT '*',
    title TEXT NOT NULL,
    steps_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(brand, model_pattern)
);

CREATE TABLE IF NOT EXISTS message_templates (
    id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(owner_user_id, name)
);

CREATE TABLE IF NOT EXISTS screen_sessions (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    operator_id TEXT NOT NULL REFERENCES users(id),
    command_id TEXT REFERENCES commands(id),
    status TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    consented_at TEXT,
    ended_at TEXT,
    error_code TEXT,
    error_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_screen_sessions_device ON screen_sessions(device_id, requested_at);

CREATE TABLE IF NOT EXISTS screen_stream_tickets (
    id TEXT PRIMARY KEY,
    ticket_hash TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL REFERENCES screen_sessions(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role IN ('browser','device')),
    expires_at_epoch INTEGER NOT NULL,
    consumed_at_epoch INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_uid TEXT NOT NULL,
    level TEXT NOT NULL,
    category TEXT NOT NULL,
    event TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT NOT NULL,
    device_time TEXT,
    received_at TEXT NOT NULL,
    UNIQUE(device_id, event_uid)
);

CREATE TABLE IF NOT EXISTS device_data_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    data_json TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_data_reports_device_action
ON device_data_reports(device_id, action, received_at);

CREATE TABLE IF NOT EXISTS device_heartbeats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    build_id TEXT NOT NULL,
    client_timestamp INTEGER NOT NULL,
    battery INTEGER NOT NULL,
    acc_status TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_heartbeats_device_received
ON device_heartbeats(device_id, received_at);

CREATE TABLE IF NOT EXISTS device_diagnostics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    diagnostic_type TEXT NOT NULL,
    event TEXT,
    message TEXT,
    reason TEXT,
    client_timestamp INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_diagnostics_device_created
ON device_diagnostics(device_id, diagnostic_type, created_at);

CREATE TABLE IF NOT EXISTS device_expected_state (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    state_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_runtime_state (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    state_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_stream_sessions (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    stream_type TEXT NOT NULL,
    status TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    started_at TEXT NOT NULL,
    stop_sent_at TEXT,
    stopped_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_device_stream_sessions_device
ON device_stream_sessions(device_id, stream_type, started_at);

CREATE TABLE IF NOT EXISTS device_binary_frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    frame_type INTEGER NOT NULL,
    sequence_no INTEGER NOT NULL,
    payload BLOB NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_binary_frames_device
ON device_binary_frames(device_id, frame_type, received_at);

CREATE TABLE IF NOT EXISTS device_cache (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cache_key TEXT NOT NULL,
    cache_json TEXT NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY(device_id, cache_key)
);

CREATE TABLE IF NOT EXISTS device_line_configs (
    device_id TEXT NOT NULL,
    apk_id TEXT NOT NULL,
    config_json TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    PRIMARY KEY(device_id, apk_id)
);

CREATE TABLE IF NOT EXISTS install_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_name TEXT NOT NULL,
    action TEXT NOT NULL,
    device_uid TEXT NOT NULL,
    requested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    result TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ws_tickets (
    id TEXT PRIMARY KEY,
    ticket_hash TEXT NOT NULL UNIQUE,
    purpose TEXT NOT NULL CHECK(purpose IN ('dashboard','device')),
    subject_id TEXT NOT NULL,
    expires_at_epoch INTEGER NOT NULL,
    consumed_at_epoch INTEGER,
    created_at TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self, admin_username: str, admin_password: str) -> None:
        with self._lock, self.connect() as conn:
            conn.executescript(SCHEMA)
            self._ensure_column(conn, "users", "ip_whitelist", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "users", "note", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "users", "totp_secret", "TEXT")
            self._ensure_column(conn, "users", "deleted_at", "TEXT")
            self._ensure_column(
                conn,
                "devices",
                "group_id",
                "TEXT REFERENCES device_groups(id) ON DELETE SET NULL",
            )
            self._ensure_column(conn, "devices", "note", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "devices", "locale", "TEXT")
            self._ensure_column(conn, "devices", "timezone", "TEXT")
            self._ensure_column(conn, "devices", "ip_address", "TEXT")
            self._ensure_column(conn, "devices", "socket_id", "TEXT")
            self._ensure_column(conn, "devices", "last_online_at", "TEXT")
            self._ensure_column(conn, "devices", "last_heartbeat_at", "TEXT")
            self._ensure_column(conn, "devices", "last_heartbeat_epoch", "INTEGER")
            self._ensure_column(conn, "devices", "fcm_token", "TEXT")
            self._ensure_column(conn, "devices", "fcm_token_updated_at", "TEXT")
            self._ensure_column(conn, "device_status", "network_quality", "TEXT")
            self._ensure_column(conn, "device_status", "network_latency_ms", "INTEGER")
            self._ensure_column(conn, "device_status", "lock_state_code", "INTEGER")
            self._ensure_column(
                conn, "device_status", "uninstall_protection_enabled", "INTEGER"
            )
            self._ensure_column(
                conn, "device_status", "launcher_icon_visible", "INTEGER"
            )
            for column, definition in (
                ("screen_interactive", "INTEGER"),
                ("idle_mode", "INTEGER"),
                ("memory_available_mb", "INTEGER"),
                ("memory_total_mb", "INTEGER"),
                ("memory_low", "INTEGER"),
                ("last_acc_event", "TEXT"),
                ("last_acc_event_at", "TEXT"),
                ("battery_stage", "TEXT"),
                ("battery_message", "TEXT"),
                ("battery_status_at", "TEXT"),
                ("device_admin_status", "TEXT"),
                ("device_admin_message", "TEXT"),
                ("device_admin_updated_at", "TEXT"),
            ):
                self._ensure_column(conn, "device_status", column, definition)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_devices_group ON devices(group_id)"
            )
            conn.execute("UPDATE device_status SET online=0")
            conn.execute(
                "UPDATE device_sessions SET disconnected_at=?, disconnect_reason='server_restart' "
                "WHERE disconnected_at IS NULL",
                (utc_now(),),
            )
            conn.execute(
                "UPDATE screen_sessions SET status='failed',ended_at=?,"
                "error_code='SERVER_RESTART',error_message='server restarted' "
                "WHERE status IN ('requesting','awaiting_consent','active')",
                (utc_now(),),
            )
            user = conn.execute("SELECT id FROM users LIMIT 1").fetchone()
            if user is None:
                if not admin_password:
                    raise RuntimeError(
                        "ADB_ADMIN_PASSWORD is required when initializing a new database"
                    )
                conn.execute(
                    "INSERT INTO users(id,username,password_hash,role,status,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        str(uuid.uuid4()),
                        admin_username,
                        hash_password(admin_password),
                        "admin",
                        "active",
                        utc_now(),
                    ),
                )
                user = conn.execute("SELECT id FROM users LIMIT 1").fetchone()
            guide = conn.execute("SELECT id FROM battery_guides LIMIT 1").fetchone()
            if guide is None:
                now = utc_now()
                conn.execute(
                    "INSERT INTO battery_guides(id,brand,model_pattern,title,steps_json,enabled,created_by,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,1,?,?,?)",
                    (
                        str(uuid.uuid4()),
                        "*",
                        "*",
                        "Android 通用电池优化设置",
                        json.dumps(
                            [
                                "打开系统设置中的应用信息页面。",
                                "进入电池或电量管理选项。",
                                "由设备持有人选择允许后台运行或不优化。",
                                "返回应用后重新检查状态。",
                            ],
                            ensure_ascii=False,
                        ),
                        user["id"] if user else None,
                        now,
                        now,
                    ),
                )

    @staticmethod
    def _ensure_column(
        conn: sqlite3.Connection, table: str, column: str, definition: str
    ) -> None:
        columns = {row["name"] for row in conn.execute(f'PRAGMA table_info("{table}")')}
        if column not in columns:
            conn.execute(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {definition}')

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self._lock, self.connect() as conn:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock, self.connect() as conn:
            return [dict(row) for row in conn.execute(sql, params).fetchall()]

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self._lock, self.connect() as conn:
            conn.execute(sql, params)

    def transaction(self, callback):
        with self._lock, self.connect() as conn:
            return callback(conn)

    @staticmethod
    def audit(
        conn: sqlite3.Connection,
        actor_type: str,
        actor_id: str,
        action: str,
        target_type: str,
        target_id: str,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        conn.execute(
            "INSERT INTO audit_logs(actor_type,actor_id,action,target_type,target_id,result,details_json,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                actor_type,
                actor_id,
                action,
                target_type,
                target_id,
                result,
                json.dumps(details or {}, ensure_ascii=False),
                utc_now(),
            ),
        )

    def consume_ticket(self, ticket: str, purpose: str) -> dict[str, Any] | None:
        digest = token_hash(ticket)

        def action(conn: sqlite3.Connection):
            row = conn.execute(
                "SELECT * FROM ws_tickets WHERE ticket_hash=? AND purpose=?",
                (digest, purpose),
            ).fetchone()
            if (
                row is None
                or row["consumed_at_epoch"] is not None
                or row["expires_at_epoch"] < epoch_now()
            ):
                return None
            conn.execute(
                "UPDATE ws_tickets SET consumed_at_epoch=? WHERE id=?",
                (epoch_now(), row["id"]),
            )
            return dict(row)

        return self.transaction(action)

    def consume_screen_ticket(self, ticket: str) -> dict[str, Any] | None:
        digest = token_hash(ticket)

        def action(conn: sqlite3.Connection):
            row = conn.execute(
                "SELECT * FROM screen_stream_tickets WHERE ticket_hash=?",
                (digest,),
            ).fetchone()
            if (
                row is None
                or row["consumed_at_epoch"] is not None
                or row["expires_at_epoch"] < epoch_now()
            ):
                return None
            conn.execute(
                "UPDATE screen_stream_tickets SET consumed_at_epoch=? WHERE id=?",
                (epoch_now(), row["id"]),
            )
            return dict(row)

        return self.transaction(action)
