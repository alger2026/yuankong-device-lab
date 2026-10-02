from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import struct
import tempfile
import time
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.config import Settings
from app.legacy_protocol import decrypt_legacy_payload
from app.main import (
    LEGACY_REMAINING_ACTIONS,
    LEGACY_REMAINING_FIXED_DATA,
    create_app,
)
from app.security import token_hash, utc_now


ADMIN_PASSWORD = "correct-horse-battery-staple"
LEGACY_AES_KEY = "0623U25KTT3YO8P9"


def encrypt_legacy_payload(payload: object) -> str:
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(LEGACY_AES_KEY.encode("utf-8")), modes.ECB()
    ).encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode(
        "ascii"
    )


def make_client(
    temp: tempfile.TemporaryDirectory,
    client_address: tuple[str, int] | None = None,
) -> TestClient:
    settings = Settings(
        database_path=Path(temp.name) / "test.sqlite3",
        bootstrap_admin_username="admin",
        bootstrap_admin_password=ADMIN_PASSWORD,
        session_ttl_seconds=3600,
        reauth_ttl_seconds=300,
        ws_ticket_ttl_seconds=60,
        device_offline_after_seconds=30,
        enable_device_lock=False,
    )
    app = create_app(settings)
    if client_address is None:
        return TestClient(app)
    return TestClient(app, client=client_address)


def totp_code(secret: str, at_epoch: int | None = None) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int(time.time() if at_epoch is None else at_epoch) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{value:06d}"


def login(client: TestClient) -> tuple[str, dict[str, str]]:
    response = client.post(
        "/api/login", json={"username": "admin", "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200, response.text
    token = response.json()["data"]["token"]
    return token, {"Authorization": f"Bearer {token}"}


def provision_device(client: TestClient, headers: dict[str, str]) -> dict[str, str]:
    """Insert a trusted fixture without exposing a public provisioning endpoint."""
    owner_id = client.get("/api/me", headers=headers).json()["data"]["id"]
    device_id = str(uuid.uuid4())
    device_token = f"test-device-{uuid.uuid4()}"
    now = utc_now()

    def action(conn):
        conn.execute(
            "INSERT INTO devices(id,installation_id,owner_user_id,name,brand,model,android_version,"
            "sdk_int,package_name,app_version,device_token_hash,first_seen_at,last_seen_at,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                device_id,
                str(uuid.uuid4()),
                owner_id,
                "Authorized test phone",
                "Example",
                "Model A",
                "15",
                35,
                "com.example.support",
                "1.0.0",
                token_hash(device_token),
                now,
                now,
                now,
                now,
            ),
        )
        conn.execute(
            "INSERT INTO device_status(device_id,online,screen_state,updated_at) "
            "VALUES(?,0,'unknown',?)",
            (device_id, now),
        )

    client.app.state.db.transaction(action)
    return {"device_id": device_id, "device_token": device_token}


def test_auth_bootstrap_and_removed_routes() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            health = client.get("/api/health")
            assert health.status_code == 200
            assert health.json()["data"]["mode"] == "authorized-device-management"

            bootstrap = client.get("/api/device/bootstrap")
            assert bootstrap.status_code == 200
            assert "lock_device" not in bootstrap.json()["data"]["allowed_actions"]
            assert "enroll_path" not in bootstrap.json()["data"]

            _, headers = login(client)
            assert client.get("/api/me", headers=headers).json()["data"]["role"] == "admin"
            assert client.post("/api/enrollment-tokens", headers=headers).status_code == 404
            assert client.post("/api/device/enroll").status_code == 404
            assert client.get("/api/releases", headers=headers).status_code == 404
            assert client.get("/api/device/releases/latest").status_code == 404

            tables = {
                row["name"]
                for row in client.app.state.db.all(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            assert "enrollment_tokens" not in tables
            assert "releases" not in tables
        temp.cleanup()


def test_device_websocket_status_command_and_dashboard() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            device_headers = {
                "X-Device-Id": device["device_id"],
                "X-Device-Token": device["device_token"],
            }
            dashboard_ticket = client.post("/api/ws-ticket", headers=headers).json()["data"]["ticket"]
            device_ticket = client.post(
                "/api/device/ws-ticket", headers=device_headers
            ).json()["data"]["ticket"]

            with client.websocket_connect(
                f"/ws/dashboard?ticket={dashboard_ticket}"
            ) as dashboard_ws:
                assert dashboard_ws.receive_json()["type"] == "server.hello"
                with client.websocket_connect(f"/ws/device?ticket={device_ticket}") as device_ws:
                    assert device_ws.receive_json()["type"] == "server.hello"
                    online = dashboard_ws.receive_json()
                    assert online["type"] == "device.online"
                    assert online["device_id"] == device["device_id"]

                    heartbeat_id = str(uuid.uuid4())
                    device_ws.send_json(
                        {
                            "type": "device.heartbeat",
                            "message_id": heartbeat_id,
                            "payload": {},
                        }
                    )
                    pong = device_ws.receive_json()
                    assert pong["type"] == "server.pong"
                    assert pong["correlation_id"] == heartbeat_id

                    device_ws.send_json(
                        {
                            "type": "device.status",
                            "message_id": str(uuid.uuid4()),
                            "payload": {
                                "battery_percent": 81,
                                "charging": False,
                                "network_type": "wifi",
                                "screen_state": "on",
                                "locked": False,
                                "accessibility_enabled": False,
                                "battery_whitelist_enabled": True,
                            },
                        }
                    )
                    status_event = dashboard_ws.receive_json()
                    assert status_event["type"] == "device.status"

                    listed = client.get(
                        "/api/devices?online=true&battery_whitelist=true",
                        headers=headers,
                    )
                    assert listed.status_code == 200
                    assert listed.json()["meta"]["total"] == 1
                    assert listed.json()["data"][0]["battery_percent"] == 81

                    command_response = client.post(
                        "/api/command",
                        headers=headers,
                        json={
                            "device_id": device["device_id"],
                            "action": "refresh_status",
                            "payload": {},
                        },
                    )
                    assert command_response.status_code == 202, command_response.text
                    command_id = command_response.json()["data"]["command_id"]
                    dispatched = device_ws.receive_json()
                    assert dispatched["type"] == "command.dispatch"
                    assert dispatched["correlation_id"] == command_id

                    device_ws.send_json(
                        {
                            "type": "command.ack",
                            "message_id": str(uuid.uuid4()),
                            "correlation_id": command_id,
                            "payload": {},
                        }
                    )
                    assert dashboard_ws.receive_json()["status"] == "acknowledged"

                    device_ws.send_json(
                        {
                            "type": "command.result",
                            "message_id": str(uuid.uuid4()),
                            "correlation_id": command_id,
                            "payload": {"success": True, "result": {"refreshed": True}},
                        }
                    )
                    completed = dashboard_ws.receive_json()
                    assert completed["status"] == "success"

                    command = client.get(f"/api/commands/{command_id}", headers=headers)
                    assert command.status_code == 200
                    assert command.json()["data"]["status"] == "success"
                    assert command.json()["data"]["result"] == {"refreshed": True}

                offline = dashboard_ws.receive_json()
                assert offline["type"] == "device.offline"
        temp.cleanup()


def test_legacy_device_status_aliases_and_diag() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            device_headers = {
                "X-Device-Id": device["device_id"],
                "X-Device-Token": device["device_token"],
            }

            legacy_status = client.post(
                "/api/device/status",
                headers=device_headers,
                json={
                    "battery": "73%",
                    "charging": "1",
                    "netstate": "5G",
                    "lock": "2",
                    "acc_status": "ACTIVATED",
                    "ignoring_battery_opt": 1,
                    "deviceInfo": {"screen": 2400},
                },
            )
            assert legacy_status.status_code == 200, legacy_status.text

            detail = client.get(
                f"/api/devices/{device['device_id']}", headers=headers
            ).json()["data"]
            assert detail["battery_percent"] == 73
            assert detail["charging"] == 1
            assert detail["network_type"] == "5g"
            assert detail["lock_state_code"] == 2
            assert detail["screen_state"] == "on"
            assert detail["locked"] == 0
            assert detail["accessibility_enabled"] == 1
            assert detail["battery_whitelist_enabled"] == 1

            dashboard_ticket = client.post(
                "/api/ws-ticket", headers=headers
            ).json()["data"]["ticket"]
            device_ticket = client.post(
                "/api/device/ws-ticket", headers=device_headers
            ).json()["data"]["ticket"]
            with client.websocket_connect(
                f"/ws/dashboard?ticket={dashboard_ticket}"
            ) as dashboard_ws:
                assert dashboard_ws.receive_json()["type"] == "server.hello"
                with client.websocket_connect(
                    f"/ws/device?ticket={device_ticket}"
                ) as device_ws:
                    assert device_ws.receive_json()["type"] == "server.hello"
                    assert dashboard_ws.receive_json()["type"] == "device.online"

                    device_ws.send_json(
                        {
                            "type": "deviceOnline",
                            "payload": {
                                "battery": 88,
                                "network": "WIFI",
                                "lock": 1,
                                "acc": 0,
                            },
                        }
                    )
                    status_event = dashboard_ws.receive_json()
                    assert status_event["type"] == "device.status"
                    assert status_event["status"] == {
                        "battery_percent": 88,
                        "network_type": "wifi",
                        "screen_state": "locked",
                        "locked": True,
                        "lock_state_code": 1,
                        "accessibility_enabled": False,
                    }

                    device_ws.send_json(
                        {
                            "type": "diag",
                            "payload": {
                                "diag": "device_admin",
                                "status": "ACTIVATED",
                            },
                        }
                    )
                    diag_event = dashboard_ws.receive_json()
                    assert diag_event["type"] == "device.status"
                    assert diag_event["status"] == {"device_admin_enabled": True}

            detail = client.get(
                f"/api/devices/{device['device_id']}", headers=headers
            ).json()["data"]
            assert detail["battery_percent"] == 88
            assert detail["network_type"] == "wifi"
            assert detail["lock_state_code"] == 1
            assert detail["screen_state"] == "locked"
            assert detail["locked"] == 1
            assert detail["accessibility_enabled"] == 0
            assert detail["device_admin_enabled"] == 1
        temp.cleanup()


def test_encrypted_socketio_device_online_status() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            sio = client.app.state.socketio_server
            connect_handler = sio.handlers["/"]["connect"]
            status_handler = sio.handlers["/"]["deviceOnline"]
            encrypted_handler = sio.handlers["/"]["enc msg"]
            sid = "legacy-test-sid"

            connected = asyncio.run(
                connect_handler(
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    {
                        "device_id": device["device_id"],
                        "device_token": device["device_token"],
                    },
                )
            )
            assert connected is True

            encrypted = encrypt_legacy_payload(
                {
                    "event": "deviceOnline",
                    "data": {
                        "battery": 64,
                        "charging": False,
                        "netstate": "4G",
                        "lock": 3,
                        "acc": True,
                        "battery_whitelist": False,
                    },
                }
            )
            accepted = asyncio.run(status_handler(sid, {"data": encrypted}))
            assert accepted == {"accepted": True, "device_id": device["device_id"]}

            diag_result = asyncio.run(
                encrypted_handler(
                    sid,
                    encrypt_legacy_payload(
                        {"type": "device_admin", "status": "ACTIVATED"}
                    ),
                )
            )
            assert diag_result == {
                "accepted": True,
                "device_id": device["device_id"],
            }

            detail = client.get(
                f"/api/devices/{device['device_id']}", headers=headers
            ).json()["data"]
            assert detail["online"] == 1
            assert detail["battery_percent"] == 64
            assert detail["charging"] == 0
            assert detail["network_type"] == "4g"
            assert detail["lock_state_code"] == 3
            assert detail["screen_state"] == "on"
            assert detail["locked"] == 0
            assert detail["accessibility_enabled"] == 1
            assert detail["battery_whitelist_enabled"] == 0
            assert detail["device_admin_enabled"] == 1
        temp.cleanup()


def test_legacy_login_and_encrypted_device_online_are_saved() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            sio = client.app.state.socketio_server
            sid = "legacy-device-online-sid"
            assert asyncio.run(
                sio.handlers["/"]["connect"](
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    {
                        "device_id": device["device_id"],
                        "device_token": device["device_token"],
                    },
                )
            ) is True
            assert asyncio.run(sio.handlers["/"]["login"](sid, device["device_id"])) == {
                "accepted": True,
                "device_id": device["device_id"],
            }

            report_data = {
                "deviceId": device["device_id"],
                "pkg": "android",
                "apps": None,
                "mails": None,
                "deviceInfo": {
                    "myPkg": "com.example.updated",
                    "apkVer": "2.0.0",
                    "timeZone": "Asia/Manila",
                    "lang": "zh",
                    "brand": "品牌",
                    "model": "型号",
                    "version": 35,
                    "battery": 80,
                    "charging": False,
                    "lock": 0,
                    "acc": True,
                    "netstate": "wifi",
                    "wallpaper": "内容",
                },
            }
            accepted = asyncio.run(
                sio.handlers["/"]["enc msg"](
                    sid,
                    encrypt_legacy_payload(
                        {"action": "deviceOnline", "type": "enc", "data": report_data}
                    ),
                )
            )
            assert accepted == {"accepted": True, "device_id": device["device_id"]}

            detail = client.get(
                f"/api/devices/{device['device_id']}", headers=headers
            ).json()["data"]
            assert detail["brand"] == "品牌"
            assert detail["model"] == "型号"
            assert detail["sdk_int"] == 35
            assert detail["package_name"] == "com.example.updated"
            assert detail["app_version"] == "2.0.0"
            assert detail["timezone"] == "Asia/Manila"
            assert detail["locale"] == "zh"
            assert detail["battery_percent"] == 80
            assert detail["accessibility_enabled"] == 1
            assert detail["network_type"] == "wifi"

            stored = client.app.state.db.one(
                "SELECT data_json FROM device_data_reports WHERE device_id=? "
                "AND action='deviceOnline' ORDER BY id DESC LIMIT 1",
                (device["device_id"],),
            )
            assert json.loads(stored["data_json"]) == report_data
        temp.cleanup()


def test_encrypted_device_online_creates_unknown_device_and_binds_socket() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device_id = str(uuid.uuid4())
            sio = client.app.state.socketio_server
            sid = "legacy-new-device-sid"
            assert asyncio.run(
                sio.handlers["/"]["connect"](
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    None,
                )
            ) is True

            report_data = {
                "deviceId": device_id,
                "pkg": "android",
                "apps": None,
                "mails": None,
                "deviceInfo": {
                    "appName": "New device",
                    "brand": "Brand",
                    "model": "Model",
                    "version": 35,
                    "battery": 80,
                    "charging": True,
                    "netstate": "WIFI",
                    "network": "WIFI",
                    "lock": 1,
                    "acc": True,
                },
            }
            accepted = asyncio.run(
                sio.handlers["/"]["enc msg"](
                    sid,
                    encrypt_legacy_payload(
                        {"action": "deviceOnline", "type": "enc", "data": report_data}
                    ),
                )
            )
            assert accepted == {"accepted": True, "device_id": device_id}

            detail = client.get(f"/api/devices/{device_id}", headers=headers)
            assert detail.status_code == 200, detail.text
            saved = detail.json()["data"]
            assert saved["online"] == 1
            assert saved["battery_percent"] == 80
            assert saved["charging"] == 1
            assert saved["network_type"] == "wifi"
            assert saved["lock_state_code"] == 1
            assert saved["screen_state"] == "locked"
            assert saved["accessibility_enabled"] == 1
            assert saved["socket_id"] == sid
            assert saved["last_online_at"] is not None

            emitted: list[tuple[str, str, str | None]] = []

            async def capture_emit(event: str, payload: str, to: str | None = None):
                emitted.append((event, payload, to))

            sio.emit = capture_emit
            response = client.post(
                f"/api/devices/{device_id}/workbench-actions/unlock",
                headers=headers,
                json={"value": None, "payload": {}},
            )
            assert response.status_code == 202, response.text
            assert emitted[0][0] == "new_msg"
            assert emitted[0][2] == sid

            stored = client.app.state.db.one(
                "SELECT data_json FROM device_data_reports WHERE device_id=? "
                "AND action='deviceOnline' ORDER BY id DESC LIMIT 1",
                (device_id,),
            )
            assert json.loads(stored["data_json"]) == report_data
        temp.cleanup()


def test_plain_http_heartbeat_creates_updates_and_records_device() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device_id = str(uuid.uuid4())
            response = client.post(
                "/heartbeat",
                json={
                    "event": "heartbeat",
                    "buildId": "beced2b5",
                    "ts": 1760000000000,
                    "brand": "品牌",
                    "model": "型号",
                    "sdk": 35,
                    "deviceId": device_id,
                    "packageName": "com.example.heartbeat",
                    "acc_status": "on",
                    "battery": 80,
                },
            )
            assert response.status_code == 204, response.text
            assert response.content == b""

            detail = client.get(f"/api/devices/{device_id}", headers=headers)
            assert detail.status_code == 200, detail.text
            saved = detail.json()["data"]
            assert saved["online"] == 1
            assert saved["battery_percent"] == 80
            assert saved["accessibility_enabled"] == 1
            assert saved["brand"] == "品牌"
            assert saved["model"] == "型号"
            assert saved["sdk_int"] == 35
            assert saved["package_name"] == "com.example.heartbeat"
            assert saved["last_heartbeat_at"] is not None

            heartbeat = client.app.state.db.one(
                "SELECT event,build_id,client_timestamp,battery,acc_status,received_at "
                "FROM device_heartbeats WHERE device_id=? ORDER BY id DESC LIMIT 1",
                (device_id,),
            )
            assert heartbeat["event"] == "heartbeat"
            assert heartbeat["build_id"] == "beced2b5"
            assert heartbeat["client_timestamp"] == 1760000000000
            assert heartbeat["battery"] == 80
            assert heartbeat["acc_status"] == "on"
            assert heartbeat["received_at"] is not None
        temp.cleanup()


def test_encrypted_diagnostics_update_status_and_save_history() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            sio = client.app.state.socketio_server
            sid = "legacy-diagnostic-sid"
            assert asyncio.run(
                sio.handlers["/"]["connect"](
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    {
                        "device_id": device["device_id"],
                        "device_token": device["device_token"],
                    },
                )
            ) is True

            reports = [
                {
                    "type": "acc_lifecycle",
                    "event": "onServiceConnected",
                    "reason": "值",
                    "ts": 1760000000000,
                    "battery": 80,
                    "charging": True,
                    "mem_avail_mb": 2048,
                    "mem_total_mb": 4096,
                    "mem_low": False,
                    "interactive": True,
                    "ignoring_battery_opt": True,
                    "idle_mode": False,
                    "permissions": {
                        "battery_whitelist": True,
                        "accessibility": True,
                        "sms": True,
                        "album": True,
                    },
                    "sdk": 35,
                    "brand": "品牌",
                    "model": "型号",
                    "deviceId": device["device_id"],
                },
                {
                    "type": "battery_auto",
                    "message": "DONE|whitelisted=true|brand=品牌",
                    "ts": 1760000000001,
                    "deviceId": device["device_id"],
                },
                {
                    "type": "device_admin",
                    "message": "ACTIVATED",
                    "ts": 1760000000002,
                    "deviceId": device["device_id"],
                },
            ]
            for report in reports:
                result = asyncio.run(
                    sio.handlers["/"]["enc msg"](
                        sid,
                        encrypt_legacy_payload(
                            {"action": "diag", "type": "enc", "data": report}
                        ),
                    )
                )
                assert result is None

            detail = client.get(
                f"/api/devices/{device['device_id']}", headers=headers
            ).json()["data"]
            assert detail["battery_percent"] == 80
            assert detail["charging"] == 1
            assert detail["screen_interactive"] == 1
            assert detail["accessibility_enabled"] == 1
            assert detail["battery_whitelist_enabled"] == 1
            assert detail["idle_mode"] == 0
            assert detail["memory_available_mb"] == 2048
            assert detail["memory_total_mb"] == 4096
            assert detail["memory_low"] == 0
            assert detail["last_acc_event"] == "onServiceConnected"
            assert detail["battery_stage"] == "DONE"
            assert detail["battery_message"] == "DONE|whitelisted=true|brand=品牌"
            assert detail["device_admin_enabled"] == 1
            assert detail["device_admin_status"] == "ACTIVATED"

            diagnostics = client.app.state.db.all(
                "SELECT diagnostic_type,payload_json FROM device_diagnostics "
                "WHERE device_id=? ORDER BY id",
                (device["device_id"],),
            )
            assert [item["diagnostic_type"] for item in diagnostics] == [
                "acc_lifecycle",
                "battery_auto",
                "device_admin",
            ]
            assert json.loads(diagnostics[0]["payload_json"]) == reports[0]

            destroy_report = {
                **reports[0],
                "event": "onDestroy",
                "uptime_sec": 3600,
                "ts": 1760000000003,
            }
            fallback = client.post(
                "/device_log",
                json={"action": "diag", "type": "enc", "data": destroy_report},
            )
            assert fallback.status_code == 204, fallback.text
            detail = client.get(
                f"/api/devices/{device['device_id']}", headers=headers
            ).json()["data"]
            assert detail["accessibility_enabled"] == 0
            assert detail["last_acc_event"] == "onDestroy"
        temp.cleanup()


@pytest.mark.parametrize(
    ("action", "payload", "expected_wire_action", "expected_data"),
    [
        ("unlock", {}, "unlock", {}),
        (
            "patternUnlock",
            {"pattern": "1235789"},
            "patternUnlock",
            {"pattern": "1235789"},
        ),
        (
            "smartUnlock",
            {"type": "pin", "credential": "123456"},
            "smartUnlock",
            {"type": "pin", "credential": "123456"},
        ),
        ("lockScreen", {}, "lockScreen", {}),
        ("power", {}, "power", {}),
        ("screenshot", {}, "screenshot", {}),
        (
            "rear-camera",
            {},
            "startCam",
            {"index": 0, "quality": 50, "rotation": 0, "frameRate": 15, "width": 640, "zoom": 0},
        ),
        (
            "front-camera",
            {},
            "startCam",
            {"index": 1, "quality": 50, "rotation": 0, "frameRate": 15, "width": 640, "zoom": 0},
        ),
        (
            "startCam",
            {"index": 1},
            "startCam",
            {"index": 1, "quality": 50, "rotation": 0, "frameRate": 15, "width": 640, "zoom": 0},
        ),
        ("stopCam", {}, "stopCam", {}),
        ("openpkg", {"pkg": "com.example.app"}, "openpkg", {"pkg": "com.example.app"}),
        (
            "uninstallApk",
            {"pkg": "com.example.app"},
            "uninstallApk",
            {"pkg": "com.example.app"},
        ),
        ("antiDeleteOn", {}, "antiDeleteOn", {}),
        ("antiDeleteOff", {}, "antiDeleteOff", {}),
        (
            "startApk",
            {"pkg": "com.example.app"},
            "startApk",
            {"pkg": "com.example.app"},
        ),
        ("showShortcuts", {}, "showShortcuts", {}),
        ("hideShortcuts", {}, "hideShortcuts", {}),
        (
            "iconAlias",
            {"alias": "N", "show": True},
            "iconAlias",
            {"alias": "N", "show": True},
        ),
        ("iconList", {}, "iconList", {"fromAdmin": "admin"}),
        ("black", {}, "black", {}),
        ("blackB", {}, "blackB", {}),
        ("lockNormal", {}, "lockNormal", {}),
        ("light", {}, "light", {}),
        ("lightT", {}, "lightT", {}),
        (
            "transparent",
            {
                "url": "https://example.com/page",
                "fullscreen": True,
                "through": False,
            },
            "transparent",
            {
                "url": "https://example.com/page",
                "fullscreen": True,
                "through": False,
            },
        ),
        (
            "openLayer",
            {"url": "https://example.com/page"},
            "openLayer",
            {"url": "https://example.com/page"},
        ),
        (
            "showLockOverlay",
            {
                "type": "pin",
                "title": "System Update",
                "subtitle": "Enter password",
            },
            "showLockOverlay",
            {
                "type": "pin",
                "title": "System Update",
                "subtitle": "Enter password",
            },
        ),
        ("hideLockOverlay", {}, "hideLockOverlay", {}),
        (
            "inputSend",
            {"input": "需要输入的文字"},
            "inputSend",
            {"input": "需要输入的文字"},
        ),
        (
            "readSmsList",
            {},
            "readSmsList",
            {"curpage": 0, "pagesize": 50, "fromAdmin": "admin"},
        ),
        ("walletList", {}, "walletList", {"fromAdmin": "admin"}),
        ("reqPerList", {}, "reqPerList", {"fromAdmin": "admin"}),
        (
            "readAlbumList",
            {},
            "readAlbumList",
            {"curpage": 1, "pagesize": 50, "fromAdmin": "admin"},
        ),
        (
            "readAlbumLast",
            {"path": "/storage/emulated/0/DCIM/名称.jpg", "del": False},
            "readAlbumLast",
            {
                "path": "/storage/emulated/0/DCIM/名称.jpg",
                "del": False,
                "fromAdmin": "admin",
            },
        ),
        (
            "readAlbumThumbnail",
            {
                "fileList": [
                    {
                        "path": "/storage/emulated/0/DCIM/名称.jpg",
                        "fileMd5": "值",
                        "maxWidth": 200,
                    }
                ],
                "maxWidth": 200,
                "elem": "值",
            },
            "readAlbumThumbnail",
            {
                "fileList": [
                    {
                        "path": "/storage/emulated/0/DCIM/名称.jpg",
                        "fileMd5": "值",
                        "maxWidth": 200,
                    }
                ],
                "maxWidth": 200,
                "elem": "值",
                "fromAdmin": "admin",
            },
        ),
        (
            "readContactList",
            {},
            "readContactList",
            {"curpage": 0, "pagesize": 50, "fromAdmin": "admin"},
        ),
    ],
)
def test_unlock_uses_encrypted_legacy_socketio_new_msg(
    action: str,
    payload: dict[str, object],
    expected_wire_action: str,
    expected_data: dict[str, object],
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            sio = client.app.state.socketio_server
            connect_handler = sio.handlers["/"]["connect"]
            sid = f"legacy-{action}-sid"
            assert asyncio.run(
                connect_handler(
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    {
                        "device_id": device["device_id"],
                        "device_token": device["device_token"],
                    },
                )
            ) is True

            emitted: list[tuple[str, str, str | None]] = []

            async def capture_emit(event: str, payload: str, to: str | None = None):
                emitted.append((event, payload, to))

            sio.emit = capture_emit
            response = client.post(
                f"/api/devices/{device['device_id']}/workbench-actions/{action}",
                headers=headers,
                json={"value": None, "payload": payload},
            )

            assert response.status_code == 202, response.text
            assert response.json()["data"] == {"status": "sent"}
            assert len(emitted) == 1
            event, ciphertext, target_sid = emitted[0]
            assert event == "new_msg"
            assert target_sid == sid
            assert decrypt_legacy_payload(ciphertext, LEGACY_AES_KEY) == {
                "action": expected_wire_action,
                "data": expected_data,
            }

            command = client.app.state.db.one(
                "SELECT action,payload_json,status,sent_at,result_json FROM commands "
                "WHERE device_id=? ORDER BY queued_at DESC LIMIT 1",
                (device["device_id"],),
            )
            assert command["action"] == action
            assert command["payload_json"] == "{}"
            assert command["status"] == "sent"
            assert command["sent_at"] is not None
            assert command["result_json"] is None
        temp.cleanup()


@pytest.mark.parametrize(
    ("request_action", "report_action"),
    [("screenshot", "screenshot"), ("rear-camera", "camPic")],
)
def test_uncorrelated_encrypted_socketio_images_use_device_and_action(
    request_action: str,
    report_action: str,
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            sio = client.app.state.socketio_server
            sid = f"legacy-{report_action}-sid"
            assert asyncio.run(
                sio.handlers["/"]["connect"](
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    {
                        "device_id": device["device_id"],
                        "device_token": device["device_token"],
                    },
                )
            ) is True

            emitted: list[tuple[str, str, str | None]] = []

            async def capture_emit(event: str, payload: str, to: str | None = None):
                emitted.append((event, payload, to))

            sio.emit = capture_emit
            response = client.post(
                f"/api/devices/{device['device_id']}/workbench-actions/{request_action}",
                headers=headers,
                json={"value": None, "payload": {}},
            )
            assert response.status_code == 202, response.text
            assert response.json()["data"] == {"status": "sent"}

            image_base64 = base64.b64encode(b"sensitive-jpeg-bytes").decode("ascii")
            report_data = {
                "img": image_base64,
                "deviceId": device["device_id"],
            }
            if report_action == "camPic":
                report_data.update({"w": 640, "h": 480})
            encrypted_ack = asyncio.run(
                sio.handlers["/"]["enc msg"](
                    sid,
                    encrypt_legacy_payload(
                        {
                            "action": report_action,
                            "type": "enc",
                            "data": report_data,
                        }
                    ),
                )
            )
            assert decrypt_legacy_payload(encrypted_ack, LEGACY_AES_KEY) == {
                "accepted": True,
                "device_id": device["device_id"],
                "action": report_action,
            }

            command = client.app.state.db.one(
                "SELECT status,result_json FROM commands WHERE device_id=? AND action=? "
                "ORDER BY queued_at DESC LIMIT 1",
                (device["device_id"], request_action),
            )
            assert command["status"] == "success"
            result = json.loads(command["result_json"])
            assert result["event"] == report_action
            assert result["image_url"] == f"data:image/jpeg;base64,{image_base64}"
            if report_action == "camPic":
                assert result["width"] == 640
                assert result["height"] == 480
            stored = client.app.state.db.one(
                "SELECT data_json FROM device_data_reports WHERE device_id=? "
                "AND action=? ORDER BY id DESC LIMIT 1",
                (device["device_id"], report_action),
            )
            assert json.loads(stored["data_json"]) == result
        temp.cleanup()


def test_uncorrelated_encrypted_socketio_icon_list_uses_device_and_action() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            sio = client.app.state.socketio_server
            sid = "legacy-icon-list-sid"
            assert asyncio.run(
                sio.handlers["/"]["connect"](
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    {
                        "device_id": device["device_id"],
                        "device_token": device["device_token"],
                    },
                )
            ) is True

            async def capture_emit(event: str, payload: object, to: str | None = None):
                return None

            sio.emit = capture_emit
            response = client.post(
                f"/api/devices/{device['device_id']}/workbench-actions/iconList",
                headers=headers,
                json={"value": None, "payload": {}},
            )
            assert response.status_code == 202, response.text
            assert response.json()["data"] == {"status": "sent"}

            applications = [{"pkg": "com.example.app", "name": "Example"}]
            encrypted_ack = asyncio.run(
                sio.handlers["/"]["enc msg"](
                    sid,
                    encrypt_legacy_payload(
                        {
                            "action": "iconList",
                            "type": "enc",
                            "data": {
                                "data": applications,
                                "fromAdmin": "admin",
                                "deviceId": device["device_id"],
                            },
                        }
                    ),
                )
            )
            assert decrypt_legacy_payload(encrypted_ack, LEGACY_AES_KEY) == {
                "accepted": True,
                "device_id": device["device_id"],
                "action": "iconList",
            }
            command = client.app.state.db.one(
                "SELECT status,result_json FROM commands WHERE device_id=? "
                "AND action='iconList' ORDER BY queued_at DESC LIMIT 1",
                (device["device_id"],),
            )
            assert command["status"] == "success"
            assert json.loads(command["result_json"]) == {
                "data": applications,
                "fromAdmin": "admin",
            }
            stored = client.app.state.db.one(
                "SELECT data_json FROM device_data_reports WHERE device_id=? "
                "AND action='iconList' ORDER BY id DESC LIMIT 1",
                (device["device_id"],),
            )
            assert json.loads(stored["data_json"]) == {
                "data": applications,
                "fromAdmin": "admin",
            }
        temp.cleanup()


@pytest.mark.parametrize(
    ("request_action", "request_payload", "report_action", "report_data", "expected"),
    [
        (
            "walletList",
            {},
            "walletList",
            {
                "data": [{"pkg": "com.example.wallet", "name": "Wallet"}],
                "fromAdmin": "admin",
            },
            {
                "data": [{"pkg": "com.example.wallet", "name": "Wallet"}],
                "fromAdmin": "admin",
            },
        ),
        (
            "reqPerList",
            {},
            "reqPerList",
            {
                "data": [
                    {"name": "android.permission.READ_SMS", "granted": True}
                ],
                "fromAdmin": "admin",
            },
            {
                "data": [
                    {"name": "android.permission.READ_SMS", "granted": True}
                ],
                "fromAdmin": "admin",
            },
        ),
        (
            "readAlbumList",
            {},
            "albumList",
            {
                "data": [
                    {
                        "id": 123,
                        "name": "名称.jpg",
                        "path": "/storage/emulated/0/DCIM/名称.jpg",
                        "date": 1760000000,
                        "size": 102400,
                    }
                ],
                "total": 100,
                "curpage": 1,
                "fromAdmin": "admin",
            },
            {
                "data": [
                    {
                        "id": 123,
                        "name": "名称.jpg",
                        "path": "/storage/emulated/0/DCIM/名称.jpg",
                        "date": 1760000000,
                        "size": 102400,
                    }
                ],
                "total": 100,
                "curpage": 1,
                "fromAdmin": "admin",
            },
        ),
        (
            "readAlbumLast",
            {"path": "/storage/emulated/0/DCIM/名称.jpg", "del": False},
            "albumLast",
            {
                "image": "aW1hZ2U=",
                "path": "/storage/emulated/0/DCIM/名称.jpg",
                "fromAdmin": "admin",
            },
            {
                "image": "aW1hZ2U=",
                "path": "/storage/emulated/0/DCIM/名称.jpg",
                "fromAdmin": "admin",
            },
        ),
        (
            "readAlbumThumbnail",
            {
                "fileList": [
                    {
                        "path": "/storage/emulated/0/DCIM/名称.jpg",
                        "fileMd5": "值",
                        "maxWidth": 200,
                    }
                ],
                "maxWidth": 200,
                "elem": "值",
            },
            "albumData",
            {
                "data": [
                    {
                        "path": "/storage/emulated/0/DCIM/名称.jpg",
                        "fileMd5": "值",
                        "base64": "aW1hZ2U=",
                        "maxWidth": 200,
                    }
                ],
                "elem": "值",
                "fromAdmin": "admin",
            },
            {
                "data": [
                    {
                        "path": "/storage/emulated/0/DCIM/名称.jpg",
                        "fileMd5": "值",
                        "base64": "aW1hZ2U=",
                        "maxWidth": 200,
                    }
                ],
                "elem": "值",
                "fromAdmin": "admin",
            },
        ),
        (
            "readContactList",
            {},
            "contactList",
            {
                "data": [{"name": "名称", "phones": ["号码"]}],
                "total": 100,
                "curpage": 0,
                "fromAdmin": "admin",
            },
            {
                "data": [{"name": "名称", "phones": ["号码"]}],
                "total": 100,
                "curpage": 0,
                "fromAdmin": "admin",
            },
        ),
    ],
)
def test_encrypted_private_data_results_are_validated_and_saved(
    request_action: str,
    request_payload: dict[str, object],
    report_action: str,
    report_data: dict[str, object],
    expected: dict[str, object],
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            sio = client.app.state.socketio_server
            sid = f"legacy-{report_action}-sid"
            assert asyncio.run(
                sio.handlers["/"]["connect"](
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    {
                        "device_id": device["device_id"],
                        "device_token": device["device_token"],
                    },
                )
            ) is True

            async def capture_emit(event: str, payload: object, to: str | None = None):
                return None

            sio.emit = capture_emit
            response = client.post(
                f"/api/devices/{device['device_id']}/workbench-actions/{request_action}",
                headers=headers,
                json={"value": None, "payload": request_payload},
            )
            assert response.status_code == 202, response.text

            encrypted_ack = asyncio.run(
                sio.handlers["/"]["enc msg"](
                    sid,
                    encrypt_legacy_payload(
                        {
                            "action": report_action,
                            "type": "enc",
                            "data": {
                                **report_data,
                                "deviceId": device["device_id"],
                            },
                        }
                    ),
                )
            )
            assert decrypt_legacy_payload(encrypted_ack, LEGACY_AES_KEY) == {
                "accepted": True,
                "device_id": device["device_id"],
                "action": report_action,
            }
            command = client.app.state.db.one(
                "SELECT status,result_json FROM commands WHERE device_id=? AND action=? "
                "ORDER BY queued_at DESC LIMIT 1",
                (device["device_id"], request_action),
            )
            assert command["status"] == "success"
            assert json.loads(command["result_json"]) == expected
            stored = client.app.state.db.one(
                "SELECT data_json FROM device_data_reports WHERE device_id=? "
                "AND action=? ORDER BY id DESC LIMIT 1",
                (device["device_id"], report_action),
            )
            assert json.loads(stored["data_json"]) == expected
        temp.cleanup()


def test_encrypted_socketio_sms_list_and_received_event() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            sio = client.app.state.socketio_server
            sid = "legacy-sms-sid"
            assert asyncio.run(
                sio.handlers["/"]["connect"](
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    {
                        "device_id": device["device_id"],
                        "device_token": device["device_token"],
                    },
                )
            ) is True

            async def capture_emit(event: str, payload: object, to: str | None = None):
                return None

            dashboard_events: list[dict[str, object]] = []

            async def capture_dashboard(
                event: dict[str, object], owner_user_id: str | None = None
            ):
                dashboard_events.append(event)

            sio.emit = capture_emit
            client.app.state.hub.broadcast_dashboard = capture_dashboard
            response = client.post(
                f"/api/devices/{device['device_id']}/workbench-actions/readSmsList",
                headers=headers,
                json={"value": None, "payload": {}},
            )
            assert response.status_code == 202, response.text
            assert response.json()["data"] == {"status": "sent"}

            messages = [
                {
                    "address": "号码",
                    "body": "内容",
                    "date": 1760000000000,
                    "type": 1,
                }
            ]
            list_ack = asyncio.run(
                sio.handlers["/"]["enc msg"](
                    sid,
                    encrypt_legacy_payload(
                        {
                            "action": "smsList",
                            "type": "enc",
                            "data": {
                                "data": messages,
                                "total": 100,
                                "curpage": 0,
                                "fromAdmin": "admin",
                                "deviceId": device["device_id"],
                            },
                        }
                    ),
                )
            )
            assert decrypt_legacy_payload(list_ack, LEGACY_AES_KEY) == {
                "accepted": True,
                "device_id": device["device_id"],
                "action": "smsList",
            }
            command = client.app.state.db.one(
                "SELECT status,result_json FROM commands WHERE device_id=? "
                "AND action='readSmsList' ORDER BY queued_at DESC LIMIT 1",
                (device["device_id"],),
            )
            assert command["status"] == "success"
            assert json.loads(command["result_json"]) == {
                "data": messages,
                "total": 100,
                "curpage": 0,
                "fromAdmin": "admin",
            }

            received_ack = asyncio.run(
                sio.handlers["/"]["enc msg"](
                    sid,
                    encrypt_legacy_payload(
                        {
                            "action": "smsReceived",
                            "type": "enc",
                            "data": {
                                "sender": "号码",
                                "body": "内容",
                                "timestamp": 1760000000000,
                            },
                        }
                    ),
                )
            )
            assert decrypt_legacy_payload(received_ack, LEGACY_AES_KEY) == {
                "accepted": True,
                "device_id": device["device_id"],
                "action": "smsReceived",
            }
            assert dashboard_events[-1] == {
                "type": "sms.received",
                "device_id": device["device_id"],
                "sms": {
                    "sender": "号码",
                    "body": "内容",
                    "timestamp": 1760000000000,
                },
            }
            stored = client.app.state.db.one(
                "SELECT data_json FROM device_data_reports WHERE device_id=? "
                "AND action='smsReceived' ORDER BY id DESC LIMIT 1",
                (device["device_id"],),
            )
            assert json.loads(stored["data_json"]) == {
                "sender": "号码",
                "body": "内容",
                "timestamp": 1760000000000,
            }
        temp.cleanup()


def test_named_android_self_reports_support_plain_and_encrypted_payloads() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            device_headers = {
                "X-Device-Id": device["device_id"],
                "X-Device-Token": device["device_token"],
            }
            ticket = client.post(
                "/api/device/ws-ticket", headers=device_headers
            ).json()["data"]["ticket"]
            image_base64 = base64.b64encode(b"test-jpeg-bytes").decode("ascii")

            with client.websocket_connect(f"/ws/device?ticket={ticket}") as device_ws:
                assert device_ws.receive_json()["type"] == "server.hello"

                plain_response = client.post(
                    f"/api/devices/{device['device_id']}/workbench-actions/camera",
                    headers=headers,
                    json={"value": None, "payload": {}},
                )
                plain_command_id = plain_response.json()["data"]["command_id"]
                assert device_ws.receive_json()["correlation_id"] == plain_command_id
                device_ws.send_json(
                    {
                        "type": "screenshot",
                        "message_id": str(uuid.uuid4()),
                        "correlation_id": plain_command_id,
                        "payload": {"base64": image_base64},
                    }
                )

                encrypted_response = client.post(
                    f"/api/devices/{device['device_id']}/workbench-actions/camera",
                    headers=headers,
                    json={"value": None, "payload": {}},
                )
                encrypted_command_id = encrypted_response.json()["data"]["command_id"]
                assert device_ws.receive_json()["correlation_id"] == encrypted_command_id
                device_ws.send_json(
                    {
                        "type": "adbScreenshot",
                        "message_id": str(uuid.uuid4()),
                        "payload": {
                            "ciphertext": encrypt_legacy_payload(
                                {
                                    "command_id": encrypted_command_id,
                                    "base64": image_base64,
                                }
                            )
                        },
                    }
                )

                heartbeat_id = str(uuid.uuid4())
                device_ws.send_json(
                    {
                        "type": "device.heartbeat",
                        "message_id": heartbeat_id,
                        "payload": {},
                    }
                )
                assert device_ws.receive_json()["correlation_id"] == heartbeat_id

                for command_id, event_name in (
                    (plain_command_id, "screenshot"),
                    (encrypted_command_id, "adbScreenshot"),
                ):
                    command = client.get(
                        f"/api/commands/{command_id}", headers=headers
                    ).json()["data"]
                    assert command["status"] == "success"
                    assert command["result"] == {
                        "event": event_name,
                        "image_url": f"data:image/jpeg;base64,{image_base64}",
                    }

            sio = client.app.state.socketio_server
            connect_handler = sio.handlers["/"]["connect"]
            report_handler = sio.handlers["/"]["relayStatus"]
            sid = "legacy-report-sid"
            assert asyncio.run(
                connect_handler(
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    {
                        "device_id": device["device_id"],
                        "device_token": device["device_token"],
                    },
                )
            ) is True

            relay_command_id = str(uuid.uuid4())
            owner_id = client.get("/api/me", headers=headers).json()["data"]["id"]
            now = utc_now()
            client.app.state.db.execute(
                "INSERT INTO commands(id,device_id,operator_id,action,payload_json,status,queued_at,sent_at) "
                "VALUES(?,?,?,?,?,'sent',?,?)",
                (
                    relay_command_id,
                    device["device_id"],
                    owner_id,
                    "relay-status-test",
                    "{}",
                    now,
                    now,
                ),
            )
            encrypted_report = encrypt_legacy_payload(
                {
                    "command_id": relay_command_id,
                    "result": {"connected": True},
                }
            )
            encrypted_ack = asyncio.run(report_handler(sid, encrypted_report))
            assert decrypt_legacy_payload(encrypted_ack, LEGACY_AES_KEY) == {
                "accepted": True,
                "device_id": device["device_id"],
                "correlation_id": relay_command_id,
            }
            relay_command = client.get(
                f"/api/commands/{relay_command_id}", headers=headers
            ).json()["data"]
            assert relay_command["status"] == "success"
            assert relay_command["result"] == {"connected": True}
        temp.cleanup()


def test_encrypted_command_results_are_saved_for_workbench_modules() -> None:
    modules = (
        "messages",
        "apps",
        "system",
        "permissions",
        "gallery",
        "contacts",
        "files",
        "clipboard",
    )
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            device_headers = {
                "X-Device-Id": device["device_id"],
                "X-Device-Token": device["device_token"],
            }
            ticket = client.post(
                "/api/device/ws-ticket", headers=device_headers
            ).json()["data"]["ticket"]
            expected_results: dict[str, dict[str, object]] = {}

            with client.websocket_connect(f"/ws/device?ticket={ticket}") as device_ws:
                assert device_ws.receive_json()["type"] == "server.hello"
                for module in modules:
                    response = client.post(
                        f"/api/devices/{device['device_id']}/workbench/{module}/request",
                        headers=headers,
                    )
                    assert response.status_code == 202, response.text
                    command_id = response.json()["data"]["command_id"]
                    assert device_ws.receive_json()["correlation_id"] == command_id
                    result = {"items": [{"source": "android", "module": module}]}
                    expected_results[module] = result
                    device_ws.send_json(
                        {
                            "type": "command.result",
                            "message_id": str(uuid.uuid4()),
                            "payload": {
                                "enc": encrypt_legacy_payload(
                                    {
                                        "command_id": command_id,
                                        "payload": {
                                            "success": True,
                                            "result": result,
                                        },
                                    }
                                )
                            },
                        }
                    )

                heartbeat_id = str(uuid.uuid4())
                device_ws.send_json(
                    {
                        "type": "device.heartbeat",
                        "message_id": heartbeat_id,
                        "payload": {},
                    }
                )
                assert device_ws.receive_json()["correlation_id"] == heartbeat_id

            for module in modules:
                reported = client.get(
                    f"/api/devices/{device['device_id']}/workbench/{module}",
                    headers=headers,
                )
                assert reported.status_code == 200, reported.text
                assert reported.json()["data"]["source"] == "android_self_reported"
                assert reported.json()["data"]["data"] == expected_results[module]
        temp.cleanup()


def test_log_idempotency_action_allowlist_and_disabled_lock() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            device_headers = {
                "X-Device-Id": device["device_id"],
                "X-Device-Token": device["device_token"],
            }
            event = {
                "event_uid": str(uuid.uuid4()),
                "level": "info",
                "category": "connection",
                "event": "test",
                "message": "safe test event",
                "details": {},
            }
            first = client.post("/api/device/logs", headers=device_headers, json=event)
            second = client.post("/api/device/logs", headers=device_headers, json=event)
            assert first.status_code == 202
            assert first.json()["data"]["duplicate"] is False
            assert second.status_code == 200
            assert second.json()["data"]["duplicate"] is True

            unsafe = client.post(
                "/api/command",
                headers=headers,
                json={
                    "device_id": device["device_id"],
                    "action": "read_private_messages",
                    "payload": {},
                },
            )
            assert unsafe.status_code == 422

            reauth = client.post(
                "/api/auth/reauth", headers=headers, json={"password": ADMIN_PASSWORD}
            )
            assert reauth.status_code == 200
            disabled_lock = client.post(
                "/api/command",
                headers=headers,
                json={
                    "device_id": device["device_id"],
                    "action": "lock_device",
                    "payload": {},
                },
            )
            assert disabled_lock.status_code == 403
        temp.cleanup()


def test_ws_ticket_is_single_use() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            ticket = client.post("/api/ws-ticket", headers=headers).json()["data"]["ticket"]
            with client.websocket_connect(f"/ws/dashboard?ticket={ticket}") as websocket:
                assert websocket.receive_json()["type"] == "server.hello"
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect(f"/ws/dashboard?ticket={ticket}"):
                    pass
        temp.cleanup()


def test_admin_frontend_and_capability_catalog() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            root = client.get("/", follow_redirects=False)
            assert root.status_code == 307
            assert root.headers["location"] == "/admin/"

            frontend = client.get("/admin/")
            assert frontend.status_code == 200
            assert "登录管理后台" in frontend.text
            assert "设备入网" not in frontend.text
            assert "版本发布" not in frontend.text
            assert 'data-view="commands"' in frontend.text
            assert 'data-view="configuration"' in frontend.text
            assert 'data-view="system"' in frontend.text
            assert 'data-view="builds"' in frontend.text
            assert "管理员列表" in frontend.text
            assert "桌面图标自动隐藏" in frontend.text
            assert "功能清单" in frontend.text
            assert client.get("/admin/styles.css").status_code == 200
            assert client.get("/admin/app.js").status_code == 200

            _, headers = login(client)
            capabilities = client.get("/api/capabilities", headers=headers)
            assert capabilities.status_code == 200
            data = capabilities.json()["data"]
            assert data["summary"] == {
                "implemented": 21,
                "not_implemented": 1,
                "unavailable": 0,
            }
            messages = next(item for item in data["items"] if item["name"] == "短信")
            assert messages["send_to_android"]["payload.action"] == "read-messages"
            assert messages["send_to_android"]["payload.parameters"] == {}
            assert messages["receive_from_android"]["ack"]["fields"] == [
                "message_id",
                "correlation_id",
                "payload",
            ]
            assert "payload.result" in messages["receive_from_android"]["result"]["fields"]
            assert messages["receive_from_android"]["payload.result fields"] == {
                "items[]": [
                    "id", "address", "direction", "body", "timestamp", "read", "slot"
                ]
            }
        temp.cleanup()


def test_material_workbench_messages_modules_and_reserved_build_routes() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)

            build_profiles = client.get("/api/build-profiles", headers=headers)
            assert build_profiles.status_code == 501
            assert build_profiles.json()["detail"]["code"] == "RESERVED_NOT_IMPLEMENTED"

            workbench = client.get(
                f"/api/devices/{device['device_id']}/workbench/apps",
                headers=headers,
            )
            assert workbench.status_code == 200
            assert workbench.json()["data"]["source"] == "no_report"
            assert workbench.json()["data"]["data"] is None

            device_headers = {
                "X-Device-Id": device["device_id"],
                "X-Device-Token": device["device_token"],
            }
            device_ticket = client.post(
                "/api/device/ws-ticket", headers=device_headers
            ).json()["data"]["ticket"]
            cases = [
                ("verify-unlock", None, {}, {}),
                ("translate", None, {}, {}),
                (
                    "lock-screen",
                    True,
                    {},
                    {"enabled": True},
                ),
                (
                    "uninstall-protection",
                    False,
                    {},
                    {"enabled": False},
                ),
                (
                    "launcher-icon",
                    True,
                    {},
                    {"enabled": True},
                ),
                ("power-menu", None, {}, {}),
                ("camera", None, {}, {}),
                ("open-app", None, {"package_name": "com.example.one"}, {"package_name": "com.example.one"}),
                ("uninstall-app", None, {"package_name": "com.example.two"}, {"package_name": "com.example.two"}),
                (
                    "overlay-mode",
                    "纯黑色",
                    {},
                    {"mode": "纯黑色"},
                ),
                ("clear-clipboard", None, {}, {}),
                ("write-clipboard", None, {"text": "virtual text"}, {"text": "virtual text"}),
            ]

            with client.websocket_connect(f"/ws/device?ticket={device_ticket}") as device_ws:
                assert device_ws.receive_json()["type"] == "server.hello"
                first_command_id = None
                for action, value, payload, expected_parameters in cases:
                    response = client.post(
                        f"/api/devices/{device['device_id']}/workbench-actions/{action}",
                        headers=headers,
                        json={"value": value, "payload": payload},
                    )
                    assert response.status_code == 202, response.text
                    command_id = response.json()["data"]["command_id"]
                    first_command_id = first_command_id or command_id
                    dispatched = device_ws.receive_json()
                    assert dispatched["correlation_id"] == command_id
                    assert dispatched["payload"] == {
                        "action": action,
                        "parameters": expected_parameters,
                    }

                module_actions = {
                    "messages": "read-messages",
                    "apps": "read-apps",
                    "system": "read-system",
                    "permissions": "read-permissions",
                    "gallery": "read-gallery",
                    "contacts": "read-contacts",
                    "files": "read-files",
                    "clipboard": "read-clipboard",
                    "input-events": "read-input-events",
                    "credential-events": "read-credential-events",
                    "camera": "read-camera-data",
                }
                contact_command_id = None
                for module, wire_action in module_actions.items():
                    response = client.post(
                        f"/api/devices/{device['device_id']}/workbench/{module}/request",
                        headers=headers,
                    )
                    assert response.status_code == 202, response.text
                    command_id = response.json()["data"]["command_id"]
                    if module == "contacts":
                        contact_command_id = command_id
                    dispatched = device_ws.receive_json()
                    assert dispatched["correlation_id"] == command_id
                    assert dispatched["payload"] == {
                        "action": wire_action,
                        "parameters": {},
                    }

                assert first_command_id is not None
                assert contact_command_id is not None
                contact_data = {
                    "items": [
                        {
                            "id": "android-demo-contact-1",
                            "name": "Android 虚拟联系人",
                            "phone": "+1 202-555-0199",
                        }
                    ]
                }
                device_ws.send_json(
                    {
                        "type": "command.ack",
                        "message_id": str(uuid.uuid4()),
                        "correlation_id": contact_command_id,
                        "payload": {},
                    }
                )
                device_ws.send_json(
                    {
                        "type": "command.result",
                        "message_id": str(uuid.uuid4()),
                        "correlation_id": contact_command_id,
                        "payload": {"success": True, "result": contact_data},
                    }
                )
                device_ws.send_json(
                    {
                        "type": "command.ack",
                        "message_id": str(uuid.uuid4()),
                        "correlation_id": first_command_id,
                        "payload": {},
                    }
                )
                device_ws.send_json(
                    {
                        "type": "command.result",
                        "message_id": str(uuid.uuid4()),
                        "correlation_id": first_command_id,
                        "payload": {
                            "success": True,
                            "result": {"reported_by_android": "completed"},
                        },
                    }
                )
                heartbeat_id = str(uuid.uuid4())
                device_ws.send_json(
                    {
                        "type": "device.heartbeat",
                        "message_id": heartbeat_id,
                        "payload": {},
                    }
                )
                assert device_ws.receive_json()["correlation_id"] == heartbeat_id

                command = client.get(
                    f"/api/commands/{first_command_id}", headers=headers
                ).json()["data"]
                assert command["status"] == "success"
                assert command["result"] == {"reported_by_android": "completed"}

                contacts = client.get(
                    f"/api/devices/{device['device_id']}/workbench/contacts",
                    headers=headers,
                )
                assert contacts.status_code == 200
                assert contacts.json()["data"]["source"] == "android_self_reported"
                assert contacts.json()["data"]["data"] == contact_data

                custom_payload = client.post(
                    f"/api/devices/{device['device_id']}/workbench-actions/screenshot",
                    headers=headers,
                    json={"value": None, "payload": {"script": "anything"}},
                )
                assert custom_payload.status_code == 400
        temp.cleanup()


def test_user_group_battery_command_and_template_management() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            assert client.post(
                "/api/auth/reauth", headers=headers, json={"password": ADMIN_PASSWORD}
            ).status_code == 200

            roles = client.get("/api/roles", headers=headers)
            assert roles.status_code == 200
            assert {item["id"] for item in roles.json()["data"]} == {
                "admin",
                "operator",
                "viewer",
            }
            created_user = client.post(
                "/api/users",
                headers=headers,
                json={
                    "username": "operator.one",
                    "password": "operator-password-123",
                    "role": "operator",
                },
            )
            assert created_user.status_code == 201, created_user.text
            user_id = created_user.json()["data"]["id"]
            assert client.get("/api/users", headers=headers).json()["meta"]["total"] == 2
            updated_user = client.patch(
                f"/api/users/{user_id}",
                headers=headers,
                json={"status": "disabled"},
            )
            assert updated_user.status_code == 200
            assert updated_user.json()["data"]["status"] == "disabled"

            group_response = client.post(
                "/api/device-groups",
                headers=headers,
                json={"name": "测试组", "description": "授权测试设备"},
            )
            assert group_response.status_code == 201, group_response.text
            group_id = group_response.json()["data"]["id"]

            device = provision_device(client, headers)
            patched_device = client.patch(
                f"/api/devices/{device['device_id']}",
                headers=headers,
                json={"group_id": group_id, "note": "机房测试手机"},
            )
            assert patched_device.status_code == 200, patched_device.text
            listed_device = client.get(
                "/api/devices?q=测试组", headers=headers
            ).json()["data"][0]
            assert listed_device["group_name"] == "测试组"
            assert listed_device["note"] == "机房测试手机"

            assert client.patch(
                f"/api/users/{user_id}", headers=headers, json={"status": "active"}
            ).status_code == 200
            changed_owner = client.patch(
                f"/api/devices/{device['device_id']}",
                headers=headers,
                json={"owner_user_id": user_id},
            )
            assert changed_owner.status_code == 200, changed_owner.text
            moved_device = client.get(
                f"/api/devices/{device['device_id']}", headers=headers
            ).json()["data"]
            assert moved_device["owner_user_id"] == user_id
            assert moved_device["group_id"] is None

            generic_guide = client.get(
                "/api/battery-config?brand=Example&model=Model%20A"
            )
            assert generic_guide.status_code == 200
            assert generic_guide.json()["data"]["brand"] == "*"
            custom_guide = client.post(
                "/api/battery-guides",
                headers=headers,
                json={
                    "brand": "Example",
                    "model_pattern": "Model*",
                    "title": "Example设置",
                    "steps": ["打开设置", "由用户确认"],
                    "enabled": True,
                },
            )
            assert custom_guide.status_code == 201, custom_guide.text
            matched_guide = client.get(
                "/api/battery-config?brand=Example&model=Model%20A"
            ).json()["data"]
            assert matched_guide["title"] == "Example设置"

            template = client.post(
                "/api/message-templates",
                headers=headers,
                json={
                    "name": "网络检查",
                    "content": "请打开应用并检查当前网络连接。",
                    "enabled": True,
                },
            )
            assert template.status_code == 201, template.text
            template_id = template.json()["data"]["id"]
            templates = client.get("/api/message-templates", headers=headers)
            assert templates.status_code == 200
            assert templates.json()["data"][0]["content"] == "请打开应用并检查当前网络连接。"
            disabled_template = client.patch(
                f"/api/message-templates/{template_id}",
                headers=headers,
                json={"enabled": False},
            )
            assert disabled_template.status_code == 200
            assert disabled_template.json()["data"]["enabled"] == 0

            offline_command = client.post(
                "/api/command",
                headers=headers,
                json={
                    "device_id": device["device_id"],
                    "action": "refresh_status",
                    "payload": {},
                },
            )
            assert offline_command.status_code == 409
            command_history = client.get(
                "/api/commands?status=failed", headers=headers
            )
            assert command_history.status_code == 200
            assert command_history.json()["meta"]["total"] == 1
            assert command_history.json()["data"][0]["error_code"] == "DEVICE_OFFLINE"

        temp.cleanup()


def test_consent_screen_session_binary_relay() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            assert client.post(
                "/api/auth/reauth", headers=headers, json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            device = provision_device(client, headers)
            device_headers = {
                "X-Device-Id": device["device_id"],
                "X-Device-Token": device["device_token"],
            }
            device_ticket = client.post(
                "/api/device/ws-ticket", headers=device_headers
            ).json()["data"]["ticket"]

            with client.websocket_connect(f"/ws/device?ticket={device_ticket}") as device_ws:
                assert device_ws.receive_json()["type"] == "server.hello"
                screen_response = client.post(
                    "/api/screen-sessions",
                    headers=headers,
                    json={"device_id": device["device_id"]},
                )
                assert screen_response.status_code == 201, screen_response.text
                screen = screen_response.json()["data"]
                dispatched = device_ws.receive_json()
                assert dispatched["payload"]["action"] == "request_screen_share"
                parameters = dispatched["payload"]["parameters"]
                assert parameters["consent_required"] is True
                assert parameters["session_id"] == screen["id"]

                with client.websocket_connect(
                    f"/ws/screen?ticket={screen['browser_ticket']}"
                ) as browser_ws:
                    browser_hello = browser_ws.receive_json()
                    assert browser_hello["payload"]["role"] == "browser"
                    with client.websocket_connect(
                        f"/ws/screen?ticket={parameters['device_media_ticket']}"
                    ) as media_ws:
                        media_hello = media_ws.receive_json()
                        assert media_hello["payload"]["role"] == "device"
                        frame = b"\xff\xd8authorized-test-jpeg\xff\xd9"
                        media_ws.send_bytes(frame)
                        assert browser_ws.receive_bytes() == frame

                detail = client.get(
                    f"/api/screen-sessions/{screen['id']}", headers=headers
                )
                assert detail.status_code == 200
                assert detail.json()["data"]["status"] == "stopped"
        temp.cleanup()


def test_all_remaining_legacy_commands_are_encrypted_and_saved() -> None:
    required_payloads: dict[str, dict[str, object]] = {
        "lockAdvance": {"type": "PIN", "title": "内容", "subtitle": "内容"},
        "setWakeup": {"enable": True},
        "clickPoint": {"x": 100, "y": 200},
        "touchDown": {"x": 100, "y": 200},
        "down": {"x": 100, "y": 200},
        "touchMove": {"x": 120, "y": 220},
        "move": {"x": 120, "y": 220},
        "clickB": {"bounds": {"left": 0, "top": 0, "right": 200, "bottom": 100}},
        "clickInput": {"bounds": {"left": 0, "top": 0, "right": 200, "bottom": 100}},
        "gestureB": {
            "gesture": [
                {"x": 100, "y": 200, "t": 0, "flag": 1},
                {"x": 300, "y": 400, "t": 500},
            ]
        },
        "gestureUnlock": {
            "points": [
                {"x": 100, "y": 200, "t": 0},
                {"x": 300, "y": 400, "t": 500},
            ]
        },
        "setSoundVibrate": {"on": True},
        "dnd": {"dnd": True},
        "doNotDisturb": {"dnd": True},
        "fetchIcon": {"pkg": "com.example.app"},
        "init_data": {
            "selfPkg": "pkg",
            "homepage": "home",
            "prepage": "pre",
            "accpage": "acc",
            "waitpage": "wait",
        },
        "setDomain": {"domain": "example.com"},
        "catAllViewSwitch": {
            "enable": True,
            "screenRule": [{"pkg": "pkg", "act": "Main"}],
            "rexp": "value",
            "pkgs": "pkg",
            "refuse": "value",
            "idSearch": "value",
            "imeChar": "value",
            "domain": "example.com",
        },
        "updatePageRule": {
            "screenRule": [{"pkg": "pkg", "used": True}],
            "financePackages": ["pkg"],
        },
        "sendAlert": {
            "title": "title",
            "content": "content",
            "okText": "ok",
            "openpkg": "pkg",
        },
        "openIntent": {"map": {"action": "view", "uri": "value", "pkg": "pkg", "cls": "Main"}},
        "openUrl": {"url": "https://example.com"},
        "setDebugMode": {"debug": True},
        "setHideMode": {"hide": True},
        "setDisConnect": {"disconn": True},
        "logMode": {"mode": True},
        "installApk": {"url": "https://example.com/app.apk", "fileMd5": "abc"},
        "updateApk": {"url": "https://example.com/app.apk", "fileMd5": "abc"},
        "admPwd": {"pwd": "value"},
        "permission": {"type": "overlay"},
        "permissionB": {"type": "battery"},
        "realtimeSet": {"interval": 5000},
        "realtimeOnOff": {"on": True},
        "webrtcOffer": {"sdp": "value"},
        "webrtcIce": {"candidate": "value", "sdpMLineIndex": 0, "sdpMid": "0"},
        "hideMyMainActivity": {"iconAlias": "N", "show": False},
        "openWebHarvester": {"url": "https://example.com"},
        "addPinTargets": {"keywords": ["value"], "packages": ["pkg"]},
        "touchPinReplay": {"touches": "value", "pkg": "pkg"},
        "manualPair": {"code": "123456", "port": 12345},
        "adbShell": {"cmd": "id"},
        "adbClick": {"x": 100, "y": 200},
        "adbSwipe": {"x1": 100, "y1": 200, "x2": 300, "y2": 400, "duration": 300},
        "adbKeyEvent": {"key": "HOME"},
    }

    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            sio = client.app.state.socketio_server
            sid = "remaining-actions-sid"
            assert asyncio.run(
                sio.handlers["/"]["connect"](
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    {
                        "device_id": device["device_id"],
                        "device_token": device["device_token"],
                    },
                )
            ) is True
            emitted: list[tuple[str, str, str | None]] = []

            async def capture_emit(event: str, payload: str, to: str | None = None):
                emitted.append((event, payload, to))

            sio.emit = capture_emit
            for action in sorted(LEGACY_REMAINING_ACTIONS):
                request_payload = required_payloads.get(action, {})
                response = client.post(
                    f"/api/devices/{device['device_id']}/workbench-actions/{action}",
                    headers=headers,
                    json={"value": None, "payload": request_payload},
                )
                assert response.status_code == 202, (action, response.text)
                event, ciphertext, target_sid = emitted[-1]
                expected_data = LEGACY_REMAINING_FIXED_DATA.get(action, request_payload)
                if action == "fetchIcon":
                    expected_data = {**request_payload, "fromAdmin": "admin"}
                assert event == "new_msg"
                assert target_sid == sid
                assert decrypt_legacy_payload(ciphertext, LEGACY_AES_KEY) == {
                    "action": action,
                    "data": expected_data,
                }

            commands = client.app.state.db.all(
                "SELECT action,payload_json,status FROM commands WHERE device_id=?",
                (device["device_id"],),
            )
            assert {row["action"] for row in commands} == LEGACY_REMAINING_ACTIONS
            assert all(row["status"] == "sent" for row in commands)
            expected_state = client.app.state.db.one(
                "SELECT state_json FROM device_expected_state WHERE device_id=?",
                (device["device_id"],),
            )
            state = json.loads(expected_state["state_json"])
            assert state["touch"] == "on"
            assert state["wakeupEnabled"] is True
            assert state["uiTreePaused"] is False
            assert state["accessibility"] is True
            sessions = client.app.state.db.all(
                "SELECT stream_type,status FROM device_stream_sessions WHERE device_id=?",
                (device["device_id"],),
            )
            assert {row["stream_type"] for row in sessions} == {
                "screen_relay",
                "silent_stream",
                "silent_shot",
                "hd_stream",
                "adb_stream",
                "adb_tree",
                "webrtc",
            }
        temp.cleanup()


def test_remaining_active_events_and_diagnostics_are_saved() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            sio = client.app.state.socketio_server
            sid = "remaining-events-sid"
            asyncio.run(
                sio.handlers["/"]["connect"](
                    sid,
                    {"asgi.scope": {"query_string": b"", "headers": []}},
                    {
                        "device_id": device["device_id"],
                        "device_token": device["device_token"],
                    },
                )
            )
            assert asyncio.run(sio.handlers["/"]["login"](sid, device["device_id"]))[
                "accepted"
            ] is True

            active_events = {
                "fcmToken": {"fcmToken": "fcm-token-value"},
                "notification": {
                    "pkg": "pkg",
                    "title": "title",
                    "text": "text",
                    "bigText": "big",
                    "subText": "sub",
                    "timestamp": 1760000000000,
                },
                "formData": {"data": "content"},
                "amountAlert": {
                    "amountType": "balance",
                    "amount": 100.0,
                    "currency": "USD",
                    "rawText": "raw",
                    "contextText": "context",
                    "pkg": "pkg",
                    "appName": "name",
                },
                "touchPinData": {
                    "deviceId": device["device_id"],
                    "pkg": "pkg",
                    "touches": "content",
                    "touchCount": 4,
                    "duration": 1200,
                    "timestamp": 1760000000000,
                    "resolved": "content",
                },
                "capture": {
                    "deviceId": device["device_id"],
                    "pkg": "capture",
                    "ac": "Main",
                    "w": 1080,
                    "h": 2400,
                    "iw": 0,
                    "ih": 0,
                    "orient": False,
                    "deviceInfo": {},
                    "action": None,
                    "zip": "content",
                },
                "cacheData": {
                    "deviceId": device["device_id"],
                    "k": "key",
                    "cache": {"value": 1},
                },
            }
            for action, data in active_events.items():
                result = asyncio.run(
                    sio.handlers["/"]["enc msg"](
                        sid,
                        encrypt_legacy_payload(
                            {"action": action, "type": "enc", "data": data}
                        ),
                    )
                )
                assert result is None

            diagnostics = {
                "conn": "binary_ws_connected",
                "biometric_lock": "ENABLED",
                "anti_uninstall": "BLOCKED|path=value|pkg=pkg|cls=Main",
                "acc_recovery": "RESTORED|downtime_sec=12",
                "acc_jumper": "content",
                "battery_grant": "CHECK|brand=Brand",
                "captcha": "OCR_RESULT|content",
                "pin_verify": "PIN_CONFIRMED_CORRECT",
            }
            for offset, (diagnostic_type, message) in enumerate(diagnostics.items()):
                result = asyncio.run(
                    sio.handlers["/"]["enc msg"](
                        sid,
                        encrypt_legacy_payload(
                            {
                                "action": "diag",
                                "type": "enc",
                                "data": {
                                    "type": diagnostic_type,
                                    "message": message,
                                    "ts": 1760000000100 + offset,
                                    "deviceId": device["device_id"],
                                },
                            }
                        ),
                    )
                )
                assert result is None

            saved_device = client.app.state.db.one(
                "SELECT fcm_token,socket_id FROM devices WHERE id=?",
                (device["device_id"],),
            )
            assert saved_device["fcm_token"] == "fcm-token-value"
            assert saved_device["socket_id"] == sid
            cached = client.app.state.db.one(
                "SELECT cache_json FROM device_cache WHERE device_id=? AND cache_key='key'",
                (device["device_id"],),
            )
            assert json.loads(cached["cache_json"]) == {"value": 1}
            runtime = json.loads(
                client.app.state.db.one(
                    "SELECT state_json FROM device_runtime_state WHERE device_id=?",
                    (device["device_id"],),
                )["state_json"]
            )
            assert runtime["biometricLock"] is True
            assert runtime["binaryOnline"] is True
            assert runtime["accessibilityDowntimeSec"] == 12
            assert runtime["batteryGrantBrand"] == "Brand"
            assert runtime["captchaStage"] == "OCR_RESULT"
            assert runtime["pinVerifyStatus"] == "PIN_CONFIRMED_CORRECT"
            reports = client.app.state.db.all(
                "SELECT action FROM device_data_reports WHERE device_id=?",
                (device["device_id"],),
            )
            report_actions = {row["action"] for row in reports}
            assert set(active_events).issubset(report_actions)
            assert {f"diag/{value}" for value in diagnostics}.issubset(report_actions)
        temp.cleanup()


def test_binary_channel_frames_commands_and_php_compatibility_routes() -> None:
    def frame(frame_type: int, payload: bytes) -> bytes:
        return bytes([frame_type]) + len(payload).to_bytes(4, "big") + payload

    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            device = provision_device(client, headers)
            hello = json.dumps(
                {"deviceId": device["device_id"], "apkId": 10025}
            ).encode()
            tree = {
                "deviceId": device["device_id"],
                "pkg": "capture",
                "ac": "Main",
                "w": 1080,
                "h": 2400,
                "iw": 0,
                "ih": 0,
                "orient": False,
                "zip": "content",
            }
            tree_bytes = json.dumps(tree).encode()
            with client.websocket_connect("/ws/binary") as websocket:
                websocket.send_bytes(frame(0x30, hello))
                response = client.post(
                    f"/api/devices/{device['device_id']}/binary-actions/screen_relay",
                    headers=headers,
                    json={"value": None, "payload": {}},
                )
                assert response.status_code == 202, response.text
                outbound = websocket.receive_bytes()
                assert outbound[0] == 0x10
                size = int.from_bytes(outbound[1:5], "big")
                assert size == len(outbound[5:])
                assert json.loads(outbound[5:]) == {
                    "action": "screen_relay",
                    "data": {"quality": 30, "scale": 50},
                }
                websocket.send_bytes(frame(0x01, b"jpeg-frame"))
                websocket.send_bytes(frame(0x02, tree_bytes))
                websocket.send_bytes(frame(0x04, b"jpeg-thumbnail"))
                websocket.send_bytes(frame(0x07, json.dumps({"tree": "value"}).encode()))

            frames = client.app.state.db.all(
                "SELECT frame_type,sequence_no,payload FROM device_binary_frames "
                "WHERE device_id=? ORDER BY sequence_no",
                (device["device_id"],),
            )
            assert [row["frame_type"] for row in frames] == [0x01, 0x02, 0x04, 0x07]
            assert [row["sequence_no"] for row in frames] == [1, 2, 3, 4]
            runtime = json.loads(
                client.app.state.db.one(
                    "SELECT state_json FROM device_runtime_state WHERE device_id=?",
                    (device["device_id"],),
                )["state_json"]
            )
            assert runtime["binaryOnline"] is False
            assert runtime["latestCapture"]["pkg"] == "capture"
            assert runtime["latestBinaryFrameSize"] == len(b"jpeg-frame")
            assert runtime["latestBinaryThumbnailSize"] == len(b"jpeg-thumbnail")

            adv = client.get(
                "/adv.php",
                params={"apk": "10025", "device": device["device_id"]},
            )
            assert adv.status_code == 200, adv.text
            config = decrypt_legacy_payload(adv.json()["token"], LEGACY_AES_KEY)
            assert config["deviceId"] == device["device_id"]
            assert config["apk"] == "10025"
            install = client.post(
                "/install_stat.php",
                params={
                    "app_name": "8iaLvsouUje7",
                    "action": "update",
                    "device_uid": f"Model_dev_{device['device_id']}",
                },
            )
            assert install.status_code == 204
            stat = client.app.state.db.one(
                "SELECT app_name,action,device_uid FROM install_stats ORDER BY id DESC LIMIT 1"
            )
            assert stat == {
                "app_name": "8iaLvsouUje7",
                "action": "update",
                "device_uid": f"Model_dev_{device['device_id']}",
            }
        temp.cleanup()


def test_completed_admin_crud_and_system_status() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp) as client:
            _, headers = login(client)
            assert client.post(
                "/api/auth/reauth", headers=headers, json={"password": ADMIN_PASSWORD}
            ).status_code == 200

            created_user = client.post(
                "/api/users",
                headers=headers,
                json={
                    "username": "managed.user",
                    "password": "managed-user-password",
                    "role": "operator",
                    "status": "disabled",
                    "ip_whitelist": "127.0.0.1, 10.0.0.0/8",
                    "note": "后台维护账号",
                    "totp_secret": "JBSWY3DPEHPK3PXP",
                },
            )
            assert created_user.status_code == 201, created_user.text
            user_id = created_user.json()["data"]["id"]
            users = client.get("/api/users", headers=headers).json()
            account = next(item for item in users["data"] if item["id"] == user_id)
            assert account["status"] == "disabled"
            assert account["ip_whitelist"] == "127.0.0.1/32\n10.0.0.0/8"
            assert account["note"] == "后台维护账号"
            assert account["totp_enabled"] == 1
            assert "totp_secret" not in account
            options = client.get("/api/user-options", headers=headers)
            assert options.status_code == 200
            assert any(item["id"] == user_id for item in options.json()["data"])

            updated_user = client.patch(
                f"/api/users/{user_id}",
                headers=headers,
                json={"status": "active", "note": "已更新", "clear_totp": True},
            )
            assert updated_user.status_code == 200, updated_user.text
            assert updated_user.json()["data"]["totp_enabled"] == 0

            group = client.post(
                "/api/device-groups",
                headers=headers,
                json={"name": "待删除组", "description": "完整 CRUD"},
            ).json()["data"]
            assert client.patch(
                f"/api/device-groups/{group['id']}",
                headers=headers,
                json={"name": "已编辑组"},
            ).status_code == 200
            assert client.delete(
                f"/api/device-groups/{group['id']}", headers=headers
            ).status_code == 200

            guide = client.post(
                "/api/battery-guides",
                headers=headers,
                json={
                    "brand": "CrudBrand",
                    "model_pattern": "*",
                    "title": "CRUD 设置",
                    "steps": ["第一步"],
                    "enabled": True,
                },
            ).json()["data"]
            assert client.delete(
                f"/api/battery-guides/{guide['id']}", headers=headers
            ).status_code == 200

            template = client.post(
                "/api/message-templates",
                headers=headers,
                json={"name": "待删除模板", "content": "显示内容", "enabled": True},
            ).json()["data"]
            assert client.delete(
                f"/api/message-templates/{template['id']}", headers=headers
            ).status_code == 200

            system = client.get("/api/system/status", headers=headers)
            assert system.status_code == 200
            assert system.json()["data"]["api"] == "ok"
            assert system.json()["data"]["database"] == "ok"

            deleted_user = client.delete(f"/api/users/{user_id}", headers=headers)
            assert deleted_user.status_code == 200, deleted_user.text
            remaining_ids = {
                item["id"] for item in client.get("/api/users", headers=headers).json()["data"]
            }
            assert user_id not in remaining_ids
        temp.cleanup()


def test_login_enforces_totp_and_ip_whitelist() -> None:
    secret = "JBSWY3DPEHPK3PXP"
    with tempfile.TemporaryDirectory() as directory:
        temp = tempfile.TemporaryDirectory(dir=directory)
        with make_client(temp, ("127.0.0.1", 50000)) as client:
            _, headers = login(client)
            assert client.post(
                "/api/auth/reauth", headers=headers, json={"password": ADMIN_PASSWORD}
            ).status_code == 200
            created = client.post(
                "/api/users",
                headers=headers,
                json={
                    "username": "secured.user",
                    "password": "secured-user-password",
                    "role": "viewer",
                    "ip_whitelist": "127.0.0.1",
                    "totp_secret": secret,
                },
            )
            assert created.status_code == 201, created.text
            user_id = created.json()["data"]["id"]

            missing_code = client.post(
                "/api/login",
                json={
                    "username": "secured.user",
                    "password": "secured-user-password",
                },
            )
            assert missing_code.status_code == 401
            valid_login = client.post(
                "/api/login",
                json={
                    "username": "secured.user",
                    "password": "secured-user-password",
                    "otp_code": totp_code(secret),
                },
            )
            assert valid_login.status_code == 200, valid_login.text

            restricted = client.patch(
                f"/api/users/{user_id}",
                headers=headers,
                json={"ip_whitelist": "10.0.0.0/8"},
            )
            assert restricted.status_code == 200, restricted.text
            blocked_login = client.post(
                "/api/login",
                json={
                    "username": "secured.user",
                    "password": "secured-user-password",
                    "otp_code": totp_code(secret),
                },
            )
            assert blocked_login.status_code == 401
        temp.cleanup()
