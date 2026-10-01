from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.config import Settings
from app.main import create_app
from app.security import token_hash, utc_now


ADMIN_PASSWORD = "correct-horse-battery-staple"


def make_client(temp: tempfile.TemporaryDirectory) -> TestClient:
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
    return TestClient(create_app(settings))


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
                ("unlock", None, {}, {}),
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
                ("screenshot", None, {}, {}),
                ("front-camera", None, {}, {}),
                ("rear-camera", None, {}, {}),
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
