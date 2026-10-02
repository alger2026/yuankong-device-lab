from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import WebSocket


@dataclass
class DeviceConnection:
    device_id: str
    websocket: WebSocket
    socket_id: str
    session_id: str
    last_heartbeat_monotonic: float = field(default_factory=time.monotonic)
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class DashboardConnection:
    websocket: WebSocket
    user_id: str
    role: str
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class ScreenConnection:
    session_id: str
    role: str
    websocket: WebSocket
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class RealtimeHub:
    """Single-node connection registry.

    TODO_APK/production: replace routing metadata with Redis when running more
    than one gateway process. WebSocket objects remain local to their process.
    """

    def __init__(self) -> None:
        self._devices: dict[str, DeviceConnection] = {}
        self._dashboards: dict[str, DashboardConnection] = {}
        self._screens: dict[str, dict[str, ScreenConnection]] = {}
        self._lock = asyncio.Lock()

    async def register_device(
        self, device_id: str, websocket: WebSocket, session_id: str
    ) -> tuple[DeviceConnection, DeviceConnection | None]:
        connection = DeviceConnection(
            device_id=device_id,
            websocket=websocket,
            socket_id=str(uuid.uuid4()),
            session_id=session_id,
        )
        previous: DeviceConnection | None
        async with self._lock:
            previous = self._devices.get(device_id)
            self._devices[device_id] = connection
        if previous is not None:
            try:
                await previous.websocket.close(code=4001, reason="replaced by a newer session")
            except RuntimeError:
                pass
        return connection, previous

    async def unregister_device(self, connection: DeviceConnection) -> bool:
        async with self._lock:
            current = self._devices.get(connection.device_id)
            if current is not connection:
                return False
            del self._devices[connection.device_id]
            return True

    async def touch(self, connection: DeviceConnection) -> None:
        connection.last_heartbeat_monotonic = time.monotonic()

    async def stale_connections(self, timeout_seconds: int) -> list[DeviceConnection]:
        cutoff = time.monotonic() - timeout_seconds
        async with self._lock:
            return [
                connection
                for connection in self._devices.values()
                if connection.last_heartbeat_monotonic < cutoff
            ]

    async def is_online(self, device_id: str) -> bool:
        async with self._lock:
            return device_id in self._devices

    async def stats(self) -> dict[str, int]:
        async with self._lock:
            return {
                "device_connections": len(self._devices),
                "dashboard_connections": len(self._dashboards),
                "screen_sessions": len(self._screens),
            }

    async def send_command(self, device_id: str, message: dict[str, Any]) -> bool:
        async with self._lock:
            connection = self._devices.get(device_id)
        if connection is None:
            return False
        try:
            async with connection.send_lock:
                await connection.websocket.send_json(message)
            return True
        except RuntimeError:
            return False

    async def register_dashboard(
        self, websocket: WebSocket, user_id: str, role: str
    ) -> str:
        connection_id = str(uuid.uuid4())
        async with self._lock:
            self._dashboards[connection_id] = DashboardConnection(
                websocket=websocket, user_id=user_id, role=role
            )
        return connection_id

    async def unregister_dashboard(self, connection_id: str) -> None:
        async with self._lock:
            self._dashboards.pop(connection_id, None)

    async def broadcast_dashboard(
        self, event: dict[str, Any], owner_user_id: str | None = None
    ) -> None:
        async with self._lock:
            targets = list(self._dashboards.items())
        stale: list[str] = []
        for connection_id, target in targets:
            if (
                owner_user_id is not None
                and target.role != "admin"
                and target.user_id != owner_user_id
            ):
                continue
            try:
                async with target.send_lock:
                    await target.websocket.send_json(event)
            except RuntimeError:
                stale.append(connection_id)
        if stale:
            async with self._lock:
                for connection_id in stale:
                    self._dashboards.pop(connection_id, None)

    async def register_screen(
        self, session_id: str, role: str, websocket: WebSocket
    ) -> tuple[ScreenConnection, ScreenConnection | None]:
        connection = ScreenConnection(
            session_id=session_id, role=role, websocket=websocket
        )
        async with self._lock:
            roles = self._screens.setdefault(session_id, {})
            previous = roles.get(role)
            roles[role] = connection
        if previous is not None:
            try:
                await previous.websocket.close(
                    code=4001, reason="replaced by a newer media connection"
                )
            except RuntimeError:
                pass
        return connection, previous

    async def unregister_screen(self, connection: ScreenConnection) -> bool:
        async with self._lock:
            roles = self._screens.get(connection.session_id)
            if roles is None or roles.get(connection.role) is not connection:
                return False
            roles.pop(connection.role, None)
            if not roles:
                self._screens.pop(connection.session_id, None)
            return True

    async def relay_screen_frame(self, session_id: str, data: bytes) -> bool:
        async with self._lock:
            target = self._screens.get(session_id, {}).get("browser")
        if target is None:
            return False
        try:
            async with target.send_lock:
                await target.websocket.send_bytes(data)
            return True
        except RuntimeError:
            return False

    async def notify_screen_peer(
        self, session_id: str, role: str, message: dict[str, Any]
    ) -> None:
        async with self._lock:
            target = self._screens.get(session_id, {}).get(role)
        if target is None:
            return
        try:
            async with target.send_lock:
                await target.websocket.send_json(message)
        except RuntimeError:
            pass
