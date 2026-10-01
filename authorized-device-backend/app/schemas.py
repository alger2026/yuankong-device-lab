from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class ReauthRequest(StrictModel):
    password: str = Field(min_length=1, max_length=256)


class PasswordChangeRequest(StrictModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class UserCreateRequest(StrictModel):
    username: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Literal["admin", "operator", "viewer"]


class UserUpdateRequest(StrictModel):
    role: Literal["admin", "operator", "viewer"] | None = None
    status: Literal["active", "disabled"] | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)

    @model_validator(mode="after")
    def require_change(self):
        if self.role is None and self.status is None and self.password is None:
            raise ValueError("at least one user field is required")
        return self


class DeviceGroupCreateRequest(StrictModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=500)


class DeviceGroupUpdateRequest(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def require_change(self):
        if self.name is None and self.description is None:
            raise ValueError("at least one group field is required")
        return self


class DeviceUpdateRequest(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    note: str | None = Field(default=None, max_length=1000)
    group_id: str | None = Field(default=None, max_length=80)
    owner_user_id: str | None = Field(default=None, max_length=80)
    clear_group: bool = False

    @model_validator(mode="after")
    def require_change(self):
        if self.name is None and self.note is None and self.group_id is None and self.owner_user_id is None and not self.clear_group:
            raise ValueError("at least one device field is required")
        if self.group_id is not None and self.clear_group:
            raise ValueError("group_id and clear_group cannot be used together")
        return self


class DeviceStatusRequest(StrictModel):
    # Legacy deviceOnline/diag payloads contain device metadata next to status
    # fields. Ignore that metadata here, most importantly deviceInfo.screen,
    # which is a display dimension rather than an interactive-screen state.
    model_config = ConfigDict(extra="ignore")

    battery_percent: int | None = Field(default=None, ge=0, le=100)
    charging: bool | None = None
    network_type: str | None = Field(default=None, max_length=40)
    network_quality: str | None = Field(default=None, max_length=40)
    network_latency_ms: int | None = Field(default=None, ge=0, le=60000)
    screen_state: Literal["on", "off", "locked", "unknown"] | None = None
    locked: bool | None = None
    lock_state_code: int | None = Field(default=None, ge=0, le=3)
    accessibility_enabled: bool | None = None
    battery_whitelist_enabled: bool | None = None
    device_admin_enabled: bool | None = None
    screen_permission_enabled: bool | None = None
    camera_permission_enabled: bool | None = None
    uninstall_protection_enabled: bool | None = None
    launcher_icon_visible: bool | None = None
    reported_at: str | None = Field(default=None, max_length=40)

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_status(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)

        def use_alias(target: str, *aliases: str) -> None:
            if data.get(target) is not None:
                return
            for alias in aliases:
                if data.get(alias) is not None:
                    data[target] = data[alias]
                    return

        def legacy_bool(raw: Any) -> bool | Any:
            if isinstance(raw, str):
                normalized = raw.strip().lower()
                if normalized in {"1", "true", "yes", "on", "active", "activated", "enabled"}:
                    return True
                if normalized in {"0", "false", "no", "off", "inactive", "deactivated", "disabled"}:
                    return False
            return raw

        use_alias("battery_percent", "battery")
        use_alias("network_type", "netstate", "network")
        use_alias("accessibility_enabled", "acc", "acc_status")
        use_alias(
            "battery_whitelist_enabled",
            "battery_whitelist",
            "ignoring_battery_opt",
        )

        battery = data.get("battery_percent")
        if isinstance(battery, str):
            data["battery_percent"] = battery.strip().removesuffix("%").strip()

        network_type = data.get("network_type")
        if isinstance(network_type, str):
            data["network_type"] = network_type.strip().lower()

        for field in (
            "charging",
            "accessibility_enabled",
            "battery_whitelist_enabled",
            "device_admin_enabled",
        ):
            if field in data:
                data[field] = legacy_bool(data[field])

        lock_value = data.get("lock_state_code", data.get("lock"))
        if isinstance(lock_value, str):
            lock_value = lock_value.strip()
        try:
            lock_code = int(lock_value) if lock_value is not None else None
        except (TypeError, ValueError):
            lock_code = lock_value
        if lock_code is not None:
            data["lock_state_code"] = lock_code
            if lock_code == 0:
                data.setdefault("screen_state", "off")
            elif lock_code == 1:
                data.setdefault("screen_state", "locked")
                data.setdefault("locked", True)
            elif lock_code in {2, 3}:
                data.setdefault("screen_state", "on")
                data.setdefault("locked", False)

        diag_name = (
            data.get("diag")
            or data.get("diagnostic")
            or data.get("type")
            or data.get("name")
            or data.get("category")
        )
        diag_state = (
            data.get("status")
            if data.get("status") is not None
            else data.get("state", data.get("value", data.get("message")))
        )
        if isinstance(diag_name, str) and "device_admin" in diag_name.lower():
            if diag_state is None and "/" in diag_name:
                diag_state = diag_name.rsplit("/", 1)[-1]
            if diag_state is not None and data.get("device_admin_enabled") is None:
                data["device_admin_enabled"] = legacy_bool(diag_state)

        return data


class DeviceLogRequest(StrictModel):
    event_uid: str = Field(min_length=8, max_length=160)
    level: Literal["info", "warning", "error"]
    category: str = Field(min_length=1, max_length=80)
    event: str = Field(min_length=1, max_length=120)
    message: str = Field(default="", max_length=2000)
    details: dict[str, Any] = Field(default_factory=dict)
    device_time: str | None = Field(default=None, max_length=40)


class BatteryGuideRequest(StrictModel):
    brand: str = Field(min_length=1, max_length=80)
    model_pattern: str = Field(default="*", min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=160)
    steps: list[str] = Field(min_length=1, max_length=20)
    enabled: bool = True

    @field_validator("steps")
    @classmethod
    def validate_steps(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values]
        if any(not value or len(value) > 500 for value in cleaned):
            raise ValueError("each battery guide step must be 1-500 characters")
        return cleaned


class MessageTemplateCreateRequest(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=200)
    enabled: bool = True


class MessageTemplateUpdateRequest(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    content: str | None = Field(default=None, min_length=1, max_length=200)
    enabled: bool | None = None

    @model_validator(mode="after")
    def require_change(self):
        if self.name is None and self.content is None and self.enabled is None:
            raise ValueError("at least one template field is required")
        return self


class ScreenSessionRequest(StrictModel):
    device_id: str = Field(min_length=8, max_length=80)


class ReservedWorkbenchActionRequest(StrictModel):
    """Fixed workbench message with an action-specific, validated payload."""

    value: bool | str | int | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class BuildProfileRequest(StrictModel):
    """Material-aligned build form contract; build/sign logic is not implemented."""

    app_name: str = Field(min_length=1, max_length=120)
    shell_name: str = Field(min_length=1, max_length=120)
    homepage_url: str = Field(min_length=1, max_length=500)
    hide_launcher_icon: bool = False
    sms: bool = False
    camera: bool = False
    contacts: bool = False
    media: bool = False


SAFE_COMMANDS = {
    "refresh_status",
    "show_support_prompt",
    "open_battery_settings",
    "open_autostart_settings",
    "request_screen_share",
    "stop_screen_share",
    "lock_device",
}


class CommandRequest(StrictModel):
    device_id: str = Field(min_length=8, max_length=80)
    action: str = Field(min_length=1, max_length=80)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        if value not in SAFE_COMMANDS:
            raise ValueError("unsupported or unsafe action")
        return value


class DeviceSocketMessage(StrictModel):
    type: Literal[
        "device.hello",
        "device.heartbeat",
        "device.status",
        "deviceOnline",
        "diag",
        "command.ack",
        "command.result",
        "screenshot",
        "adbScreenshot",
        "camPic",
        "relayStatus",
        "adbShellResult",
        "screen.session.status",
    ]
    message_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), min_length=8, max_length=160
    )
    correlation_id: str | None = Field(default=None, max_length=160)
    payload: dict[str, Any] = Field(default_factory=dict)
