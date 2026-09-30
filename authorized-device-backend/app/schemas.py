from __future__ import annotations

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
    clear_group: bool = False

    @model_validator(mode="after")
    def require_change(self):
        if self.name is None and self.note is None and self.group_id is None and not self.clear_group:
            raise ValueError("at least one device field is required")
        if self.group_id is not None and self.clear_group:
            raise ValueError("group_id and clear_group cannot be used together")
        return self


class DeviceStatusRequest(StrictModel):
    battery_percent: int | None = Field(default=None, ge=0, le=100)
    charging: bool | None = None
    network_type: str | None = Field(default=None, max_length=40)
    network_quality: str | None = Field(default=None, max_length=40)
    network_latency_ms: int | None = Field(default=None, ge=0, le=60000)
    screen_state: Literal["on", "off", "locked", "unknown"] | None = None
    locked: bool | None = None
    accessibility_enabled: bool | None = None
    battery_whitelist_enabled: bool | None = None
    device_admin_enabled: bool | None = None
    screen_permission_enabled: bool | None = None
    camera_permission_enabled: bool | None = None
    uninstall_protection_enabled: bool | None = None
    launcher_icon_visible: bool | None = None
    reported_at: str | None = Field(default=None, max_length=40)


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
    """Shape only: reserved workbench routes intentionally have no executor."""

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
        "command.ack",
        "command.result",
        "screen.session.status",
    ]
    message_id: str = Field(min_length=8, max_length=160)
    correlation_id: str | None = Field(default=None, max_length=160)
    payload: dict[str, Any] = Field(default_factory=dict)
