package com.example.lifecyclelab

data class DeviceOwnerBoundary(
    val experiment: String,
    val autoGrant: String,
    val canDisable: String,
    val changeFlow: String,
    val bypass: String,
)

object BoundaryRules {
    const val DEMO_USERNAME = "demo_user"
    const val DEMO_PASSWORD = "demo-pass-123"

    val deviceOwnerMatrix = listOf(
        DeviceOwnerBoundary(
            experiment = "本 App 输入事件",
            autoGrant = "无需运行时权限",
            canDisable = "不能借此读取或禁止其他 App 输入",
            changeFlow = "不改变 Activity / View / IME 分发流程",
            bypass = "不支持跨 App 输入读取",
        ),
        DeviceOwnerBoundary(
            experiment = "SECURITY DEMO 模拟登录",
            autoGrant = "无需运行时权限",
            canDisable = "不能把普通 Activity 变成系统认证界面",
            changeFlow = "不改变 App 内文本流转",
            bypass = "不支持获取或验证系统凭据",
        ),
        DeviceOwnerBoundary(
            experiment = "模拟锁屏 UI / Keyguard",
            autoGrant = "无需运行时权限",
            canDisable = "可条件性调用 setKeyguardDisabled；已有 PIN/图案/密码时不能关闭",
            changeFlow = "可 lockNow；requestDismissKeyguard 仍交给系统认证",
            bypass = "不支持绕过系统 PIN、图案或密码",
        ),
        DeviceOwnerBoundary(
            experiment = "MediaProjection",
            autoGrant = "不能授予 MediaProjection；只能固定通知运行时权限",
            canDisable = "支持 setScreenCaptureDisabled",
            changeFlow = "只能禁用；Android 14+ 每次会话仍需系统同意",
            bypass = "不支持绕过系统授权界面",
        ),
        DeviceOwnerBoundary(
            experiment = "CameraX",
            autoGrant = "支持 setPermissionGrantState 固定授予 CAMERA",
            canDisable = "支持 setCameraDisabled",
            changeFlow = "可固定授予/拒绝 CAMERA 运行时权限",
            bypass = "不支持绕过隐私指示器或后台相机限制",
        ),
    )

    fun acceptsDemoCredentials(username: String, password: String): Boolean =
        username == DEMO_USERNAME && password == DEMO_PASSWORD
}
