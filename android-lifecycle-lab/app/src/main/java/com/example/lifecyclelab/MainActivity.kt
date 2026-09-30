package com.example.lifecyclelab

import android.Manifest
import android.app.Activity
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var statusView: TextView

    private val devicePolicyManager by lazy {
        getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    }

    private val adminReceiver by lazy {
        ComponentName(this, LabDeviceAdminReceiver::class.java)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(verticalPage {
            title("Android Device Owner 安全边界实验")
            banner(
                "SECURITY DEMO — 本应用没有 INTERNET 权限，不读取其他 App 输入，" +
                    "不保存模拟凭据，也不会隐藏屏幕或摄像头采集。",
            )
            paragraph(
                "每项实验都从本机可见界面启动。Device Owner 只用于对照官方策略能力；" +
                    "任何系统不允许绕过的授权流程都会显示“不支持”。",
            )

            section("实验入口")
            experimentButton("1. 本 App 输入事件与分发", InputEventActivity::class.java)
            experimentButton("2. SECURITY DEMO 模拟登录", DemoLoginActivity::class.java)
            experimentButton("3. DEMO LOCK SCREEN 与 Keyguard", DemoLockActivity::class.java)
            experimentButton("4. MediaProjection 截图与录屏", ScreenCaptureActivity::class.java)
            experimentButton("5. CameraX 预览、拍照与录像", CameraExperimentActivity::class.java)
            experimentButton("6. Device Owner 能力对照与本机策略", PolicyMatrixActivity::class.java)
            experimentButton("7. 后台任务与 Launcher 图标", LifecycleLauncherActivity::class.java)

            section("当前测试环境")
            statusView = paragraph("正在读取状态…")
            actionButton("刷新状态") { refreshStatus() }

            section("重要边界")
            paragraph(
                "• 输入实验只观察本 Activity 的 View 事件。\n" +
                    "• 登录实验只接受页面公开显示的虚构账号。\n" +
                    "• 模拟锁屏始终显示非系统锁屏标记。\n" +
                    "• 每次截图/录屏都先显示 Android 系统授权页。\n" +
                    "• CameraX 仅在 Activity 可见且 CAMERA 权限有效时绑定。\n" +
                    "• 后台实验使用 JobScheduler；关闭 Launcher 入口不等于隐藏进程。",
            )
        })
    }

    override fun onResume() {
        super.onResume()
        if (::statusView.isInitialized) refreshStatus()
    }

    private fun LinearLayout.experimentButton(label: String, activity: Class<out Activity>) {
        actionButton(label) {
            startActivity(Intent(this@MainActivity, activity))
        }
    }

    private fun refreshStatus() {
        val isDeviceOwner = devicePolicyManager.isDeviceOwnerApp(packageName)
        val cameraGranted = checkSelfPermission(Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val cameraDisabled = isDeviceOwner &&
            runCatching { devicePolicyManager.getCameraDisabled(adminReceiver) }.getOrDefault(false)
        val captureDisabled = isDeviceOwner &&
            runCatching { devicePolicyManager.getScreenCaptureDisabled(adminReceiver) }
                .getOrDefault(false)

        statusView.text = buildString {
            appendLine("包名：$packageName")
            appendLine("Android API：${android.os.Build.VERSION.SDK_INT}")
            appendLine("Device Owner：${if (isDeviceOwner) "是" else "否（普通 App 模式）"}")
            appendLine("CAMERA 权限：${if (cameraGranted) "已授予" else "未授予"}")
            appendLine("DO 相机禁用策略：${if (cameraDisabled) "已禁用" else "未禁用"}")
            appendLine("DO 屏幕采集禁用策略：${if (captureDisabled) "已禁用" else "未禁用"}")
            append("系统安全锁：${if (keyguard.isDeviceSecure) "已设置" else "未设置"}")
        }
    }
}
