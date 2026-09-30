package com.example.lifecyclelab

import android.app.Activity
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

class DemoLockActivity : Activity() {
    private lateinit var statusView: TextView

    private val keyguardManager by lazy {
        getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    }
    private val devicePolicyManager by lazy {
        getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    }
    private val adminReceiver by lazy {
        ComponentName(this, LabDeviceAdminReceiver::class.java)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showAboveKeyguardWithoutDismissingIt()
        setContentView(buildLockDemo())
        hideSystemBars()
        refreshStatus("Activity 已进入 immersive fullscreen；这不是系统 Keyguard。")
    }

    override fun onResume() {
        super.onResume()
        hideSystemBars()
        if (::statusView.isInitialized) refreshStatus("onResume：重新读取系统 Keyguard 状态。")
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) hideSystemBars()
    }

    private fun buildLockDemo(): View = verticalPage {
        setBackgroundColor(Color.BLACK)
        title("DEMO LOCK SCREEN — NOT SYSTEM LOCK SCREEN", Color.YELLOW)
        banner(
            "明确边界：这是普通全屏 Activity。它不收集系统 PIN/密码，" +
                "不模仿 Android 解锁控件，也不能自行解除安全 Keyguard。",
        )
        paragraph(
            "fullscreen/immersive 只控制本 Activity 的系统栏可见性；showWhenLocked 允许页面显示在 " +
                "Keyguard 上方，但不会认证用户；真正的锁定与解锁仍由 Android 系统完成。",
            Color.WHITE,
        )

        section("实时状态")
        statusView = paragraph("正在读取…", Color.WHITE)

        actionButton("请求系统解除 Keyguard（可能显示系统认证）") {
            requestSystemDismiss()
        }
        actionButton("Device Owner：调用 lockNow() 真实锁屏") {
            lockSystemNow()
        }
        actionButton("退出 Demo 全屏 Activity") { finish() }

        section("Device Owner 边界")
        paragraph(
            "Device Owner 可调用 lockNow()。setKeyguardDisabled(true) 只在官方允许且设备没有现有" +
                "安全凭据时生效；它不是 PIN 绕过。本实验的开关位于“Device Owner 能力对照”页面。",
            Color.LTGRAY,
        )
    }

    private fun showAboveKeyguardWithoutDismissingIt() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED)
        }
    }

    private fun hideSystemBars() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.insetsController?.apply {
                hide(WindowInsets.Type.statusBars() or WindowInsets.Type.navigationBars())
                systemBarsBehavior =
                    WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
            }
        } else {
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility =
                View.SYSTEM_UI_FLAG_FULLSCREEN or
                View.SYSTEM_UI_FLAG_HIDE_NAVIGATION or
                View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION or
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE
        }
    }

    private fun requestSystemDismiss() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            refreshStatus("Android 8.0 以下没有 requestDismissKeyguard；不尝试替代方案。")
            return
        }
        keyguardManager.requestDismissKeyguard(
            this,
            object : KeyguardManager.KeyguardDismissCallback() {
                override fun onDismissSucceeded() {
                    refreshStatus("系统确认：Keyguard 已解除。")
                }

                override fun onDismissCancelled() {
                    refreshStatus("系统确认：用户取消了 Keyguard 解除。")
                }

                override fun onDismissError() {
                    refreshStatus("系统拒绝解除 Keyguard；不尝试绕过。")
                }
            },
        )
    }

    private fun lockSystemNow() {
        if (!devicePolicyManager.isDeviceOwnerApp(packageName)) {
            Toast.makeText(this, "当前 App 不是 Device Owner", Toast.LENGTH_LONG).show()
            return
        }
        runCatching { devicePolicyManager.lockNow() }
            .onFailure { refreshStatus("lockNow 失败：${it.javaClass.simpleName}") }
    }

    private fun refreshStatus(event: String) {
        statusView.text = buildString {
            appendLine(event)
            appendLine("isKeyguardLocked=${keyguardManager.isKeyguardLocked}")
            appendLine("isDeviceSecure=${keyguardManager.isDeviceSecure}")
            append("Device Owner=${devicePolicyManager.isDeviceOwnerApp(packageName)}")
        }
    }
}
