package com.example.lifecyclelab

import android.Manifest
import android.app.Activity
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

class PolicyMatrixActivity : Activity() {
    private lateinit var statusView: TextView

    private val policyManager by lazy {
        getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    }
    private val adminReceiver by lazy {
        ComponentName(this, LabDeviceAdminReceiver::class.java)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(verticalPage {
            title("Device Owner 官方能力对照")
            banner(
                "所有策略按钮只影响本机测试设备，并且必须从这个可见页面点击。" +
                    "“不支持”表示不寻找漏洞、私有 API 或规避方法。",
            )

            BoundaryRules.deviceOwnerMatrix.forEach { row -> boundaryCard(row) }

            section("可逆的本机策略实验")
            statusView = paragraph("正在读取状态…")
            actionButton("固定授予本 App CAMERA 权限") {
                setPermission(Manifest.permission.CAMERA, DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED)
            }
            actionButton("将 CAMERA 权限恢复为用户控制") {
                setPermission(Manifest.permission.CAMERA, DevicePolicyManager.PERMISSION_GRANT_STATE_DEFAULT)
            }
            actionButton("固定拒绝本 App CAMERA 权限") {
                setPermission(Manifest.permission.CAMERA, DevicePolicyManager.PERMISSION_GRANT_STATE_DENIED)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                actionButton("固定授予通知权限（不等于 MediaProjection 授权）") {
                    setPermission(
                        Manifest.permission.POST_NOTIFICATIONS,
                        DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED,
                    )
                }
                actionButton("将通知权限恢复为用户控制") {
                    setPermission(
                        Manifest.permission.POST_NOTIFICATIONS,
                        DevicePolicyManager.PERMISSION_GRANT_STATE_DEFAULT,
                    )
                }
            }
            actionButton("禁用整台测试设备的相机") { setCameraDisabled(true) }
            actionButton("恢复整台测试设备的相机") { setCameraDisabled(false) }
            actionButton("禁用系统屏幕截图/采集") { setScreenCaptureDisabled(true) }
            actionButton("恢复系统屏幕截图/采集") { setScreenCaptureDisabled(false) }
            actionButton("条件性关闭系统 Keyguard") { setKeyguardDisabled(true) }
            actionButton("重新启用系统 Keyguard") { setKeyguardDisabled(false) }
            actionButton("立即调用系统 lockNow()") { lockNow() }
            actionButton("刷新状态") { refreshStatus("状态已刷新") }

            section("恢复顺序")
            paragraph(
                "离开实验前依次恢复相机、屏幕采集、Keyguard 和 CAMERA/通知权限的用户控制，" +
                    "再按 README 移除测试 Device Owner。",
            )
            backButton(this)
        })
        refreshStatus("页面已打开；尚未更改策略。")
    }

    override fun onResume() {
        super.onResume()
        if (::statusView.isInitialized) refreshStatus("onResume：读取当前策略。")
    }

    private fun LinearLayout.boundaryCard(row: DeviceOwnerBoundary) {
        addView(TextView(context).apply {
            text = row.experiment
            textSize = 17f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.rgb(6, 74, 54))
            setPadding(0, dp(14), 0, dp(3))
        })
        paragraph(
            "自动授予：${row.autoGrant}\n" +
                "禁止能力：${row.canDisable}\n" +
                "改变流程：${row.changeFlow}\n" +
                "绕过流程：${row.bypass}",
        )
    }

    private fun setPermission(permission: String, state: Int) = withDeviceOwner {
        val changed = policyManager.setPermissionGrantState(
            adminReceiver,
            packageName,
            permission,
            state,
        )
        refreshStatus("setPermissionGrantState($permission, $state) 返回 $changed")
    }

    private fun setCameraDisabled(disabled: Boolean) = withDeviceOwner {
        policyManager.setCameraDisabled(adminReceiver, disabled)
        refreshStatus("setCameraDisabled($disabled) 已调用")
    }

    private fun setScreenCaptureDisabled(disabled: Boolean) = withDeviceOwner {
        policyManager.setScreenCaptureDisabled(adminReceiver, disabled)
        refreshStatus("setScreenCaptureDisabled($disabled) 已调用")
    }

    private fun setKeyguardDisabled(disabled: Boolean) = withDeviceOwner {
        val changed = policyManager.setKeyguardDisabled(adminReceiver, disabled)
        refreshStatus(
            "setKeyguardDisabled($disabled) 返回 $changed。false 表示系统条件不允许；不尝试绕过。",
        )
    }

    private fun lockNow() = withDeviceOwner {
        Toast.makeText(this, "正在调用 Android 系统真实锁屏", Toast.LENGTH_LONG).show()
        policyManager.lockNow()
    }

    private fun withDeviceOwner(action: () -> Unit) {
        if (!policyManager.isDeviceOwnerApp(packageName)) {
            Toast.makeText(
                this,
                "当前 App 不是 Device Owner；请按 README 在全新测试设备配置",
                Toast.LENGTH_LONG,
            ).show()
            return
        }
        runCatching(action).onFailure {
            refreshStatus("系统拒绝策略调用：${it.javaClass.simpleName}: ${it.message.orEmpty()}")
        }
    }

    private fun refreshStatus(event: String) {
        val isOwner = policyManager.isDeviceOwnerApp(packageName)
        val cameraPermission = checkSelfPermission(Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        val notificationPermission = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        val cameraDisabled = isOwner &&
            runCatching { policyManager.getCameraDisabled(adminReceiver) }.getOrDefault(false)
        val captureDisabled = isOwner &&
            runCatching { policyManager.getScreenCaptureDisabled(adminReceiver) }.getOrDefault(false)
        val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

        statusView.text = buildString {
            appendLine(event)
            appendLine("Device Owner：${if (isOwner) "是" else "否"}")
            appendLine("CAMERA：${if (cameraPermission) "已授予" else "未授予"}")
            appendLine("通知：${if (notificationPermission) "已授予/无需" else "未授予"}")
            appendLine("相机禁用策略：$cameraDisabled")
            appendLine("屏幕采集禁用策略：$captureDisabled")
            append("系统已有安全凭据：${keyguard.isDeviceSecure}")
        }
    }
}
