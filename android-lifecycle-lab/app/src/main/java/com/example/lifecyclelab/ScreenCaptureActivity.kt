package com.example.lifecyclelab

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat

class ScreenCaptureActivity : ComponentActivity() {
    private lateinit var statusView: TextView
    private var pendingMode: String? = null

    private val projectionManager by lazy {
        getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        val mode = pendingMode
        if (granted && mode != null) {
            launchSystemConsent(mode)
        } else {
            pendingMode = null
            updateStatus(
                "通知权限未授予。为避免形成用户不可见的前台采集，本实验拒绝开始。",
            )
        }
    }

    private val projectionConsentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val mode = pendingMode
        pendingMode = null
        val data = result.data
        if (result.resultCode != Activity.RESULT_OK || data == null || mode == null) {
            updateStatus("用户未授权 MediaProjection；没有创建采集会话。")
            return@registerForActivityResult
        }
        val serviceIntent = Intent(this, ScreenCaptureService::class.java).apply {
            action = ScreenCaptureService.ACTION_START
            putExtra(ScreenCaptureService.EXTRA_MODE, mode)
            putExtra(ScreenCaptureService.EXTRA_RESULT_CODE, result.resultCode)
            putExtra(ScreenCaptureService.EXTRA_RESULT_DATA, data)
        }
        ContextCompat.startForegroundService(this, serviceIntent)
        updateStatus("系统已授权本次会话；正在启动带持续通知的采集服务。")
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            updateStatus(intent?.getStringExtra(ScreenCaptureService.EXTRA_MESSAGE).orEmpty())
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(verticalPage {
            title("MediaProjection 屏幕采集实验")
            banner(
                "每一次截图或录屏都必须先经过 Android 系统授权界面。" +
                    "本实验不会缓存或复用授权 token，不会后台自动重启，也不会隐藏前台通知。",
            )
            paragraph(
                "截图和无声录屏保存到本 App 的外部实验目录；没有上传代码。" +
                    "录屏期间可从本页面或持续通知停止。",
            )
            statusView = paragraph("尚未开始采集。")
            actionButton("请求系统授权并截取一张图") {
                beginCapture(ScreenCaptureService.MODE_SCREENSHOT)
            }
            actionButton("请求系统授权并开始无声录屏") {
                beginCapture(ScreenCaptureService.MODE_RECORDING)
            }
            actionButton("停止当前采集") {
                startService(
                    Intent(this@ScreenCaptureActivity, ScreenCaptureService::class.java).apply {
                        action = ScreenCaptureService.ACTION_STOP
                    },
                )
            }

            section("版本限制")
            paragraph(
                "Android 5.0 / API 21：引入 MediaProjection，始终由系统授权。\n" +
                    "Android 10+：目标版本要求在 mediaProjection 类型前台服务中维持会话。\n" +
                    "Android 13+：本实验要求通知权限后才启动，以保证持续通知可见。\n" +
                    "Android 14+：每次 capture session 必须重新同意；每个 token 与 " +
                    "MediaProjection 实例只能创建一次 VirtualDisplay。用户可停止系统状态栏中的会话。\n" +
                    "Device Owner：可禁用屏幕采集，但不能授予或绕过 MediaProjection 同意。",
            )
            backButton(this)
        })
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(ScreenCaptureService.ACTION_STATUS)
        ContextCompat.registerReceiver(
            this,
            statusReceiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    override fun onStop() {
        runCatching { unregisterReceiver(statusReceiver) }
        super.onStop()
    }

    private fun beginCapture(mode: String) {
        if (ScreenCaptureService.isSessionRunning) {
            updateStatus("已有采集会话正在运行；请先停止，再重新经过系统授权。")
            return
        }
        pendingMode = mode
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            return
        }
        launchSystemConsent(mode)
    }

    private fun launchSystemConsent(mode: String) {
        pendingMode = mode
        updateStatus("正在打开 Android 系统 MediaProjection 授权界面…")
        projectionConsentLauncher.launch(projectionManager.createScreenCaptureIntent())
    }

    private fun updateStatus(message: String) {
        if (::statusView.isInitialized && message.isNotBlank()) statusView.text = message
    }
}
