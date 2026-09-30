package com.example.lifecyclelab

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Bitmap
import android.graphics.drawable.Icon
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.MediaRecorder
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.util.DisplayMetrics
import android.view.WindowManager
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.min

class ScreenCaptureService : Service() {
    private lateinit var workerThread: HandlerThread
    private lateinit var workerHandler: Handler

    private var projection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null
    private var mediaRecorder: MediaRecorder? = null
    private var recordingFile: File? = null
    private var recorderStarted = false
    private var stopping = false

    private val projectionCallback = object : MediaProjection.Callback() {
        override fun onStop() {
            stopCapture("系统或用户终止了 MediaProjection 会话。")
        }
    }

    override fun onCreate() {
        super.onCreate()
        workerThread = HandlerThread("SecurityDemoProjection").also { it.start() }
        workerHandler = Handler(workerThread.looper)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopCapture("用户主动停止了屏幕采集。")
            ACTION_START -> {
                if (isSessionRunning) {
                    broadcastStatus("已有会话正在运行；拒绝复用 MediaProjection token。")
                    stopSelf(startId)
                } else {
                    startVisibleForegroundNotification()
                    startAuthorizedCapture(intent)
                }
            }
            else -> stopSelf(startId)
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        if (!stopping) {
            stopping = true
            releaseCaptureResources()
            isSessionRunning = false
            broadcastStatus("采集服务已停止。")
        }
        workerThread.quitSafely()
        super.onDestroy()
    }

    private fun startVisibleForegroundNotification() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun startAuthorizedCapture(intent: Intent) {
        val resultCode = intent.getIntExtra(EXTRA_RESULT_CODE, Activity.RESULT_CANCELED)
        val resultData = intent.intentExtra(EXTRA_RESULT_DATA)
        val mode = intent.getStringExtra(EXTRA_MODE)
        if (
            resultCode != Activity.RESULT_OK ||
            resultData == null ||
            mode !in setOf(MODE_SCREENSHOT, MODE_RECORDING)
        ) {
            stopCapture("MediaProjection 参数无效；没有开始采集。")
            return
        }

        runCatching {
            val manager = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
            projection = manager.getMediaProjection(resultCode, resultData).also {
                it.registerCallback(projectionCallback, workerHandler)
            }
            isSessionRunning = true
            val metrics = captureMetrics(mode == MODE_RECORDING)
            if (mode == MODE_SCREENSHOT) {
                startScreenshot(metrics)
            } else {
                startRecording(metrics)
            }
        }.onFailure {
            stopCapture(
                "系统拒绝 MediaProjection：${it.javaClass.simpleName}: ${it.message.orEmpty()}。" +
                    "不会尝试绕过。",
            )
        }
    }

    private fun startScreenshot(metrics: CaptureMetrics) {
        val reader = ImageReader.newInstance(
            metrics.width,
            metrics.height,
            PixelFormat.RGBA_8888,
            2,
        )
        imageReader = reader
        reader.setOnImageAvailableListener({ source ->
            val image = source.acquireLatestImage() ?: return@setOnImageAvailableListener
            source.setOnImageAvailableListener(null, null)
            runCatching {
                val plane = image.planes.first()
                val rowPadding = plane.rowStride - plane.pixelStride * metrics.width
                val paddedWidth = metrics.width + rowPadding / plane.pixelStride
                val padded = Bitmap.createBitmap(
                    paddedWidth,
                    metrics.height,
                    Bitmap.Config.ARGB_8888,
                )
                padded.copyPixelsFromBuffer(plane.buffer)
                val cropped = Bitmap.createBitmap(padded, 0, 0, metrics.width, metrics.height)
                val output = File(
                    outputDirectory(Environment.DIRECTORY_PICTURES),
                    fileName("png"),
                )
                FileOutputStream(output).use { stream ->
                    check(cropped.compress(Bitmap.CompressFormat.PNG, 100, stream))
                }
                cropped.recycle()
                padded.recycle()
                output
            }.onSuccess { output ->
                image.close()
                stopCapture("截图完成：${output.absolutePath}")
            }.onFailure { error ->
                image.close()
                stopCapture("截图失败：${error.javaClass.simpleName}: ${error.message.orEmpty()}")
            }
        }, workerHandler)

        virtualDisplay = projection?.createVirtualDisplay(
            "SecurityDemoScreenshot",
            metrics.width,
            metrics.height,
            metrics.densityDpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            reader.surface,
            null,
            workerHandler,
        )
        broadcastStatus("系统已创建一次性截图会话；等待首帧…")
        workerHandler.postDelayed({
            if (isSessionRunning && imageReader != null) {
                stopCapture("截图超时；会话已安全停止。")
            }
        }, SCREENSHOT_TIMEOUT_MS)
    }

    private fun startRecording(metrics: CaptureMetrics) {
        val output = File(outputDirectory(Environment.DIRECTORY_MOVIES), fileName("mp4"))
        recordingFile = output
        val recorder = createMediaRecorder()
        mediaRecorder = recorder
        recorder.apply {
            setVideoSource(MediaRecorder.VideoSource.SURFACE)
            setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
            setOutputFile(output.absolutePath)
            setVideoEncoder(MediaRecorder.VideoEncoder.H264)
            setVideoSize(metrics.width, metrics.height)
            setVideoFrameRate(30)
            setVideoEncodingBitRate(
                (metrics.width.toLong() * metrics.height * 5L)
                    .coerceIn(2_000_000L, 12_000_000L)
                    .toInt(),
            )
            prepare()
        }
        virtualDisplay = projection?.createVirtualDisplay(
            "SecurityDemoRecording",
            metrics.width,
            metrics.height,
            metrics.densityDpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            recorder.surface,
            null,
            workerHandler,
        )
        recorder.start()
        recorderStarted = true
        broadcastStatus(
            "无声录屏进行中；持续通知和 Android 系统采集指示保持可见。输出：${output.absolutePath}",
        )
    }

    private fun stopCapture(message: String) {
        if (stopping) return
        stopping = true
        releaseCaptureResources()
        isSessionRunning = false
        broadcastStatus(message)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        stopSelf()
    }

    private fun releaseCaptureResources() {
        workerHandler.removeCallbacksAndMessages(null)
        imageReader?.setOnImageAvailableListener(null, null)
        virtualDisplay?.release()
        virtualDisplay = null
        imageReader?.close()
        imageReader = null

        val recorder = mediaRecorder
        if (recorder != null) {
            if (recorderStarted) {
                runCatching { recorder.stop() }.onFailure {
                    recordingFile?.let { file -> runCatching { file.delete() } }
                }
            }
            runCatching { recorder.reset() }
            runCatching { recorder.release() }
        }
        mediaRecorder = null
        recorderStarted = false
        recordingFile = null

        projection?.unregisterCallback(projectionCallback)
        projection?.stop()
        projection = null
    }

    private fun captureMetrics(limitForEncoder: Boolean): CaptureMetrics {
        val (rawWidth, rawHeight) = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val bounds = getSystemService(WindowManager::class.java).maximumWindowMetrics.bounds
            bounds.width() to bounds.height()
        } else {
            @Suppress("DEPRECATION")
            val display = (getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay
            val metrics = DisplayMetrics()
            @Suppress("DEPRECATION")
            display.getRealMetrics(metrics)
            metrics.widthPixels to metrics.heightPixels
        }
        val scale = if (limitForEncoder) {
            min(1f, MAX_RECORDING_EDGE.toFloat() / maxOf(rawWidth, rawHeight))
        } else {
            1f
        }
        val width = ((rawWidth * scale).toInt().coerceAtLeast(2) / 2) * 2
        val height = ((rawHeight * scale).toInt().coerceAtLeast(2) / 2) * 2
        return CaptureMetrics(width, height, resources.configuration.densityDpi)
    }

    @Suppress("DEPRECATION")
    private fun createMediaRecorder(): MediaRecorder =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) MediaRecorder(this) else MediaRecorder()

    private fun outputDirectory(type: String): File {
        val base = getExternalFilesDir(type) ?: filesDir
        return File(base, "SecurityBoundaryLab").apply { mkdirs() }
    }

    private fun fileName(extension: String): String =
        "SECURITY_DEMO_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())}.$extension"

    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, ScreenCaptureActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, ScreenCaptureService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val stopAction = Notification.Action.Builder(
            Icon.createWithResource(this, android.R.drawable.ic_media_pause),
            "停止采集",
            stopIntent,
        ).build()
        return builder
            .setSmallIcon(android.R.drawable.ic_menu_camera)
            .setContentTitle(getString(R.string.projection_notification_title))
            .setContentText(getString(R.string.projection_notification_text))
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(stopAction)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.projection_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.projection_channel_description)
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun broadcastStatus(message: String) {
        sendBroadcast(
            Intent(ACTION_STATUS)
                .setPackage(packageName)
                .putExtra(EXTRA_MESSAGE, message),
        )
    }

    @Suppress("DEPRECATION")
    private fun Intent.intentExtra(name: String): Intent? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            getParcelableExtra(name, Intent::class.java)
        } else {
            getParcelableExtra(name)
        }

    private data class CaptureMetrics(
        val width: Int,
        val height: Int,
        val densityDpi: Int,
    )

    companion object {
        const val ACTION_START = "com.example.lifecyclelab.action.START_PROJECTION"
        const val ACTION_STOP = "com.example.lifecyclelab.action.STOP_PROJECTION"
        const val ACTION_STATUS = "com.example.lifecyclelab.action.PROJECTION_STATUS"
        const val EXTRA_MODE = "mode"
        const val EXTRA_RESULT_CODE = "result_code"
        const val EXTRA_RESULT_DATA = "result_data"
        const val EXTRA_MESSAGE = "message"
        const val MODE_SCREENSHOT = "screenshot"
        const val MODE_RECORDING = "recording"

        @Volatile
        var isSessionRunning: Boolean = false
            private set

        private const val CHANNEL_ID = "security_demo_projection"
        private const val NOTIFICATION_ID = 4201
        private const val SCREENSHOT_TIMEOUT_MS = 10_000L
        private const val MAX_RECORDING_EDGE = 1920
    }
}
