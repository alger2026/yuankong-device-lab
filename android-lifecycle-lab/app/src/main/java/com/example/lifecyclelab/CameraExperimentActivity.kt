package com.example.lifecyclelab

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Environment
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.video.FileOutputOptions
import androidx.camera.video.FallbackStrategy
import androidx.camera.video.Quality
import androidx.camera.video.QualitySelector
import androidx.camera.video.Recorder
import androidx.camera.video.Recording
import androidx.camera.video.VideoCapture
import androidx.camera.video.VideoRecordEvent
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class CameraExperimentActivity : ComponentActivity() {
    private lateinit var previewView: PreviewView
    private lateinit var statusView: TextView
    private lateinit var recordButton: android.widget.Button

    private var cameraProvider: ProcessCameraProvider? = null
    private var imageCapture: ImageCapture? = null
    private var videoCapture: VideoCapture<Recorder>? = null
    private var activeRecording: Recording? = null
    private var bindingCamera = false

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            updateStatus("用户已授予 CAMERA；开始绑定 CameraX。")
            bindCameraUseCases()
        } else {
            updateStatus("用户拒绝 CAMERA；预览、拍照和录像保持禁用。")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(verticalPage {
            title("CameraX 可见采集实验")
            banner(
                "SECURITY DEMO — 只在本 Activity 可见时使用相机。正常申请 CAMERA 权限，" +
                    "不录音、不启动后台相机、不隐藏 Android 隐私指示器。",
            )
            paragraph(
                "Android 12+ 会显示系统摄像头隐私指示。Device Owner 可以固定授予/拒绝 CAMERA，" +
                    "也可以禁用相机，但不能绕过隐私指示和后台访问限制。",
            )

            previewView = PreviewView(this@CameraExperimentActivity).apply {
                implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                scaleType = PreviewView.ScaleType.FIT_CENTER
            }
            addView(
                previewView,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    dp(320),
                ),
            )

            statusView = paragraph("尚未获得 CAMERA 权限。")
            actionButton("正常请求 CAMERA 权限") {
                cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
            actionButton("拍照（保存到本 App 实验目录）") { takePhoto() }
            recordButton = actionButton("开始无声录像") { toggleRecording() }

            section("版本限制")
            paragraph(
                "Android 6.0+：CAMERA 是运行时权限。\n" +
                    "Android 11+：用户可选择仅本次授权。\n" +
                    "Android 12+：系统显示摄像头隐私指示器并提供全局相机开关。\n" +
                    "现代 Android：后台启动和 while-in-use 权限受到限制；本实验不使用 camera 前台服务。",
            )
            backButton(this)
        })
    }

    override fun onResume() {
        super.onResume()
        if (hasCameraPermission()) {
            bindCameraUseCases()
        } else {
            cameraProvider?.unbindAll()
            cameraProvider = null
            imageCapture = null
            videoCapture = null
            updateStatus("CAMERA 未授予；所有 CameraX use case 已解除绑定。")
        }
    }

    override fun onStop() {
        activeRecording?.stop()
        activeRecording = null
        if (::recordButton.isInitialized) recordButton.text = "开始无声录像"
        super.onStop()
    }

    override fun onDestroy() {
        activeRecording?.close()
        activeRecording = null
        cameraProvider?.unbindAll()
        cameraProvider = null
        super.onDestroy()
    }

    private fun bindCameraUseCases() {
        if (!hasCameraPermission() || bindingCamera) return
        bindingCamera = true
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            runCatching {
                val provider = future.get()
                val selector = when {
                    provider.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA) ->
                        CameraSelector.DEFAULT_BACK_CAMERA
                    provider.hasCamera(CameraSelector.DEFAULT_FRONT_CAMERA) ->
                        CameraSelector.DEFAULT_FRONT_CAMERA
                    else -> error("设备没有 CameraX 可用摄像头")
                }
                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }
                val photo = ImageCapture.Builder()
                    .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
                    .build()
                val recorder = Recorder.Builder()
                    .setQualitySelector(
                        QualitySelector.from(
                            Quality.HD,
                            FallbackStrategy.higherQualityOrLowerThan(Quality.HD),
                        ),
                    )
                    .build()
                val video = VideoCapture.withOutput(recorder)

                provider.unbindAll()
                provider.bindToLifecycle(
                    this,
                    selector,
                    preview,
                    photo,
                    video,
                )
                cameraProvider = provider
                imageCapture = photo
                videoCapture = video
                updateStatus("CameraX 已绑定：Preview + ImageCapture + VideoCapture（无音频）。")
            }.onFailure {
                updateStatus(
                    "CameraX 绑定失败：${it.javaClass.simpleName}: ${it.message.orEmpty()}。" +
                        "若 Device Owner 已禁用相机，请先恢复。",
                )
            }.also { bindingCamera = false }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun takePhoto() {
        val capture = imageCapture ?: run {
            updateStatus("相机尚未就绪；请先正常授予 CAMERA 权限。")
            return
        }
        val file = File(outputDirectory(Environment.DIRECTORY_PICTURES), fileName("jpg"))
        val options = ImageCapture.OutputFileOptions.Builder(file).build()
        capture.takePicture(
            options,
            ContextCompat.getMainExecutor(this),
            object : ImageCapture.OnImageSavedCallback {
                override fun onImageSaved(output: ImageCapture.OutputFileResults) {
                    updateStatus("拍照完成：${file.absolutePath}")
                }

                override fun onError(exception: ImageCaptureException) {
                    updateStatus("拍照失败：${exception.message.orEmpty()}")
                }
            },
        )
    }

    private fun toggleRecording() {
        val current = activeRecording
        if (current != null) {
            current.stop()
            updateStatus("正在停止录像…")
            return
        }
        val capture = videoCapture ?: run {
            updateStatus("相机尚未就绪；请先正常授予 CAMERA 权限。")
            return
        }
        val file = File(outputDirectory(Environment.DIRECTORY_MOVIES), fileName("mp4"))
        val output = FileOutputOptions.Builder(file).build()
        activeRecording = capture.output
            .prepareRecording(this, output)
            .start(ContextCompat.getMainExecutor(this)) { event ->
                when (event) {
                    is VideoRecordEvent.Start -> {
                        recordButton.text = "停止录像"
                        updateStatus("无声录像进行中；Android 摄像头隐私指示保持可见。")
                    }
                    is VideoRecordEvent.Finalize -> {
                        activeRecording?.close()
                        activeRecording = null
                        recordButton.text = "开始无声录像"
                        if (event.hasError()) {
                            runCatching { file.delete() }
                            updateStatus("录像失败：error=${event.error} cause=${event.cause?.message.orEmpty()}")
                        } else {
                            updateStatus("录像完成：${file.absolutePath}")
                        }
                    }
                }
            }
    }

    private fun outputDirectory(type: String): File {
        val base = getExternalFilesDir(type) ?: filesDir
        return File(base, "SecurityBoundaryLab").apply { mkdirs() }
    }

    private fun fileName(extension: String): String =
        "SECURITY_DEMO_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())}.$extension"

    private fun hasCameraPermission(): Boolean =
        checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

    private fun updateStatus(message: String) {
        if (::statusView.isInitialized) statusView.text = message
    }
}
