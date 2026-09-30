package com.example.lifecyclelab

import android.app.Application
import android.content.Context
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraManager
import androidx.camera.camera2.Camera2Config
import androidx.camera.core.CameraSelector
import androidx.camera.core.CameraXConfig

class SecurityLabApplication : Application(), CameraXConfig.Provider {
    override fun getCameraXConfig(): CameraXConfig {
        val builder = CameraXConfig.Builder.fromConfig(Camera2Config.defaultConfig())
        detectAvailableLensFacing()?.let { selector ->
            builder.setAvailableCamerasLimiter(selector)
        }
        return builder.build()
    }

    private fun detectAvailableLensFacing(): CameraSelector? = runCatching {
        val manager = getSystemService(Context.CAMERA_SERVICE) as CameraManager
        val lensFacings = manager.cameraIdList.mapNotNull { id ->
            manager.getCameraCharacteristics(id)
                .get(CameraCharacteristics.LENS_FACING)
        }
        when {
            CameraCharacteristics.LENS_FACING_BACK in lensFacings ->
                CameraSelector.DEFAULT_BACK_CAMERA
            CameraCharacteristics.LENS_FACING_FRONT in lensFacings ->
                CameraSelector.DEFAULT_FRONT_CAMERA
            else -> null
        }
    }.getOrNull()
}
