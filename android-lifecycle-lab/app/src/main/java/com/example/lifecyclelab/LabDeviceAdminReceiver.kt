package com.example.lifecyclelab

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import android.widget.Toast

class LabDeviceAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        Log.i(TAG, "Device admin enabled")
        Toast.makeText(context, "Security Boundary Lab DPC 已启用", Toast.LENGTH_SHORT).show()
    }

    override fun onDisabled(context: Context, intent: Intent) {
        Log.i(TAG, "Device admin disabled")
        Toast.makeText(context, "实验 DPC 已停用", Toast.LENGTH_SHORT).show()
    }

    companion object {
        private const val TAG = "SecurityBoundaryDpc"
    }
}
