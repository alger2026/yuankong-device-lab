package com.example.lifecyclelab

import android.app.Activity
import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import java.text.DateFormat
import java.util.Date

class LifecycleLauncherActivity : Activity() {
    private lateinit var statusView: TextView

    private val scheduler by lazy {
        getSystemService(Context.JOB_SCHEDULER_SERVICE) as JobScheduler
    }
    private val jobService by lazy { ComponentName(this, LabJobService::class.java) }
    private val launcherAlias by lazy { ComponentName(packageName, "$packageName.LauncherAlias") }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(verticalPage {
            title("后台任务与 Launcher 入口")
            banner(
                "LIFECYCLE DEMO — 使用 Android JobScheduler 和组件启停 API；" +
                    "不常驻保活、不隐藏通知，也不绕过系统后台限制。",
            )
            paragraph(
                "关闭 Launcher 入口只会让桌面图标消失，不会伪装应用、隐藏系统设置中的应用，" +
                    "也不保证进程继续运行。关闭后仍可用 ADB 显式启动 MainActivity。",
            )

            section("JobScheduler 后台任务")
            actionButton("安排一次任务（最早约 2 秒后）") { scheduleOneOffJob() }
            actionButton("安排周期任务（系统最小周期 15 分钟）") { schedulePeriodicJob() }
            actionButton("取消本实验的全部后台任务") { cancelJobs() }

            section("Launcher 图标")
            actionButton("禁用 Launcher 入口") { setLauncherEnabled(false) }
            actionButton("恢复 Launcher 入口") { setLauncherEnabled(true) }

            section("当前状态")
            statusView = paragraph("正在读取状态…")
            actionButton("刷新状态") { refreshStatus() }

            section("Android 限制摘要")
            paragraph(
                "• Android 7+：Doze/省电策略会延后和批处理任务。\n" +
                    "• Android 8+：后台 Service 受限，应使用 JobScheduler；长任务需可见前台服务。\n" +
                    "• Android 12+：后台启动前台服务受到额外限制。\n" +
                    "• Android 14+：JobScheduler 会更严格检查任务及时完成。\n" +
                    "• 强行停止 App 后，系统会停止其任务，直到用户再次启动应用。",
            )
            backButton(this)
        })
    }

    override fun onResume() {
        super.onResume()
        if (::statusView.isInitialized) refreshStatus()
    }

    private fun scheduleOneOffJob() {
        val result = scheduler.schedule(
            JobInfo.Builder(LabJobService.ONE_OFF_JOB_ID, jobService)
                .setMinimumLatency(2_000L)
                .setOverrideDeadline(15_000L)
                .build(),
        )
        showScheduleResult("一次任务", result)
    }

    private fun schedulePeriodicJob() {
        val result = scheduler.schedule(
            JobInfo.Builder(LabJobService.PERIODIC_JOB_ID, jobService)
                .setPeriodic(LabJobService.MIN_PERIOD_MILLIS)
                .build(),
        )
        showScheduleResult("周期任务", result)
    }

    private fun showScheduleResult(label: String, result: Int) {
        val message = if (result == JobScheduler.RESULT_SUCCESS) {
            "${label}已交给系统调度；实际执行时间由 Android 决定"
        } else {
            "${label}安排失败"
        }
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        refreshStatus()
    }

    private fun cancelJobs() {
        scheduler.cancel(LabJobService.ONE_OFF_JOB_ID)
        scheduler.cancel(LabJobService.PERIODIC_JOB_ID)
        Toast.makeText(this, "已取消本实验的后台任务", Toast.LENGTH_SHORT).show()
        refreshStatus()
    }

    private fun setLauncherEnabled(enabled: Boolean) {
        packageManager.setComponentEnabledSetting(
            launcherAlias,
            if (enabled) {
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            } else {
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            },
            PackageManager.DONT_KILL_APP,
        )
        Toast.makeText(
            this,
            if (enabled) "Launcher 入口已恢复" else "Launcher 入口已禁用；可用 ADB 显式启动",
            Toast.LENGTH_LONG,
        ).show()
        refreshStatus()
    }

    private fun refreshStatus() {
        val preferences = getSharedPreferences(LabJobService.PREFERENCES, Context.MODE_PRIVATE)
        val lastRunAt = preferences.getLong(LabJobService.KEY_LAST_RUN_AT, 0L)
        val pendingIds = scheduler.allPendingJobs
            .filter { it.id == LabJobService.ONE_OFF_JOB_ID || it.id == LabJobService.PERIODIC_JOB_ID }
            .map { it.id }
            .sorted()
        val componentState = packageManager.getComponentEnabledSetting(launcherAlias)
        val launcherEnabled = componentState != PackageManager.COMPONENT_ENABLED_STATE_DISABLED &&
            componentState != PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER

        statusView.text = buildString {
            appendLine("Launcher 入口：${if (launcherEnabled) "启用" else "禁用"}")
            appendLine(
                "等待系统执行的 Job ID：" +
                    if (pendingIds.isEmpty()) "无" else pendingIds.joinToString(),
            )
            appendLine("累计执行次数：${preferences.getInt(LabJobService.KEY_RUN_COUNT, 0)}")
            appendLine("最后 Job ID：${preferences.getInt(LabJobService.KEY_LAST_JOB_ID, -1)}")
            append(
                "最后执行：" + if (lastRunAt == 0L) {
                    "尚未执行"
                } else {
                    DateFormat.getDateTimeInstance().format(Date(lastRunAt))
                },
            )
        }
    }
}
