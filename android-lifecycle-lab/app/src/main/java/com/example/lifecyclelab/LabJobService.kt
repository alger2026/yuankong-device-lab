package com.example.lifecyclelab

import android.app.job.JobParameters
import android.app.job.JobService
import android.content.Context

/**
 * Small, bounded JobScheduler task used to observe process recreation and
 * scheduler timing. It has no network access and stores only a counter/time.
 */
class LabJobService : JobService() {
    override fun onStartJob(params: JobParameters?): Boolean {
        val preferences = getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        val nextCount = preferences.getInt(KEY_RUN_COUNT, 0) + 1
        preferences.edit()
            .putInt(KEY_RUN_COUNT, nextCount)
            .putLong(KEY_LAST_RUN_AT, System.currentTimeMillis())
            .putInt(KEY_LAST_JOB_ID, params?.jobId ?: -1)
            .apply()

        // The experiment is deliberately tiny, so all work is complete here.
        return false
    }

    override fun onStopJob(params: JobParameters?): Boolean = false

    companion object {
        const val PREFERENCES = "job_scheduler_lab"
        const val KEY_RUN_COUNT = "run_count"
        const val KEY_LAST_RUN_AT = "last_run_at"
        const val KEY_LAST_JOB_ID = "last_job_id"

        const val ONE_OFF_JOB_ID = 7101
        const val PERIODIC_JOB_ID = 7102
        const val MIN_PERIOD_MILLIS = 15 * 60 * 1000L
    }
}
