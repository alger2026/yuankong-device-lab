package com.example.lifecyclelab

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

internal fun Activity.dp(value: Int): Int =
    (value * resources.displayMetrics.density).toInt()

internal fun Activity.verticalPage(
    content: LinearLayout.() -> Unit,
): ScrollView {
    val column = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(20), dp(20), dp(20), dp(40))
        content()
    }
    return ScrollView(this).apply { addView(column) }
}

internal fun LinearLayout.title(text: String, color: Int = Color.rgb(6, 74, 54)) {
    addView(TextView(context).apply {
        this.text = text
        textSize = 25f
        setTextColor(color)
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, 0, 0, context.dpValue(10))
    })
}

internal fun LinearLayout.banner(text: String) {
    addView(TextView(context).apply {
        this.text = text
        textSize = 15f
        setTextColor(Color.rgb(115, 44, 0))
        setBackgroundColor(Color.rgb(255, 239, 204))
        setPadding(context.dpValue(14), context.dpValue(12), context.dpValue(14), context.dpValue(12))
    }, matchWrap().apply { bottomMargin = context.dpValue(14) })
}

internal fun LinearLayout.paragraph(text: String, color: Int = Color.DKGRAY): TextView {
    return TextView(context).apply {
        this.text = text
        textSize = 15f
        setTextColor(color)
        setLineSpacing(0f, 1.15f)
        setPadding(0, context.dpValue(4), 0, context.dpValue(10))
        this@paragraph.addView(this)
    }
}

internal fun LinearLayout.section(text: String) {
    addView(TextView(context).apply {
        this.text = text
        textSize = 18f
        setTextColor(Color.rgb(6, 74, 54))
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, context.dpValue(16), 0, context.dpValue(6))
    })
}

internal fun LinearLayout.actionButton(label: String, onClick: () -> Unit): Button {
    return Button(context).apply {
        text = label
        isAllCaps = false
        setOnClickListener { onClick() }
        this@actionButton.addView(this, matchWrap().apply {
            topMargin = context.dpValue(4)
            bottomMargin = context.dpValue(4)
        })
    }
}

internal fun Activity.backButton(column: LinearLayout) {
    column.actionButton("返回实验首页") { finish() }
}

internal fun View.matchWrap(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(
    ViewGroup.LayoutParams.MATCH_PARENT,
    ViewGroup.LayoutParams.WRAP_CONTENT,
)

internal fun centeredWrap(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(
    ViewGroup.LayoutParams.WRAP_CONTENT,
    ViewGroup.LayoutParams.WRAP_CONTENT,
).apply { gravity = Gravity.CENTER_HORIZONTAL }

private fun android.content.Context.dpValue(value: Int): Int =
    (value * resources.displayMetrics.density).toInt()

