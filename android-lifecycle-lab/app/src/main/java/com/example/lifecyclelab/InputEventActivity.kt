package com.example.lifecyclelab

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.KeyEvent
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inputmethod.InputConnectionWrapper
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

class InputEventActivity : Activity() {
    private lateinit var eventLogView: TextView
    private lateinit var demoInput: TraceEditText
    private val events = ArrayDeque<String>()
    private var sequence = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(verticalPage {
            title("本 App 输入事件实验")
            banner("只观察下面这个 Demo 输入框；不含 AccessibilityService，也不读取其他 App。")
            paragraph(
                "硬件按键通常经过 Activity.dispatchKeyEvent → View.dispatchKeyEvent → " +
                    "onKeyDown/onKeyUp。软键盘常直接调用 InputConnection.commitText，" +
                    "随后触发 TextWatcher，不一定产生 KeyEvent。日志只记录长度和 keyCode，不记录文本内容。",
            )

            demoInput = TraceEditText(this@InputEventActivity, ::recordEvent).apply {
                hint = "在此输入虚构测试文本"
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                isSingleLine = false
                minLines = 3
                maxLines = 6
                setPadding(dp(12), dp(12), dp(12), dp(12))
                setSaveEnabled(false)
            }
            addView(demoInput, demoInput.matchWrap())

            actionButton("清空输入与内存事件") {
                demoInput.text.clear()
                events.clear()
                sequence = 0
                eventLogView.text = "事件日志已清空"
            }

            section("事件产生与分发（仅内存）")
            eventLogView = paragraph("点击输入框并开始输入。")
            backButton(this)
        })
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        if (::demoInput.isInitialized && demoInput.hasFocus()) {
            recordEvent(
                "Activity.dispatchKeyEvent action=${event.action.label()} " +
                    "keyCode=${KeyEvent.keyCodeToString(event.keyCode)}",
            )
        }
        return super.dispatchKeyEvent(event)
    }

    override fun onDestroy() {
        if (::demoInput.isInitialized) demoInput.text.clear()
        events.clear()
        super.onDestroy()
    }

    private fun recordEvent(message: String) {
        sequence += 1
        events.addLast("$sequence. $message")
        while (events.size > MAX_EVENTS) events.removeFirst()
        if (::eventLogView.isInitialized) eventLogView.text = events.joinToString("\n")
    }

    private fun Int.label(): String = when (this) {
        KeyEvent.ACTION_DOWN -> "DOWN"
        KeyEvent.ACTION_UP -> "UP"
        else -> toString()
    }

    companion object {
        private const val MAX_EVENTS = 80
    }
}

@SuppressLint("ViewConstructor")
private class TraceEditText(
    context: Context,
    private val trace: (String) -> Unit,
) : EditText(context) {
    init {
        addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) {
                trace("TextWatcher.before start=$start removed=$count added=$after")
            }

            override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) {
                trace("TextWatcher.on start=$start before=$before count=$count totalLength=${text?.length ?: 0}")
            }

            override fun afterTextChanged(text: Editable?) {
                trace("TextWatcher.after totalLength=${text?.length ?: 0}")
            }
        })
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        trace(
            "View.dispatchKeyEvent action=${event.action} " +
                "keyCode=${KeyEvent.keyCodeToString(event.keyCode)}",
        )
        return super.dispatchKeyEvent(event)
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent?): Boolean {
        trace("View.onKeyDown keyCode=${KeyEvent.keyCodeToString(keyCode)}")
        return super.onKeyDown(keyCode, event)
    }

    override fun onKeyUp(keyCode: Int, event: KeyEvent?): Boolean {
        trace("View.onKeyUp keyCode=${KeyEvent.keyCodeToString(keyCode)}")
        return super.onKeyUp(keyCode, event)
    }

    override fun onKeyPreIme(keyCode: Int, event: KeyEvent?): Boolean {
        trace("View.onKeyPreIme keyCode=${KeyEvent.keyCodeToString(keyCode)}")
        return super.onKeyPreIme(keyCode, event)
    }

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection? {
        val target = super.onCreateInputConnection(outAttrs) ?: return null
        trace("View.onCreateInputConnection：软键盘输入通道已创建")
        return object : InputConnectionWrapper(target, true) {
            override fun commitText(text: CharSequence?, newCursorPosition: Int): Boolean {
                trace("IME.commitText length=${text?.length ?: 0} → Editable")
                return super.commitText(text, newCursorPosition)
            }

            override fun setComposingText(text: CharSequence?, newCursorPosition: Int): Boolean {
                trace("IME.setComposingText length=${text?.length ?: 0} → Editable")
                return super.setComposingText(text, newCursorPosition)
            }

            override fun deleteSurroundingText(beforeLength: Int, afterLength: Int): Boolean {
                trace("IME.deleteSurroundingText before=$beforeLength after=$afterLength")
                return super.deleteSurroundingText(beforeLength, afterLength)
            }
        }
    }
}
