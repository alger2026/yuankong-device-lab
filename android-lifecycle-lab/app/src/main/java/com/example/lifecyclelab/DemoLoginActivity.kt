package com.example.lifecyclelab

import android.app.Activity
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.EditText
import android.widget.TextView

class DemoLoginActivity : Activity() {
    private lateinit var usernameInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var flowView: TextView
    private lateinit var resultView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(verticalPage {
            title("SECURITY DEMO — 模拟登录", Color.rgb(140, 45, 0))
            banner(
                "这不是任何真实服务的登录页。只能输入下方公开的虚构测试账号；" +
                    "请勿输入真实用户名、密码、PIN 或验证码。",
            )
            paragraph("虚构账号：${BoundaryRules.DEMO_USERNAME}")
            paragraph("虚构密码：${BoundaryRules.DEMO_PASSWORD}")

            section("Activity 本地输入")
            usernameInput = EditText(this@DemoLoginActivity).apply {
                hint = "虚构用户名"
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                setSaveEnabled(false)
                disableAutofill()
            }
            addView(usernameInput, usernameInput.matchWrap())

            passwordInput = EditText(this@DemoLoginActivity).apply {
                hint = "虚构密码"
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                setSaveEnabled(false)
                disableAutofill()
            }
            addView(passwordInput, passwordInput.matchWrap())

            actionButton("仅在本 Activity 内验证虚构账号") { validateDemoOnly() }
            actionButton("填入公开的虚构账号") {
                usernameInput.setText(BoundaryRules.DEMO_USERNAME)
                passwordInput.setText(BoundaryRules.DEMO_PASSWORD)
                recordFlow("按钮 → 两个 EditText（仅虚构常量）")
            }
            actionButton("立即清除") { clearInputs("用户主动清除") }

            section("App 内数据流")
            flowView = paragraph(
                "等待输入：IME → EditText Editable → 点击事件 → Activity 内存比较 → 结果 TextView",
            )
            resultView = paragraph("尚未验证")

            section("保证")
            paragraph(
                "Manifest 未声明 INTERNET 权限；本页面不写 SharedPreferences、文件或数据库，" +
                    "不写 Logcat，离开页面时会清空两个输入框。",
            )
            backButton(this)
        }.also {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                it.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            }
        })
    }

    override fun onStop() {
        clearInputs("Activity.onStop → 清空内存中的输入")
        super.onStop()
    }

    private fun validateDemoOnly() {
        val username = usernameInput.text.toString()
        val password = passwordInput.text.toString()
        val accepted = BoundaryRules.acceptsDemoCredentials(username, password)
        recordFlow(
            "点击 → Activity 读取长度(user=${username.length}, pass=${password.length}) " +
                "→ 与公开虚构常量比较 → ${if (accepted) "通过" else "拒绝"}",
        )
        resultView.text = if (accepted) {
            "通过：这是虚构账号的本地演示结果，没有建立会话。"
        } else {
            "拒绝：本实验只接受页面公开的虚构账号。"
        }
        passwordInput.text.clear()
    }

    private fun clearInputs(reason: String) {
        if (::usernameInput.isInitialized) usernameInput.text.clear()
        if (::passwordInput.isInitialized) passwordInput.text.clear()
        if (::flowView.isInitialized) recordFlow(reason)
    }

    private fun recordFlow(message: String) {
        flowView.text = message
    }

    private fun EditText.disableAutofill() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            setAutofillHints()
        }
    }
}
