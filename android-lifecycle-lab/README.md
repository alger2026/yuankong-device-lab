# Android Device Owner 安全边界实验

这是一个可直接用 Android Studio 打开的 Kotlin 实验工程，包名为
`com.example.lifecyclelab`，最低 Android 6.0（API 23），目标 Android 15（API 35）。

它不是完整 MDM，也没有远程控制或网络上传能力。Manifest **没有** `INTERNET`、
`RECORD_AUDIO`、Accessibility 或悬浮窗权限。所有实验都由设备上的可见 UI 启动。

## 实验内容与边界

### 1. 本 App 输入事件

`InputEventActivity` 提供单个 Demo 输入框，并在内存中显示：

- `Activity.dispatchKeyEvent`；
- View 的 `dispatchKeyEvent`、`onKeyDown`、`onKeyUp` 和 `onKeyPreIme`；
- 软键盘的 `InputConnection.commitText` / `setComposingText`；
- `TextWatcher` 的 before/on/after 阶段。

事件日志只显示 keyCode、范围和文本长度，不显示输入内容；退出 Activity 后清空。
工程没有 `AccessibilityService`，不能也不会读取其他 App 的输入。

### 2. SECURITY DEMO 模拟登录

`DemoLoginActivity` 始终显示 `SECURITY DEMO`，只接受页面公开的虚构账号：

```text
用户名：demo_user
密码：demo-pass-123
```

验证只是在 Activity 内与两个常量比较。页面禁用 View 状态保存和 Autofill，不写文件、
SharedPreferences、数据库或 Logcat；提交后立即清除密码，离开页面清除全部输入。

### 3. DEMO LOCK SCREEN

`DemoLockActivity` 始终显示：

```text
DEMO LOCK SCREEN — NOT SYSTEM LOCK SCREEN
```

页面演示 immersive fullscreen、`setShowWhenLocked()`、
`KeyguardManager.requestDismissKeyguard()` 和 Device Owner `lockNow()` 的差别：

- fullscreen 只隐藏当前 Activity 的系统栏；
- show-when-locked 只允许 Activity 显示在 Keyguard 上方；
- request-dismiss 把决定权交给系统，安全设备仍可能要求用户认证；
- lockNow 才是真实系统锁屏；
- App 不创建 PIN 控件，也不读取、验证或保存系统凭据。

### 4. MediaProjection

`ScreenCaptureActivity` 与 `ScreenCaptureService` 实现：

- 每次截图前显示 Android 系统 MediaProjection 授权页；
- 每次录屏前重新显示授权页；
- 一次 token、一个 `MediaProjection`、一次 `createVirtualDisplay()`；
- 录屏使用 `mediaProjection` 类型前台服务和持续通知；
- App 页面和通知都可停止录屏；
- 截图为 PNG，录屏为无声 H.264/MP4；
- 输出只写入本 App 的外部文件目录，不上传。

Android 13+ 时，本实验要求先允许通知；如果拒绝，为避免形成不明显的采集状态，实验不会
开始。Android 14+ 每个 capture session 都必须重新获得系统同意，代码不会缓存或复用
授权 `Intent`。

### 5. CameraX

`CameraExperimentActivity` 使用 CameraX 的 `Preview`、`ImageCapture` 和
`VideoCapture<Recorder>`：

- 仅在用户打开页面后正常请求 `CAMERA`；
- 实现后置摄像头预览、JPEG 拍照和无声 MP4 录像；
- 不声明麦克风权限；
- Activity 进入后台时主动停止录像；
- 不创建 camera 前台服务，不尝试隐藏系统摄像头隐私指示器。

照片和录像写入本 App 的外部文件目录。

### 6. 后台任务与 Launcher 图标

`LifecycleLauncherActivity` 使用 Android 框架 API 演示：

- 用 `JobScheduler` 安排一次性任务和系统允许的 15 分钟周期任务；
- 任务只记录执行次数、时间和 Job ID，不访问网络或用户数据；
- 用 `PackageManager.setComponentEnabledSetting()` 启用/禁用独立的
  `LauncherAlias`；
- 禁用的只是 Launcher 入口，App 仍显示在系统设置中，也不会因此获得常驻能力；
- `MainActivity` 保持 `exported=true`，所以图标禁用后仍能通过 ADB 显式启动。

这不是“隐身运行”：Android 可以延后、合并或取消后台任务，用户强行停止 App 后任务不会继续，
长时间工作仍必须使用带持续通知的前台服务。

## Device Owner 对照

| 实验 | 自动授予 | 禁止能力 | 改变授权流程 | 绕过授权 |
| --- | --- | --- | --- | --- |
| 本 App 输入事件 | 无需运行时权限 | 不能借此读取/禁止其他 App 输入 | 不改变 View/IME 分发 | **不支持**跨 App 输入读取 |
| 模拟登录 | 无需运行时权限 | 不能把 Activity 变成系统认证 UI | 不改变 App 内文本流转 | **不支持**获取系统凭据 |
| Demo 锁屏/Keyguard | 无需运行时权限 | 可条件性 `setKeyguardDisabled` | 可 `lockNow`；dismiss 仍由系统决定 | **不支持**绕过 PIN/图案/密码 |
| MediaProjection | 不能授予投屏；可固定通知权限 | 可 `setScreenCaptureDisabled` | 只能禁用，不能跳过系统同意 | **不支持**绕过系统授权页 |
| CameraX | 可固定授予/拒绝 `CAMERA` | 可 `setCameraDisabled` | 可改变 CAMERA 运行时权限是否弹窗 | **不支持**绕过隐私指示器和后台限制 |

`setKeyguardDisabled(true)` 在已有 PIN、图案或密码时返回 `false`，本实验直接展示结果，不尝试
替代方案。所有 Device Owner 策略都必须从“Device Owner 能力对照”页面手动点击。

## 构建

要求：

- JDK 17；
- Android SDK Platform 35；
- Build Tools 35.0.0；
- Android Studio 或项目自带 Gradle Wrapper。

```bash
cd /www/bb/yuankong/android-lifecycle-lab
./gradlew clean testDebugUnitTest lintDebug assembleDebug
```

APK：

```text
app/build/outputs/apk/debug/app-debug.apk
```

## 普通模式 ADB 测试

安装并启动：

```bash
adb devices
adb install -t -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.example.lifecyclelab/.MainActivity
```

### 输入实验

打开“本 App 输入事件”并点中输入框，然后输入虚构文本；也可在输入框已聚焦时执行：

```bash
adb shell input text SECURITY_DEMO_123
adb shell input keyevent KEYCODE_ENTER
```

页面应显示 Activity、View、InputConnection 和 TextWatcher 的分发记录。不要输入真实凭据。

### 模拟登录实验

只使用页面公开的 `demo_user` / `demo-pass-123`。提交后密码框应立即清空；按 Home 再返回时
两个输入框都应为空。

### Demo 锁屏实验

从首页进入 Demo。确认顶部始终显示非系统锁屏标记。点击“请求系统解除 Keyguard”时，是否
要求认证完全由 Android 决定；不要在 App 内输入系统 PIN。

### MediaProjection 实验

1. 点击截图或录屏按钮。
2. Android 13+ 先允许通知。
3. 在 Android 系统投屏授权页明确选择并确认。
4. 录屏时确认持续通知和系统采集指示可见。
5. 从页面或通知停止。

每次新截图/录屏都应重新出现系统授权页。输出目录可用以下命令查看：

```bash
adb shell find /sdcard/Android/data/com.example.lifecyclelab/files -type f
adb pull /sdcard/Android/data/com.example.lifecyclelab/files ./security-demo-output
```

若文件访问受设备 shell 策略限制，可直接用 Android Studio Device Explorer 查看 App 专属目录。

### CameraX 实验

1. 进入 CameraX 页面，点击“正常请求 CAMERA 权限”。
2. 允许后确认预览出现且系统隐私指示器可见。
3. 拍照并开始/停止无声录像。
4. 录像期间按 Home；录像应停止。

撤销权限后可重新验证正常授权流程：

```bash
adb shell pm revoke com.example.lifecyclelab android.permission.CAMERA
adb shell am force-stop com.example.lifecyclelab
adb shell am start -n com.example.lifecyclelab/.MainActivity
```

### 后台任务与 Launcher 图标实验

先从首页进入“后台任务与 Launcher 图标”，安排一次任务。可用以下命令观察调度和进程：

```bash
adb shell dumpsys jobscheduler com.example.lifecyclelab
adb shell pidof com.example.lifecyclelab
adb shell ps -A | grep com.example.lifecyclelab
```

在页面点击“禁用 Launcher 入口”后，等待 Launcher 刷新并确认图标消失。然后显式启动真实
Activity；该命令不依赖 Launcher alias：

```bash
adb shell am start -n com.example.lifecyclelab/.MainActivity
```

停止 App、取消调度任务和查看进程：

```bash
adb shell am force-stop com.example.lifecyclelab
adb shell cmd jobscheduler cancel com.example.lifecyclelab
adb shell pidof com.example.lifecyclelab
```

恢复 Launcher 图标：

```bash
adb shell pm enable --user 0 com.example.lifecyclelab/.LauncherAlias
adb shell am force-stop com.android.launcher3
```

最后一条命令仅用于使用 AOSP Launcher3 的测试模拟器刷新桌面；真机 Launcher 包名不同，通常
等待桌面自动刷新即可。也可以显式启动 App 后，在实验页点击“恢复 Launcher 入口”。

## 配置测试 Device Owner

只在可擦除的全新模拟器或专用测试设备上执行。Android 要求设备处于允许预配 Device Owner
的状态；如果系统拒绝命令，应 wipe 测试模拟器后重试，不要规避预配条件。

```bash
adb install -t -r app/build/outputs/apk/debug/app-debug.apk
adb shell dpm set-device-owner --user 0 \
  com.example.lifecyclelab/.LabDeviceAdminReceiver

adb shell dumpsys device_policy
adb shell am start -n com.example.lifecyclelab/.MainActivity
```

进入“Device Owner 能力对照”页面，可分别测试：

- 固定授予、固定拒绝、恢复用户控制 `CAMERA`；
- Android 13+ 固定授予、恢复用户控制通知权限；
- 禁用/恢复整台测试设备相机；
- 禁用/恢复屏幕截图和 MediaProjection；
- 条件性关闭/恢复 Keyguard；
- `lockNow()` 真实系统锁屏。

验证策略状态：

```bash
adb shell dumpsys device_policy | sed -n '1,240p'
adb shell dumpsys package com.example.lifecyclelab | grep -A 20 grantedPermissions
```

## 必须执行的恢复步骤

在页面中先执行：

1. 恢复整台设备相机；
2. 恢复系统屏幕截图/采集；
3. 重新启用系统 Keyguard；
4. 将 CAMERA 和通知权限恢复为用户控制。

然后移除测试 Device Owner 并卸载：

```bash
adb shell dpm remove-active-admin --user 0 \
  com.example.lifecyclelab/.LabDeviceAdminReceiver
adb uninstall com.example.lifecyclelab
```

`remove-active-admin` 依赖本 APK 的 `android:testOnly="true"`，仅用于实验恢复。

## Android 版本限制摘要

| 版本 | 与本实验相关的限制 |
| --- | --- |
| Android 6.0 / API 23 | CAMERA 使用运行时权限；Device Owner 可管理运行时权限状态。 |
| Android 7.0 / API 24 | Doze 和后台优化会批处理 Job；周期任务不能保证准点执行。 |
| Android 8.0 / API 26 | 后台 Service 执行受限，应使用 JobScheduler；`requestDismissKeyguard()` 仍由系统决定是否认证。 |
| Android 10 / API 29 | 目标 Q+ 的 MediaProjection 必须在 `mediaProjection` 前台服务中运行。 |
| Android 11 / API 30 | CAMERA 支持一次性授权；用户离开 App 后权限可能被系统撤回。 |
| Android 12 / API 31 | 后台启动前台服务受限；系统显示摄像头/麦克风隐私指示器。 |
| Android 13 / API 33 | 通知成为运行时权限；本实验未获通知权限时拒绝启动屏幕采集。 |
| Android 14 / API 34 | Job 必须及时完成；每次 MediaProjection session 都要重新同意。 |
| Android 15 / API 35 | 系统继续按配额调度后台工作；图标开关不会改变进程优先级或限制。 |

## 官方资料

- [MediaProjection 指南](https://developer.android.com/media/grow/media-projection)
- [Android 14：每次 MediaProjection 会话需要用户同意](https://developer.android.com/about/versions/14/behavior-changes-14#media-projection-consent)
- [CameraX 架构与权限](https://developer.android.com/media/camera/camerax/architecture)
- [CameraX 拍照](https://developer.android.com/media/camera/camerax/take-photo)
- [CameraX 录像](https://developer.android.com/media/camera/camerax/video-capture)
- [运行时权限工作流](https://developer.android.com/training/permissions/requesting)
- [`DevicePolicyManager`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager)
- [Android Enterprise Device control](https://developer.android.com/work/dpc/device-management)
