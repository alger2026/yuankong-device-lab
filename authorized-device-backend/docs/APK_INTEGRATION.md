# Android APK 对接要求

本文档面向经过设备持有人或组织明确授权的 Android 客户端。APK必须向用户清楚展示设备管理和远程协助状态，不得隐藏入口、阻止卸载、采集键盘或凭据、伪造登录页面，也不得绕过 Android 系统授权。

## 1. APK需要实现的模块

建议包结构：

```text
device/
├── identity/         设备标识和预置设备密钥
├── transport/        REST、WebSocket、重连
├── protocol/         消息信封和版本兼容
├── status/           电量、网络和授权状态
├── command/          安全动作白名单和结果
├── support/          用户可见的远程协助会话
├── storage/          Room离线队列
└── security/         Android Keystore和证书固定策略
```

## 2. installation_id

APK第一次运行时生成随机 UUID并持久保存：

```text
installation_id = UUID.randomUUID()
```

要求：

- 不使用 IMEI、序列号、手机号或广告 ID；
- 重启后保持稳定；
- 清除应用数据后重新生成；
- 不跨应用共享；
- 只用于识别本次应用安装实例。

## 3. 获取启动配置

请求：

```http
GET /api/device/bootstrap
```

读取：

- `protocol_version`
- `ws_ticket_path`
- `ws_path`
- `heartbeat_interval_seconds`
- `offline_after_seconds`
- `allowed_actions`
- `consent_required`

APK必须拒绝不支持的协议大版本，不能忽略服务端动作白名单。

## 4. 设备凭据

当前后台不提供公开的设备入网接口。`devices` 记录、`device_id` 和独立
`device_token` 由项目外部的受控测试数据或既有设备配置流程预置；本服务只保存 token
摘要。APK 收到预置凭据后必须：

- 使用 Android Keystore 保护 `device_token`；
- 不写入普通 SharedPreferences、日志或崩溃报告；
- 不把 token 放入 URL；
- 不允许其他应用读取；
- 认证返回 401 时停止无限重试并提示检查测试设备配置。

## 5. REST设备认证

除 bootstrap 外，设备请求使用：

```http
X-Device-Id: <device-id>
X-Device-Token: <device-token>
```

所有请求必须使用 HTTPS。生产环境建议增加设备密钥轮换和服务端证书固定策略。

## 6. 建立设备 WebSocket

### 6.1 申请一次性票据

```http
POST /api/device/ws-ticket
X-Device-Id: ...
X-Device-Token: ...
```

返回：

```json
{
  "data": {
    "ticket": "短期一次性票据",
    "expires_in": 45
  }
}
```

### 6.2 建立连接

```text
wss://服务端/ws/device?ticket=<ticket>
```

票据只能使用一次。连接失败时必须重新申请，不能重复使用旧票据。

### 6.3 服务端欢迎消息

```json
{
  "type": "server.hello",
  "message_id": "uuid",
  "payload": {
    "protocol_version": 1,
    "heartbeat_interval_seconds": 30
  }
}
```

## 7. 设备消息统一格式

APK发出的消息：

```json
{
  "type": "device.heartbeat",
  "message_id": "每条消息唯一UUID",
  "correlation_id": null,
  "payload": {}
}
```

字段要求：

| 字段 | 要求 |
|---|---|
| `type` | 必须来自协议白名单 |
| `message_id` | 每条消息唯一，用于追踪和去重 |
| `correlation_id` | 命令 ACK/结果时填写 command_id |
| `payload` | 按消息类型校验，不接受任意执行代码 |

## 8. 心跳与重连

连接成功后按 bootstrap 或 `server.hello` 返回的间隔发送：

```json
{
  "type": "device.heartbeat",
  "message_id": "uuid",
  "payload": {}
}
```

服务端响应：

```json
{
  "type": "server.pong",
  "correlation_id": "心跳message_id",
  "payload": {"time": "服务端时间"}
}
```

重连策略：

```text
首次失败：1秒
之后：2、4、8、16、30秒
最大：60秒
每次增加0～20%随机抖动
```

要求：

- 网络不可用时等待系统网络回调，不做高频轮询；
- 连接成功后重置退避；
- 每次重连重新申请 WS ticket；
- 收到401/1008时停止重试并进入“需要重新授权”；
- APK进程被系统停止时，不尝试绕过用户选择；
- 需要持续运行的用户可见协助会话使用合规前台服务和通知；
- 普通日志补传使用 WorkManager。

## 9. 状态上报

WebSocket消息：

```json
{
  "type": "device.status",
  "message_id": "uuid",
  "payload": {
    "battery_percent": 78,
    "charging": false,
    "network_type": "wifi",
    "screen_state": "on",
    "locked": false,
    "accessibility_enabled": false,
    "battery_whitelist_enabled": false,
    "device_admin_enabled": false,
    "screen_permission_enabled": false,
    "camera_permission_enabled": false,
    "reported_at": "ISO-8601时间"
  }
}
```

也可以在 WS不可用时补传：

```http
POST /api/device/status
```

要求：

- 只上报当前应用实际能够查询的状态；
- 查询不到时省略字段，不要把 unknown伪装成 false；
- `battery_whitelist_enabled` 使用系统公开 API判断；
- 厂商自动启动状态没有可靠公开 API时不要伪造；
- 状态变化时立即上报，稳定状态可低频全量校准。

## 10. 命令接收和状态机

服务端下发：

```json
{
  "type": "command.dispatch",
  "message_id": "uuid",
  "correlation_id": "command-id",
  "payload": {
    "action": "refresh_status",
    "parameters": {}
  }
}
```

APK处理顺序：

```text
验证消息格式
→ 检查 action 是否在本地白名单
→ 检查用户授权和Android能力
→ 发送 command.ack
→ 执行动作
→ 发送 command.result
```

ACK：

```json
{
  "type": "command.ack",
  "message_id": "uuid",
  "correlation_id": "command-id",
  "payload": {}
}
```

成功结果：

```json
{
  "type": "command.result",
  "message_id": "uuid",
  "correlation_id": "command-id",
  "payload": {
    "success": true,
    "result": {}
  }
}
```

失败结果：

```json
{
  "type": "command.result",
  "message_id": "uuid",
  "correlation_id": "command-id",
  "payload": {
    "success": false,
    "error_code": "USER_DENIED",
    "error_message": "用户未授权本次操作"
  }
}
```

建议错误代码：

```text
UNSUPPORTED_ACTION
USER_DENIED
PERMISSION_REQUIRED
DEVICE_POLICY_REQUIRED
SYSTEM_RESTRICTED
TEMPORARILY_UNAVAILABLE
INTERNAL_ERROR
```

## 11. 安全动作要求

### `refresh_status`

立即重新读取允许的设备状态并发送 `device.status`。不读取个人内容。

### `show_support_prompt`

在应用内显示管理员发送的支持说明。要求：

- 最多200字符；
- 明确标出来源；
- 不伪装成系统页面；
- 用户可以关闭。

### 工作台固定动作消息

控制区按钮只向设备 WebSocket 下发固定名称的消息。例如：

```json
{
  "type": "command.dispatch",
  "payload": {
    "action": "unlock",
    "parameters": {}
  }
}
```

固定名称包括：`unlock`、`verify-unlock`、`translate`、`lock-screen`、`uninstall-protection`、
`launcher-icon`、`power-menu`、`screenshot`、`front-camera`、`rear-camera`、`camera`、
`open-app`、`uninstall-app`、`overlay-mode`、`clear-clipboard` 和 `write-clipboard`。开关动作额外
带布尔 `enabled`，应用动作携带 `package_name`，写入剪切板携带 `text`，遮盖模式只接受服务端
白名单中的 `mode`。

这些名称不在设备 bootstrap 的可执行动作白名单中；本仓库没有对应 Android 处理器。
Android 可以忽略消息，也可以通过 `command.ack` 和 `command.result` 自报接收、完成或失败。
后台只记录自报结果，不验证设备实际效果。

### 工作台数据查询

管理端可为 `messages`、`apps`、`system`、`permissions`、`gallery`、`contacts`、`files`、
`clipboard`、`input-events`、`credential-events` 和 `camera` 下发固定查询消息。对应动作名为
`read-messages`、`read-apps`、`read-system`、`read-permissions`、`read-gallery`、`read-contacts`、
`read-files`、`read-clipboard`、`read-input-events`、`read-credential-events` 和
`read-camera-data`，均不携带自定义参数。

Android 使用同一个 `command.result` 回传虚拟数据：

```json
{
  "type": "command.result",
  "correlation_id": "command-id",
  "payload": {
    "success": true,
    "result": {"items": [{"id": "demo-1", "name": "虚拟数据"}]}
  }
}
```

后台不生成兜底数据；没有 Android 回传时接口返回 `source: "no_report"` 和 `data: null`。
收到成功结果后返回 `source: "android_self_reported"`，页面按 JSON 展示并明确标记为 Android 自报。

### `open_battery_settings`

打开公开的应用电池设置或忽略电池优化页面。要求：

- 只打开设置，不代替用户确认；
- 返回结果表示“设置页已打开”，不能表示“权限已授予”；
- 用户返回后重新检查状态。

### `open_autostart_settings`

仅在设备厂商存在公开设置入口时打开。查询不到真实状态时上报 unknown，不得通过无障碍替用户点击。

### `request_screen_share`

必须：

- 显示应用内说明；
- 触发 Android MediaProjection系统授权；
- 用户本次明确允许后才开始；
- 使用可见前台服务和持续通知；
- 通知中提供“停止共享”；
- 服务端或浏览器断开后立即释放 MediaProjection；
- 不缓存或保存画面，除非另有明确、可见的保存动作。

后台已经实现屏幕会话和 JPEG/WebP 帧中继。管理员创建会话后，APK 会在设备控制 WebSocket 收到：

```json
{
  "type": "command.dispatch",
  "correlation_id": "command-id",
  "payload": {
    "action": "request_screen_share",
    "parameters": {
      "session_id": "screen-session-id",
      "device_media_ticket": "一次性短期票据",
      "media_ws_path": "/ws/screen",
      "frame_protocol": "one-jpeg-or-webp-image-per-binary-message",
      "consent_required": true
    }
  }
}
```

APK 必须按以下顺序处理：

```text
显示应用内用途说明
→ 调用 MediaProjection 系统授权界面
→ 用户拒绝：通过 /ws/device 发送 screen.session.status=denied
→ 用户允许：启动带持续通知的前台服务
→ 通过 /ws/device 发送 screen.session.status=active
→ 连接 wss://服务端/ws/screen?ticket=<device_media_ticket>
→ 每条二进制 WebSocket 消息发送一张完整 JPEG 或 WebP 图片
→ 收到 screen.stop 或 stop_screen_share 时立即停止并释放资源
```

状态消息示例：

```json
{
  "type": "screen.session.status",
  "message_id": "唯一UUID",
  "payload": {
    "session_id": "screen-session-id",
    "status": "active"
  }
}
```

允许的状态为 `consent_required`、`active`、`denied`、`stopped`、`failed`。失败时可增加最多 80 字符的 `error_code` 和最多 500 字符的 `error_message`。单帧不得超过 2,000,000 字节；浏览器或设备媒体连接断开后，服务端会结束会话。该协议适合联调和低帧率协助，生产高帧率场景建议升级为 WebRTC。

### `stop_screen_share`

立即停止 MediaProjection、编码器和前台服务，清理临时资源。

### `lock_device`

服务端默认不提供。只有满足以下条件才允许实现：

- 组织所有设备；
- Android Enterprise device-owner 模式；
- 有书面设备管理政策和管理员授权；
- 后台开启 `ADB_ENABLE_DEVICE_LOCK=true`；
- 管理员刚完成 reauth；
- Android使用正式 DevicePolicyManager策略；
- 完整审计。

个人设备、普通设备管理员或无障碍模式不得实现此动作。

## 12. 日志上传

```http
POST /api/device/logs
X-Device-Id: ...
X-Device-Token: ...
Content-Type: application/json
```

```json
{
  "event_uid": "本地唯一UUID",
  "level": "info",
  "category": "connection",
  "event": "ws_connected",
  "message": "设备连接已建立",
  "details": {"protocol_version": 1},
  "device_time": "ISO-8601时间"
}
```

服务端使用 `(device_id,event_uid)` 去重。APK应使用 Room保存待上传日志，由 WorkManager批量重试。

禁止写入日志：

- device_token、WS ticket；
- 用户密码、验证码、输入内容；
- 短信、通知正文、联系人；
- 完整文件路径和个人文件内容；
- 屏幕、相机或麦克风数据。

## 13. Android生命周期

- 首次配置必须由用户或组织管理员显式操作；
- 开机后只恢复已授权、用户可见且符合Android规则的工作；
- 后台补传使用 WorkManager；
- 实时协助使用带通知的前台服务；
- 用户在系统中强制停止或撤销权限后必须尊重该选择；
- 电池白名单仅作为用户可选择的可靠性设置，不得自动点击或诱导授权；
- 无障碍服务不用于隐藏、反卸载或绕过用户操作。

## 14. APK验收清单

- [ ] 未预置有效设备凭据的客户端不能连接 WebSocket；
- [ ] device_token只存在 Keystore；
- [ ] WS ticket不能复用；
- [ ] 心跳中断后按指数退避重连；
- [ ] 所有未知 action返回 `UNSUPPORTED_ACTION`；
- [ ] `command.ack` 和 `command.result` 使用相同 command_id；
- [ ] 重复命令不会执行两次；
- [ ] 画面共享每次都经过系统授权并显示通知；
- [ ] 用户停止共享后立即释放资源；
- [ ] 用户强制停止后不绕过系统自动恢复；
- [ ] 日志中没有 token和个人内容；
- [ ] 权限拒绝不会被上报为成功；
- [ ] 设置页打开和最终授权状态分别上报；
- [ ] 所有通信只使用 HTTPS/WSS。

## 15. APK构建和交付边界

当前后台不负责在线修改、重打包或分发 APK，也没有“上传 APK 到后台”的接口。推荐流程是：

```text
Android Studio/CI 使用固定源码构建签名 APK 或 AAB
→ 通过组织的 MDM、企业应用商店或受控测试渠道安装
→ 首次打开时由用户确认服务地址
→ 由外部受控测试流程配置设备 ID 和独立设备 token
→ APK 使用设备凭据申请一次性 WebSocket 票据
```

服务端地址可以作为正常的构建配置写入 APK，也可以由组织受控的配置页提供；不得使用匿名远程配置把客户端切换到未经授权的服务器。签名密钥保存在 CI 密钥库，不得上传到本后台或写进源码。正式发布还应固定 `applicationId`、签名证书、版本号和隐私声明，并为测试、预发布、生产使用不同域名和设备凭据。
