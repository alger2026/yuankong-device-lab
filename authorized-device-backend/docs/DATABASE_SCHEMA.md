# 数据表与字段说明

本文对应当前代码中的 SQLite 实际结构，不是对旧项目数据库的猜测。建表语句位于 `app/db.py`。时间字段分两类：带 `_epoch` 的字段是 Unix 秒，其他时间字段是 UTC ISO-8601 字符串。

## 数据从哪里来

| 数据 | 写入来源 | 主要表 |
|---|---|---|
| 后台账号、登录状态 | 服务端初始化和管理端登录 | `users`、`sessions` |
| 设备静态信息 | 外部受控流程预置；APK 后续使用设备凭据连接 | `devices` |
| 电量、网络、屏幕及权限状态 | APK 通过 `/ws/device` 的 `device.status`，或 `POST /api/device/status` | `device_status` |
| 在线状态 | `/ws/device` 当前是否存在有效连接；断连或心跳超时后置为离线 | `device_status`、`device_sessions` |
| 控制请求和执行结果 | 浏览器创建命令，APK 返回 ACK/result | `commands` |
| 运行日志 | APK 调用 `POST /api/device/logs` | `device_logs` |
| 敏感动作留痕 | 服务端在事务中写入 | `audit_logs` |
| WebSocket 临时凭证 | 浏览器或 APK 先通过 HTTP 申请 | `ws_tickets` |
| 分组、备注和电池说明 | 管理前端维护 | `device_groups`、`devices`、`battery_guides` |
| 支持消息模板 | 管理员或操作员维护 | `message_templates` |
| 屏幕协助会话 | 浏览器发起、APK明确同意、媒体连接状态变化 | `screen_sessions`、`screen_stream_tickets` |

`online` 的权威来源是本进程的实时 WebSocket 连接表，数据库中的值是供列表查询使用的快照。服务重启时会把残留的在线值全部清零，不能仅凭 APK 最后一次上报的布尔值判断在线。

## `users`：后台账号

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | TEXT PK | 用户 UUID |
| `username` | TEXT UNIQUE | 登录名 |
| `password_hash` | TEXT | PBKDF2 密码摘要，不保存明文 |
| `role` | TEXT | `admin`、`operator` 或 `viewer` |
| `status` | TEXT | `active` 或 `disabled` |
| `created_at` | TEXT | 创建时间 |

首次启动创建一个管理员，之后可由管理员在账号管理页面新增账号、修改角色或状态、重置密码。敏感账号操作要求最近二次验证。

## `sessions`：管理端登录会话

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | TEXT PK | 会话 UUID |
| `user_id` | TEXT FK | 对应 `users.id` |
| `token_hash` | TEXT UNIQUE | Bearer token 的 SHA-256 摘要 |
| `created_at_epoch` | INTEGER | 登录时间 |
| `expires_at_epoch` | INTEGER | 会话过期时间 |
| `reauth_at_epoch` | INTEGER NULL | 最近一次敏感操作二次验证时间 |
| `revoked_at_epoch` | INTEGER NULL | 退出登录后的撤销时间 |

## `devices`：设备静态档案

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | TEXT PK | 服务端分配的 `device_id` |
| `installation_id` | TEXT UNIQUE | APK 首次运行生成的安装实例 UUID，不使用 IMEI |
| `owner_user_id` | TEXT FK | 设备归属账号 |
| `group_id` | TEXT FK NULL | 可选设备分组，对应 `device_groups.id` |
| `name` | TEXT | 用户确认的设备名称 |
| `note` | TEXT | 管理员维护的设备备注 |
| `brand` | TEXT | APK 上报的 `Build.BRAND` |
| `model` | TEXT | APK 上报的 `Build.MODEL` |
| `android_version` | TEXT | Android 版本 |
| `sdk_int` | INTEGER | Android SDK API level |
| `package_name` | TEXT | 客户端包名 |
| `app_version` | TEXT | 客户端版本 |
| `device_token_hash` | TEXT | 每台设备独立 token 的摘要，原文由外部受控流程交付 |
| `first_seen_at` | TEXT | 首次发现时间 |
| `last_seen_at` | TEXT | 最近收到设备 HTTP/WS 消息的时间 |
| `created_at` | TEXT | 数据行创建时间 |
| `updated_at` | TEXT | 最近更新时间 |

## `device_groups`：设备分组

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | TEXT PK | 分组 UUID |
| `owner_user_id` | TEXT FK | 分组创建者及非管理员可见范围 |
| `name` | TEXT | 同一所有者下唯一的分组名称 |
| `description` | TEXT | 分组说明 |
| `created_at` | TEXT | 创建时间 |
| `updated_at` | TEXT | 修改时间 |

## `battery_guides`：品牌/型号电池设置说明

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | TEXT PK | 设置说明 UUID |
| `brand` | TEXT | 品牌，`*` 表示通用兜底 |
| `model_pattern` | TEXT | 型号通配模式，如 `14*` 或 `*` |
| `title` | TEXT | 用户可见标题 |
| `steps_json` | TEXT | 用户需要手动完成的步骤数组 |
| `enabled` | INTEGER | 是否启用 |
| `created_by` | TEXT FK NULL | 创建管理员 |
| `created_at` | TEXT | 创建时间 |
| `updated_at` | TEXT | 修改时间 |

服务端按照“品牌精确、型号精确度最高、通用说明兜底”的规则匹配。该配置只提供说明，不替用户点击系统设置。

## `message_templates`：用户可见的支持说明模板

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | TEXT PK | 模板 UUID |
| `owner_user_id` | TEXT FK | 创建者及非管理员可见范围 |
| `name` | TEXT | 同一创建者下唯一的模板名 |
| `content` | TEXT | 最多 200 字符的支持说明，不得包含欺骗性系统提示 |
| `enabled` | INTEGER | 是否可在设备操作窗口选择 |
| `created_at` | TEXT | 创建时间 |
| `updated_at` | TEXT | 修改时间 |

## `device_status`：设备当前状态快照

| 字段 | 类型 | 备注 |
|---|---|---|
| `device_id` | TEXT PK/FK | 对应 `devices.id`，一台设备一行 |
| `online` | INTEGER | `1` 在线、`0` 离线，由服务端连接状态维护 |
| `battery_percent` | INTEGER NULL | 0～100；APK 查询不到时不传 |
| `charging` | INTEGER NULL | 是否充电 |
| `network_type` | TEXT NULL | 如 `wifi`、`cellular`、`none` |
| `screen_state` | TEXT | `on`、`off`、`locked` 或 `unknown` |
| `locked` | INTEGER NULL | APK 能确认时上报的系统锁定状态 |
| `lock_state_code` | INTEGER NULL | 兼容 APK 的 `lock` 原值：0 息屏、1 锁屏、2 已解锁桌面、3 已解锁其他前台 |
| `accessibility_enabled` | INTEGER NULL | 本应用无障碍服务是否启用，只用于状态展示 |
| `battery_whitelist_enabled` | INTEGER NULL | 是否忽略本应用电池优化 |
| `device_admin_enabled` | INTEGER NULL | 合规设备管理能力状态 |
| `screen_permission_enabled` | INTEGER NULL | 当前是否具备屏幕共享条件，不代表可静默采集 |
| `camera_permission_enabled` | INTEGER NULL | 相机权限状态，仅作清单展示 |
| `reported_at` | TEXT NULL | APK 声明的采集时间 |
| `updated_at` | TEXT | 服务端写入该快照的时间 |

数据库中的 SQLite 布尔值使用 `0/1`。字段允许 `NULL` 是为了区分“关闭”和“APK 无法判断”。

## `device_sessions`：设备长连接历史

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | TEXT PK | 本次连接的会话 UUID |
| `device_id` | TEXT FK | 对应设备 |
| `socket_id` | TEXT | 进程内连接标识，不是认证凭证 |
| `connected_at` | TEXT | WebSocket 建立时间 |
| `last_heartbeat_at` | TEXT | 最近收到任何有效设备消息的时间 |
| `disconnected_at` | TEXT NULL | 断开时间 |
| `disconnect_reason` | TEXT NULL | `socket_closed`、`heartbeat_timeout`、`server_restart` 或被新连接替换 |

同一设备只保留一个当前活动连接。新连接会关闭旧连接并结束旧会话记录。

## `commands`：命令状态机

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | TEXT PK | `command_id`，同时作为 WS `correlation_id` |
| `device_id` | TEXT FK | 目标设备 |
| `operator_id` | TEXT FK | 发起操作的后台用户 |
| `action` | TEXT | 服务端白名单中的动作名 |
| `payload_json` | TEXT | 经动作级校验后的参数 JSON |
| `status` | TEXT | `queued`、`sent`、`acknowledged`、`success` 或 `failed` |
| `queued_at` | TEXT | 创建时间 |
| `sent_at` | TEXT NULL | 写入设备连接的时间 |
| `acknowledged_at` | TEXT NULL | APK 确认收到的时间 |
| `completed_at` | TEXT NULL | 最终成功或失败时间 |
| `error_code` | TEXT NULL | 失败代码，如 `USER_DENIED` |
| `error_message` | TEXT NULL | 截断后的失败说明，不允许包含隐私数据 |
| `result_json` | TEXT NULL | 非敏感结构化结果 |

设备离线时，当前 MVP 不排队，命令会保存为 `failed/DEVICE_OFFLINE` 并向浏览器返回 HTTP 409。

## `device_logs`：APK 运行日志

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | INTEGER PK | 自增编号 |
| `device_id` | TEXT FK | 日志所属设备 |
| `event_uid` | TEXT | APK 为每条日志生成的唯一 UUID |
| `level` | TEXT | `info`、`warning` 或 `error` |
| `category` | TEXT | 日志分类，如 `connection` |
| `event` | TEXT | 事件名，如 `ws_connected` |
| `message` | TEXT | 最多 2000 字符的安全说明 |
| `details_json` | TEXT | 非敏感扩展字段 JSON |
| `device_time` | TEXT NULL | 设备发生时间 |
| `received_at` | TEXT | 服务端接收时间 |

`(device_id, event_uid)` 唯一，APK 重试不会写出重复记录。不得上传 token、凭据、通知正文、输入内容或个人文件内容。

## `screen_sessions`：授权屏幕协助会话

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | TEXT PK | 屏幕会话 UUID |
| `device_id` | TEXT FK | 目标设备 |
| `operator_id` | TEXT FK | 发起管理员 |
| `command_id` | TEXT FK NULL | 对应请求屏幕共享命令 |
| `status` | TEXT | `requesting`、`awaiting_consent`、`active`、`denied`、`stopped` 或 `failed` |
| `requested_at` | TEXT | 发起时间 |
| `consented_at` | TEXT NULL | APK确认用户已同意的时间 |
| `ended_at` | TEXT NULL | 会话结束时间 |
| `error_code` | TEXT NULL | 失败或断开代码 |
| `error_message` | TEXT NULL | 不含隐私内容的错误说明 |

浏览器断开、APK媒体连接断开或服务重启都会结束活动会话。画面帧只在内存中转发，不写数据库。

## `screen_stream_tickets`：屏幕媒体一次性票据

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | TEXT PK | 票据 UUID |
| `ticket_hash` | TEXT UNIQUE | 原始票据的 SHA-256 摘要 |
| `session_id` | TEXT FK | 对应 `screen_sessions.id` |
| `role` | TEXT | `browser` 或 `device`，限制连接方向 |
| `expires_at_epoch` | INTEGER | 短期过期时间 |
| `consumed_at_epoch` | INTEGER NULL | WebSocket 握手时原子消费 |
| `created_at` | TEXT | 创建时间 |

## `audit_logs`：服务端审计

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | INTEGER PK | 自增编号 |
| `actor_type` | TEXT | 操作者类型，如 `user` 或 `device` |
| `actor_id` | TEXT | 操作者 ID |
| `action` | TEXT | 审计动作名 |
| `target_type` | TEXT | 目标类型 |
| `target_id` | TEXT | 目标 ID |
| `result` | TEXT | 处理结果或状态 |
| `details_json` | TEXT | 不含秘密的补充信息 |
| `created_at` | TEXT | 服务端记录时间 |

当前会记录命令创建、账号管理、设备信息修改和屏幕会话；生产版本还应增加独立审计归档与保留策略。

## `ws_tickets`：一次性 WebSocket 票据

| 字段 | 类型 | 备注 |
|---|---|---|
| `id` | TEXT PK | 票据记录 UUID |
| `ticket_hash` | TEXT UNIQUE | 票据摘要，原文不落库 |
| `purpose` | TEXT | `dashboard` 或 `device`，不能跨用途使用 |
| `subject_id` | TEXT | 对应用户 ID 或设备 ID |
| `expires_at_epoch` | INTEGER | 短期过期时间 |
| `consumed_at_epoch` | INTEGER NULL | 第一次握手时原子消费，防止重放 |
| `created_at` | TEXT | 创建时间 |

## 生产数据库建议

SQLite 和进程锁适用于本地开发、接口联调和小规模验收。生产多实例部署时应迁移到 PostgreSQL，并补充迁移工具、备份、保留周期、租户隔离和隐私字段清理策略；设备连接路由则放在 Redis，但 WebSocket 对象仍保留在各自 Gateway 进程内。
