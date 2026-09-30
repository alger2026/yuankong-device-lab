# 后台接口与数据流

本文描述当前代码真正实现的接口。HTTP 成功响应统一为：

```json
{
  "data": {},
  "meta": {"request_id": "UUID"}
}
```

列表接口的 `meta` 还包含 `page`、`page_size` 和 `total`。错误使用 FastAPI 标准 `detail`；每个 HTTP 响应都带 `X-Request-Id`。除健康检查和启动配置外，接口均需要管理端或设备端认证。

## 管理端接口

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/health` | 健康状态 |
| POST | `/api/login` | 登录并返回 Bearer token |
| GET | `/api/me` | 当前用户 |
| POST | `/api/logout` | 撤销当前会话 |
| POST | `/api/auth/reauth` | 刷新敏感操作验证时间 |
| POST | `/api/auth/password` | 修改自己的密码并撤销其他会话 |
| GET/POST/PATCH | `/api/users`、`/api/users/{id}` | 账号列表、新增、角色、状态和密码重置 |
| PATCH/DELETE | `/api/users/{id}/settings`、`/api/users/{id}` | 管理员扩展字段与删除占位，返回 501 |
| GET | `/api/roles` | 查询角色及其权限说明 |
| POST | `/api/ws-ticket` | Dashboard WS 一次性票据 |
| GET | `/api/capabilities` | 查询已实现、未实现和不能提供的功能清单 |
| GET/POST/PATCH | `/api/device-groups` | 设备分组列表、新增和修改 |
| GET/POST/PUT | `/api/battery-config`、`/api/battery-guides` | 获取和维护品牌/型号设置说明 |
| GET/POST/PATCH | `/api/message-templates` | 维护用户可见的支持说明模板 |
| GET | `/api/overview` | 总设备、在线、离线 |
| GET | `/api/devices` | 搜索、权限状态筛选和分页 |
| GET | `/api/devices/{id}` | 设备详情 |
| PATCH | `/api/devices/{id}` | 修改设备名称、分组和备注 |
| GET | `/api/devices/{id}/events` | 设备审计事件 |
| GET | `/api/devices/{id}/workbench/{module}` | 素材工作台模块占位，返回 501 |
| POST | `/api/devices/{id}/workbench-actions/{action}` | 素材工作台动作占位，返回 501 |
| POST | `/api/command` | 向在线设备提交白名单动作 |
| GET | `/api/commands` | 命令历史、筛选和分页 |
| GET | `/api/commands/{id}` | 查询命令状态 |
| GET/POST | `/api/screen-sessions` | 查询或创建屏幕协助会话 |
| POST | `/api/screen-sessions/{id}/stop` | 停止屏幕协助 |
| WS | `/ws/dashboard` | 设备和命令实时事件 |
| WS | `/ws/screen` | 手机到浏览器的授权画面帧中继 |
| GET/POST/PATCH | `/api/build-profiles` | APK 打包配置占位，返回 501 |
| POST/GET | `/api/build-jobs`、`/api/build-jobs/{id}` | APK 构建任务占位，返回 501 |
| GET | `/api/build-artifacts/{id}/download` | APK 产物下载占位，返回 501 |

占位接口只验证登录、设备可见范围和固定名称，然后返回：

```json
{
  "detail": {
    "code": "RESERVED_NOT_IMPLEMENTED",
    "feature": "...",
    "message": "接口已按参考素材预留，当前未实现执行逻辑"
  }
}
```

这些路由没有设备命令分发器、数据采集器、Gradle 子进程或签名逻辑。

### 管理端接口参数

| 接口 | 关键输入 | 主要输出或行为 |
|---|---|---|
| `POST /api/login` | `username`、`password` | Bearer token、有效期和用户角色 |
| `GET /api/me` | Bearer token | 当前用户 ID、用户名、角色 |
| `POST /api/logout` | Bearer token | 撤销当前会话 |
| `POST /api/auth/reauth` | 当前密码 | 把当前会话标记为最近已二次验证 |
| `POST /api/ws-ticket` | Bearer token | 只可消费一次的 Dashboard WS 票据 |
| `GET /api/overview` | 无业务参数 | `total`、`online`、`offline` |
| `GET /api/devices` | `q`、`device_id`、`owner_user_id`、`online`、`accessibility`、`uninstall_protection`、`battery_whitelist`、分页 | 设备静态信息、状态快照和汇总计数 |
| `GET /api/devices/{id}` | 设备 ID | 单设备详情；非管理员只能看归属自己的设备 |
| `GET /api/devices/{id}/events` | 设备 ID | 最近 200 条服务端审计记录 |
| `POST /api/command` | `device_id`、`action`、`payload` | 创建并实时下发命令；成功为 202，设备离线为 409 |
| `GET /api/commands/{id}` | 命令 ID | 命令状态、各阶段时间、结果或错误 |
| `GET /api/commands` | 设备、动作、状态、关键词、分页 | 完整命令历史 |
| `POST /api/screen-sessions` | `device_id` | 创建会话、下发用户授权请求并返回浏览器媒体票据 |
| `WS /ws/screen` | 一次性 browser/device ticket | 每条二进制消息转发一张 JPEG/WebP 帧 |

`viewer` 只能查看；`operator` 可操作自己范围内的设备；`admin` 可查看所有设备。`request_screen_share` 需要最近二次验证，`lock_device` 还要求管理员、最近二次验证以及服务端显式启用。

管理端请求使用：

```http
Authorization: Bearer <session-token>
```

## Android 接口

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/device/bootstrap` | 协议版本、路径、心跳和动作能力 |
| POST | `/api/device/ws-ticket` | 获取设备 WS 一次性票据 |
| POST | `/api/device/status` | WS不可用时的状态补传 |
| POST | `/api/device/logs` | 幂等日志上传 |
| WS | `/ws/device` | 心跳、状态和命令交互 |

### Android接口参数

| 接口 | 关键输入 | 主要输出或行为 |
|---|---|---|
| `GET /api/device/bootstrap` | 无 | 协议版本、连接路径、心跳间隔、服务端动作白名单 |
| `POST /api/device/ws-ticket` | 设备认证头 | 一次性设备 WS 票据 |
| `POST /api/device/status` | 电量、网络、屏幕、权限状态 | WS 不可用时更新状态快照，不会把设备标记为在线 |
| `POST /api/device/logs` | `event_uid`、级别、分类、事件和安全日志 | 以 `(device_id,event_uid)` 幂等写入 |
| `WS /ws/device` | URL 查询参数 `ticket` | 建立实时心跳、状态上报和命令通道 |

设备认证请求头：

```http
X-Device-Id: <device-id>
X-Device-Token: <device-token>
```

## Dashboard事件

```text
server.hello
device.online
device.offline
device.status
command.updated
screen.session.updated
```

浏览器的完整启动顺序：

```text
POST /api/login
→ GET /api/me
→ GET /api/overview 和 GET /api/devices 取得初始快照
→ POST /api/ws-ticket
→ WS /ws/dashboard?ticket=...
→ 用 device.online/offline/status 和 command.updated 增量更新页面
```

## 命令状态

```text
queued
→ sent
→ acknowledged
→ success | failed
```

设备离线时，当前 MVP 将命令标记为失败并返回 HTTP 409，不做离线排队。

命令交互示例：

```text
浏览器 POST /api/command
→ 服务端检查登录、角色、设备归属、动作白名单和二次验证
→ 写入 commands，生成 command_id
→ 根据 device_id 找到当前 /ws/device 连接
→ 下发 command.dispatch
→ APK 校验本地动作白名单和用户授权
→ APK 返回 command.ack
→ APK 执行后返回 command.result
→ 服务端更新 commands
→ /ws/dashboard 推送 command.updated
```

服务端只接受固定动作，不接受脚本、Shell、任意 Intent 或任意反射调用。当前白名单见 README 和 APK 对接文档。

## 数据表

| 表 | 用途 |
|---|---|
| `users` | 后台账号和角色 |
| `sessions` | 管理会话和 reauth 时间 |
| `devices` | 设备静态档案和独立 token hash |
| `device_status` | 当前状态和权限快照 |
| `device_sessions` | 每次 WebSocket 连接历史 |
| `commands` | 命令、ACK、结果和错误 |
| `device_logs` | 带 event_uid 的幂等日志 |
| `audit_logs` | 管理和设备审计 |
| `ws_tickets` | 一次性短期 WebSocket 票据 |
| `device_groups` | 设备分组与归属 |
| `battery_guides` | 品牌/型号电池设置说明 |
| `screen_sessions` | 屏幕协助会话状态 |
| `screen_stream_tickets` | 屏幕中继的一次性角色票据 |
| `message_templates` | 支持消息模板 |

每个字段的类型、来源和备注见 [数据表与字段说明](DATABASE_SCHEMA.md)。

## 多节点生产替换点

当前 `RealtimeHub` 是内存实现。多节点时需要：

```text
device_id → gateway_id/socket_id     Redis
Dashboard跨节点广播                  Redis Pub/Sub
可靠设备事件                         Redis Streams/NATS JetStream
业务数据                             PostgreSQL
文件和画面                           S3/MinIO
```

不要把 WebSocket对象写入 Redis；Redis只保存连接位于哪个 Gateway，实际对象仍留在本机进程。
