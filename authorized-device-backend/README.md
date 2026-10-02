# Authorized Device Backend

这是一个基于 FastAPI 的、面向**已授权 Android 设备管理与远程协助**的后台 MVP。它实现在线状态、心跳、设备列表、浏览器实时事件、受限命令、设备日志和审计。

参考素材中还出现了隐藏图标、防删、输入/凭据日志、文件、通讯录、相册和自动打包等能力。管理页面保留固定消息协议和 Android 自报数据展示，但没有对应 Android 执行器、采集器、编译或签名执行器。

## 已实现

- 管理员登录、会话、退出和敏感操作重新认证；
- 每台设备独立 token；
- Android WebSocket 一次性票据；
- 兼容旧 APK 的 Socket.IO `deviceOnline`/`enc msg` AES 状态接收；
- Dashboard WebSocket 一次性票据；
- Android 心跳、在线/离线和状态更新；
- 设备列表、详情、筛选、分页和概览；
- 安全动作白名单和命令状态；
- 命令 ACK、执行结果和浏览器实时通知；
- 幂等设备日志上传；
- SQLite 持久化和审计；
- 启动时清理残留在线状态；
- 心跳超时自动离线。
- 自带管理前端：首页、管理员、设备列表、消息模板、编译打包和功能清单；
- 设备工作台包含素材中的日志、短信、应用、系统、权限、相册、通讯录、文件、剪切板、投屏及控制区；
- 前端通过 Dashboard WebSocket 自动刷新设备和命令状态。
- 后台账号、角色、启停状态和密码修改；
- 设备分组、名称与备注管理；
- 品牌/型号电池设置说明；
- 用户可见的支持消息模板；
- 完整命令历史、筛选和分页；
- 经二次验证和手机端明确授权的屏幕会话；
- `/ws/screen` JPEG/WebP 二进制画面中继和浏览器查看窗口。

## 素材对齐的消息动作与占位接口

- `GET /api/devices/{id}/workbench/{module}`：读取最近一次 Android 自报数据；
- `POST /api/devices/{id}/workbench/{module}/request`：向在线 Android 请求模块数据；
- `/api/devices/{id}/workbench-actions/{action}`：控制区的固定动作会写入命令表并发给在线 Android；
- `/api/build-profiles`、`/api/build-jobs`、`/api/build-artifacts/{id}/download`：编译打包流程；
- `/api/users/{id}/settings`：谷歌验证码、IP 白名单和备注等管理员扩展字段，登录时会实际校验；
- `/api/system/status`：返回 API、数据库和实时连接状态。

只有构建流程仍返回 `501 RESERVED_NOT_IMPLEMENTED`。工作台数据和固定动作只实现
消息传输、审计、Android 自报结果的保存与展示，不代表设备具备或完成相应能力；后台不会生成
短信、联系人、相册等兜底数据。

## 运行

需要 Python 3.10 或更新版本。

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export ADB_ADMIN_PASSWORD='替换为至少12位的强密码'
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

首次启动创建 `data/backend.sqlite3` 和管理员。后续启动读取已有数据库，不再使用环境变量覆盖密码。

打开：

- 管理后台：`http://127.0.0.1:8000/`
- OpenAPI：`http://127.0.0.1:8000/docs`
- 健康检查：`http://127.0.0.1:8000/api/health`

正式部署必须置于 HTTPS/WSS 反向代理后，并把 SQLite、单进程连接表替换为 PostgreSQL、Redis 和多 Gateway 路由。

## 主要流程

### 管理端

```text
POST /api/login
→ GET /api/me
→ POST /api/ws-ticket
→ WS /ws/dashboard?ticket=...
```

### 设备长连接

```text
APK POST /api/device/ws-ticket
→ WS /ws/device?ticket=...
→ device.hello
→ device.heartbeat/device.status
```

### 命令

```text
浏览器 POST /api/command
→ command.dispatch
→ APK command.ack
→ APK command.result
→ /ws/dashboard 推送 command.updated
```

## 安全动作白名单

- `refresh_status`
- `show_support_prompt`
- `open_battery_settings`
- `open_autostart_settings`
- `request_screen_share`：必须在 Android 端显示系统授权和持续通知；
- `stop_screen_share`
- `lock_device`：默认禁用，只允许经过书面授权的 Android Enterprise device-owner 场景。

任意其他动作会在请求模型校验阶段被拒绝。

设备工作台中的“一键解锁”通过工作台固定动作接口向在线 Android 连接下发
`action: "unlock"` 和空参数对象；本仓库没有 Android 处理器，也没有任何服务端解锁执行逻辑。

## 文档

- [APK 对接要求](docs/APK_INTEGRATION.md)
- [后台接口与数据流](docs/BACKEND_API.md)
- [数据表与字段说明](docs/DATABASE_SCHEMA.md)

## 当前实现边界

- 连接表保存在单个 Python 进程内，不能直接启动多个 Gateway worker；
- SQLite 适合开发和小规模验收，不适合高并发生产；
- 屏幕中继使用“一条二进制消息一张 JPEG/WebP 图片”的联调协议，生产高帧率场景应替换为 WebRTC；
- 没有 Android 源码、Gradle 工程和签名证书，因此不能在本项目内完成 APK 编译和签名；
- 当前后台不提供设备入网或 APK 版本发布接口，设备档案与凭据由外部受控流程预置；
- 设备 token 当前为长期 token，生产环境应支持轮换和撤销。
