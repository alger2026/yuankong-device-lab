"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const state = {
  token: sessionStorage.getItem("device_admin_token") || "",
  user: null,
  currentView: "dashboard",
  overview: { total: 0, online: 0, offline: 0 },
  devices: [],
  page: 1,
  pageSize: 20,
  total: 0,
  deviceSummary: {},
  groups: [],
  commands: [],
  commandPage: 1,
  commandTotal: 0,
  commandPageSize: 20,
  users: [],
  batteryGuides: [],
  templates: [],
  selectedDeviceId: null,
  selectedDevice: null,
  pendingAfterReauth: null,
  screenSocket: null,
  screenSessionId: null,
  screenObjectUrl: null,
  ws: null,
  wsTimer: null,
  wsPing: null,
  refreshTimer: null,
  manualSocketClose: false,
  workbench: {
    scale: 100,
    fontSize: 16,
    keyStep: 100,
    theme: "default",
    overlayMode: "隐藏",
  },
};

const viewMeta = {
  dashboard: ["REMOTE ADMIN", "首页"],
  devices: ["DEVICE INVENTORY", "设备列表"],
  commands: ["COMMAND AUDIT", "命令历史"],
  templates: ["SUPPORT TEMPLATES", "消息模板"],
  configuration: ["DEVICE CONFIGURATION", "设备配置"],
  users: ["ADMINISTRATORS", "管理员"],
  builds: ["APK BUILDER", "编译打包"],
  capabilities: ["CAPABILITY MATRIX", "功能清单"],
  system: ["CONNECTION & SYSTEM", "连接与系统"],
};

const actionLabels = {
  refresh_status: "刷新",
  show_support_prompt: "显示支持说明",
  open_battery_settings: "打开电池设置",
  open_autostart_settings: "打开自启动设置",
  request_screen_share: "显示投屏",
  stop_screen_share: "停止屏幕共享",
  lock_device: "锁定设备",
  "command.create": "管理员创建命令",
};

const workbenchActionLabels = {
  unlock: "一键解锁",
  "verify-unlock": "已解锁 · 锁屏验证",
  translate: "一键翻译",
  "lock-screen": "锁屏",
  "uninstall-protection": "防删",
  "launcher-icon": "桌面图标",
  "power-menu": "电源",
  screenshot: "截图",
  "front-camera": "前-拍照",
  "rear-camera": "后-拍照",
  camera: "打开实时预览",
  "open-app": "打开应用",
  "uninstall-app": "卸载应用",
  "overlay-mode": "遮盖层/仿页",
  "clear-clipboard": "清空剪切板",
  "write-clipboard": "写入剪切板",
};

const workbenchModuleLabels = {
  messages: "短信",
  apps: "应用",
  system: "系统",
  permissions: "权限",
  gallery: "相册",
  contacts: "通讯录",
  files: "文件",
  clipboard: "剪切板",
  "input-events": "输入事件",
  "credential-events": "凭据事件",
  camera: "摄像头数据",
};

const workbenchEmptyLabels = {
  messages: "暂无数据~",
  apps: "暂无数据~",
  permissions: "暂无数据~",
  gallery: "暂无数据~",
  contacts: "暂无数据~",
  files: "暂无权限",
  clipboard: "读取失败或文本为空",
  "input-events": "暂无数据~",
  "credential-events": "暂无数据~",
  camera: "暂无数据~",
};

class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function api(path, options = {}) {
  const { auth = true, ...fetchOptions } = options;
  const headers = new Headers(fetchOptions.headers || {});
  if (fetchOptions.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (auth && state.token) headers.set("Authorization", `Bearer ${state.token}`);
  const response = await fetch(path, { ...fetchOptions, headers });
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    const message = errorMessage(body, response.status);
    if (auth && response.status === 401) forceLogout("登录已失效，请重新登录");
    throw new ApiError(message, response.status, body);
  }
  return body;
}

function errorMessage(body, status) {
  const detail = body?.detail;
  if (typeof detail === "string") {
    const map = {
      "invalid credentials": "账号或密码错误",
      "missing bearer token": "缺少登录凭证",
      "invalid or expired session": "登录已过期",
      "insufficient role": "当前账号没有操作权限",
      "recent reauthentication required": "该操作需要再次验证密码",
      "device is offline": "设备当前离线，命令未下发",
      "device not found": "设备不存在或无权访问",
      "this action accepts no payload": "该操作不接受附加参数",
      "this action accepts no value": "该操作不接受该值",
      "package_name is required": "请选择要操作的应用",
      "invalid package_name": "应用包名格式不正确",
      "clipboard text is required": "请输入剪切板内容",
      "invalid clipboard text": "剪切板内容格式不正确或过长",
    };
    return map[detail] || detail;
  }
  if (detail && typeof detail === "object" && typeof detail.message === "string") {
    return detail.message;
  }
  if (Array.isArray(detail) && detail[0]?.msg) return detail[0].msg;
  return `请求失败（${status}）`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return escapeHtml(value);
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
  }).format(date);
}

function roleLabel(role) {
  return { admin: "超级管理员", operator: "操作员", viewer: "只读账号" }[role] || role;
}

function boolLabel(value) {
  if (value === 1 || value === true) return "开启";
  if (value === 0 || value === false) return "关闭";
  return "未知";
}

function screenLabel(value, lockStateCode = null) {
  const legacyLabels = { 0: "息屏", 1: "锁屏", 2: "已解锁 · 桌面", 3: "已解锁 · 前台" };
  if (lockStateCode !== null && lockStateCode !== undefined && legacyLabels[lockStateCode]) return legacyLabels[lockStateCode];
  return { on: "亮屏", off: "息屏", locked: "已锁定", unknown: "未知" }[value] || "未知";
}

function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${type === "error" ? "!" : "✓"}</span><b>${escapeHtml(message)}</b><button aria-label="关闭">×</button>`;
  $("button", toast).addEventListener("click", () => toast.remove());
  $("#toast-container").append(toast);
  window.setTimeout(() => toast.remove(), 4300);
}

function setLoading(button, loading, text = "处理中…") {
  if (!button) return;
  if (loading) {
    button.dataset.originalText = button.textContent;
    button.textContent = text;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
  }
}

function showLogin(message = "") {
  $("#login-screen").classList.remove("hidden");
  $("#app-shell").classList.add("hidden");
  $("#login-error").textContent = message;
  window.setTimeout(() => $("#password")?.focus(), 50);
}

function showApp() {
  $("#login-screen").classList.add("hidden");
  $("#app-shell").classList.remove("hidden");
  $("#user-name").textContent = state.user.username;
  $("#user-role").textContent = roleLabel(state.user.role);
  $("#user-avatar").textContent = state.user.username.slice(0, 1).toUpperCase();
  $$(".admin-only").forEach((item) => item.classList.toggle("hidden", state.user.role !== "admin"));
}

async function handleLogin(event) {
  event.preventDefault();
  const button = $("#login-button");
  $("#login-error").textContent = "";
  setLoading(button, true, "正在登录…");
  try {
    const result = await api("/api/login", {
      auth: false,
      method: "POST",
      body: JSON.stringify({
        username: $("#username").value.trim(),
        password: $("#password").value,
      }),
    });
    state.token = result.data.token;
    state.user = result.data.user;
    sessionStorage.setItem("device_admin_token", state.token);
    $("#password").value = "";
    showApp();
    await startAuthenticatedApp();
  } catch (error) {
    $("#login-error").textContent = error.message || "登录失败";
  } finally {
    setLoading(button, false);
  }
}

async function restoreSession() {
  if (!state.token) {
    showLogin();
    return;
  }
  try {
    const result = await api("/api/me");
    state.user = result.data;
    showApp();
    await startAuthenticatedApp();
  } catch (error) {
    if (error.status !== 401) showLogin(error.message);
  }
}

async function startAuthenticatedApp() {
  const requested = location.hash.replace("#", "");
  const initialView = viewMeta[requested] ? requested : "dashboard";
  showView(initialView, false, false);
  const initialLoader = {
    commands: loadCommands,
    configuration: loadBatteryGuides,
    capabilities: loadCapabilities,
  }[initialView];
  await Promise.allSettled([
    loadOverview(), loadDevices(), loadGroups(), loadTemplates(),
    state.user?.role === "admin" ? loadUsers() : Promise.resolve(),
    initialLoader ? initialLoader() : Promise.resolve(),
  ]);
  connectDashboardSocket();
}

async function logout() {
  try {
    await api("/api/logout", { method: "POST" });
  } catch (_) {
    // The local session is cleared even if the server cannot be reached.
  }
  forceLogout();
}

function forceLogout(message = "") {
  state.manualSocketClose = true;
  clearTimeout(state.wsTimer);
  clearInterval(state.wsPing);
  if (state.ws) state.ws.close();
  if (state.screenSocket) state.screenSocket.close();
  state.screenSocket = null;
  state.screenSessionId = null;
  if ($("#screen-dialog")?.open) $("#screen-dialog").close();
  state.ws = null;
  state.token = "";
  state.user = null;
  sessionStorage.removeItem("device_admin_token");
  closeDrawer();
  showLogin(message);
}

function showView(view, updateHash = true, loadData = true) {
  if (!viewMeta[view]) return;
  if (["users", "builds"].includes(view) && state.user?.role !== "admin") {
    showToast("当前账号没有访问该页面的权限", "error");
    return;
  }
  state.currentView = view;
  $$(".view").forEach((item) => item.classList.toggle("active", item.id === `view-${view}`));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  $("#page-kicker").textContent = viewMeta[view][0];
  $("#page-title").textContent = viewMeta[view][1];
  $("#sidebar").classList.remove("open");
  if (updateHash) history.replaceState(null, "", `#${view}`);
  if (loadData) {
    if (view === "dashboard") loadOverview();
    if (view === "devices") loadDevices();
    if (view === "commands") loadCommands();
    if (view === "templates") loadTemplates();
    if (view === "configuration") loadConfiguration();
    if (view === "users") loadUsers();
    if (view === "capabilities") loadCapabilities();
  }
}

async function loadCapabilities() {
  if (!state.token) return;
  try {
    const result = await api("/api/capabilities");
    const { items, summary } = result.data;
    $("#capability-implemented").textContent = summary.implemented;
    $("#capability-planned").textContent = summary.not_implemented;
    $("#capability-blocked").textContent = summary.unavailable;
    const labels = { implemented: "已实现", not_implemented: "未实现", unavailable: "未启用" };
    let currentGroup = "";
    $("#capability-list").innerHTML = items.map((item) => {
      const group = item.group !== currentGroup
        ? `<div class="capability-group-head">${escapeHtml(item.group)}</div>`
        : "";
      currentGroup = item.group;
      const interfaces = item.interfaces.map((value) => `<code>${escapeHtml(value)}</code>`).join("");
      const sent = item.send_to_android == null
        ? "不向 Android 发送消息"
        : JSON.stringify(item.send_to_android, null, 2);
      const received = item.receive_from_android == null
        ? "不接收 Android 命令回执"
        : JSON.stringify(item.receive_from_android, null, 2);
      return `${group}<article class="capability-row ${item.status}">
        <div class="capability-title"><h3>${escapeHtml(item.name)}</h3><span class="capability-status ${item.status}">${labels[item.status]}</span></div>
        <div class="capability-interfaces">${interfaces}</div>
        <div class="capability-protocol-grid">
          <section><b>发送给 Android</b><pre>${escapeHtml(sent)}</pre></section>
          <section><b>接收 Android</b><pre>${escapeHtml(received)}</pre></section>
        </div>
        <div class="capability-storage"><b>后台记录</b><code>${escapeHtml(item.stored_as)}</code></div>
        <p>${escapeHtml(item.note)}</p>
      </article>`;
    }).join("");
  } catch (error) {
    $("#capability-list").innerHTML = `<div class="loading-block">${escapeHtml(error.message)}</div>`;
  }
}

async function loadCommands() {
  if (!state.token) return;
  const body = $("#command-table-body");
  body.innerHTML = `<tr><td colspan="8"><div class="loading-block">正在加载命令历史…</div></td></tr>`;
  const params = new URLSearchParams({
    page: String(state.commandPage),
    page_size: String(state.commandPageSize),
  });
  const q = $("#command-search").value.trim();
  const action = $("#command-action").value;
  const commandStatus = $("#command-status").value;
  if (q) params.set("q", q);
  if (action) params.set("action", action);
  if (commandStatus) params.set("status", commandStatus);
  try {
    const result = await api(`/api/commands?${params}`);
    state.commands = result.data;
    state.commandTotal = result.meta.total;
    state.commandPage = result.meta.page;
    renderCommands();
  } catch (error) {
    body.innerHTML = `<tr><td colspan="8"><div class="loading-block">${escapeHtml(error.message)}</div></td></tr>`;
  }
}

function renderCommands() {
  const labels = {
    queued: "等待发送", sent: "已发送", acknowledged: "设备已收到",
    success: "成功", failed: "失败",
  };
  const body = $("#command-table-body");
  if (!state.commands.length) {
    body.innerHTML = `<tr><td colspan="8"><div class="loading-block">暂无符合条件的命令</div></td></tr>`;
  } else {
    body.innerHTML = state.commands.map((command) => {
      const result = command.error_message || (command.result ? JSON.stringify(command.result) : "—");
      return `<tr>
        <td><code class="command-id" title="${escapeHtml(command.id)}">${escapeHtml(command.id)}</code></td>
        <td><strong>${escapeHtml(command.device_name)}</strong><span class="device-subline">${escapeHtml(command.device_id)}</span></td>
        <td>${escapeHtml(actionLabels[command.action] || workbenchActionLabels[command.action] || command.action)}</td>
        <td>${escapeHtml(command.operator_name)}</td>
        <td><span class="command-state ${command.status}">${labels[command.status] || escapeHtml(command.status)}</span></td>
        <td>${formatTime(command.queued_at)}</td><td>${formatTime(command.completed_at)}</td>
        <td><div class="command-result" title="${escapeHtml(result)}">${escapeHtml(result)}</div></td>
      </tr>`;
    }).join("");
  }
  const pages = Math.max(1, Math.ceil(state.commandTotal / state.commandPageSize));
  $("#command-pagination-summary").textContent = `共 ${state.commandTotal} 条命令`;
  $("#command-page-indicator").textContent = `${state.commandPage} / ${pages}`;
  $("#command-previous-page").disabled = state.commandPage <= 1;
  $("#command-next-page").disabled = state.commandPage >= pages;
}

async function loadGroups() {
  if (!state.token) return;
  try {
    const result = await api("/api/device-groups");
    state.groups = result.data;
    renderGroups();
  } catch (error) {
    if ($("#group-list")) $("#group-list").innerHTML = `<div class="loading-block">${escapeHtml(error.message)}</div>`;
  }
}

function renderGroups() {
  const list = $("#group-list");
  if (!list) return;
  list.innerHTML = state.groups.length ? state.groups.map((group) => `
    <article class="management-item"><div><h4>${escapeHtml(group.name)}</h4><p>${escapeHtml(group.description || "暂无说明")}</p></div><span class="management-count">${group.device_count}</span></article>`).join("") : `<div class="loading-block">还没有设备分组</div>`;
}

async function loadConfiguration() {
  await Promise.allSettled([loadGroups(), loadBatteryGuides()]);
}

async function createGroup(event) {
  event.preventDefault();
  const button = $("#group-form button");
  setLoading(button, true, "添加中…");
  try {
    await api("/api/device-groups", {
      method: "POST",
      body: JSON.stringify({
        name: $("#group-name").value.trim(),
        description: $("#group-description").value.trim(),
      }),
    });
    $("#group-form").reset();
    await loadGroups();
    showToast("设备分组已添加");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(button, false);
  }
}

async function loadBatteryGuides() {
  try {
    const result = await api("/api/battery-guides");
    state.batteryGuides = result.data;
    const list = $("#battery-guide-list");
    list.innerHTML = state.batteryGuides.length ? state.batteryGuides.map((guide) => `
      <article class="management-item"><div><h4>${escapeHtml(guide.title)}</h4><p>${guide.steps.map((step, index) => `${index + 1}. ${escapeHtml(step)}`).join("<br>")}</p><code>${escapeHtml(guide.brand)} / ${escapeHtml(guide.model_pattern)}</code></div><span class="capability-status ${guide.enabled ? "implemented" : "unavailable"}">${guide.enabled ? "启用" : "停用"}</span></article>`).join("") : `<div class="loading-block">暂无电池设置说明</div>`;
  } catch (error) {
    $("#battery-guide-list").innerHTML = `<div class="loading-block">${escapeHtml(error.message)}</div>`;
  }
}

async function createBatteryGuide(event) {
  event.preventDefault();
  const button = $("#battery-guide-form button");
  const steps = $("#guide-steps").value.split("\n").map((value) => value.trim()).filter(Boolean);
  setLoading(button, true, "保存中…");
  try {
    await api("/api/battery-guides", {
      method: "POST",
      body: JSON.stringify({
        brand: $("#guide-brand").value.trim(),
        model_pattern: $("#guide-model").value.trim(),
        title: $("#guide-title").value.trim(),
        steps,
        enabled: true,
      }),
    });
    $("#battery-guide-form").reset();
    $("#guide-model").value = "*";
    await loadBatteryGuides();
    showToast("电池设置说明已添加");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(button, false);
  }
}

async function loadTemplates() {
  if (!state.token) return;
  try {
    const result = await api("/api/message-templates");
    state.templates = result.data;
    const list = $("#template-list");
    list.innerHTML = state.templates.length ? state.templates.map((template) => `
      <article class="template-item"><h4>${escapeHtml(template.name)}</h4><p>${escapeHtml(template.content)}</p><small>${escapeHtml(template.owner_name)} · ${formatTime(template.updated_at)}</small><span class="capability-status ${template.enabled ? "implemented" : "unavailable"}">${template.enabled ? "启用" : "停用"}</span></article>`).join("") : `<div class="loading-block">还没有消息模板</div>`;
    const select = $("#support-template");
    select.innerHTML = `<option value="">选择消息模板（可选）</option>` + state.templates.filter((item) => item.enabled).map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)}</option>`).join("");
  } catch (error) {
    $("#template-list").innerHTML = `<div class="loading-block">${escapeHtml(error.message)}</div>`;
  }
}

async function createTemplate(event) {
  event.preventDefault();
  const button = $("#template-form button[type='submit']");
  setLoading(button, true, "保存中…");
  try {
    await api("/api/message-templates", {
      method: "POST",
      body: JSON.stringify({
        name: $("#template-name").value.trim(),
        content: $("#template-content").value.trim(),
        enabled: true,
      }),
    });
    $("#template-form").reset();
    $("#template-count").textContent = "0";
    await loadTemplates();
    showToast("消息模板已保存");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(button, false);
  }
}

async function loadUsers() {
  if (state.user?.role !== "admin") return;
  const body = $("#user-table-body");
  body.innerHTML = `<tr><td colspan="9"><div class="loading-block">正在加载账号…</div></td></tr>`;
  const params = new URLSearchParams({ page_size: "100" });
  const q = $("#user-search")?.value.trim();
  const status = $("#user-status-filter")?.value;
  if (q) params.set("q", q);
  if (status) params.set("status", status);
  try {
    const result = await api(`/api/users?${params}`);
    state.users = result.data;
    const ownerSelect = $("#filter-owner");
    if (ownerSelect) {
      const currentOwner = ownerSelect.value;
      ownerSelect.innerHTML = `<option value="">管理员</option>` + state.users.map((account) => `<option value="${escapeHtml(account.id)}">${escapeHtml(account.username)}</option>`).join("");
      ownerSelect.value = currentOwner;
    }
    body.innerHTML = state.users.map((account) => {
      const isSelf = account.id === state.user.id;
      const lastLogin = account.last_login_epoch ? new Date(account.last_login_epoch * 1000).toLocaleString("zh-CN") : "—";
      return `<tr><td><strong>${escapeHtml(account.username)}</strong>${isSelf ? '<span class="device-subline">当前账号</span>' : ""}</td><td>${roleLabel(account.role)}</td><td><button class="material-toggle ${account.status === "active" ? "on" : ""}" ${isSelf ? "disabled" : ""} data-user-toggle="${escapeHtml(account.id)}" data-next-status="${account.status === "active" ? "disabled" : "active"}" aria-label="切换状态"><i></i></button></td><td>${escapeHtml(account.ip_whitelist || "—")}</td><td><span class="command-state ${account.last_login_epoch ? "success" : "queued"}">${account.last_login_epoch ? "在线" : "—"}</span></td><td>${lastLogin}</td><td>${formatTime(account.created_at)}</td><td>${escapeHtml(account.note || "—")}</td><td><div class="user-actions"><button class="mini-button" data-user-edit="${escapeHtml(account.id)}">编辑</button>${isSelf ? "" : `<button class="mini-button danger" data-user-delete="${escapeHtml(account.id)}">删除</button>`}</div></td></tr>`;
    }).join("");
  } catch (error) {
    body.innerHTML = `<tr><td colspan="9"><div class="loading-block">${escapeHtml(error.message)}</div></td></tr>`;
  }
}

async function createUser(event) {
  event.preventDefault();
  const button = $("#user-form button[type='submit']");
  setLoading(button, true, "创建中…");
  try {
    await api("/api/auth/reauth", {
      method: "POST",
      body: JSON.stringify({ password: $("#admin-confirm-password").value }),
    });
    await api("/api/users", {
      method: "POST",
      body: JSON.stringify({
        username: $("#new-username").value.trim(),
        password: $("#new-user-password").value,
        role: $("#new-user-role").value,
      }),
    });
    $("#user-form").reset();
    $("#user-dialog").close();
    await loadUsers();
    showToast("后台账号已创建");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(button, false);
  }
}

async function changeOwnPassword(event) {
  event.preventDefault();
  const button = $("#password-form button[type='submit']");
  const password = $("#changed-password").value;
  if (password !== $("#changed-password-confirm").value) {
    showToast("两次输入的新密码不一致", "error");
    return;
  }
  setLoading(button, true, "修改中…");
  try {
    await api("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: $("#current-password").value,
        new_password: password,
      }),
    });
    $("#password-form").reset();
    showToast("密码已修改，其他登录会话已撤销");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(button, false);
  }
}

async function toggleUser(userId, status) {
  requestReauth(async () => {
    await api(`/api/users/${encodeURIComponent(userId)}`, {
      method: "PATCH", body: JSON.stringify({ status }),
    });
    await loadUsers();
    showToast(status === "active" ? "账号已启用" : "账号已停用");
  });
}

async function callReservedUserDelete(userId) {
  try {
    await api(`/api/users/${encodeURIComponent(userId)}`, { method: "DELETE" });
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function submitReservedBuildProfile(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type='submit']");
  setLoading(button, true, "提交中…");
  try {
    await api("/api/build-profiles", {
      method: "POST",
      body: JSON.stringify({
        app_name: $("#build-app-name").value.trim(),
        shell_name: $("#build-shell-name").value.trim(),
        homepage_url: $("#build-homepage").value.trim(),
        hide_launcher_icon: form.elements.hide_launcher_icon.checked,
        sms: form.elements.sms.checked,
        camera: form.elements.camera.checked,
        contacts: form.elements.contacts.checked,
        media: form.elements.media.checked,
      }),
    });
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(button, false);
  }
}

async function callReservedWorkbenchAction(action, value = null, payload = {}) {
  if (!state.selectedDeviceId) return;
  try {
    await api(`/api/devices/${encodeURIComponent(state.selectedDeviceId)}/workbench-actions/${encodeURIComponent(action)}`, {
      method: "POST",
      body: JSON.stringify({
        value,
        payload,
      }),
    });
    showToast(`发送命令成功: ${workbenchActionLabels[action] || action}。具体结果会在处理完毕时通知`);
    return true;
  } catch (error) {
    showToast(error.message, "error");
    return false;
  }
}

function workbenchItems(data) {
  if (Array.isArray(data)) return data;
  return Array.isArray(data?.items) ? data.items : [];
}

function itemValue(item, ...keys) {
  for (const key of keys) {
    if (item?.[key] !== undefined && item?.[key] !== null && item?.[key] !== "") return item[key];
  }
  return "—";
}

function formatBytes(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) return value == null ? "—" : String(value);
  if (number < 1024) return `${number} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = number / 1024;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[index]}`;
}

function safeMediaUrl(value) {
  if (typeof value !== "string") return "";
  if (/^(https?:\/\/|\/[^/]|data:image\/(?:png|jpeg|webp|gif);base64,)/i.test(value)) return value;
  return "";
}

function renderWorkbenchModule(module, data, completedAt) {
  const items = workbenchItems(data);
  const disabled = canOperateSelectedDevice() ? "" : "disabled";
  const head = `<div class="module-result-head"><strong>处理结果</strong><small>${formatTime(completedAt)}</small><button type="button" data-reserved-module="${escapeHtml(module)}" ${disabled}>刷新</button></div>`;
  const empty = `<div class="loading-block">${escapeHtml(workbenchEmptyLabels[module] || "暂无数据~")}</div>`;
  if (module === "messages") {
    if (!items.length) return head + empty;
    return head + `<div class="message-cards">${items.map((item) => {
      const direction = itemValue(item, "direction", "type") === "sent" ? "发出" : "收到";
      const read = item.read === true || item.read === 1;
      return `<article class="message-card"><div><strong>${escapeHtml(itemValue(item, "address", "phone", "sender"))}</strong><span>${escapeHtml(direction)} · ${escapeHtml(itemValue(item, "slot", "sim_slot"))}${read ? " · 已读" : ""}</span></div><p>${escapeHtml(itemValue(item, "body", "content", "text"))}</p><small>${formatTime(itemValue(item, "timestamp", "created_at", "time"))}</small><button type="button" data-copy-text="${escapeHtml(itemValue(item, "body", "content", "text"))}">复制</button></article>`;
    }).join("")}</div>`;
  }
  if (module === "apps") {
    if (!items.length) return head + empty;
    return head + `<div class="module-tools"><select data-app-filter><option value="">APP · 全部</option>${[...new Set(items.map((item) => String(item.tag || item.type || "")).filter(Boolean))].map((tag) => `<option value="${escapeHtml(tag)}">${escapeHtml(tag)}</option>`).join("")}</select><select data-app-mark><option value="">标记 · 全部</option><option value="system">系统</option><option value="third-party">三方APP</option></select><input data-app-search placeholder="搜索 APP 名称或包名"></div><div class="app-cards">${items.map((item) => {
      const packageName = itemValue(item, "package_name", "package");
      const name = itemValue(item, "name", "app_name", "label");
      const icon = safeMediaUrl(item.icon || item.icon_url);
      const tag = String(item.tag || item.type || "");
      const mark = item.system === true || tag.toLowerCase() === "system" ? "system" : "third-party";
      const haystack = `${name} ${packageName}`.toLowerCase();
      return `<article class="app-card" data-app-card data-app-tag="${escapeHtml(tag)}" data-app-mark-value="${mark}" data-app-search-value="${escapeHtml(haystack)}"><div class="app-icon">${icon ? `<img src="${escapeHtml(icon)}" alt="">` : escapeHtml(String(name).slice(0, 1).toUpperCase())}</div><div><strong>${escapeHtml(name)}</strong><small>${escapeHtml(packageName)}</small><span>${escapeHtml(itemValue(item, "version", "version_name"))}</span></div><div class="app-card-actions"><button type="button" data-app-action="open-app" data-package-name="${escapeHtml(packageName)}" ${disabled}>打开</button><button type="button" class="danger" data-app-action="uninstall-app" data-package-name="${escapeHtml(packageName)}" ${disabled}>卸载</button></div></article>`;
    }).join("")}</div>`;
  }
  if (module === "system") {
    const system = data && typeof data === "object" ? data : {};
    const fields = [
      ["当前窗口", itemValue(system, "current_window", "window")], ["当前包名", itemValue(system, "current_package", "package_name")],
      ["控制包名", itemValue(system, "control_package")], ["应用名称", itemValue(system, "app_name")],
      ["用户时区", itemValue(system, "timezone")], ["用户语言", itemValue(system, "locale", "language")],
      ["终端时间", itemValue(system, "device_time", "terminal_time")], ["最后点击", itemValue(system, "last_click")],
      ["手机品牌", itemValue(system, "brand")], ["手机型号", itemValue(system, "model")],
      ["安卓版本", itemValue(system, "android_version")], ["是否插卡", itemValue(system, "sim_present")],
      ["号码1", itemValue(system, "phone_number", "phone_number_1")], ["有效内存", itemValue(system, "available_memory")],
      ["总计内存", itemValue(system, "total_memory")], ["CPU", itemValue(system, "cpu")],
    ];
    return head + `<div class="detail-grid module-detail-grid">${fields.map(([label, value]) => detailItem(label, value)).join("")}</div>`;
  }
  if (module === "permissions") {
    if (!items.length) return head + empty;
    const enabledCount = items.filter((item) => [true, 1, "granted", "enabled"].includes(item.state ?? item.enabled)).length;
    return head + `<div class="permission-summary"><b>已开 ${enabledCount}</b><span>待开 ${items.length - enabledCount}</span><span>共 ${items.length}</span></div><div class="permission-list">${items.map((item) => permissionRow(itemValue(item, "label", "name", "permission"), item.state ?? item.enabled)).join("")}</div>`;
  }
  if (module === "gallery") {
    if (!items.length) return head + empty;
    return head + `<div class="gallery-grid">${items.map((item) => {
      const url = safeMediaUrl(item.thumbnail || item.url || item.uri);
      return `<article>${url ? `<img src="${escapeHtml(url)}" alt="${escapeHtml(itemValue(item, "name"))}">` : `<div class="gallery-placeholder">▧</div>`}<strong>${escapeHtml(itemValue(item, "name", "display_name"))}</strong><small>${escapeHtml(formatBytes(item.size))}</small></article>`;
    }).join("")}</div>`;
  }
  if (module === "contacts") {
    if (!items.length) return head + empty;
    return head + `<div class="contact-list">${items.map((item) => `<article><span>${escapeHtml(String(itemValue(item, "name")).slice(0, 1))}</span><div><strong>${escapeHtml(itemValue(item, "name"))}</strong><small>${escapeHtml(itemValue(item, "phone", "number"))}</small></div><button type="button" data-copy-text="${escapeHtml(itemValue(item, "phone", "number"))}">复制</button></article>`).join("")}</div>`;
  }
  if (module === "files") {
    if (!items.length) return head + empty;
    return head + `<div class="file-path">根目录：${escapeHtml(data?.path || "/")}</div><div class="table-wrap"><table class="module-table"><thead><tr><th>名称</th><th>大小</th><th>修改时间</th><th>操作</th></tr></thead><tbody>${items.map((item) => `<tr><td>${item.type === "directory" ? "▰" : "▤"} ${escapeHtml(itemValue(item, "name"))}</td><td>${escapeHtml(item.type === "directory" ? "—" : formatBytes(item.size))}</td><td>${formatTime(itemValue(item, "modified_at", "updated_at"))}</td><td>${item.uri ? `<button type="button" data-copy-text="${escapeHtml(item.uri)}">复制路径</button>` : "—"}</td></tr>`).join("")}</tbody></table></div>`;
  }
  if (module === "clipboard") {
    const text = typeof data === "string" ? data : String(data?.text ?? "");
    return head + `<div class="clipboard-panel"><label>剪切板内容<textarea data-clipboard-text>${escapeHtml(text)}</textarea></label><div><button type="button" data-reserved-action="clear-clipboard" ${disabled}>清空</button></div><label>写入剪切板<textarea data-clipboard-write placeholder="请输入内容"></textarea></label><button type="button" class="primary-button small" data-clipboard-submit ${disabled}>提交写入</button></div>`;
  }
  return head + `<pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
}

async function loadWorkbenchModule(module) {
  if (!state.selectedDeviceId) return;
  const target = $(`[data-workbench-result="${module}"]`, $("#drawer-content"));
  if (target) target.innerHTML = `<div class="loading-block">正在读取数据…</div>`;
  try {
    const result = await api(`/api/devices/${encodeURIComponent(state.selectedDeviceId)}/workbench/${encodeURIComponent(module)}`);
    if (!target) return;
    const report = result.data;
    if (report.source !== "android_self_reported" || report.data == null) {
      const status = report.last_command?.status;
      const copy = status === "sent" || status === "acknowledged"
        ? "查询命令已发送，等待处理结果"
        : status === "failed"
          ? `处理失败：${report.last_command.error_message || report.last_command.error_code || "未知错误"}`
          : workbenchEmptyLabels[module] || "暂无数据~";
      target.innerHTML = `<div class="loading-block">${escapeHtml(copy)}</div>`;
      return;
    }
    target.classList.add("structured-result");
    target.innerHTML = renderWorkbenchModule(module, report.data, report.last_command?.completed_at);
    target.closest(".module-placeholder")?.classList.add("has-data");
  } catch (error) {
    if (target) target.innerHTML = `<div class="loading-block">${escapeHtml(error.message)}</div>`;
  }
}

async function requestWorkbenchModule(module) {
  if (!state.selectedDeviceId) return;
  try {
    const result = await api(`/api/devices/${encodeURIComponent(state.selectedDeviceId)}/workbench/${encodeURIComponent(module)}/request`, {
      method: "POST",
    });
    showToast(`发送命令成功: ${workbenchModuleLabels[module] || module}。具体结果会在处理完毕时通知`);
    await loadWorkbenchModule(module);
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function loadOverview() {
  if (!state.token) return;
  try {
    const result = await api("/api/overview");
    state.overview = result.data;
    const { total, online, offline } = result.data;
    const rate = total ? Math.round((online / total) * 100) : 0;
    $("#metric-total").textContent = total;
    $("#metric-online").textContent = online;
    $("#metric-offline").textContent = offline;
    $("#metric-rate").textContent = `${rate}%`;
    $("#metric-online-copy").textContent = `共 ${total} 台设备`;
    $("#nav-device-count").textContent = total;
    $("#health-rate").textContent = `${rate}%`;
    $(".health-ring").style.setProperty("--health-angle", `${rate}%`);
  } catch (error) {
    if (error.status !== 401) showToast(error.message, "error");
  }
}

function deviceQuery() {
  const params = new URLSearchParams({
    page: String(state.page),
    page_size: String(state.pageSize),
  });
  const values = {
    q: $("#device-search").value.trim(),
    device_id: $("#filter-device-id").value.trim(),
    owner_user_id: $("#filter-owner").value,
    online: $("#filter-online").value,
    accessibility: $("#filter-accessibility").value,
    uninstall_protection: $("#filter-uninstall").value,
    battery_whitelist: $("#filter-battery").value,
  };
  Object.entries(values).forEach(([key, value]) => value && params.set(key, value));
  return params.toString();
}

async function loadDevices() {
  if (!state.token) return;
  const tableBody = $("#device-table-body");
  if (state.currentView === "devices") {
    tableBody.innerHTML = `<tr><td colspan="16"><div class="loading-block">正在加载设备…</div></td></tr>`;
  }
  try {
    const result = await api(`/api/devices?${deviceQuery()}`);
    state.devices = result.data;
    state.total = result.meta.total;
    state.page = result.meta.page;
    state.pageSize = result.meta.page_size;
    state.deviceSummary = result.meta.summary || {};
    renderDeviceTable();
    renderDeviceSummary();
    renderRecentDevices();
    updatePagination();
  } catch (error) {
    if (error.status !== 401) {
      tableBody.innerHTML = `<tr><td colspan="16"><div class="loading-block">${escapeHtml(error.message)}</div></td></tr>`;
    }
  }
}

function renderDeviceSummary() {
  const summary = state.deviceSummary;
  $("#summary-total").textContent = summary.total ?? state.overview.total ?? state.total;
  $("#summary-online").textContent = summary.online ?? state.overview.online ?? 0;
  $("#summary-offline").textContent = summary.offline ?? state.overview.offline ?? 0;
  $("#summary-accessibility").textContent = `${summary.accessibility ?? "—"}/${summary.total ?? state.total}`;
  $("#summary-uninstall").textContent = `${summary.uninstall_protection ?? "—"}/${summary.total ?? state.total}`;
  $("#summary-battery").textContent = `${summary.battery_whitelist ?? "—"}/${summary.total ?? state.total}`;
}

function renderRecentDevices() {
  const container = $("#recent-device-list");
  if (!state.devices.length) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">▯</div><h3>还没有设备</h3><p>设备连接后台后会显示在这里。</p></div>`;
    return;
  }
  container.innerHTML = state.devices.slice(0, 5).map((device) => `
    <div class="recent-device">
      <div class="device-avatar">▯</div>
      <div><strong>${escapeHtml(device.name)}</strong><small>${escapeHtml(device.id)}</small></div>
      <div><strong>${escapeHtml(device.brand)} ${escapeHtml(device.model)}</strong><small>Android ${escapeHtml(device.android_version)}</small></div>
      <div><strong>${device.battery_percent == null ? "—" : `${device.battery_percent}%`}</strong><small>${escapeHtml(device.network_type || "网络未知")}</small></div>
      <span class="status-badge ${device.online ? "online" : "offline"}">${device.online ? "在线" : "离线"}</span>
    </div>`).join("");
}

function batteryHtml(value) {
  if (value == null) return "—";
  const safeValue = Math.max(0, Math.min(100, Number(value)));
  return `<div class="battery-cell ${safeValue <= 20 ? "battery-low" : ""}"><div class="battery-shell"><div class="battery-fill" style="width:${safeValue}%"></div></div><b>${safeValue}%</b></div>`;
}

function permissionBadge(label, value) {
  const active = value === 1 || value === true;
  return `<span class="permission-badge ${active ? "yes" : ""}">${escapeHtml(label)} ${active ? "✓" : "—"}</span>`;
}

function countryFlag(locale) {
  const match = String(locale || "").match(/[-_]([A-Za-z]{2})$/);
  if (!match) return "🌐";
  return [...match[1].toUpperCase()].map((letter) => String.fromCodePoint(127397 + letter.charCodeAt(0))).join("");
}

function realtimeStateIcon(label, symbol, value) {
  const className = value === true || value === 1 ? "enabled" : value === false || value === 0 ? "disabled" : "unknown";
  const copy = value == null ? "未知" : value ? "已开启" : "未开启";
  return `<span class="${className}" title="${escapeHtml(label)}：${copy}">${symbol}</span>`;
}

function renderDeviceTable() {
  const body = $("#device-table-body");
  const empty = $("#device-empty");
  if (!state.devices.length) {
    body.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");
  body.innerHTML = state.devices.map((device) => `
    <tr class="clickable-device-row" data-device-id="${escapeHtml(device.id)}">
      <td><div class="realtime-icons"><i class="${device.online ? "on" : ""}" title="${device.online ? "在线" : "离线"}"></i>${realtimeStateIcon("无障碍", "♿", device.accessibility_enabled)}${realtimeStateIcon("防删", "▣", device.uninstall_protection_enabled)}<b title="${escapeHtml(device.locale || "地区未知")}">${countryFlag(device.locale)}</b></div></td>
      <td><strong class="device-name">${escapeHtml(device.id)}</strong><span class="device-subline">${escapeHtml(device.name)}</span></td>
      <td><strong>${escapeHtml(device.brand)}</strong><span class="device-subline">${escapeHtml(device.model)}</span></td>
      <td>${batteryHtml(device.battery_percent)}</td>
      <td><span class="network-quality ${device.online ? "good" : ""}">${escapeHtml(device.network_quality || (device.online ? "良好" : "—"))}${device.network_latency_ms ? ` · ${escapeHtml(device.network_latency_ms)} ms` : ""}</span></td>
      <td>${escapeHtml(device.note || "—")}</td>
      <td>${screenLabel(device.screen_state, device.lock_state_code)}</td>
      <td>${device.locked == null ? "—" : device.locked ? "✓" : "×"}</td>
      <td><span class="network-type-pill">${escapeHtml(device.network_type || "—")}</span></td>
      <td>${escapeHtml(device.locale || "—")}</td>
      <td>${escapeHtml(device.ip_address || "—")}</td>
      <td>${escapeHtml(device.timezone || "—")}</td>
      <td>Android ${escapeHtml(device.android_version)} (SDK ${escapeHtml(device.sdk_int)})</td>
      <td><span class="package-cell">${escapeHtml(device.package_name)}</span></td>
      <td>${formatTime(device.created_at)}</td>
      <td><button class="row-button" data-device-id="${escapeHtml(device.id)}">进入 →</button></td>
    </tr>`).join("");
}

function updatePagination() {
  const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
  if (state.page > pages) state.page = pages;
  $("#pagination-summary").textContent = `共 ${state.total} 台设备`;
  $("#page-indicator").textContent = `${state.page} / ${pages}`;
  $("#previous-page").disabled = state.page <= 1;
  $("#next-page").disabled = state.page >= pages;
  $("#page-size").value = String(state.pageSize);
}

async function openDevice(deviceId) {
  state.selectedDeviceId = deviceId;
  $("#drawer-backdrop").classList.remove("hidden");
  $("#device-drawer").classList.add("open");
  $("#device-drawer").setAttribute("aria-hidden", "false");
  $("#drawer-content").innerHTML = `<div class="loading-block">正在加载设备详情…</div>`;
  try {
    const [detailResult, eventsResult] = await Promise.all([
      api(`/api/devices/${encodeURIComponent(deviceId)}`),
      api(`/api/devices/${encodeURIComponent(deviceId)}/events`),
    ]);
    if (state.selectedDeviceId !== deviceId) return;
    renderDeviceDetail(detailResult.data, eventsResult.data);
  } catch (error) {
    $("#drawer-content").innerHTML = `<div class="loading-block">${escapeHtml(error.message)}</div>`;
  }
}

function detailItem(label, value) {
  return `<div class="detail-item"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value ?? "—")}</strong></div>`;
}

function canOperateSelectedDevice() {
  return Boolean(state.selectedDevice?.online && ["admin", "operator"].includes(state.user?.role));
}

function renderDeviceDetail(device, events) {
  state.selectedDevice = device;
  $("#drawer-device-name").textContent = device.name;
  const canOperate = device.online && ["admin", "operator"].includes(state.user.role);
  const canEdit = ["admin", "operator"].includes(state.user.role);
  const actionDisabled = canOperate ? "" : "disabled";
  const groupOptions = [`<option value="">未分组</option>`, ...state.groups.map((group) => `<option value="${escapeHtml(group.id)}" ${device.group_id === group.id ? "selected" : ""}>${escapeHtml(group.name)}</option>`)].join("");
  const eventHtml = events.length ? events.map((event) => {
    const label = actionLabels[event.action] || workbenchActionLabels[event.action] || event.action;
    const category = event.action.includes("lock") ? "锁屏" : event.action.includes("app") ? "三方APP" : "应用锁";
    const search = `${label} ${event.result} ${JSON.stringify(event.details || {})}`.toLowerCase();
    return `<div class="event-item" data-log-item data-log-category="${escapeHtml(category)}" data-log-search="${escapeHtml(search)}"><i></i><div><strong>${escapeHtml(label)} · ${escapeHtml(event.result)}</strong><small>${formatTime(event.created_at)}</small></div></div>`;
  }).join("") : `<p class="muted">暂无审计事件</p>`;
  $("#drawer-content").innerHTML = `
    <div class="detail-hero">
      <div class="device-avatar">▯</div>
      <div><h3>${escapeHtml(device.name)}</h3><p>${escapeHtml(device.brand)} ${escapeHtml(device.model)} · Android ${escapeHtml(device.android_version)}</p></div>
      <span class="status-badge ${device.online ? "online" : "offline"}">${device.online ? "在线" : "离线"}</span>
    </div>
    <div class="workbench-toolbar">
      <div><span>网络：</span><b>${escapeHtml(device.network_quality || (device.online ? "良好" : "未知"))}</b></div>
      <div><span>电池：</span><b>${device.battery_percent == null ? "—" : `${device.battery_percent}%`}</b></div>
      <label>设备<select disabled><option>Android 设备</option></select></label>
      <label>宽高 / 缩放<input data-workbench-scale type="range" min="70" max="130" value="${state.workbench.scale}"><output data-workbench-scale-output>${state.workbench.scale}%</output></label>
      <label>字体大小<input data-workbench-font type="range" min="12" max="22" value="${state.workbench.fontSize}"><output data-workbench-font-output>${state.workbench.fontSize}px</output></label>
      <label>快捷键步长<select data-workbench-key-step><option value="50">50</option><option value="100" ${state.workbench.keyStep === 100 ? "selected" : ""}>100</option><option value="200" ${state.workbench.keyStep === 200 ? "selected" : ""}>200</option></select></label>
      <label>主题背景<select data-workbench-theme><option value="default" ${state.workbench.theme === "default" ? "selected" : ""}>默认</option><option value="light" ${state.workbench.theme === "light" ? "selected" : ""}>浅色</option><option value="dark" ${state.workbench.theme === "dark" ? "selected" : ""}>深色</option></select></label>
      <button class="secondary-button small" data-workbench-reset type="button">重置布局</button>
    </div>
    <div class="device-workbench theme-${escapeHtml(state.workbench.theme)}" style="font-size:${state.workbench.fontSize}px;--wb-control-font:${state.workbench.fontSize * 0.625}px;--wb-small-font:${state.workbench.fontSize * 0.56}px;zoom:${state.workbench.scale / 100}">
      <section class="workbench-data-panel">
        <div class="workbench-tabs" role="tablist">
          <button class="active" data-workbench-tab="logs">◴ 日志</button>
          <button data-workbench-tab="messages">▣ 短信</button>
          <button data-workbench-tab="apps">▦ 应用</button>
          <button data-workbench-tab="system">▯ 系统</button>
          <button data-workbench-tab="permissions">⬟ 权限</button>
          <button data-workbench-tab="gallery">▧ 相册</button>
          <button data-workbench-tab="contacts">▤ 通讯录</button>
          <button data-workbench-tab="files">▰ 文件</button>
          <button data-workbench-tab="clipboard">✂ 剪切板</button>
        </div>
        <div class="workbench-panel active" data-workbench-panel="logs">
          <div class="material-status-tabs" data-log-filters><button class="active" data-log-filter="">全部</button><button data-log-filter="三方APP">三方APP</button><button data-log-filter="锁屏">锁屏</button><button data-log-filter="应用锁">应用锁</button></div>
          <div class="search-box"><span>⌕</span><input data-log-search placeholder="搜索：网址/APP名称/内容等"></div>
          <div class="event-list">${eventHtml}</div>
          <p class="muted hidden" data-log-empty>没有符合条件的日志</p>
        </div>
        <div class="workbench-panel" data-workbench-panel="messages">${workbenchPlaceholder("短信", device.id, "messages")}</div>
        <div class="workbench-panel" data-workbench-panel="apps"><h4>点击图标打开APP</h4>${workbenchPlaceholder("应用", device.id, "apps")}</div>
        <div class="workbench-panel" data-workbench-panel="system"><div class="detail-grid">
          ${detailItem("当前窗口", "—")}${detailItem("当前包名", "—")}${detailItem("控制包名", device.package_name)}
          ${detailItem("应用名称", device.name)}${detailItem("用户时区", device.timezone || "—")}${detailItem("用户语言", device.locale || "—")}
          ${detailItem("终端时间", "—")}${detailItem("最后点击", "—")}${detailItem("手机品牌", device.brand)}
          ${detailItem("手机型号", device.model)}${detailItem("安卓版本", `Android ${device.android_version} (SDK ${device.sdk_int})`)}${detailItem("是否插卡", "—")}
          ${detailItem("号码1", "—")}${detailItem("有效内存", "—")}${detailItem("总计内存", "—")}${detailItem("CPU", "—")}
        </div><div class="camera-copy"><strong>摄像头</strong><small>点击拍照图片在 截图 查看</small></div><div class="camera-actions"><button data-reserved-action="front-camera" ${actionDisabled}>前-拍照</button><button data-reserved-action="rear-camera" ${actionDisabled}>后-拍照</button><button data-reserved-action="camera" ${actionDisabled}>打开实时预览</button></div><div class="module-result action-media-result" data-action-result="camera"></div><button class="secondary-button small" data-reserved-module="system" ${actionDisabled}>刷新系统信息</button><div class="module-result" data-workbench-result="system"></div></div>
        <div class="workbench-panel" data-workbench-panel="permissions"><div class="permission-header"><h3>权限管理 <small>手动引导授权</small></h3><label><input type="checkbox" ${actionDisabled}> 自动化</label><button data-action="refresh_status" ${actionDisabled}>↻ 刷新</button></div><div class="permission-list">
          ${permissionRow("无障碍权限", device.accessibility_enabled)}${permissionRow("电池白名单", device.battery_whitelist_enabled)}${permissionRow("短信权限", null)}${permissionRow("相册权限", null)}${permissionRow("自动启动", null)}${permissionRow("管理员", device.device_admin_enabled)}
        </div><button class="secondary-button small" data-reserved-module="permissions" ${actionDisabled}>刷新</button><div class="module-result" data-workbench-result="permissions"><div class="loading-block">暂无数据~</div></div></div>
        <div class="workbench-panel" data-workbench-panel="gallery">${workbenchPlaceholder("相册", device.id, "gallery")}</div>
        <div class="workbench-panel" data-workbench-panel="contacts">${workbenchPlaceholder("通讯录", device.id, "contacts")}</div>
        <div class="workbench-panel" data-workbench-panel="files">${workbenchPlaceholder("根目录", device.id, "files")}</div>
        <div class="workbench-panel" data-workbench-panel="clipboard">${workbenchPlaceholder("剪切板内容", device.id, "clipboard")}</div>
      </section>
      <section class="overlay-mode-panel">
        <strong>遮盖层/仿页</strong>
        <select data-reserved-action="overlay-mode" ${actionDisabled}>${["纯黑色", "纯白色", "隐藏", "Gpay PIN", "Phonepe PIN", "Paytm PIN"].map((mode) => `<option ${state.workbench.overlayMode === mode ? "selected" : ""}>${mode}</option>`).join("")}</select>
        <small>选择后向 Android 发送对应 mode</small>
      </section>
      <section class="remote-stage-panel">
        <div class="phone-frame"><div class="phone-camera"></div><div class="phone-screen"><small>打开投屏显示</small><button data-action="request_screen_share" ${actionDisabled}>立即打开</button></div></div>
      </section>
      <aside class="remote-control-panel">
        <div class="remote-state"><span class="status-badge ${device.online ? "online" : "offline"}">${device.online ? "在线" : "离线"}</span><b>${screenLabel(device.screen_state, device.lock_state_code)}</b></div>
        <button class="wide-control green" data-reserved-action="unlock" ${actionDisabled}>▣ 一键解锁</button>
        <div class="inline-controls"><button data-action="request_screen_share" ${actionDisabled}>显示投屏</button><button data-action="refresh_status" ${actionDisabled}>↻ 刷新</button></div>
        <button class="wide-control" data-reserved-action="translate" ${actionDisabled}>文 一键翻译</button>
        <button class="wide-control green" data-reserved-action="verify-unlock" ${actionDisabled}>▣ 已解锁 · 锁屏验证</button>
        ${controlToggle("锁屏", "打开后立刻锁屏", "lock-screen", device.locked, actionDisabled)}
        ${controlToggle("防删", "防止应用被卸载", "uninstall-protection", device.uninstall_protection_enabled, actionDisabled)}
        ${controlToggle("桌面图标", "显示或隐藏应用图标", "launcher-icon", device.launcher_icon_visible, actionDisabled)}
        <button class="control-list-button" data-reserved-action="power-menu" ${actionDisabled}><span>⏻</span><div><b>电源</b><small>弹出电源菜单</small></div></button>
        <button class="control-list-button" data-reserved-action="screenshot" ${actionDisabled}><span>▧</span><div><b>截图</b><small>抓取当前屏幕</small></div></button>
        <button class="control-list-button" data-action="refresh_status" ${actionDisabled}><span>↥</span><div><b>上报</b><small>上报节点</small></div></button>
      </aside>
      <section class="remote-stage-panel secondary-stage">
        <div class="stage-label">截图 / 辅助画面</div><div class="phone-frame"><div class="phone-camera"></div><div class="phone-screen" data-action-result="screenshot"><small>截图结果将在这里显示</small></div></div>
      </section>
    </div>
    <section class="detail-section"><div class="detail-section-head"><h4>名称、分组与备注</h4>${state.user.role === "admin" ? '<button type="button" class="secondary-button small" data-change-device-owner>更换设备管理员</button>' : ""}</div><form id="device-metadata-form" class="metadata-form">
      <input id="device-edit-name" maxlength="120" value="${escapeHtml(device.name)}" ${canEdit ? "" : "disabled"}>
      <select id="device-edit-group" ${canEdit ? "" : "disabled"}>${groupOptions}</select>
      <textarea id="device-edit-note" maxlength="1000" placeholder="设备备注" ${canEdit ? "" : "disabled"}>${escapeHtml(device.note || "")}</textarea>
      ${canEdit ? '<button class="primary-button" type="submit">保存设备信息</button>' : ""}
    </form></section>`;
  applyWorkbenchLayout();
  loadLatestActionResult("screenshot");
  loadLatestCameraResult();
}

function workbenchPlaceholder(label, deviceId, module) {
  const disabled = canOperateSelectedDevice() ? "" : "disabled";
  return `<div class="module-placeholder"><div class="empty-icon">▯</div><h3>${escapeHtml(label)}</h3><div class="module-result" data-workbench-result="${escapeHtml(module)}"><div class="loading-block">${escapeHtml(workbenchEmptyLabels[module] || "暂无数据~")}</div></div><button class="secondary-button small" data-reserved-module="${escapeHtml(module)}" ${disabled}>刷新</button></div>`;
}

function permissionRow(label, value) {
  const normalized = typeof value === "string" ? value.toLowerCase() : value;
  const enabled = [true, 1, "granted", "enabled", "allowed"].includes(normalized);
  const disabled = [false, 0, "denied", "disabled", "blocked"].includes(normalized);
  const unknown = !enabled && !disabled;
  return `<div class="permission-row ${enabled ? "enabled" : ""}"><span>${enabled ? "✓" : unknown ? "+" : "×"}</span><b>${escapeHtml(label)}</b><em>${unknown ? "未接入" : enabled ? "已开启" : "未开启"}</em></div>`;
}

function controlToggle(title, copy, action, value, disabled = "") {
  const enabled = value === true || value === 1;
  return `<button class="control-toggle" data-reserved-action="${escapeHtml(action)}" data-current-value="${enabled}" ${disabled}><div><b>${escapeHtml(title)}</b><small>${escapeHtml(copy)}</small></div><i class="${enabled ? "on" : ""}"></i></button>`;
}

function applyWorkbenchLayout() {
  const workbench = $(".device-workbench", $("#drawer-content"));
  if (!workbench) return;
  workbench.style.zoom = String(state.workbench.scale / 100);
  workbench.style.fontSize = `${state.workbench.fontSize}px`;
  workbench.style.setProperty("--wb-control-font", `${state.workbench.fontSize * 0.625}px`);
  workbench.style.setProperty("--wb-small-font", `${state.workbench.fontSize * 0.56}px`);
  workbench.classList.remove("theme-default", "theme-light", "theme-dark");
  workbench.classList.add(`theme-${state.workbench.theme}`);
  const scale = $("[data-workbench-scale]", $("#drawer-content"));
  const font = $("[data-workbench-font]", $("#drawer-content"));
  if (scale) scale.value = String(state.workbench.scale);
  if (font) font.value = String(state.workbench.fontSize);
  const scaleOutput = $("[data-workbench-scale-output]", $("#drawer-content"));
  const fontOutput = $("[data-workbench-font-output]", $("#drawer-content"));
  if (scaleOutput) scaleOutput.textContent = `${state.workbench.scale}%`;
  if (fontOutput) fontOutput.textContent = `${state.workbench.fontSize}px`;
}

function filterWorkbenchLogs() {
  const root = $("#drawer-content");
  const active = $("[data-log-filter].active", root)?.dataset.logFilter || "";
  const search = $("[data-log-search]", root)?.value.trim().toLowerCase() || "";
  let visible = 0;
  $$('[data-log-item]', root).forEach((item) => {
    const matches = (!active || item.dataset.logCategory === active) && (!search || item.dataset.logSearch.includes(search));
    item.classList.toggle("hidden", !matches);
    if (matches) visible += 1;
  });
  $("[data-log-empty]", root)?.classList.toggle("hidden", visible !== 0);
}

function filterWorkbenchApps() {
  const root = $("#drawer-content");
  const tag = $("[data-app-filter]", root)?.value || "";
  const mark = $("[data-app-mark]", root)?.value || "";
  const search = $("[data-app-search]", root)?.value.trim().toLowerCase() || "";
  $$('[data-app-card]', root).forEach((item) => {
    const matches = (!tag || item.dataset.appTag === tag) && (!mark || item.dataset.appMarkValue === mark) && (!search || item.dataset.appSearchValue.includes(search));
    item.classList.toggle("hidden", !matches);
  });
}

function renderActionMedia(result, fallback) {
  if (!result) return `<small>${escapeHtml(fallback)}</small>`;
  const url = safeMediaUrl(result.image_url || result.url || result.uri || result.frame);
  if (url) return `<img class="action-result-image" src="${escapeHtml(url)}" alt="Android 回传画面">`;
  return `<pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>`;
}

async function loadLatestActionResult(action, targetName = action) {
  if (!state.selectedDeviceId) return;
  const target = $(`[data-action-result="${targetName}"]`, $("#drawer-content"));
  if (!target) return;
  try {
    const params = new URLSearchParams({ device_id: state.selectedDeviceId, action, page: "1", page_size: "1" });
    const response = await api(`/api/commands?${params}`);
    const command = response.data[0];
    if (!command) return;
    if (["queued", "sent", "acknowledged"].includes(command.status)) {
      target.innerHTML = `<small>命令已发送，等待 Android 回传结果</small>`;
    } else if (command.status === "failed") {
      target.innerHTML = `<small>处理失败：${escapeHtml(command.error_message || command.error_code || "未知错误")}</small>`;
    } else {
      target.innerHTML = renderActionMedia(command.result, "Android 已报告完成");
    }
  } catch (_) {
    // 结果区域是辅助信息，不重复弹出全局错误提示。
  }
}

async function loadLatestCameraResult() {
  if (!state.selectedDeviceId) return;
  const target = $('[data-action-result="camera"]', $("#drawer-content"));
  if (!target) return;
  try {
    const commands = await Promise.all(["camera", "front-camera", "rear-camera"].map(async (action) => {
      const params = new URLSearchParams({ device_id: state.selectedDeviceId, action, page: "1", page_size: "1" });
      const response = await api(`/api/commands?${params}`);
      return response.data[0] || null;
    }));
    const command = commands.filter(Boolean).sort((a, b) => String(b.queued_at).localeCompare(String(a.queued_at)))[0];
    if (!command) return;
    if (["queued", "sent", "acknowledged"].includes(command.status)) {
      target.innerHTML = `<small>命令已发送，等待 Android 回传结果</small>`;
    } else if (command.status === "failed") {
      target.innerHTML = `<small>处理失败：${escapeHtml(command.error_message || command.error_code || "未知错误")}</small>`;
    } else {
      target.innerHTML = renderActionMedia(command.result, "Android 已报告完成");
    }
  } catch (_) {
    // 结果区域是辅助信息，不重复弹出全局错误提示。
  }
}

async function updateDeviceMetadata(event) {
  event.preventDefault();
  if (!state.selectedDeviceId) return;
  const button = $("#device-metadata-form button");
  const groupId = $("#device-edit-group").value;
  setLoading(button, true, "保存中…");
  try {
    await api(`/api/devices/${encodeURIComponent(state.selectedDeviceId)}`, {
      method: "PATCH",
      body: JSON.stringify({
        name: $("#device-edit-name").value.trim(),
        note: $("#device-edit-note").value.trim(),
        ...(groupId ? { group_id: groupId } : { clear_group: true }),
      }),
    });
    showToast("设备信息已保存");
    await Promise.all([loadDevices(), loadGroups()]);
    openDevice(state.selectedDeviceId);
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(button, false);
  }
}

async function openDeviceOwnerDialog() {
  if (!state.selectedDevice || state.user?.role !== "admin") return;
  if (!state.users.length) await loadUsers();
  const select = $("#device-owner-select");
  select.innerHTML = state.users.filter((account) => account.status === "active").map((account) => `<option value="${escapeHtml(account.id)}" ${account.id === state.selectedDevice.owner_user_id ? "selected" : ""}>${escapeHtml(account.username)} · ${roleLabel(account.role)}</option>`).join("");
  $("#device-owner-dialog").showModal();
}

async function changeDeviceOwner(event) {
  event.preventDefault();
  if (!state.selectedDeviceId) return;
  const button = $("#device-owner-form button[type='submit']");
  setLoading(button, true, "更换中…");
  try {
    await api(`/api/devices/${encodeURIComponent(state.selectedDeviceId)}`, {
      method: "PATCH",
      body: JSON.stringify({ owner_user_id: $("#device-owner-select").value }),
    });
    $("#device-owner-dialog").close();
    showToast("设备管理员已更换");
    await Promise.all([loadDevices(), loadGroups()]);
    await openDevice(state.selectedDeviceId);
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(button, false);
  }
}

function closeDrawer() {
  state.selectedDeviceId = null;
  state.selectedDevice = null;
  $("#drawer-backdrop").classList.add("hidden");
  $("#device-drawer").classList.remove("open");
  $("#device-drawer").setAttribute("aria-hidden", "true");
}

async function sendCommand(action, payload = {}) {
  if (!state.selectedDeviceId) return;
  try {
    const result = await api("/api/command", {
      method: "POST",
      body: JSON.stringify({ device_id: state.selectedDeviceId, action, payload }),
    });
    showToast(`${actionLabels[action] || action}已发送，命令号 ${result.data.command_id.slice(0, 8)}`);
  } catch (error) {
    if (error.status !== 401) showToast(error.message, "error");
  }
}

function handleCommandAction(action) {
  if (action === "show_support_prompt") {
    $("#support-message").value = "";
    $("#support-template").value = "";
    $("#support-count").textContent = "0";
    $("#support-dialog").showModal();
    $("#support-message").focus();
    return;
  }
  if (action === "request_screen_share") {
    requestReauth(startScreenSession);
    return;
  }
  if (action === "stop_screen_share" && state.screenSessionId) {
    stopScreenSession();
    return;
  }
  sendCommand(action);
}

function requestReauth(callback) {
  state.pendingAfterReauth = callback;
  $("#reauth-error").textContent = "";
  $("#reauth-password").value = "";
  $("#reauth-dialog").showModal();
  $("#reauth-password").focus();
}

async function handleSupportSubmit(event) {
  event.preventDefault();
  if (event.submitter?.value === "cancel") {
    $("#support-dialog").close();
    return;
  }
  const message = $("#support-message").value.trim();
  if (!message) return;
  const button = $("#send-support-button");
  setLoading(button, true, "发送中…");
  await sendCommand("show_support_prompt", { message });
  setLoading(button, false);
  $("#support-dialog").close();
}

async function handleReauthSubmit(event) {
  event.preventDefault();
  if (event.submitter?.value === "cancel") {
    state.pendingAfterReauth = null;
    $("#reauth-dialog").close();
    return;
  }
  const button = $("#reauth-button");
  $("#reauth-error").textContent = "";
  setLoading(button, true, "验证中…");
  try {
    await api("/api/auth/reauth", {
      method: "POST",
      body: JSON.stringify({ password: $("#reauth-password").value }),
    });
    const callback = state.pendingAfterReauth;
    state.pendingAfterReauth = null;
    $("#reauth-dialog").close();
    if (callback) {
      try {
        await callback();
      } catch (error) {
        showToast(error.message || "操作失败", "error");
      }
    }
  } catch (error) {
    $("#reauth-error").textContent = error.message;
  } finally {
    setLoading(button, false);
  }
}

async function startScreenSession() {
  if (!state.selectedDeviceId) return;
  const deviceId = state.selectedDeviceId;
  try {
    const result = await api("/api/screen-sessions", {
      method: "POST",
      body: JSON.stringify({ device_id: deviceId }),
    });
    state.screenSessionId = result.data.id;
    $("#screen-dialog-title").textContent = `${state.selectedDevice?.name || "设备"} · 屏幕协助`;
    $("#screen-frame").classList.add("hidden");
    $("#screen-waiting").classList.remove("hidden");
    setScreenStatus("awaiting_consent");
    $("#screen-dialog").showModal();
    connectScreenSocket(result.data.browser_ticket);
  } catch (error) {
    showToast(error.message, "error");
  }
}

function connectScreenSocket(ticket) {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${scheme}//${location.host}/ws/screen?ticket=${encodeURIComponent(ticket)}`);
  socket.binaryType = "arraybuffer";
  state.screenSocket = socket;
  socket.addEventListener("message", (event) => {
    if (typeof event.data === "string") {
      try {
        const message = JSON.parse(event.data);
        if (message.type === "screen.session.updated") setScreenStatus(message.status);
        if (message.type === "screen.stop") setScreenStatus("stopped");
      } catch (_) { /* Ignore unknown control messages. */ }
      return;
    }
    const bytes = new Uint8Array(event.data);
    const webp = bytes.length > 12 && String.fromCharCode(...bytes.slice(8, 12)) === "WEBP";
    const blob = new Blob([event.data], { type: webp ? "image/webp" : "image/jpeg" });
    if (state.screenObjectUrl) URL.revokeObjectURL(state.screenObjectUrl);
    state.screenObjectUrl = URL.createObjectURL(blob);
    $("#screen-frame").src = state.screenObjectUrl;
    $("#screen-frame").classList.remove("hidden");
    $("#screen-waiting").classList.add("hidden");
    setScreenStatus("active");
  });
  socket.addEventListener("close", () => {
    if (state.screenSocket === socket) state.screenSocket = null;
    if (state.screenSessionId) setScreenStatus("stopped");
  });
  socket.addEventListener("error", () => setScreenStatus("failed"));
}

function setScreenStatus(status) {
  const labels = {
    awaiting_consent: "等待手机授权", active: "共享中", denied: "用户拒绝",
    stopped: "已停止", failed: "连接失败",
  };
  const badge = $("#screen-session-status");
  badge.textContent = labels[status] || status;
  badge.className = `status-pill ${status === "active" ? "success" : ["denied", "failed"].includes(status) ? "unavailable" : "warning"}`;
  if (status === "awaiting_consent") {
    $("#screen-waiting h3").textContent = "等待手机授权";
    $("#screen-waiting p").textContent = "请在手机上确认本次屏幕共享请求。";
  }
  if (["denied", "stopped", "failed"].includes(status)) {
    $("#screen-waiting h3").textContent = labels[status];
    $("#screen-waiting p").textContent = status === "denied" ? "手机持有人没有同意本次共享。" : "当前屏幕协助会话已经结束。";
  }
}

async function stopScreenSession() {
  const sessionId = state.screenSessionId;
  state.screenSessionId = null;
  if (sessionId) {
    try {
      await api(`/api/screen-sessions/${encodeURIComponent(sessionId)}/stop`, { method: "POST" });
    } catch (error) {
      if (error.status !== 401) showToast(error.message, "error");
    }
  }
  if (state.screenSocket) state.screenSocket.close();
  state.screenSocket = null;
  if (state.screenObjectUrl) URL.revokeObjectURL(state.screenObjectUrl);
  state.screenObjectUrl = null;
  $("#screen-frame").src = "";
  if ($("#screen-dialog").open) $("#screen-dialog").close();
}

function setSocketStatus(connected) {
  const chip = $("#socket-chip");
  chip.classList.toggle("offline", !connected);
  $("b", chip).textContent = connected ? "实时通道正常" : "实时连接中";
  $("#ws-health-dot").className = connected ? "green-dot" : "";
  $("#ws-health-text").textContent = connected ? "已连接" : "连接中";
  $("#ws-health-text").className = connected ? "success-text" : "";
  const systemStatus = $("#system-dashboard-ws");
  systemStatus.textContent = connected ? "已连接" : "连接中";
  systemStatus.className = `status-pill ${connected ? "success" : "warning"}`;
}

async function connectDashboardSocket() {
  if (!state.token) return;
  state.manualSocketClose = false;
  clearTimeout(state.wsTimer);
  clearInterval(state.wsPing);
  if (state.ws && state.ws.readyState < 2) {
    state.manualSocketClose = true;
    state.ws.close();
    state.manualSocketClose = false;
  }
  setSocketStatus(false);
  try {
    const result = await api("/api/ws-ticket", { method: "POST" });
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${scheme}//${location.host}/ws/dashboard?ticket=${encodeURIComponent(result.data.ticket)}`);
    state.ws = socket;
    socket.addEventListener("open", () => {
      setSocketStatus(true);
      state.wsPing = window.setInterval(() => {
        if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "client.ping" }));
      }, 25000);
    });
    socket.addEventListener("message", (event) => handleSocketMessage(event.data));
    socket.addEventListener("close", () => {
      clearInterval(state.wsPing);
      if (state.ws === socket) state.ws = null;
      setSocketStatus(false);
      if (!state.manualSocketClose && state.token) {
        state.wsTimer = window.setTimeout(connectDashboardSocket, 3000);
      }
    });
    socket.addEventListener("error", () => setSocketStatus(false));
  } catch (error) {
    if (error.status !== 401 && state.token) {
      state.wsTimer = window.setTimeout(connectDashboardSocket, 4000);
    }
  }
}

function handleSocketMessage(raw) {
  let event;
  try { event = JSON.parse(raw); } catch (_) { return; }
  if (["device.online", "device.offline", "device.status"].includes(event.type)) {
    scheduleDataRefresh();
    if (state.selectedDeviceId === event.device_id) {
      window.setTimeout(() => openDevice(event.device_id), 350);
    }
  }
  if (event.type === "command.updated") {
    const label = { acknowledged: "设备已收到命令", success: "处理成功", failed: "处理失败" }[event.status];
    if (label) showToast(label, event.status === "failed" ? "error" : "success");
    if (["success", "failed"].includes(event.status)) {
      scheduleDataRefresh();
      const activePanel = $("[data-workbench-panel].active", $("#drawer-content"));
      const module = activePanel?.dataset.workbenchPanel;
      if (workbenchModuleLabels[module]) loadWorkbenchModule(module);
      if (module === "logs") {
        loadWorkbenchModule("input-events");
        loadWorkbenchModule("credential-events");
      }
      loadLatestActionResult("screenshot");
      loadLatestCameraResult();
    }
  }
  if (event.type === "screen.session.updated" && event.session_id === state.screenSessionId) {
    setScreenStatus(event.status);
  }
}

function scheduleDataRefresh() {
  clearTimeout(state.refreshTimer);
  state.refreshTimer = window.setTimeout(() => {
    loadOverview();
    loadDevices();
  }, 300);
}

async function refreshCurrentView() {
  const button = $("#refresh-button");
  setLoading(button, true, "↻");
  const refreshers = {
    dashboard: () => Promise.all([loadOverview(), loadDevices()]),
    devices: loadDevices,
    commands: loadCommands,
    configuration: loadConfiguration,
    templates: loadTemplates,
    users: loadUsers,
    capabilities: loadCapabilities,
  };
  await Promise.allSettled([refreshers[state.currentView]?.() || loadOverview()]);
  setLoading(button, false);
  showToast("数据已刷新");
}

function bindEvents() {
  $("#login-form").addEventListener("submit", handleLogin);
  $("#toggle-password").addEventListener("click", () => {
    const input = $("#password");
    input.type = input.type === "password" ? "text" : "password";
    $("#toggle-password").textContent = input.type === "password" ? "显示" : "隐藏";
  });
  $("#logout-button").addEventListener("click", logout);
  $("#refresh-button").addEventListener("click", refreshCurrentView);
  $("#menu-button").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  $$(".nav-item").forEach((item) => item.addEventListener("click", () => showView(item.dataset.view)));
  document.addEventListener("click", (event) => {
    const target = event.target.closest("[data-go]");
    if (target) showView(target.dataset.go);
  });
  $("#device-search-button").addEventListener("click", () => { state.page = 1; loadDevices(); });
  $("#device-search").addEventListener("keydown", (event) => {
    if (event.key === "Enter") { state.page = 1; loadDevices(); }
  });
  $("#clear-filters-button").addEventListener("click", () => {
    $("#device-search").value = "";
    $("#filter-device-id").value = "";
    $("#filter-owner").value = "";
    $("#filter-online").value = "";
    $("#filter-accessibility").value = "";
    $("#filter-uninstall").value = "";
    $("#filter-battery").value = "";
    $$("[data-quick-online]").forEach((item) => item.classList.toggle("active", item.dataset.quickOnline === ""));
    state.page = 1;
    loadDevices();
  });
  $$("[data-quick-online]").forEach((item) => item.addEventListener("click", () => {
    $$("[data-quick-online]").forEach((button) => button.classList.toggle("active", button === item));
    const value = item.dataset.quickOnline;
    $("#filter-online").value = value === "accessible" ? "true" : value;
    $("#filter-accessibility").value = value === "accessible" ? "true" : "";
    state.page = 1;
    loadDevices();
  }));
  $("#previous-page").addEventListener("click", () => { if (state.page > 1) { state.page -= 1; loadDevices(); } });
  $("#next-page").addEventListener("click", () => { state.page += 1; loadDevices(); });
  $("#page-size").addEventListener("change", (event) => { state.pageSize = Number(event.target.value); state.page = 1; loadDevices(); });
  $("#device-table-body").addEventListener("click", (event) => {
    const button = event.target.closest("[data-device-id]");
    if (button) openDevice(button.dataset.deviceId);
  });
  $("#close-drawer").addEventListener("click", closeDrawer);
  $("#drawer-backdrop").addEventListener("click", closeDrawer);
  $("#drawer-content").addEventListener("click", (event) => {
    const tab = event.target.closest("[data-workbench-tab]");
    if (tab) {
      const name = tab.dataset.workbenchTab;
      $$("[data-workbench-tab]", $("#drawer-content")).forEach((item) => item.classList.toggle("active", item === tab));
      $$("[data-workbench-panel]", $("#drawer-content")).forEach((item) => item.classList.toggle("active", item.dataset.workbenchPanel === name));
      if (workbenchModuleLabels[name]) loadWorkbenchModule(name);
      return;
    }
    const logFilter = event.target.closest("[data-log-filter]");
    if (logFilter) {
      $$('[data-log-filter]', $("#drawer-content")).forEach((item) => item.classList.toggle("active", item === logFilter));
      filterWorkbenchLogs();
      return;
    }
    const copy = event.target.closest("[data-copy-text]");
    if (copy) {
      navigator.clipboard?.writeText(copy.dataset.copyText).then(() => showToast("已复制")).catch(() => showToast("复制失败", "error"));
      return;
    }
    const appAction = event.target.closest("[data-app-action]");
    if (appAction && !appAction.disabled) {
      callReservedWorkbenchAction(appAction.dataset.appAction, null, { package_name: appAction.dataset.packageName });
      return;
    }
    const reset = event.target.closest("[data-workbench-reset]");
    if (reset) {
      state.workbench = { ...state.workbench, scale: 100, fontSize: 16, keyStep: 100, theme: "default" };
      const keyStep = $("[data-workbench-key-step]", $("#drawer-content"));
      const theme = $("[data-workbench-theme]", $("#drawer-content"));
      if (keyStep) keyStep.value = "100";
      if (theme) theme.value = "default";
      applyWorkbenchLayout();
      return;
    }
    if (event.target.closest("[data-change-device-owner]")) {
      openDeviceOwnerDialog();
      return;
    }
    const clipboardSubmit = event.target.closest("[data-clipboard-submit]");
    if (clipboardSubmit && !clipboardSubmit.disabled) {
      const text = $("[data-clipboard-write]", $("#drawer-content"))?.value || "";
      callReservedWorkbenchAction("write-clipboard", null, { text });
      return;
    }
    const reservedAction = event.target.closest("[data-reserved-action]");
    if (reservedAction && reservedAction.tagName !== "SELECT" && !reservedAction.disabled) {
      const currentValue = reservedAction.dataset.currentValue;
      const value = currentValue === undefined ? null : currentValue !== "true";
      callReservedWorkbenchAction(reservedAction.dataset.reservedAction, value).then((sent) => {
        if (!sent) return;
        if (reservedAction.dataset.reservedAction === "clear-clipboard") {
          const clipboard = $("[data-clipboard-text]", $("#drawer-content"));
          if (clipboard) clipboard.value = "";
        }
        if (reservedAction.dataset.reservedAction === "screenshot") loadLatestActionResult("screenshot");
        if (["front-camera", "rear-camera", "camera"].includes(reservedAction.dataset.reservedAction)) loadLatestCameraResult();
      });
      return;
    }
    const reservedModule = event.target.closest("[data-reserved-module]");
    if (reservedModule) {
      requestWorkbenchModule(reservedModule.dataset.reservedModule);
      return;
    }
    const button = event.target.closest("[data-action]");
    if (button && !button.disabled) handleCommandAction(button.dataset.action);
  });
  $("#drawer-content").addEventListener("change", (event) => {
    if (event.target.matches("select[data-reserved-action]") && !event.target.disabled) {
      if (event.target.dataset.reservedAction === "overlay-mode") state.workbench.overlayMode = event.target.value;
      callReservedWorkbenchAction(event.target.dataset.reservedAction, event.target.value);
      return;
    }
    if (event.target.matches("[data-workbench-key-step]")) state.workbench.keyStep = Number(event.target.value);
    if (event.target.matches("[data-workbench-theme]")) {
      state.workbench.theme = event.target.value;
      applyWorkbenchLayout();
    }
    if (event.target.matches("[data-app-filter], [data-app-mark]")) filterWorkbenchApps();
  });
  $("#drawer-content").addEventListener("input", (event) => {
    if (event.target.matches("[data-workbench-scale]")) {
      state.workbench.scale = Number(event.target.value);
      applyWorkbenchLayout();
    }
    if (event.target.matches("[data-workbench-font]")) {
      state.workbench.fontSize = Number(event.target.value);
      applyWorkbenchLayout();
    }
    if (event.target.matches("[data-log-search]")) filterWorkbenchLogs();
    if (event.target.matches("[data-app-search]")) filterWorkbenchApps();
  });
  $("#drawer-content").addEventListener("submit", (event) => {
    if (event.target.id === "device-metadata-form") updateDeviceMetadata(event);
  });
  $("#command-search-button").addEventListener("click", () => { state.commandPage = 1; loadCommands(); });
  $("#command-search").addEventListener("keydown", (event) => {
    if (event.key === "Enter") { state.commandPage = 1; loadCommands(); }
  });
  $("#command-previous-page").addEventListener("click", () => { if (state.commandPage > 1) { state.commandPage -= 1; loadCommands(); } });
  $("#command-next-page").addEventListener("click", () => { state.commandPage += 1; loadCommands(); });
  $("#group-form").addEventListener("submit", createGroup);
  $("#battery-guide-form").addEventListener("submit", createBatteryGuide);
  $("#template-form").addEventListener("submit", createTemplate);
  $("#template-content").addEventListener("input", (event) => { $("#template-count").textContent = event.target.value.length; });
  $("#reload-templates").addEventListener("click", loadTemplates);
  $("#user-form").addEventListener("submit", createUser);
  $("#open-user-dialog").addEventListener("click", () => $("#user-dialog").showModal());
  $("#close-user-dialog").addEventListener("click", () => $("#user-dialog").close());
  $("#cancel-user-dialog").addEventListener("click", () => $("#user-dialog").close());
  $("#device-owner-form").addEventListener("submit", changeDeviceOwner);
  $("#close-device-owner-dialog").addEventListener("click", () => $("#device-owner-dialog").close());
  $("#cancel-device-owner-dialog").addEventListener("click", () => $("#device-owner-dialog").close());
  $("#user-search-button").addEventListener("click", loadUsers);
  $("#user-status-filter").addEventListener("change", loadUsers);
  $("#reload-users").addEventListener("click", loadUsers);
  $("#user-table-body").addEventListener("click", (event) => {
    const button = event.target.closest("[data-user-toggle]");
    if (button) toggleUser(button.dataset.userToggle, button.dataset.nextStatus);
    const edit = event.target.closest("[data-user-edit]");
    if (edit) showToast("编辑扩展字段接口已预留，当前未实现", "error");
    const remove = event.target.closest("[data-user-delete]");
    if (remove) callReservedUserDelete(remove.dataset.userDelete);
  });
  $("#open-build-dialog").addEventListener("click", () => $("#build-dialog").showModal());
  $("#close-build-dialog").addEventListener("click", () => $("#build-dialog").close());
  $("#cancel-build-dialog").addEventListener("click", () => $("#build-dialog").close());
  $("#build-form").addEventListener("submit", submitReservedBuildProfile);
  $("#open-build-details").addEventListener("click", () => $("#build-details-dialog").showModal());
  $("#close-build-details").addEventListener("click", () => $("#build-details-dialog").close());
  $("#confirm-build-details").addEventListener("click", () => $("#build-details-dialog").close());
  $("#build-details-dialog").addEventListener("click", async (event) => {
    const artifact = event.target.closest("[data-build-artifact]");
    if (!artifact) return;
    try {
      await api(`/api/build-artifacts/${encodeURIComponent(artifact.dataset.buildArtifact)}/download`);
    } catch (error) {
      showToast(error.message, "error");
    }
  });
  $("#support-form").addEventListener("submit", handleSupportSubmit);
  $("#support-message").addEventListener("input", (event) => { $("#support-count").textContent = event.target.value.length; });
  $("#support-template").addEventListener("change", (event) => {
    const template = state.templates.find((item) => item.id === event.target.value);
    if (template) {
      $("#support-message").value = template.content;
      $("#support-count").textContent = template.content.length;
    }
  });
  $("#reauth-form").addEventListener("submit", handleReauthSubmit);
  $("#close-screen-dialog").addEventListener("click", stopScreenSession);
  $("#stop-screen-button").addEventListener("click", stopScreenSession);
  $("#screen-dialog").addEventListener("cancel", (event) => {
    event.preventDefault();
    stopScreenSession();
  });
  window.addEventListener("hashchange", () => {
    const requested = location.hash.replace("#", "");
    if (viewMeta[requested]) showView(requested, false);
  });
  window.addEventListener("online", () => state.token && connectDashboardSocket());
  window.addEventListener("keydown", (event) => {
    if (!event.altKey || !$("#device-drawer").classList.contains("open")) return;
    if (!["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(event.key)) return;
    const amount = state.workbench.keyStep;
    $("#drawer-content").scrollBy({
      top: event.key === "ArrowUp" ? -amount : event.key === "ArrowDown" ? amount : 0,
      left: event.key === "ArrowLeft" ? -amount : event.key === "ArrowRight" ? amount : 0,
      behavior: "smooth",
    });
    event.preventDefault();
  });
}

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  restoreSession();
});
