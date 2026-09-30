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
};

const viewMeta = {
  dashboard: ["REMOTE ADMIN", "首页"],
  devices: ["DEVICE INVENTORY", "设备列表"],
  templates: ["SUPPORT TEMPLATES", "消息模板"],
  users: ["ADMINISTRATORS", "管理员"],
  builds: ["APK BUILDER", "编译打包"],
  capabilities: ["CAPABILITY MATRIX", "功能清单"],
};

const actionLabels = {
  refresh_status: "刷新设备状态",
  show_support_prompt: "显示支持说明",
  open_battery_settings: "打开电池设置",
  open_autostart_settings: "打开自启动设置",
  request_screen_share: "请求屏幕共享",
  stop_screen_share: "停止屏幕共享",
  lock_device: "锁定设备",
  "command.create": "管理员创建命令",
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

function screenLabel(value) {
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
  showView(viewMeta[requested] ? requested : "dashboard", false);
  await Promise.allSettled([
    loadOverview(), loadDevices(), loadGroups(), loadTemplates(),
    state.user?.role === "admin" ? loadUsers() : Promise.resolve(),
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

function showView(view, updateHash = true) {
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
  if (view === "dashboard") loadOverview();
  if (view === "devices") loadDevices();
  if (view === "templates") loadTemplates();
  if (view === "users") loadUsers();
  if (view === "capabilities") loadCapabilities();
}

async function loadCapabilities() {
  if (!state.token) return;
  try {
    const result = await api("/api/capabilities");
    const { items, summary } = result.data;
    $("#capability-implemented").textContent = summary.implemented;
    $("#capability-planned").textContent = summary.not_implemented;
    $("#capability-blocked").textContent = summary.unavailable;
    const labels = { implemented: "已实现", not_implemented: "未实现", unavailable: "不能做" };
    let currentGroup = "";
    $("#capability-list").innerHTML = items.map((item) => {
      const group = item.group !== currentGroup
        ? `<div class="capability-group-head">${escapeHtml(item.group)}</div>`
        : "";
      currentGroup = item.group;
      const interfaces = item.interfaces.map((value) => `<code>${escapeHtml(value)}</code>`).join("");
      return `${group}<article class="capability-row ${item.status}">
        <div><h3>${escapeHtml(item.name)}</h3></div>
        <div class="capability-interfaces">${interfaces}</div>
        <p>${escapeHtml(item.note)}</p>
        <span class="capability-status ${item.status}">${labels[item.status]}</span>
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
        <td>${escapeHtml(actionLabels[command.action] || command.action)}</td>
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

async function callReservedWorkbenchAction(action, currentValue) {
  if (!state.selectedDeviceId) return;
  try {
    await api(`/api/devices/${encodeURIComponent(state.selectedDeviceId)}/workbench-actions/${encodeURIComponent(action)}`, {
      method: "POST",
      body: JSON.stringify({
        value: currentValue === undefined ? null : currentValue !== "true",
        payload: {},
      }),
    });
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function checkReservedWorkbenchModule(module) {
  if (!state.selectedDeviceId) return;
  try {
    await api(`/api/devices/${encodeURIComponent(state.selectedDeviceId)}/workbench/${encodeURIComponent(module)}`);
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
    $("#summary-total").textContent = total;
    $("#summary-online").textContent = online;
    $("#summary-offline").textContent = offline;
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
      <td><div class="realtime-icons"><i class="${device.online ? "on" : ""}"></i><span title="无障碍">♿</span><span title="防删">▣</span><b>🌐</b></div></td>
      <td><strong class="device-name">${escapeHtml(device.id)}</strong><span class="device-subline">${escapeHtml(device.name)}</span></td>
      <td><strong>${escapeHtml(device.brand)}</strong><span class="device-subline">${escapeHtml(device.model)}</span></td>
      <td>${batteryHtml(device.battery_percent)}</td>
      <td><span class="network-quality ${device.online ? "good" : ""}">${escapeHtml(device.network_quality || (device.online ? "良好" : "—"))}${device.network_latency_ms ? ` · ${escapeHtml(device.network_latency_ms)} ms` : ""}</span></td>
      <td>${escapeHtml(device.note || "—")}</td>
      <td>${screenLabel(device.screen_state)}</td>
      <td>${device.locked ? "✓" : "×"}</td>
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

function renderDeviceDetail(device, events) {
  state.selectedDevice = device;
  $("#drawer-device-name").textContent = device.name;
  const canOperate = device.online && ["admin", "operator"].includes(state.user.role);
  const canEdit = ["admin", "operator"].includes(state.user.role);
  const actionDisabled = canOperate ? "" : "disabled";
  const groupOptions = [`<option value="">未分组</option>`, ...state.groups.map((group) => `<option value="${escapeHtml(group.id)}" ${device.group_id === group.id ? "selected" : ""}>${escapeHtml(group.name)}</option>`)].join("");
  const eventHtml = events.length ? events.map((event) => `
    <div class="event-item"><i></i><div><strong>${escapeHtml(actionLabels[event.action] || event.action)} · ${escapeHtml(event.result)}</strong><small>${formatTime(event.created_at)}</small></div></div>`).join("") : `<p class="muted">暂无审计事件</p>`;
  $("#drawer-content").innerHTML = `
    <div class="detail-hero">
      <div class="device-avatar">▯</div>
      <div><h3>${escapeHtml(device.name)}</h3><p>${escapeHtml(device.brand)} ${escapeHtml(device.model)} · Android ${escapeHtml(device.android_version)}</p></div>
      <span class="status-badge ${device.online ? "online" : "offline"}">${device.online ? "在线" : "离线"}</span>
    </div>
    <div class="workbench-toolbar">
      <div><span>网络：</span><b>${escapeHtml(device.network_quality || (device.online ? "良好" : "未知"))}</b></div>
      <div><span>电池：</span><b>${device.battery_percent == null ? "—" : `${device.battery_percent}%`}</b></div>
      <label>设备<select><option>Android 设备</option></select></label>
      <label>宽高 / 缩放<input type="range" min="70" max="130" value="100"></label>
      <label>字体大小<input type="range" min="12" max="22" value="16"></label>
      <button class="secondary-button small" type="button">重置布局</button>
    </div>
    <div class="device-workbench">
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
          <div class="material-status-tabs"><button class="active">全部</button><button>三方APP</button><button>锁屏</button><button>应用锁</button></div>
          <div class="search-box"><span>⌕</span><input placeholder="搜索：网址/APP名称/内容等"></div>
          <div class="reserved-module-banner">输入/凭据日志占位：GET /api/devices/${encodeURIComponent(device.id)}/workbench/input-events 与 /credential-events · 均返回 501</div>
          <div class="event-list">${eventHtml}</div>
        </div>
        <div class="workbench-panel" data-workbench-panel="messages">${workbenchPlaceholder("短信", device.id, "messages")}</div>
        <div class="workbench-panel" data-workbench-panel="apps"><h4>点击图标打开APP</h4>${workbenchPlaceholder("应用列表、打开与卸载", device.id, "apps")}</div>
        <div class="workbench-panel" data-workbench-panel="system"><div class="detail-grid">
          ${detailItem("当前窗口", "—")}${detailItem("当前包名", "—")}${detailItem("控制包名", device.package_name)}
          ${detailItem("应用名称", device.name)}${detailItem("用户时区", device.timezone || "—")}${detailItem("用户语言", device.locale || "—")}
          ${detailItem("手机品牌", device.brand)}${detailItem("手机型号", device.model)}${detailItem("安卓版本", `Android ${device.android_version} (SDK ${device.sdk_int})`)}
        </div><div class="camera-actions"><button data-reserved-action="front-camera">前拍照</button><button data-reserved-action="rear-camera">后拍照</button><button data-reserved-action="camera">打开实时预览</button></div></div>
        <div class="workbench-panel" data-workbench-panel="permissions"><div class="permission-header"><h3>权限管理 <small>手动引导授权</small></h3><label><input type="checkbox"> 自动化</label><button data-action="refresh_status">↻ 刷新</button></div><div class="permission-list">
          ${permissionRow("无障碍权限", device.accessibility_enabled)}${permissionRow("电池白名单", device.battery_whitelist_enabled)}${permissionRow("短信权限", null)}${permissionRow("相册权限", null)}${permissionRow("自动启动", null)}${permissionRow("管理员", device.device_admin_enabled)}
        </div><div class="reserved-module-banner">GET /api/devices/${encodeURIComponent(device.id)}/workbench/permissions · 未接入字段返回 501</div></div>
        <div class="workbench-panel" data-workbench-panel="gallery">${workbenchPlaceholder("相册", device.id, "gallery")}</div>
        <div class="workbench-panel" data-workbench-panel="contacts">${workbenchPlaceholder("通讯录", device.id, "contacts")}</div>
        <div class="workbench-panel" data-workbench-panel="files">${workbenchPlaceholder("文件", device.id, "files")}</div>
        <div class="workbench-panel" data-workbench-panel="clipboard">${workbenchPlaceholder("剪切板", device.id, "clipboard")}</div>
      </section>
      <section class="remote-stage-panel">
        <div class="overlay-picker"><strong>遮盖层/仿页</strong><select data-reserved-action="overlay-mode"><option>纯黑色</option><option>纯白色</option><option>隐藏</option><option>Gpay PIN</option><option>PhonePe PIN</option><option>Paytm PIN</option></select></div>
        <div class="phone-frame"><div class="phone-camera"></div><div class="phone-screen"><span>${device.online ? "设备在线" : "设备离线"}</span><small>打开投屏后显示经用户授权的画面</small><button data-action="request_screen_share" ${actionDisabled}>打开投屏应用</button></div></div>
      </section>
      <aside class="remote-control-panel">
        <div class="remote-state"><span class="status-badge ${device.online ? "online" : "offline"}">${device.online ? "在线" : "离线"}</span><b>${screenLabel(device.screen_state)}</b></div>
        <button class="wide-control green" data-reserved-action="unlock">▣ 一键解锁</button>
        <div class="inline-controls"><button data-action="request_screen_share" ${actionDisabled}>显示投屏</button><button data-action="refresh_status" ${actionDisabled}>↻ 刷新</button></div>
        <button class="wide-control" data-reserved-action="translate">文 一键翻译</button>
        <button class="wide-control green" data-reserved-action="unlock">▣ 已解锁 · 锁屏验证</button>
        ${controlToggle("锁屏", "已锁屏，关掉即可亮屏", "lock-screen", device.locked)}
        ${controlToggle("防删", "防止应用被卸载", "uninstall-protection", device.uninstall_protection_enabled)}
        ${controlToggle("桌面图标", "显示或隐藏应用图标", "launcher-icon", device.launcher_icon_visible)}
        <button class="control-list-button" data-reserved-action="power-menu"><span>⏻</span><div><b>电源</b><small>弹出电源菜单</small></div></button>
        <button class="control-list-button" data-reserved-action="screenshot"><span>▧</span><div><b>截图</b><small>截取当前屏幕</small></div></button>
        <button class="control-list-button" data-action="show_support_prompt" ${actionDisabled}><span>?</span><div><b>消息模板</b><small>显示支持说明</small></div></button>
      </aside>
    </div>
    <section class="detail-section"><h4>名称、分组与备注</h4><form id="device-metadata-form" class="metadata-form">
      <input id="device-edit-name" maxlength="120" value="${escapeHtml(device.name)}" ${canEdit ? "" : "disabled"}>
      <select id="device-edit-group" ${canEdit ? "" : "disabled"}>${groupOptions}</select>
      <textarea id="device-edit-note" maxlength="1000" placeholder="设备备注" ${canEdit ? "" : "disabled"}>${escapeHtml(device.note || "")}</textarea>
      ${canEdit ? '<button class="primary-button" type="submit">保存设备信息</button>' : ""}
    </form></section>`;
}

function workbenchPlaceholder(label, deviceId, module) {
  return `<div class="module-placeholder"><div class="empty-icon">▯</div><h3>${escapeHtml(label)}</h3><p>暂无数据 / 当前 APK 未接入</p><code>GET /api/devices/${escapeHtml(deviceId)}/workbench/${escapeHtml(module)}</code><button class="secondary-button small" data-reserved-module="${escapeHtml(module)}">检查预留接口</button></div>`;
}

function permissionRow(label, value) {
  const enabled = value === true || value === 1;
  const unknown = value == null;
  return `<div class="permission-row ${enabled ? "enabled" : ""}"><span>${enabled ? "✓" : unknown ? "+" : "×"}</span><b>${escapeHtml(label)}</b><em>${unknown ? "未接入" : enabled ? "已开启" : "未开启"}</em></div>`;
}

function controlToggle(title, copy, action, value) {
  const enabled = value === true || value === 1;
  return `<button class="control-toggle" data-reserved-action="${escapeHtml(action)}" data-current-value="${enabled}"><div><b>${escapeHtml(title)}</b><small>${escapeHtml(copy)}</small></div><i class="${enabled ? "on" : ""}"></i></button>`;
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
    const label = { acknowledged: "设备已收到命令", success: "设备操作成功", failed: "设备操作失败" }[event.status];
    if (label) showToast(label, event.status === "failed" ? "error" : "success");
    if (["success", "failed"].includes(event.status)) scheduleDataRefresh();
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
    if (value === "accessible") $("#filter-accessibility").value = "true";
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
      return;
    }
    const reservedAction = event.target.closest("[data-reserved-action]");
    if (reservedAction) {
      callReservedWorkbenchAction(reservedAction.dataset.reservedAction, reservedAction.dataset.currentValue);
      return;
    }
    const reservedModule = event.target.closest("[data-reserved-module]");
    if (reservedModule) {
      checkReservedWorkbenchModule(reservedModule.dataset.reservedModule);
      return;
    }
    const button = event.target.closest("[data-action]");
    if (button && !button.disabled) handleCommandAction(button.dataset.action);
  });
  $("#drawer-content").addEventListener("change", (event) => {
    if (event.target.matches("select[data-reserved-action]")) {
      callReservedWorkbenchAction(event.target.dataset.reservedAction, event.target.value);
    }
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
}

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  restoreSession();
});
