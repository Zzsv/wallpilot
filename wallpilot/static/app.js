(() => {
  "use strict";
  const base = document.querySelector('meta[name="wallpilot-base"]').content;
  const state = { csrf: "", status: null, rules: [], recycle: [], apply: null, timer: null };
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];

  async function api(path, options = {}) {
    const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
    if (state.csrf && options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrf;
    const response = await fetch(`${base}/api/v1${path}`, { credentials: "same-origin", ...options, headers });
    const body = response.headers.get("content-type")?.includes("json") ? await response.json() : await response.text();
    if (!response.ok) throw new Error(body.detail || body || `HTTP ${response.status}`);
    return body;
  }

  function toast(message, error = false) {
    const node = $("#toast");
    node.textContent = message;
    node.style.background = error ? "#ffd9d5" : "#dff9ed";
    node.classList.remove("hidden");
    setTimeout(() => node.classList.add("hidden"), 3600);
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[char]);
  }

  function bytes(value) {
    const n = Number(value || 0);
    if (!n) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const index = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
    return `${(n / 1024 ** index).toFixed(index > 1 ? 1 : 0)} ${units[index]}`;
  }

  function uptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    return days ? `${days}天 ${hours}小时` : `${hours}小时`;
  }

  async function init() {
    try {
      const auth = await api("/auth/state");
      $("#authDescription").textContent = auth.initialized
        ? `正在管理 ${auth.hostname}，需要管理员密码与动态验证码。`
        : "请先在服务器运行 wallpilot bootstrap，然后填写本机引导信息。";
      $("#setupForm").classList.toggle("hidden", auth.initialized);
      $("#loginForm").classList.toggle("hidden", !auth.initialized);
      $("#connectionState").textContent = "入口已验证";
    } catch (error) {
      $("#authError").textContent = error.message;
      $("#connectionState").textContent = "连接失败";
    }
  }

  async function enterApp(csrf) {
    state.csrf = csrf;
    $("#authView").classList.add("hidden");
    $("#appView").classList.remove("hidden");
    $("#logoutButton").classList.remove("hidden");
    await refreshAll();
  }

  $("#setupForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.target));
    try {
      await api("/auth/setup", { method: "POST", body: JSON.stringify(data) });
      toast("初始化完成，请登录");
      $("#setupForm").classList.add("hidden");
      $("#loginForm").classList.remove("hidden");
      $("#authDescription").textContent = "安全初始化完成，请使用管理员密码和动态验证码登录。";
    } catch (error) { $("#authError").textContent = error.message; }
  });

  $("#loginForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.target));
    try {
      const result = await api("/auth/login", { method: "POST", body: JSON.stringify(data) });
      await enterApp(result.csrf);
    } catch (error) { $("#authError").textContent = error.message; }
  });

  $("#logoutButton").addEventListener("click", async () => {
    try { await api("/auth/logout", { method: "POST", body: "{}" }); } catch (_) {}
    location.reload();
  });

  $$("nav a").forEach((link) => link.addEventListener("click", () => {
    $$("nav a").forEach((item) => item.classList.remove("active"));
    link.classList.add("active");
    $$(".page").forEach((page) => page.classList.remove("active"));
    $(link.getAttribute("href")).classList.add("active");
  }));

  async function refreshAll() {
    try {
      const [status, rules, recycle, audit] = await Promise.all([
        api("/system/status"), api("/firewall/rules"), api("/recycle-bin"), api("/audit")
      ]);
      state.status = status; state.rules = rules; state.recycle = recycle;
      renderStatus(status); renderRules(rules); renderRecycle(recycle); renderAudit(audit);
      $("#connectionState").textContent = "安全连接";
      $("#lastRefresh").textContent = `更新于 ${new Date().toLocaleTimeString()}`;
    } catch (error) {
      if (String(error.message).includes("登录")) return location.reload();
      toast(error.message, true);
      $("#connectionState").textContent = "读取失败";
    }
  }

  function renderStatus(doc) {
    const fw = doc.firewall, metrics = doc.metrics, profile = doc.profile;
    $("#hostTitle").textContent = `${profile.hostname} · ${profile.os_name} ${profile.os_version}`;
    $("#firewallMetric").textContent = fw.active ? "运行中" : "未运行";
    $("#firewallMetric").style.color = fw.active ? "var(--accent)" : "var(--danger)";
    $("#backendMetric").textContent = fw.backend;
    $("#loadMetric").textContent = `${metrics.load_1.toFixed(2)} / ${metrics.load_5.toFixed(2)} / ${metrics.load_15.toFixed(2)}`;
    const used = Math.max(0, metrics.memory_total - metrics.memory_available);
    $("#memoryMetric").textContent = bytes(metrics.memory_available);
    $("#memoryDetail").textContent = `已用 ${bytes(used)} / ${bytes(metrics.memory_total)}`;
    $("#uptimeMetric").textContent = uptime(metrics.uptime_seconds);
    $("#kernelMetric").textContent = profile.kernel;
    $("#backendName").textContent = fw.backend;
    $("#backendMessage").textContent = fw.message || `${fw.service_unit || "未检测到服务"} · 默认策略 ${fw.default_policy}`;
    $("#firewallBadge").textContent = fw.active ? "运行中" : "未运行";
    $("#capabilityList").innerHTML = fw.capabilities.features.length
      ? fw.capabilities.features.map((item) => `<span>${escapeHtml(item)}</span>`).join("")
      : `<span>${escapeHtml(fw.capabilities.reason || "只读")}</span>`;
    $$("[data-service-action]").forEach((button) => {
      button.disabled = !fw.capabilities.service_actions.includes(button.dataset.serviceAction);
    });
    $("#alertList").innerHTML = doc.alerts.map((alert) => `
      <div class="alert ${escapeHtml(alert.severity)}"><strong>${escapeHtml(alert.title)}</strong><span>${escapeHtml(alert.detail)}</span></div>
    `).join("");
    $("#listenerCount").textContent = doc.listeners.length;
    $("#listenerTable").innerHTML = table(
      ["协议", "监听地址", "进程"],
      doc.listeners.slice(0, 20).map((row) => [row.protocol, `<code>${escapeHtml(row.local)}</code>`, escapeHtml(row.process || "未知")])
    );
    $("#serviceList").innerHTML = Object.entries(doc.security_services).map(([name, value]) => `
      <div class="service"><span>${escapeHtml(name)}</span><b class="${value === "active" ? "active" : ""}">${escapeHtml(value)}</b></div>
    `).join("") || '<div class="empty">没有读取到关键服务</div>';
  }

  function ruleLabel(rule) {
    return rule.service || (rule.port ? `${rule.port}/${rule.protocol}` : rule.metadata?.rich_rule || rule.id);
  }

  function renderRules(rules) {
    const query = ($("#ruleSearch").value || "").toLowerCase();
    const filtered = rules.filter((rule) => JSON.stringify(rule).toLowerCase().includes(query));
    $("#rulesTable").innerHTML = table(
      ["动作", "端口或服务", "来源", "区域", "备注", ""],
      filtered.map((rule) => [
        `<span class="status-pill">${escapeHtml(rule.action)}</span>`,
        `<code>${escapeHtml(ruleLabel(rule))}</code>`,
        escapeHtml(rule.source || "任意来源"),
        escapeHtml(rule.zone || "默认"),
        escapeHtml(rule.comment || "—"),
        `<div class="row-actions"><button data-copy-rule="${escapeHtml(rule.id)}">复制</button><button class="danger-outline" data-delete-rule="${escapeHtml(rule.id)}">删除</button></div>`
      ])
    );
    $$("[data-delete-rule]").forEach((button) => button.addEventListener("click", () => deleteRule(button.dataset.deleteRule)));
    $$("[data-copy-rule]").forEach((button) => button.addEventListener("click", () => copyRule(button.dataset.copyRule)));
  }

  function renderRecycle(items) {
    $("#recycleTable").innerHTML = table(
      ["对象", "后端", "删除时间", "完整性", "原因", ""],
      items.map((item) => [
        `<code>${escapeHtml(item.object_name)}</code>`,
        escapeHtml(item.backend),
        new Date(item.deleted_at).toLocaleString(),
        item.integrity_ok ? '<span style="color:var(--accent)">校验通过</span>' : '<span style="color:var(--danger)">校验失败</span>',
        escapeHtml(item.reason || "—"),
        `<div class="row-actions"><button data-restore="${escapeHtml(item.id)}" ${item.integrity_ok ? "" : "disabled"}>恢复</button><button class="danger-outline" data-purge="${escapeHtml(item.id)}">永久删除</button></div>`
      ])
    );
    $$("[data-restore]").forEach((button) => button.addEventListener("click", () => restoreRule(button.dataset.restore)));
    $$("[data-purge]").forEach((button) => button.addEventListener("click", () => purgeRule(button.dataset.purge)));
  }

  function renderAudit(items) {
    $("#auditTable").innerHTML = table(
      ["时间", "事件", "操作者", "来源", "详情"],
      items.map((item) => [
        new Date(item.created_at).toLocaleString(),
        `<code>${escapeHtml(item.event)}</code>`,
        escapeHtml(item.actor),
        escapeHtml(item.source),
        `<span title="${escapeHtml(JSON.stringify(item.details))}">${escapeHtml(JSON.stringify(item.details).slice(0, 80))}</span>`
      ])
    );
  }

  function table(headers, rows) {
    if (!rows.length) return '<div class="empty">暂无数据</div>';
    return `<table><thead><tr>${headers.map((item) => `<th>${item}</th>`).join("")}</tr></thead><tbody>${
      rows.map((row) => `<tr>${row.map((item) => `<td>${item}</td>`).join("")}</tr>`).join("")
    }</tbody></table>`;
  }

  $("#refreshButton").addEventListener("click", refreshAll);
  $("#ruleSearch").addEventListener("input", () => renderRules(state.rules));
  $("#openRuleForm").addEventListener("click", () => $("#ruleFormPanel").classList.remove("hidden"));
  $("#cancelRuleForm").addEventListener("click", () => $("#ruleFormPanel").classList.add("hidden"));

  $("#ruleForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = Object.fromEntries(new FormData(event.target));
    const rule = {
      backend: state.status.firewall.backend, action: form.action, direction: "in",
      protocol: form.protocol, port: form.port, source: form.source || null,
      zone: form.zone || null, comment: form.comment || ""
    };
    await draftAndApply("add", rule, "通过规则向导添加");
    event.target.reset();
    $("#ruleFormPanel").classList.add("hidden");
  });

  async function deleteRule(id) {
    const rule = state.rules.find((item) => item.id === id);
    if (!rule) return;
    if (!confirm(`第一次确认：删除 ${ruleLabel(rule)}？\n删除会改变服务器访问控制，成功后可从回收站恢复。`)) return;
    await draftAndApply("delete", rule, "管理员从规则列表删除");
  }

  function copyRule(id) {
    const rule = state.rules.find((item) => item.id === id);
    if (!rule) return;
    $("#openRuleForm").click();
    const form = $("#ruleForm");
    form.action.value = rule.action;
    form.port.value = rule.port || "";
    form.protocol.value = rule.protocol;
    form.source.value = rule.source || "";
    form.zone.value = rule.zone || "";
    form.comment.value = rule.comment ? `${rule.comment}（副本）` : "";
  }

  async function draftAndApply(operation, rule, reason, extra = {}) {
    try {
      const result = await api("/drafts", {
        method: "POST", body: JSON.stringify({ operation, object_type: "rule", payload: { rule, ...extra }, reason })
      });
      const impact = result.impact;
      const code = prompt(`第二次确认\n${impact.summary}\n来源：${impact.source}\n风险：${impact.risk}\n\n请输入确认码：${result.confirmation_code}`);
      if (code === null) return;
      const confirmation = { code };
      if (result.draft.requires_totp) {
        confirmation.totp = prompt("这是高风险操作，请输入动态验证码：") || "";
        confirmation.hostname = prompt(`请输入主机名确认：${state.status.profile.hostname}`) || "";
      }
      const applied = await api(`/drafts/${result.draft.id}/confirm`, {
        method: "POST", body: JSON.stringify(confirmation)
      });
      showApply(applied.apply_session);
    } catch (error) { toast(error.message, true); }
  }

  async function restoreRule(id) {
    if (!confirm("恢复会重新添加这条防火墙规则。继续预览恢复内容吗？")) return;
    try {
      const result = await api(`/recycle-bin/${id}/restore`, { method: "POST", body: "{}" });
      if (result.status === "already_restored") return toast("相同规则已经存在，已标记为恢复");
      const code = prompt(`第二次确认：请输入恢复确认码 ${result.confirmation_code}`);
      if (code === null) return;
      const applied = await api(`/drafts/${result.draft.id}/confirm`, {
        method: "POST", body: JSON.stringify({ code })
      });
      showApply(applied.apply_session);
    } catch (error) { toast(error.message, true); }
  }

  async function purgeRule(id) {
    if (!confirm("永久删除后无法恢复，但对应审计记录仍会保留。继续吗？")) return;
    const password = prompt("重新输入管理员密码：");
    if (password === null) return;
    const totp = prompt("输入动态验证码：");
    if (totp === null) return;
    const confirmation = prompt("请输入“永久删除”四个字：");
    if (confirmation === null) return;
    try {
      await api(`/recycle-bin/${id}/purge`, {
        method: "POST", body: JSON.stringify({ password, totp, confirmation })
      });
      toast("回收快照已永久删除，审计记录仍然保留");
      await refreshAll();
    } catch (error) { toast(error.message, true); }
  }

  $$("[data-service-action]").forEach((button) => button.addEventListener("click", async () => {
    const action = button.dataset.serviceAction;
    const payload = { action };
    if (["stop", "disable"].includes(action)) {
      if (!confirm("这会降低或关闭服务器的本机防火墙保护。90秒内未确认将自动恢复，是否继续？")) return;
      payload.totp = prompt("请输入动态验证码：") || "";
      payload.hostname = prompt(`请输入主机名确认：${state.status.profile.hostname}`) || "";
    }
    try {
      const result = await api("/firewall/service-action", { method: "POST", body: JSON.stringify(payload) });
      if (result.apply_session) showApply(result.apply_session);
      else { toast("服务操作已完成"); await refreshAll(); }
    } catch (error) { toast(error.message, true); }
  }));

  function showApply(session) {
    state.apply = session;
    $("#applyBanner").classList.remove("hidden");
    if (state.timer) clearInterval(state.timer);
    const tick = () => {
      const remaining = Math.max(0, Math.ceil((new Date(session.deadline) - Date.now()) / 1000));
      $("#applyCountdown").textContent = `${remaining} 秒后自动回滚`;
      if (!remaining) {
        clearInterval(state.timer);
        $("#applyBanner").classList.add("hidden");
        toast("确认超时，WallPilot 已请求自动回滚", true);
        setTimeout(refreshAll, 1200);
      }
    };
    tick(); state.timer = setInterval(tick, 1000);
  }

  $("#confirmApply").addEventListener("click", async () => {
    if (!state.apply) return;
    try {
      await api(`/apply-sessions/${state.apply.id}/confirm`, { method: "POST", body: "{}" });
      clearInterval(state.timer); state.apply = null; $("#applyBanner").classList.add("hidden");
      toast("变更已经确认并保存"); await refreshAll();
    } catch (error) { toast(error.message, true); }
  });

  $("#rollbackApply").addEventListener("click", async () => {
    if (!state.apply) return;
    try {
      await api(`/apply-sessions/${state.apply.id}/rollback`, { method: "POST", body: "{}" });
      clearInterval(state.timer); state.apply = null; $("#applyBanner").classList.add("hidden");
      toast("变更已经回滚"); await refreshAll();
    } catch (error) { toast(error.message, true); }
  });

  $("#exportButton").addEventListener("click", () => { location.href = `${base}/api/v1/export`; });
  setInterval(() => { if (!$("#appView").classList.contains("hidden")) refreshAll(); }, 5000);
  init();
})();

