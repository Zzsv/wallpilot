(() => {
  "use strict";
  const base = document.querySelector('meta[name="wallpilot-base"]').content;
  const state = {
    csrf: "", status: null, rules: [], objects: [], recycle: [], logs: [],
    selectedRules: new Set(), selectedObjects: new Set(), apply: null, timer: null
  };
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const field = (form, name) => form.elements.namedItem(name);

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
    node.classList.toggle("error-toast", error);
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
      const result = await api("/auth/setup", { method: "POST", body: JSON.stringify(data) });
      toast("初始化完成，请保存恢复码后登录");
      $("#setupForm").classList.add("hidden");
      $("#loginForm").classList.remove("hidden");
      const recovery = $("#recoveryCodes");
      recovery.textContent = `一次性恢复码（每个只能使用一次，请离线保存）：\n${result.recovery_codes.join("\n")}`;
      recovery.classList.remove("hidden");
      $("#authDescription").textContent = "安全初始化完成。请先保存恢复码，再使用管理员密码和动态验证码登录。";
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
      const [status, rules, objects, recycle, audit, logs] = await Promise.all([
        api("/system/status"), api("/firewall/rules"), api("/firewall/objects"),
        api("/recycle-bin"), api("/audit"), api("/firewall/logs")
      ]);
      state.status = status; state.rules = rules; state.objects = objects; state.recycle = recycle; state.logs = logs;
      renderStatus(status); renderRules(rules); renderObjects(objects); renderRecycle(recycle); renderAudit(audit);
      renderLogs();
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
    $("#firewallMetric").classList.toggle("good", fw.active);
    $("#firewallMetric").classList.toggle("bad", !fw.active);
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
    $("#openObjectForm").disabled = fw.backend !== "firewalld" || !fw.capabilities.writable;
    $$(".ufw-only").forEach((element) => {
      element.classList.toggle("hidden", fw.backend !== "ufw");
    });
    const ruleForm = $("#ruleForm");
    [...field(ruleForm, "direction").options].forEach((option) => {
      option.hidden = fw.backend === "firewalld" && option.value !== "in";
    });
    [...field(ruleForm, "action").options].forEach((option) => {
      option.hidden = fw.backend === "firewalld" && option.value === "limit";
    });
    $("#alertList").innerHTML = doc.alerts.map((alert) => `
      <div class="alert ${escapeHtml(alert.severity)}"><strong>${escapeHtml(alert.title)}</strong><span>${escapeHtml(alert.detail)}</span></div>
    `).join("");
    $("#listenerCount").textContent = doc.listeners.length;
    $("#listenerTable").innerHTML = table(
      ["协议", "监听地址", "进程", "关联"],
      doc.listeners.slice(0, 20).map((row) => [
        row.protocol,
        `<code>${escapeHtml(row.local)}</code>`,
        escapeHtml(row.process || "未知"),
        escapeHtml(
          [row.service, row.containers, row.firewall_rules ? `${row.firewall_rules.split(",").length} 条防火墙规则` : ""]
            .filter(Boolean).join(" · ") || "未关联"
        )
      ])
    );
    const services = {
      ...doc.security_services,
      ...doc.security_modules,
      "安全更新缓存": doc.security_updates?.last_cache_update || "unknown",
      "需要重启": doc.reboot_required ? "yes" : "no"
    };
    $("#serviceList").innerHTML = Object.entries(services).map(([name, value]) => `
      <div class="service"><span>${escapeHtml(name)}</span><b class="${value === "active" ? "active" : ""}">${escapeHtml(value)}</b></div>
    `).join("") || '<div class="empty">没有读取到关键服务</div>';
    const traffic = Object.fromEntries((metrics.network || []).map((item) => [item.interface, item]));
    $("#networkTable").innerHTML = table(
      ["网卡", "状态", "地址", "流量"],
      (doc.network_interfaces || []).map((item) => [
        `<code>${escapeHtml(item.name)}</code>`,
        escapeHtml(item.state),
        escapeHtml((item.addresses || []).join(", ") || "—"),
        `↓ ${bytes(traffic[item.name]?.rx_bytes)} · ↑ ${bytes(traffic[item.name]?.tx_bytes)}`
      ]).concat((doc.default_routes || []).map((route) => [
        "默认路由",
        escapeHtml(route.device || "—"),
        escapeHtml(route.gateway || "—"),
        `metric ${escapeHtml(route.metric)}`
      ])).concat(doc.dns_servers?.length ? [[
        "DNS", "—", escapeHtml(doc.dns_servers.join(", ")), "—"
      ]] : [])
    );
    $("#diskTable").innerHTML = table(
      ["挂载点", "已用", "可用", "inode 可用"],
      (metrics.disks || []).map((disk) => [
        `<code>${escapeHtml(disk.mount)}</code>`,
        `${bytes(disk.used)} / ${bytes(disk.total)}`,
        bytes(disk.free),
        disk.inodes_total ? `${Number(disk.inodes_free).toLocaleString()} / ${Number(disk.inodes_total).toLocaleString()}` : "—"
      ])
    );
    $("#connectionTable").innerHTML = table(
      ["类型", "本地", "远端/来源", "进程/用户"],
      (doc.connections || []).slice(0, 20).map((item) => [
        escapeHtml(item.protocol),
        `<code>${escapeHtml(item.local)}</code>`,
        `<code>${escapeHtml(item.remote)}</code>`,
        escapeHtml(item.process || "—")
      ]).concat((doc.ssh_sessions || []).map((item) => [
        "SSH",
        escapeHtml(item.terminal),
        escapeHtml(item.source || item.since || "—"),
        escapeHtml(item.user)
      ]))
    );
    $("#containerTable").innerHTML = table(
      ["容器", "镜像", "状态", "端口"],
      (doc.containers || []).map((item) => [
        `<code>${escapeHtml(item.name)}</code>`,
        escapeHtml(item.image),
        escapeHtml(item.status),
        escapeHtml(item.ports || "—")
      ])
    );
  }

  function ruleLabel(rule) {
    return rule.service || (rule.port ? `${rule.port}/${rule.protocol}` : rule.metadata?.rich_rule || rule.id);
  }

  function renderRules(rules) {
    const query = ($("#ruleSearch").value || "").toLowerCase();
    const filtered = rules.filter((rule) => JSON.stringify(rule).toLowerCase().includes(query));
    $("#rulesTable").innerHTML = table(
      ["", "动作", "端口或服务", "来源", "区域", "备注", ""],
      filtered.map((rule) => [
        `<input type="checkbox" data-select-rule="${escapeHtml(rule.id)}" aria-label="选择规则" ${state.selectedRules.has(rule.id) ? "checked" : ""}>`,
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
    $$("[data-select-rule]").forEach((input) => input.addEventListener("change", () => {
      if (input.checked) state.selectedRules.add(input.dataset.selectRule);
      else state.selectedRules.delete(input.dataset.selectRule);
    }));
  }

  function renderRecycle(items) {
    $("#recycleTable").innerHTML = table(
      ["对象", "后端", "删除时间", "完整性", "原因", ""],
      items.map((item) => [
        `<code>${escapeHtml(item.object_name)}</code>`,
        escapeHtml(item.backend),
        new Date(item.deleted_at).toLocaleString(),
        item.integrity_ok ? '<span class="good">校验通过</span>' : '<span class="bad">校验失败</span>',
        escapeHtml(item.reason || "—"),
        `<div class="row-actions"><button data-restore="${escapeHtml(item.id)}" ${item.integrity_ok ? "" : "disabled"}>恢复</button><button data-restore-batch="${escapeHtml(item.batch_id)}" ${item.integrity_ok ? "" : "disabled"}>恢复批次</button><button class="danger-outline" data-purge="${escapeHtml(item.id)}">永久删除</button><button class="danger-outline" data-purge-batch="${escapeHtml(item.batch_id)}">清除批次</button></div>`
      ])
    );
    $$("[data-restore]").forEach((button) => button.addEventListener("click", () => restoreRule(button.dataset.restore)));
    $$("[data-restore-batch]").forEach((button) => button.addEventListener("click", () => restoreBatch(button.dataset.restoreBatch)));
    $$("[data-purge]").forEach((button) => button.addEventListener("click", () => purgeRule(button.dataset.purge)));
    $$("[data-purge-batch]").forEach((button) => button.addEventListener("click", () => purgeBatch(button.dataset.purgeBatch)));
  }

  function renderLogs() {
    const query = ($("#logSearch").value || "").toLowerCase();
    const lines = state.logs.filter((line) => line.toLowerCase().includes(query));
    $("#firewallLogs").textContent = lines.length
      ? lines.join("\n")
      : "最近一小时没有匹配的拒绝日志。";
  }

  function renderObjects(items) {
    $("#objectsTable").innerHTML = table(
      ["", "类型", "名称", "来源", ""],
      items.map((item) => [
        item.builtin ? "" : `<input type="checkbox" data-select-object="${escapeHtml(item.object_type)}:${escapeHtml(item.name)}" aria-label="选择对象" ${state.selectedObjects.has(`${item.object_type}:${item.name}`) ? "checked" : ""}>`,
        escapeHtml(item.object_type),
        `<code>${escapeHtml(item.name)}</code>`,
        item.builtin ? "系统内置" : '<span class="good">自定义</span>',
        item.builtin ? "" : `<div class="row-actions"><button data-edit-object="${escapeHtml(item.object_type)}:${escapeHtml(item.name)}">编辑</button><button class="danger-outline" data-delete-object="${escapeHtml(item.object_type)}:${escapeHtml(item.name)}">删除</button></div>`
      ])
    );
    $$("[data-edit-object]").forEach((button) => button.addEventListener("click", () => editObject(button.dataset.editObject)));
    $$("[data-delete-object]").forEach((button) => button.addEventListener("click", () => deleteObject(button.dataset.deleteObject)));
    $$("[data-select-object]").forEach((input) => input.addEventListener("change", () => {
      if (input.checked) state.selectedObjects.add(input.dataset.selectObject);
      else state.selectedObjects.delete(input.dataset.selectObject);
    }));
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
  $("#logSearch").addEventListener("input", renderLogs);
  $("#openRuleForm").addEventListener("click", () => $("#ruleFormPanel").classList.remove("hidden"));
  $("#cancelRuleForm").addEventListener("click", () => $("#ruleFormPanel").classList.add("hidden"));
  $("#openObjectForm").addEventListener("click", () => {
    const form = $("#objectForm");
    form.reset();
    field(form, "mode").value = "add";
    field(form, "name").readOnly = false;
    form.classList.remove("hidden"); updateObjectFields();
  });
  $("#cancelObjectForm").addEventListener("click", () => $("#objectForm").classList.add("hidden"));
  $("#objectForm [name=object_type]").addEventListener("change", updateObjectFields);

  function updateObjectFields() {
    const type = $("#objectForm [name=object_type]").value;
    $$(".object-field").forEach((field) => {
      field.classList.toggle("hidden", !field.dataset.types.split(" ").includes(type));
    });
    const target = $("#objectForm [name=target]");
    [...target.options].forEach((option) => {
      option.hidden = type === "zone" ? option.value === "CONTINUE" : option.value === "DEFAULT";
    });
    if (type === "policy" && target.value === "DEFAULT") target.value = "CONTINUE";
    if (type === "zone" && target.value === "CONTINUE") target.value = "DEFAULT";
  }

  $("#ruleForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = Object.fromEntries(new FormData(event.target));
    const rule = {
      backend: state.status.firewall.backend, action: form.action, direction: form.direction,
      protocol: form.protocol, port: form.port, source: form.source || null,
      destination: form.destination || null, interface_in: form.interface_in || null,
      interface_out: form.interface_out || null, service: form.service || null,
      zone: form.zone || null, family: form.family,
      log: form.log || "off", temporary_seconds: Number(form.temporary_seconds || 0),
      comment: form.comment || ""
    };
    await draftAndApply("add", rule, "通过规则向导添加");
    event.target.reset();
    $("#ruleFormPanel").classList.add("hidden");
  });

  $("#objectForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
    const data = Object.fromEntries(new FormData(event.target));
    const type = data.object_type;
    const split = (value) => String(value || "").split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
    const lines = (value) => String(value || "").split(/\n+/).map((item) => item.trim()).filter(Boolean);
    const ports = split(data.ports).map((value) => {
      const [port, protocol = "tcp"] = value.split("/");
      return { port, protocol };
    });
    const sourcePorts = split(data.source_ports).map((value) => {
      const [port, protocol = "tcp"] = value.split("/");
      return { port, protocol };
    });
    const forwardPorts = lines(data.forward_ports).map((value) => {
      const match = value.match(/^(\d+(?:-\d+)?)\/(tcp|udp|sctp|dccp)\s*>\s*(\d+(?:-\d+)?)?(?:\s*@\s*(\S+))?$/i);
      if (!match || (!match[3] && !match[4])) throw new Error(`端口转发格式无效：${value}`);
      return { port: match[1], protocol: match[2].toLowerCase(), to_port: match[3] || "", to_address: match[4] || "" };
    });
    const common = {
      services: split(data.services), ports, source_ports: sourcePorts,
      protocols: split(data.protocols), icmp_blocks: split(data.icmp_blocks),
      icmp_block_inversion: data.icmp_block_inversion === "on",
      rich_rules: lines(data.rich_rules), masquerade: data.masquerade === "on",
      forward_ports: forwardPorts
    };
    let settings;
    if (type === "zone") {
      settings = {
        ...common, target: data.target,
        sources: split(data.sources), interfaces: split(data.interfaces),
        forward: data.forward === "on",
        ingress_priority: Number(data.ingress_priority || 0),
        egress_priority: Number(data.egress_priority || 0)
      };
    } else if (type === "policy") {
      settings = {
        ...common,
        target: data.target, ingress_zones: split(data.ingress_zones),
        egress_zones: split(data.egress_zones),
        priority: Number(data.priority || -1), disabled: data.disabled === "on"
      };
    } else if (type === "service") {
      const destinations = {};
      if (data.destination_ipv4) destinations.ipv4 = data.destination_ipv4;
      if (data.destination_ipv6) destinations.ipv6 = data.destination_ipv6;
      settings = {
        short: data.short || "", description: data.description || "",
        ports, source_ports: sourcePorts, protocols: split(data.protocols),
        modules: split(data.modules), destinations
      };
    } else {
      settings = {
        short: data.short || "", description: data.description || "",
        type: data.ipset_type, family: data.family,
        hashsize: Number(data.hashsize || 1024),
        maxelem: Number(data.maxelem || 65536),
        timeout: Number(data.timeout || 0), entries: lines(data.entries)
      };
    }
    const item = { backend: "firewalld", object_type: type, name: data.name, settings };
    const operation = data.mode === "update" ? "update" : "add";
    await objectDraftAndApply(operation, item, operation === "add" ? "创建高级对象" : "更新高级对象");
    event.target.classList.add("hidden");
    } catch (error) {
      toast(error.message, true);
    }
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
    field(form, "action").value = rule.action;
    field(form, "port").value = rule.port || "";
    field(form, "service").value = rule.service || "";
    field(form, "protocol").value = rule.protocol;
    field(form, "direction").value = rule.direction || "in";
    field(form, "source").value = rule.source || "";
    field(form, "destination").value = rule.destination || "";
    field(form, "interface_in").value = rule.interface_in || "";
    field(form, "interface_out").value = rule.interface_out || "";
    field(form, "zone").value = rule.zone || "";
    field(form, "family").value = rule.family || "any";
    field(form, "log").value = rule.log || "off";
    field(form, "temporary_seconds").value = rule.temporary_seconds || 0;
    field(form, "comment").value = rule.comment ? `${rule.comment}（副本）` : "";
  }

  async function draftAndApply(operation, rule, reason, extra = {}) {
    try {
      const result = await api("/drafts", {
        method: "POST", body: JSON.stringify({ operation, object_type: "rule", payload: { rule, ...extra }, reason })
      });
      const impact = result.impact;
      const conflictWarning = result.rule_analysis?.conflicts?.length
        ? `\n检测到 ${result.rule_analysis.conflicts.length} 条动作相反且范围重叠的规则`
        : "";
      const code = prompt(`第二次确认\n${impact.summary}\n来源：${impact.source}\n风险：${impact.risk}${conflictWarning}\n\n请输入确认码：${result.confirmation_code}`);
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

  async function objectDraftAndApply(operation, item, reason) {
    try {
      const result = await api("/drafts", {
        method: "POST",
        body: JSON.stringify({ operation, object_type: item.object_type, payload: { object: item }, reason })
      });
      const references = result.dependencies?.length
        ? `\n引用关系：${result.dependencies.map((value) => `${value.type}:${value.name}`).join(", ")}`
        : "";
      const code = prompt(`第二次确认\n${result.impact.summary}\n风险：${result.impact.risk}${references}\n\n请输入确认码：${result.confirmation_code}`);
      if (code === null) return;
      const confirmation = { code };
      if (result.draft.requires_totp) {
        confirmation.totp = prompt("高级对象可能改变网络路径，请输入动态验证码：") || "";
        confirmation.hostname = prompt(`请输入主机名确认：${state.status.profile.hostname}`) || "";
      }
      const applied = await api(`/drafts/${result.draft.id}/confirm`, {
        method: "POST", body: JSON.stringify(confirmation)
      });
      showApply(applied.apply_session);
    } catch (error) { toast(error.message, true); }
  }

  async function editObject(ref) {
    const [type, name] = ref.split(":", 2);
    try {
      const item = await api(`/firewall/objects/${encodeURIComponent(type)}/${encodeURIComponent(name)}`);
      const form = $("#objectForm"), settings = item.settings;
      form.classList.remove("hidden"); form.reset();
      field(form, "mode").value = "update";
      field(form, "object_type").value = type;
      field(form, "name").value = name;
      field(form, "name").readOnly = true;
      const join = (values) => (values || []).join(", ");
      const portList = (values) => (values || []).map((value) => `${value.port}/${value.protocol}`).join(", ");
      field(form, "target").value = settings.target || (type === "policy" ? "CONTINUE" : "DEFAULT");
      field(form, "services").value = join(settings.services);
      field(form, "ports").value = portList(settings.ports);
      field(form, "source_ports").value = portList(settings.source_ports);
      field(form, "sources").value = join(settings.sources);
      field(form, "interfaces").value = join(settings.interfaces);
      field(form, "ingress_zones").value = join(settings.ingress_zones);
      field(form, "egress_zones").value = join(settings.egress_zones);
      field(form, "protocols").value = join(settings.protocols);
      field(form, "icmp_blocks").value = join(settings.icmp_blocks);
      field(form, "rich_rules").value = (settings.rich_rules || []).join("\n");
      field(form, "forward_ports").value = (settings.forward_ports || []).map((value) =>
        `${value.port}/${value.protocol} > ${value.to_port || ""}${value.to_address ? ` @ ${value.to_address}` : ""}`
      ).join("\n");
      field(form, "ingress_priority").value = settings.ingress_priority ?? 0;
      field(form, "egress_priority").value = settings.egress_priority ?? 0;
      field(form, "priority").value = settings.priority ?? -1;
      field(form, "short").value = settings.short || "";
      field(form, "description").value = settings.description || "";
      field(form, "modules").value = join(settings.modules);
      field(form, "destination_ipv4").value = settings.destinations?.ipv4 || "";
      field(form, "destination_ipv6").value = settings.destinations?.ipv6 || "";
      field(form, "ipset_type").value = settings.type || "hash:ip";
      field(form, "family").value = settings.family || "inet";
      field(form, "hashsize").value = settings.hashsize ?? 1024;
      field(form, "maxelem").value = settings.maxelem ?? 65536;
      field(form, "timeout").value = settings.timeout ?? 0;
      field(form, "entries").value = (settings.entries || []).join("\n");
      field(form, "masquerade").checked = !!settings.masquerade;
      field(form, "forward").checked = !!settings.forward;
      field(form, "icmp_block_inversion").checked = !!settings.icmp_block_inversion;
      field(form, "disabled").checked = !!settings.disabled;
      updateObjectFields(); form.scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (error) { toast(error.message, true); }
  }

  async function deleteObject(ref) {
    const [type, name] = ref.split(":", 2);
    if (!confirm(`第一次确认：删除 ${type} ${name}？\n对象与完整配置会在确认成功后进入回收站。`)) return;
    try {
      const item = await api(`/firewall/objects/${encodeURIComponent(type)}/${encodeURIComponent(name)}`);
      await objectDraftAndApply("delete", item, "管理员删除高级对象");
    } catch (error) { toast(error.message, true); }
  }

  async function confirmPreparedBatch(result) {
    const code = prompt(`第二次确认\n${result.impact.summary}\n风险：${result.impact.risk}\n\n请输入确认码：${result.confirmation_code}`);
    if (code === null) return;
    const confirmation = { code };
    if (result.draft.requires_totp) {
      confirmation.totp = prompt("批量操作包含高风险项目，请输入动态验证码：") || "";
      confirmation.hostname = prompt(`请输入主机名确认：${state.status.profile.hostname}`) || "";
    }
    const applied = await api(`/drafts/${result.draft.id}/confirm`, {
      method: "POST", body: JSON.stringify(confirmation)
    });
    showApply(applied.apply_session);
  }

  async function startBatchDelete() {
    const ruleIds = [...state.selectedRules];
    const objects = [...state.selectedObjects].map((reference) => {
      const [object_type, name] = reference.split(":", 2);
      return { object_type, name };
    });
    if (!ruleIds.length && !objects.length) return toast("请先勾选要删除的规则或高级对象", true);
    if (!confirm(`第一次确认：将删除 ${ruleIds.length} 条规则和 ${objects.length} 个高级对象。\n确认成功后可按批次从回收站恢复。`)) return;
    try {
      const result = await api("/batch-delete", {
        method: "POST",
        body: JSON.stringify({ rule_ids: ruleIds, objects, reason: "管理员批量删除" })
      });
      state.selectedRules.clear();
      state.selectedObjects.clear();
      await confirmPreparedBatch(result);
    } catch (error) { toast(error.message, true); }
  }
  $("#batchDeleteButton").addEventListener("click", startBatchDelete);
  $("#batchDeleteObjectButton").addEventListener("click", startBatchDelete);

  async function restoreBatch(batchId) {
    if (!confirm("将恢复这个批次中仍在回收站的全部对象。继续预览吗？")) return;
    try {
      const result = await api(`/recycle-bin/batches/${encodeURIComponent(batchId)}/restore`, {
        method: "POST", body: "{}"
      });
      if (result.status === "already_restored") return toast("该批次的配置已经存在，已标记为恢复");
      await confirmPreparedBatch(result);
    } catch (error) { toast(error.message, true); }
  }

  async function restoreRule(id) {
    if (!confirm("恢复会重新添加这条防火墙规则。继续预览恢复内容吗？")) return;
    try {
      const result = await api(`/recycle-bin/${id}/restore`, { method: "POST", body: "{}" });
      if (result.status === "already_restored") return toast("相同配置已经存在，已标记为恢复");
      const code = prompt(`第二次确认：请输入恢复确认码 ${result.confirmation_code}`);
      if (code === null) return;
      const confirmation = { code };
      if (result.draft.requires_totp) {
        confirmation.totp = prompt("这是高风险恢复，请输入动态验证码：") || "";
        confirmation.hostname = prompt(`请输入主机名确认：${state.status.profile.hostname}`) || "";
      }
      const applied = await api(`/drafts/${result.draft.id}/confirm`, {
        method: "POST", body: JSON.stringify(confirmation)
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

  async function purgeBatch(batchId) {
    const count = state.recycle.filter((item) => item.batch_id === batchId).length;
    if (!confirm(`将永久删除这个批次中的 ${count} 个恢复快照，审计记录仍会保留。继续吗？`)) return;
    const password = prompt("重新输入管理员密码：");
    if (password === null) return;
    const totp = prompt("输入动态验证码：");
    if (totp === null) return;
    const expected = `永久删除 ${count} 项`;
    const confirmation = prompt(`请输入“${expected}”：`);
    if (confirmation === null) return;
    try {
      await api(`/recycle-bin/batches/${encodeURIComponent(batchId)}/purge`, {
        method: "POST", body: JSON.stringify({ password, totp, confirmation })
      });
      toast(`已永久删除 ${count} 个恢复快照，审计记录仍然保留`);
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

  const downloadConfig = () => { location.href = `${base}/api/v1/export`; };
  $("#exportButton").addEventListener("click", downloadConfig);
  $("#ruleExportButton").addEventListener("click", downloadConfig);
  $("#importButton").addEventListener("click", () => $("#importFile").click());
  $("#importFile").addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const document = JSON.parse(await file.text());
      const result = await api("/import", {
        method: "POST", body: JSON.stringify(document)
      });
      const skipped = result.impact.skipped?.length
        ? `\n将跳过 ${result.impact.skipped.length} 个已存在项目`
        : "";
      const code = prompt(`${result.impact.summary}${skipped}\n风险：${result.impact.risk}\n\n请输入导入确认码：${result.confirmation_code}`);
      if (code === null) return;
      const confirmation = { code };
      if (result.draft.requires_totp) {
        confirmation.totp = prompt("批量导入包含高风险配置，请输入动态验证码：") || "";
        confirmation.hostname = prompt(`请输入主机名确认：${state.status.profile.hostname}`) || "";
      }
      const applied = await api(`/drafts/${result.draft.id}/confirm`, {
        method: "POST", body: JSON.stringify(confirmation)
      });
      showApply(applied.apply_session);
    } catch (error) {
      toast(`导入失败：${error.message}`, true);
    } finally {
      event.target.value = "";
    }
  });
  setInterval(() => { if (!$("#appView").classList.contains("hidden")) refreshAll(); }, 5000);
  init();
})();
