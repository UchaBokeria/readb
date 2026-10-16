"use strict";
const $ = (s) => document.querySelector(s);
const state = {
  key: sessionStorage.getItem("readb-key") || "",
  devices: [],
  events: [],
  actions: [],
  page: "devices",
  selected: "",
  query: "",
  actionQuery: "",
  busy: false,
  polling: false,
  connected: false,
  pid: null,
};
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const icon = (kind) =>
  kind === "quest"
    ? '<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M6 10h20l3 12-5 3-6-5h-4l-6 5-5-3z"/><path d="M10 14h4v4h-4zm8 0h4v4h-4z"/></svg>'
    : '<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="8" y="3" width="16" height="26" rx="4"/><path d="M13 7h6M14 25h4"/></svg>';
let currentAbort = null;
let lastImage = null;
let toastTimer;
let renderedModel = "";
function modelKey() {
  return JSON.stringify({
    page: state.page,
    selected: state.selected,
    query: state.query,
    actionQuery: state.actionQuery,
    devices: state.devices.map((d) => ({
      id: d.id,
      name: d.name,
      kind: d.kind,
      connected: d.connected,
      identity: d.identity_verified,
      battery: d.battery,
      job: d.job?.owner,
      viewers: d.viewers?.map((v) => ({ owner: v.owner, active: v.active })),
      policy: d.keepalive_policy,
      cleanup: d.cleanup_unknown,
      awake: d.maintenance_fresh ? d.maintenance?.awake : null,
      unlocked: d.maintenance?.unlocked,
    })),
    events: state.page === "activity" ? state.events : [],
  });
}
function updateReportAges() {
  document.querySelectorAll("[data-age]").forEach((el) => {
    const d = state.devices.find((d) => d.id === el.dataset.age);
    if (d) el.textContent = age(d);
  });
}

async function api(path, options = {}) {
  const controller = options.signal ? null : new AbortController();
  const timer = controller ? setTimeout(() => controller.abort(), 10000) : null;
  try {
    const response = await fetch(path, {
      ...options,
      signal: options.signal || controller.signal,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${state.key}`,
        ...(options.headers || {}),
      },
    });
    if (response.status === 403)
      throw new Error("Access key was rejected. Check the key on your server.");
    if (response.headers.get("content-type")?.startsWith("image/png")) {
      if (!response.ok) throw new Error("Screenshot failed.");
      return { image: await response.blob() };
    }
    const data = await response.json();
    if (!response.ok || data.error)
      throw new Error(data.error || `Request failed (${response.status}).`);
    return data;
  } finally {
    if (timer) clearTimeout(timer);
  }
}
function toast(message) {
  $("#toast").textContent = message;
  $("#toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    $("#toast").hidden = true;
  }, 6000);
}
function showApp() {
  $("#login").hidden = true;
  $("#app").hidden = false;
}
function signout() {
  sessionStorage.removeItem("readb-key");
  state.key = "";
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#access-key").value = "";
}
async function refresh(initial = false) {
  if (state.polling || !state.key) return;
  state.polling = true;
  try {
    const [status, history, actions] = await Promise.all([
      api("/api/status"),
      api("/api/history"),
      state.actions.length
        ? Promise.resolve({ actions: state.actions })
        : api("/api/actions"),
    ]);
    state.devices = status.devices;
    state.pid = status.pid;
    state.events = history.events;
    state.actions = actions.actions;
    state.connected = true;
    if (!state.devices.some((d) => d.id === state.selected))
      state.selected = state.devices[0]?.id || "";
    showApp();
    $("#device-count").textContent = state.devices.length;
    $("#server-state").textContent = "Connected";
    $("#server-dot").classList.remove("off");
    $("#last-updated").textContent = "Updated just now";
    $("#footer-meta").textContent = `Server PID ${state.pid}`;
    const editing =
      $("#main").contains(document.activeElement) &&
      ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName);
    if (
      !editing &&
      !$("#action-dialog").open &&
      !state.busy &&
      modelKey() !== renderedModel
    )
      render();
    else updateReportAges();
  } catch (error) {
    state.connected = false;
    $("#server-state").textContent = "Unavailable";
    $("#server-dot").classList.add("off");
    $("#last-updated").textContent = "Connection lost";
    if (initial) {
      $("#login-error").textContent = error.message;
      $("#app").hidden = true;
      $("#login").hidden = false;
    } else
      toast(
        error.name === "AbortError"
          ? "Server did not respond. Retrying status."
          : error.message,
      );
  } finally {
    state.polling = false;
  }
}
function badge(d) {
  return d.connected
    ? '<span class="badge"><i class="status-dot"></i>Connected</span>'
    : '<span class="badge warning"><i class="status-dot off"></i>Offline</span>';
}
function age(d) {
  const n = d.report_age_seconds;
  return Number.isFinite(n)
    ? `${Math.max(0, Math.round(n))}s ago`
    : "No report";
}
function title(text, description, controls = "") {
  return `<div class="page-head"><div><h1>${esc(text)}</h1><p>${esc(description)}</p></div>${controls ? `<div class="head-actions">${controls}</div>` : ""}</div>`;
}
function card(d) {
  const owner = d.job?.owner;
  return `<button class="device-card ${state.selected === d.id ? "selected" : ""}" data-device="${esc(d.id)}" aria-label="Open ${esc(d.name)}"><div class="device-top"><span class="device-avatar">${icon(d.kind)}</span>${badge(d)}</div><h2>${esc(d.name)}</h2><div class="device-kind">${d.kind === "quest" ? "Quest headset" : "Android device"} · ${esc(d.id)}</div><div class="device-stats"><span>Battery<strong>${d.battery >= 0 && d.report_age_seconds !== null ? `${d.battery}%` : "Unknown"}</strong></span><span>Last report<strong data-age="${esc(d.id)}">${age(d)}</strong></span><span>Controller<strong>${owner ? esc(owner.agent) : "Available"}</strong></span></div></button>`;
}
function deviceDetails(d) {
  const fresh = d.maintenance_fresh;
  const m = d.maintenance || {};
  const awake =
    fresh && typeof m.awake === "boolean"
      ? m.awake
        ? "Awake"
        : "Sleeping"
      : "Unknown";
  const jobs = [
    d.job
      ? {
          owner: d.job.owner,
          mode: "Control",
          remaining: d.lease_remaining_seconds,
        }
      : null,
    ...(d.viewers || []).map((v) => ({
      owner: v.owner,
      mode: "View",
      remaining: v.remaining_seconds,
    })),
  ].filter(Boolean);
  return `<section class="detail" aria-label="${esc(d.name)} details"><div class="detail-head"><div><h2>${esc(d.name)}</h2><p>Shared views. One controller.</p></div><button data-page="actions" class="secondary">All actions</button></div><div class="detail-body"><div class="detail-section"><div class="section-label">Connection</div><div class="connection-path"><div class="connection-node"><strong>This view</strong><small>Dashboard</small></div><span class="connection-line"></span><div class="connection-node"><strong>Server</strong><small>Secure ADB</small></div><span class="connection-line"></span><div class="connection-node"><strong>${esc(d.name)}</strong><small>${d.connected ? "Verified" : "Unavailable"}</small></div></div><dl class="facts"><dt>Identity</dt><dd>${d.identity_verified ? "Verified" : "Not verified"}</dd><dt>Power</dt><dd>${awake}</dd><dt>Lockscreen</dt><dd>${m.unlocked === true && fresh ? "Unlocked" : "Not confirmed"}</dd><dt>Last report</dt><dd data-age="${esc(d.id)}">${age(d)}</dd><dt>Transport</dt><dd>ADB ${esc(d.adb_server_port)}</dd></dl><div class="quick-actions"><button data-action="wake">Wake</button><button data-action="screenshot">Screenshot</button><button data-action="home">Home</button><button data-action="logs">View logs</button></div>${d.cleanup_unknown ? `<div class="callout warning">Cleanup needs review. ${esc(d.cleanup_unknown)} New commands stay blocked.</div>` : ""}</div><div class="detail-section"><div class="section-label">While you work</div><div class="policy-row"><div><strong>Keep awake</strong><p>Keep the screen active during development.</p></div><button data-policy="enabled" class="toggle ${d.keepalive_policy.enabled ? "on" : ""}" role="switch" aria-checked="${d.keepalive_policy.enabled}" aria-label="Keep awake"></button></div><div class="policy-row"><div><strong>Prevent locking</strong><p>Request the supported keep-active behavior.</p></div><button data-policy="prevent_lock" class="toggle ${d.keepalive_policy.prevent_lock ? "on" : ""}" role="switch" aria-checked="${d.keepalive_policy.prevent_lock}" aria-label="Prevent locking"></button></div><div class="callout">A protected lockscreen can still need manual unlock. Awake does not mean unlocked.</div><div class="jobs-list"><div class="section-label">Current jobs <span class="muted">${jobs.length}</span></div>${jobs.length ? jobs.map((j) => `<div class="job-row"><div><strong>${esc(j.owner.job)}</strong><small>${esc(j.owner.agent)} on ${esc(j.owner.origin)}</small></div><span class="badge neutral">${j.mode}</span></div>`).join("") : "<p>No active jobs. Ready when you are.</p>"}</div></div></div></section>`;
}
function renderDevices() {
  const visible = state.devices.filter((d) =>
    `${d.name} ${d.id} ${d.kind}`
      .toLowerCase()
      .includes(state.query.toLowerCase()),
  );
  const head = title(
    "Devices",
    "Your phones and headsets. One place to work.",
    '<input class="search" id="device-search" type="search" placeholder="Find a device" aria-label="Find a device" value="' +
      esc(state.query) +
      '">',
  );
  if (!state.devices.length)
    return (
      head +
      '<section class="empty"><h2>No devices yet.</h2><p>Enroll a device from the CLI. Pairing is not available in this development dashboard yet.</p><code>readb device --help</code></section>'
    );
  return (
    head +
    `<div class="device-grid">${visible.map(card).join("")}</div>` +
    (visible.length
      ? deviceDetails(
          state.devices.find((d) => d.id === state.selected) || visible[0],
        )
      : '<div class="empty">No matching devices.</div>')
  );
}
function renderActions() {
  return (
    title("Actions", "Small tools for everyday device work.") +
    `<div class="actions-head"><input class="search" id="action-search" type="search" placeholder="Find an action" aria-label="Find an action" value="${esc(state.actionQuery)}"><select id="action-device" aria-label="Device for actions">${state.devices.map((d) => `<option value="${esc(d.id)}" ${d.id === state.selected ? "selected" : ""}>${esc(d.name)}</option>`).join("")}</select></div><div class="action-list">${state.actions
      .filter((a) =>
        `${a.id} ${a.description}`
          .toLowerCase()
          .includes(state.actionQuery.toLowerCase()),
      )
      .map(
        (a) =>
          `<button class="action-item" data-action="${esc(a.id)}"><strong>${esc(a.id.replaceAll("-", " "))}</strong><p>${esc(a.description)}</p><span class="badge ${a.review ? "warning" : "neutral"}">${a.review ? "Review first" : a.class === "view" || a.class === "status" ? "View" : "Control"}</span></button>`,
      )
      .join("")}</div>`
  );
}
function renderActivity() {
  return (
    title("Activity", "Recent work across your devices.") +
    (state.events.length
      ? `<div class="activity"><div class="activity-row header"><span>Time</span><span>Device</span><span>Action</span><span>Result</span></div>${state.events
          .slice()
          .reverse()
          .map(
            (e) =>
              `<div class="activity-row"><time>${new Date(e.epoch * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time><span>${esc(e.device)}</span><strong>${esc(e.command || e.kind)}</strong><span>${esc(e.outcome)}</span></div>`,
          )
          .join("")}</div>`
      : '<section class="empty"><h2>Nothing here yet.</h2><p>Actions appear here once you use a device.</p></section>')
  );
}
function renderSettings() {
  return (
    title("Settings", "Clear defaults. Per-device control.") +
    `<div class="settings-grid"><section class="settings-panel"><h2>Device behavior</h2><p>Keep awake and prevent locking are on by default. Change each device from its details page.</p><div class="callout">Actual power and lock state are reported separately. A requested setting is not a successful unlock.</div></section><section class="settings-panel"><h2>Dashboard access</h2><p>Web access is off by default. This session uses your server's access key.</p><dl class="facts"><dt>Server</dt><dd>${state.connected ? "Connected" : "Unavailable"}</dd><dt>Process</dt><dd>${state.pid || "Unknown"}</dd><dt>Device access</dt><dd>Through the server</dd></dl><button id="settings-signout" class="secondary">Disconnect dashboard</button></section><section class="settings-panel"><h2>Concurrent work</h2><p>View together. One controller changes a device. Different devices can work in parallel.</p><p>A busy device names its current job. Cancelled work with unknown cleanup stays blocked until reviewed.</p></section><section class="settings-panel"><h2>Server configuration</h2><p>Use the CLI to inspect your current configuration. Private keys and report credentials stay hidden.</p><div class="code-block">readb config show\nreadb service --help</div><p>Pairing and full configuration editing are still in development.</p></section></div>`
  );
}
function render() {
  renderedModel = modelKey();
  const names = {
    devices: "Devices",
    actions: "Actions",
    activity: "Activity",
    settings: "Settings",
  };
  $("#page-label").textContent = names[state.page];
  document.title = `readb · ${names[state.page].toLowerCase()}`;
  document.querySelectorAll(".nav").forEach((b) => {
    b.classList.toggle("active", b.dataset.page === state.page);
    b.setAttribute("aria-label", names[b.dataset.page]);
  });
  $("#main").innerHTML = {
    devices: renderDevices,
    actions: renderActions,
    activity: renderActivity,
    settings: renderSettings,
  }[state.page]();
}
function openAction(id) {
  const action = state.actions.find((a) => a.id === id);
  if (!action) return toast("Action is unavailable. Refresh the dashboard.");
  const device = state.devices.find((d) => d.id === state.selected);
  if (!device) return toast("Select a device first.");
  $("#action-form").dataset.action = id;
  $("#action-form").dataset.device = device.id;
  $("#action-title").textContent = id.replaceAll("-", " ");
  $("#action-class").textContent = device.name;
  $("#action-description").textContent = action.description;
  $("#action-fields").innerHTML = action.usage
    .split(" ")
    .filter(Boolean)
    .map(
      (name, i) =>
        `<label for="param-${i}">${esc(name.replaceAll("_", " "))}</label><input id="param-${i}" data-param="${i}" ${name.startsWith("[") ? "" : "required"} autocomplete="off">`,
    )
    .join("");
  $("#action-result").textContent = "";
  $("#review-check").checked = false;
  $("#review-row").hidden = !action.review;
  $("#action-review").hidden = !action.review;
  $("#action-review").textContent =
    id === "reboot"
      ? "Reboot can leave this device waiting for manual unlock or debugging consent. Remote recovery is not guaranteed."
      : "This changes the selected device or its files. Check the target before running.";
  $("#run-action").disabled = false;
  $("#run-action").textContent = "Run action";
  $("#action-dialog").showModal();
}
async function runAction(event) {
  event.preventDefault();
  const id = $("#action-form").dataset.action;
  const action = state.actions.find((a) => a.id === id);
  if (action.review && !$("#review-check").checked)
    return toast("Review the action before running it.");
  const args = [...document.querySelectorAll("[data-param]")]
    .map((i) => i.value)
    .filter((v) => v !== "");
  currentAbort = new AbortController();
  $("#run-action").disabled = true;
  $("#run-action").textContent = "Running…";
  $("#action-result").textContent = "Checking connection and job ownership…";
  try {
    const result = await api("/api/action", {
      method: "POST",
      body: JSON.stringify({
        device: $("#action-form").dataset.device,
        action: id,
        args,
        reviewed: $("#review-check").checked,
      }),
      signal: currentAbort.signal,
    });
    if (result.image) {
      if (lastImage) URL.revokeObjectURL(lastImage);
      lastImage = URL.createObjectURL(result.image);
      const img = document.createElement("img");
      img.src = lastImage;
      img.alt = "Captured device screen";
      $("#action-result").replaceChildren(img);
    } else
      $("#action-result").textContent =
        result.stdout || result.message || JSON.stringify(result, null, 2);
  } catch (error) {
    $("#action-result").textContent =
      error.name === "AbortError"
        ? "Cancelled. Check device jobs for cleanup status."
        : error.message;
  } finally {
    currentAbort = null;
    $("#run-action").disabled = false;
    $("#run-action").textContent = "Run again";
    refresh();
  }
}
async function policy(field) {
  const d = state.devices.find((d) => d.id === state.selected);
  if (!d) return;
  const value = { ...d.keepalive_policy, [field]: !d.keepalive_policy[field] };
  state.busy = true;
  try {
    await api("/api/policy", {
      method: "POST",
      body: JSON.stringify({ device: d.id, ...value }),
    });
    toast("Device behavior saved.");
  } catch (error) {
    toast(error.message);
  } finally {
    state.busy = false;
    await refresh();
  }
}
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  state.key = $("#access-key").value.trim();
  $("#login-error").textContent = "";
  await refresh(true);
  if (state.connected) sessionStorage.setItem("readb-key", state.key);
});
$("#signout").addEventListener("click", signout);
$("#refresh").addEventListener("click", () => refresh());
document.addEventListener("click", (e) => {
  const page = e.target.closest("[data-page]");
  if (page) {
    state.page = page.dataset.page;
    render();
    return;
  }
  const device = e.target.closest("[data-device]");
  if (device) {
    state.selected = device.dataset.device;
    render();
    return;
  }
  const action = e.target.closest("[data-action]");
  if (action) {
    openAction(action.dataset.action);
    return;
  }
  const toggle = e.target.closest("[data-policy]");
  if (toggle) {
    policy(toggle.dataset.policy);
    return;
  }
  if (e.target.id === "settings-signout") signout();
});
$("#main").addEventListener("input", (e) => {
  if (e.target.id === "device-search") state.query = e.target.value;
  if (e.target.id === "action-search") state.actionQuery = e.target.value;
  const pos = e.target.selectionStart;
  const id = e.target.id;
  if (["device-search", "action-search"].includes(id)) {
    render();
    const input = document.getElementById(id);
    input.focus();
    try {
      input.setSelectionRange(pos, pos);
    } catch {}
  }
});
$("#main").addEventListener("change", (e) => {
  if (e.target.id === "action-device") state.selected = e.target.value;
});
$("#action-form").addEventListener("submit", runAction);
$("#close-dialog").addEventListener("click", () => {
  if (currentAbort) currentAbort.abort();
  $("#action-dialog").close();
});
$("#cancel-action").addEventListener("click", () => {
  if (currentAbort) {
    currentAbort.abort();
  } else {
    $("#action-dialog").close();
  }
});
$("#action-dialog").addEventListener("cancel", () => {
  if (currentAbort) currentAbort.abort();
});
setInterval(() => {
  if (!document.hidden) refresh();
}, 3000);
if (state.key) refresh(true);
