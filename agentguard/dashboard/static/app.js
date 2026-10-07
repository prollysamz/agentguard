"use strict";
// AgentGuard dashboard. All data is inserted with textContent, never as HTML.

const $ = (selector) => document.querySelector(selector);
const state = { me: null, tab: "approvals", logOffset: 0, timer: null };

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== undefined && value !== null && value !== false) node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined && child !== false) {
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
  }
  return node;
}

async function api(path, options = {}) {
  const init = { credentials: "same-origin", headers: {}, ...options };
  if (init.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.body);
  }
  if (init.method && init.method !== "GET") init.headers["X-AgentGuard-CSRF"] = "1";
  const response = await fetch(path, init);
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && path !== "/api/login") {
    showLogin();
    throw new Error("Not signed in");
  }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

const time = (seconds) => new Date(seconds * 1000).toLocaleString();
const isoTime = (iso) => (iso ? new Date(iso).toLocaleString() : "");
const pill = (decision) => el("span", { class: `pill ${decision || ""}`, text: decision || "–" });
function relative(seconds) {
  const delta = Math.round(seconds - Date.now() / 1000);
  const minutes = Math.round(Math.abs(delta) / 60);
  const span = minutes < 60 ? `${minutes} min` : `${Math.round(minutes / 60)} h`;
  return delta >= 0 ? `in ${span}` : `${span} ago`;
}

// ------------------------------------------------------------------ session

function showLogin() {
  state.me = null;
  clearInterval(state.timer);
  $("#login").hidden = false;
  $("#tabs").hidden = $("#who").hidden = true;
  document.querySelectorAll(".view").forEach((view) => (view.hidden = true));
  $("#token").focus();
}

function showApp() {
  $("#login").hidden = true;
  $("#tabs").hidden = $("#who").hidden = false;
  $("#who-name").textContent = state.me.name + (state.me.can_strong ? " · strong approver" : "");
  const fromHash = location.hash.replace("#", "").split("/")[0];
  switchTab(["approvals", "log", "report"].includes(fromHash) ? fromHash : "approvals");
  clearInterval(state.timer);
  state.timer = setInterval(() => {
    if (state.tab === "approvals" && !document.hidden) loadApprovals().catch(() => {});
  }, 5000);
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#login-error").textContent = "";
  try {
    state.me = await api("/api/login", { method: "POST", body: { token: $("#token").value.trim() } });
    $("#token").value = "";
    showApp();
  } catch (error) {
    $("#login-error").textContent = error.message;
  }
});

$("#logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" }).catch(() => {});
  showLogin();
});

function switchTab(tab) {
  state.tab = tab;
  document.querySelectorAll("#tabs button").forEach((button) => {
    if (button.dataset.tab === tab) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  document.querySelectorAll(".view").forEach((view) => (view.hidden = view.id !== `view-${tab}`));
  history.replaceState(null, "", `#${tab}`);
  ({ approvals: loadApprovals, log: () => loadEvents(true), report: loadReport })[tab]().catch(() => {});
}

document.querySelectorAll("#tabs button").forEach((button) =>
  button.addEventListener("click", () => switchTab(button.dataset.tab)),
);
window.addEventListener("hashchange", () => {
  const tab = location.hash.replace("#", "").split("/")[0];
  if (state.me && tab !== state.tab && ["approvals", "log", "report"].includes(tab)) switchTab(tab);
});

// ------------------------------------------------------------------ approvals

async function loadApprovals() {
  const [pending, recent, grants] = await Promise.all([
    api("/api/approvals?status=pending"),
    api("/api/approvals?limit=30"),
    api("/api/grants"),
  ]);
  const count = pending.requests.length;
  $("#pending-count").hidden = count === 0;
  $("#pending-count").textContent = count;
  $("#approvals-updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;

  const list = $("#pending");
  const focused = document.activeElement && list.contains(document.activeElement);
  if (!focused) {
    list.replaceChildren(
      ...(count ? pending.requests.map(requestCard) : [el("div", { class: "empty", text: "Nothing is waiting. Agents are working within policy." })]),
    );
  }

  $("#grants").replaceChildren(
    grants.grants.length
      ? table(["Scope", "Target", "Agent", "Approved by", "Expires", ""], grants.grants.map((grant) => [
          grant.scope === "action" ? (grant.max_uses === 1 ? "once" : "same call") : grant.scope,
          grant.scope === "capability" ? grant.capability : grant.tool,
          grant.agent_id,
          grant.approved_by + (grant.strong ? " (strong)" : ""),
          relative(grant.expires),
          el("button", { class: "danger", text: "Revoke", onclick: () => revoke(grant.id) }),
        ]))
      : el("div", { class: "empty", text: "No active grants." }),
  );

  const decided = recent.requests.filter((request) => request.status !== "pending").slice(0, 15);
  $("#decided").replaceChildren(
    decided.length
      ? table(["Request", "Tool", "Agent", "Status", "By", "When"], decided.map((request) => [
          request.id, request.tool, request.agent_id,
          pill(request.status === "approved" ? "allow" : request.status === "rejected" ? "deny" : ""),
          request.decided_by || "–",
          request.decided_at ? time(request.decided_at) : time(request.expires),
        ]))
      : el("div", { class: "empty", text: "No decisions yet." }),
  );
}

function requestCard(request) {
  const note = el("input", { type: "text", placeholder: "Note (optional)", "aria-label": "Note" });
  const minutes = el("select", { "aria-label": "Duration" },
    ...[10, 30, 60, 240, 480].map((m) => el("option", { value: m, text: m < 60 ? `${m} min` : `${m / 60} h` })));
  const scope = el("select", { "aria-label": "Grant scope" },
    el("option", { value: "once", text: "This call, once" }),
    el("option", { value: "action", text: "This exact call for…" }),
    el("option", { value: "tool", text: `Tool ${request.tool} for…` }),
    el("option", { value: "capability", text: `All ${request.capability} for…` }));
  minutes.hidden = true;
  scope.addEventListener("change", () => (minutes.hidden = scope.value === "once"));
  const error = el("p", { class: "error", role: "alert" });

  let strongToken = null;
  const strongBox = request.strong_required
    ? el("div", { class: "strong-box" },
        state.me.can_strong ? "Strong approval: re-enter your token." : "Needs a strong approver.",
        state.me.can_strong ? (strongToken = el("input", { type: "password", placeholder: "agt_…", autocomplete: "off", "aria-label": "Your token" })) : null)
    : null;

  async function decide(approve) {
    error.textContent = "";
    const body = { approve, scope: scope.value, note: note.value };
    if (approve && scope.value !== "once") body.minutes = Number(minutes.value);
    if (approve && request.strong_required) Object.assign(body, { strong: true, token: strongToken ? strongToken.value : "" });
    try {
      await api(`/api/approvals/${encodeURIComponent(request.id)}/decision`, { method: "POST", body });
      card.remove();
      loadApprovals().catch(() => {});
    } catch (failure) {
      error.textContent = failure.message;
    }
  }

  const card = el("article", { class: "card", id: `approval-${request.id}` },
    el("div", { class: "card-head" },
      el("strong", { text: request.tool }),
      el("span", { class: "muted", text: request.capability }),
      pill(request.risk >= 76 ? "deny" : "ask"),
      el("span", { class: "muted small", text: `risk ${request.risk}/100` })),
    el("div", { class: "meta" },
      el("span", { text: `Agent ${request.agent_id}` }),
      el("span", { text: request.environment }),
      el("span", { text: `Asked ${relative(request.created)}` }),
      el("span", { text: `Expires ${relative(request.expires)}` }),
      el("span", { text: request.id })),
    el("ul", { class: "reasons" }, ...request.reasons.map((reason) => el("li", { text: reason }))),
    el("pre", { text: JSON.stringify(request.action.arguments, null, 2) }),
    strongBox,
    el("div", { class: "actions" },
      scope, minutes,
      el("button", { class: "primary", text: "Approve", disabled: request.strong_required && !state.me.can_strong, onclick: () => decide(true) }),
      el("button", { class: "danger", text: "Reject", onclick: () => decide(false) }),
      note),
    error);
  return card;
}

async function revoke(id) {
  await api(`/api/grants/${encodeURIComponent(id)}/revoke`, { method: "POST" });
  loadApprovals().catch(() => {});
}

function table(headers, rows) {
  return el("div", { class: "table-wrap" }, el("table", {},
    el("thead", {}, el("tr", {}, ...headers.map((header) => el("th", { text: header })))),
    el("tbody", {}, ...rows.map((cells) => el("tr", {}, ...cells.map((cell) => el("td", {}, cell)))))));
}

// ------------------------------------------------------------------ audit log

function filterQuery() {
  const data = new FormData($("#filters"));
  const params = new URLSearchParams();
  for (const [key, value] of data) if (value) params.set(key, value);
  return params;
}

async function loadEvents(reset) {
  if (reset) state.logOffset = 0;
  const params = filterQuery();
  params.set("offset", state.logOffset);
  params.set("limit", 100);
  const data = await api(`/api/events?${params}`);
  const chain = $("#chain");
  chain.className = `badge ${data.verified ? "ok" : "bad"}`;
  chain.textContent = data.verified
    ? `Chain verified · ${data.verified_events} events${data.signatures_checked ? " · signatures checked" : ""}`
    : `Verification failed: ${data.error}`;
  const body = $("#events tbody");
  const rows = data.events.map((event) =>
    el("tr", { tabindex: 0, onclick: () => showEvent(event.event_id), onkeydown: (e) => e.key === "Enter" && showEvent(event.event_id) },
      el("td", { text: isoTime(event.timestamp) }),
      el("td", {}, event.stage, event.mode === "dry-run" ? el("span", { class: "pill tag", text: "dry-run" }) : null),
      el("td", { class: "tool", text: event.tool || "" }),
      el("td", { text: event.agent_id || "" }),
      el("td", {}, pill(event.final_decision || event.evaluated_decision)),
      el("td", { class: "num", text: event.risk_score ?? "" })));
  if (reset) body.replaceChildren(...rows);
  else body.append(...rows);
  state.logOffset += data.events.length;
  if (reset && !data.events.length) body.replaceChildren(el("tr", {}, el("td", { colspan: 6, class: "muted", text: "No matching events." })));
  $("#more").hidden = state.logOffset >= data.total;
  $("#events-total").textContent = `${Math.min(state.logOffset, data.total)} of ${data.total}`;
}

$("#filters").addEventListener("submit", (event) => {
  event.preventDefault();
  loadEvents(true).catch(() => {});
});
$("#more").addEventListener("click", () => loadEvents(false).catch(() => {}));

async function showEvent(id) {
  const data = await api(`/api/events/${encodeURIComponent(id)}`);
  $("#timeline").replaceChildren(...data.timeline.map((event) =>
    el("li", { class: event.event_id === id ? "current" : "", text: event.stage })));
  $("#detail-json").textContent = JSON.stringify(data.event, null, 2);
  $("#detail").showModal();
}
$("#detail-close").addEventListener("click", () => $("#detail").close());

// ------------------------------------------------------------------ report

async function loadReport() {
  const data = await api(`/api/report${$("#dry-only").checked ? "?dry_run_only=1" : ""}`);
  const tile = (value, label) => el("div", { class: "tile" }, el("div", { class: "value", text: value }), el("div", { class: "label", text: label }));
  $("#tiles").replaceChildren(
    tile(data.calls, "evaluated calls"),
    tile(data.decisions.allow, "allowed"),
    tile(data.decisions.ask, "sent for approval"),
    tile(data.decisions.deny, "denied"),
    tile(data.modes["dry-run"] || 0, "ran in dry-run"));
  $("#would-change").replaceChildren(
    data.would_change.length
      ? el("div", { class: "cards" }, ...data.would_change.map((group) =>
          el("article", { class: "card" },
            el("div", { class: "card-head" },
              el("strong", { text: group.tool }),
              el("span", { class: "muted", text: group.capability }),
              pill(group.decision),
              el("span", { class: "muted small", text: `${group.count} call${group.count === 1 ? "" : "s"} · max risk ${group.max_risk}${group.executed_in_dry_run ? ` · ${group.executed_in_dry_run} ran in dry-run` : ""}` })),
            el("ul", { class: "reasons" }, ...group.reasons.map((r) => el("li", { text: `${r.count}× ${r.reason}` }))),
            el("pre", { text: JSON.stringify(group.examples[0]?.arguments ?? {}, null, 2) }))))
      : el("div", { class: "empty", text: "Nothing would be asked or denied." }));
  $("#by-tool tbody").replaceChildren(...data.tools.map((row) =>
    el("tr", {},
      el("td", { class: "tool", text: row.tool }),
      el("td", { text: row.capability }),
      el("td", { class: "num", text: row.allow }),
      el("td", { class: "num", text: row.ask }),
      el("td", { class: "num", text: row.deny }))));
}
$("#dry-only").addEventListener("change", () => loadReport().catch(() => {}));

// ------------------------------------------------------------------ start

api("/api/me").then((me) => { state.me = me; showApp(); }).catch(() => showLogin());
