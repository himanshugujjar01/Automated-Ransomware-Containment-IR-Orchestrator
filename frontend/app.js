const API_BASE = ""; // same origin as the FastAPI app that serves this page
const WEBHOOK_SECRET = "supersecret123"; // matches WEBHOOK_SECRET default in app/config.py
const REFRESH_INTERVAL_MS = 6000;

let alerts = [];
let selectedAlertId = null;

// ---------------------------------------------------------------------------
// tiny fetch helper
// ---------------------------------------------------------------------------

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(API_BASE + path, opts);
  let data = null;
  try { data = await res.json(); } catch (e) { /* no body */ }
  return { ok: res.ok, status: res.status, data };
}

function toast(message, kind) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.className = "toast" + (kind ? " " + kind : "");
  if (message) {
    setTimeout(() => { if (el.textContent === message) el.textContent = ""; }, 4000);
  }
}

function fmtSeconds(value) {
  if (value === null || value === undefined) return "—";
  if (value < 1) return Math.round(value * 1000) + " ms";
  return value.toFixed(2) + " s";
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ---------------------------------------------------------------------------
// header: clock, health, mode, safety strip
// ---------------------------------------------------------------------------

function tickClock() {
  const now = new Date();
  document.getElementById("clock").textContent = now.toLocaleTimeString();
}
setInterval(tickClock, 1000);
tickClock();

async function loadHealthAndSafety() {
  const health = await api("GET", "/health");
  const healthBadge = document.getElementById("healthBadge");
  if (health.ok) {
    healthBadge.innerHTML = '<span class="dot dot-green"></span> ' + escapeHtml(health.data.environment || "online");
  } else {
    healthBadge.innerHTML = '<span class="dot dot-red"></span> unreachable';
  }

  const safety = await api("GET", "/safety/config");
  const modeBadge = document.getElementById("modeBadge");
  const strip = document.getElementById("safetyStrip");

  if (safety.ok) {
    const anyReal = safety.data.use_real_edr || safety.data.use_real_idp;
    if (anyReal) {
      modeBadge.innerHTML = '<span class="dot dot-red"></span> LIVE MODE';
      strip.textContent = "WARNING: one or more real integrations are enabled. Actions taken here can affect real systems.";
      strip.classList.add("warn");
    } else {
      modeBadge.innerHTML = '<span class="dot dot-green"></span> SIMULATED MODE';
    }
  }
}

// ---------------------------------------------------------------------------
// signal board
// ---------------------------------------------------------------------------

function statusDotClass(status) {
  if (status === "evidence_collected" || status === "contained") return "dot-green";
  if (status === "received") return "dot-amber pulse";
  return "dot-dim";
}

async function loadAlerts() {
  const result = await api("GET", "/alerts");
  if (!result.ok) return;

  alerts = result.data.alerts || [];
  renderBoard();
}

function renderBoard() {
  const board = document.getElementById("board");

  if (alerts.length === 0) {
    board.innerHTML = '<div class="empty-state">No signals yet. Ingest an alert or run a tabletop exercise to populate the board.</div>';
    return;
  }

  board.innerHTML = alerts.map(alert => {
    const isSelected = alert.alert_id === selectedAlertId;
    return `
      <div class="signal-row ${isSelected ? "selected" : ""}" data-alert-id="${escapeHtml(alert.alert_id)}">
        <i class="dot ${statusDotClass(alert.status)}"></i>
        <div class="signal-main">
          <div class="signal-host">${escapeHtml(alert.hostname)}</div>
          <div class="signal-meta">${escapeHtml(alert.alert_id)} · ${escapeHtml(alert.username)}</div>
        </div>
        <span class="sev-tag sev-${escapeHtml((alert.severity || "medium").toLowerCase())}">${escapeHtml(alert.severity)}</span>
      </div>
    `;
  }).join("");

  board.querySelectorAll(".signal-row").forEach(row => {
    row.addEventListener("click", () => selectAlert(row.dataset.alertId));
  });
}

// ---------------------------------------------------------------------------
// detail panel
// ---------------------------------------------------------------------------

async function selectAlert(alertId) {
  selectedAlertId = alertId;
  renderBoard();
  await renderDetail(alertId);
}

function actionIcon(actionType) {
  const labels = {
    host_isolation: "Host isolated",
    user_suspension: "User suspended",
    session_revocation: "Sessions revoked",
    forensic_collection: "Forensic evidence collected",
    chain_of_custody: "Chain of custody logged",
    local_s3_upload: "Evidence uploaded to storage"
  };
  return labels[actionType] || actionType;
}

async function renderDetail(alertId) {
  const panel = document.getElementById("detailPanel");
  panel.innerHTML = '<div class="empty-detail"><span class="glyph big">◆</span><p>Loading incident…</p></div>';

  const [alertRes, actionsRes, rtRes, ticketRes] = await Promise.all([
    api("GET", `/alerts/${encodeURIComponent(alertId)}`),
    api("GET", `/actions/${encodeURIComponent(alertId)}`),
    api("GET", `/response-time/${encodeURIComponent(alertId)}`),
    api("GET", `/tickets/${encodeURIComponent(alertId)}`)
  ]);

  if (!alertRes.ok) {
    panel.innerHTML = '<div class="empty-detail"><p>Could not load this incident.</p></div>';
    return;
  }

  const alert = alertRes.data;
  const actions = actionsRes.ok ? actionsRes.data.actions : [];
  const stages = (rtRes.ok && rtRes.data.found) ? rtRes.data.stages : null;
  const ticket = (ticketRes.ok && ticketRes.data.total_tickets > 0) ? ticketRes.data.tickets[0] : null;

  const canRunPlaybook = actions.length === 0;

  panel.innerHTML = `
    <div class="detail-header">
      <div class="detail-host">${escapeHtml(alert.hostname)}</div>
      <div class="detail-id">${escapeHtml(alert.alert_id)}</div>
    </div>
    <div class="detail-meta-row">
      <span>severity <b>${escapeHtml(alert.severity)}</b></span>
      <span>user <b>${escapeHtml(alert.username)}</b></span>
      <span>process <b>${escapeHtml(alert.process_name)}</b></span>
      <span>status <b>${escapeHtml(alert.status)}</b></span>
    </div>

    <div class="detail-actions">
      <button class="btn btn-primary" id="runPlaybookBtn" ${canRunPlaybook ? "" : "disabled"}>
        ${canRunPlaybook ? "Run containment playbook" : "Playbook already run"}
      </button>
    </div>

    <div class="timeline-title">Containment &amp; chain of custody</div>
    <div class="timeline" id="timeline">
      ${actions.length === 0
        ? '<div class="empty-state">No actions taken yet.</div>'
        : actions.map(a => `
          <div class="timeline-item ${a.status !== "success" ? "failed" : ""}">
            <div class="timeline-action">${escapeHtml(actionIcon(a.action_type))}</div>
            <div class="timeline-detail">${escapeHtml(a.target || "")} — ${escapeHtml(a.status)}</div>
          </div>
        `).join("")
      }
    </div>

    ${stages ? `
      <div class="timeline-title">Response time</div>
      <div class="stage-list">
        ${renderStageRow("Detection → first action", stages.detection_to_first_action_seconds, stages.total_response_time_seconds)}
        ${renderStageRow("Detection → containment", stages.detection_to_containment_seconds, stages.total_response_time_seconds)}
        ${renderStageRow("Detection → evidence collected", stages.detection_to_evidence_collected_seconds, stages.total_response_time_seconds)}
        ${renderStageRow("Detection → ticket filed", stages.detection_to_ticket_filed_seconds, stages.total_response_time_seconds)}
        ${renderStageRow("Total response time", stages.total_response_time_seconds, stages.total_response_time_seconds)}
      </div>
    ` : ""}

    ${ticket ? `
      <div class="ticket-box">
        <b>${escapeHtml(ticket.ticket_id)}</b> · ${escapeHtml(ticket.priority)} priority · ${escapeHtml(ticket.status)}<br>
        ${escapeHtml(ticket.summary)}
      </div>
    ` : ""}
  `;

  const btn = document.getElementById("runPlaybookBtn");
  if (btn && canRunPlaybook) {
    btn.addEventListener("click", () => runPlaybook(alertId));
  }
}

function renderStageRow(label, value, maxValue) {
  const pct = (value && maxValue) ? Math.max(6, Math.min(100, (value / maxValue) * 100)) : 0;
  return `
    <div class="stage-row">
      <div class="stage-label">${escapeHtml(label)}</div>
      <div class="stage-bar-track"><div class="stage-bar-fill" style="width:${pct}%"></div></div>
      <div class="stage-value">${fmtSeconds(value)}</div>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// actions: run playbook / ingest alert / tabletop exercise
// ---------------------------------------------------------------------------

async function runPlaybook(alertId) {
  toast("Running containment playbook…");
  const result = await api("POST", `/playbooks/${encodeURIComponent(alertId)}/run`);
  if (result.ok) {
    toast("Containment playbook completed", "success");
    await loadAlerts();
    await renderDetail(alertId);
  } else {
    toast("Playbook run failed", "error");
  }
}

async function ingestAlert(formData) {
  const alertId = "MANUAL-" + Math.random().toString(16).slice(2, 8).toUpperCase();

  const payload = {
    alert_id: alertId,
    severity: formData.get("severity"),
    detection_type: "Ransomware",
    hostname: formData.get("hostname"),
    ip_address: "192.168.50." + (10 + Math.floor(Math.random() * 200)),
    username: formData.get("username"),
    process_name: formData.get("process_name"),
    process_hash: Math.random().toString(16).slice(2, 18),
    description: "Manually ingested from the IR Console"
  };

  const res = await fetch(API_BASE + "/webhooks/edr", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-webhook-secret": WEBHOOK_SECRET
    },
    body: JSON.stringify(payload)
  });

  if (res.ok) {
    toast("Alert ingested: " + alertId, "success");
    await loadAlerts();
    await selectAlert(alertId);
  } else {
    const errBody = await res.json().catch(() => ({}));
    toast("Ingestion failed: " + (errBody.detail || res.status), "error");
  }
}

async function runTabletopExercise() {
  toast("Running full table-top exercise…");
  const result = await api("POST", "/simulation/tabletop-exercise");
  if (result.ok) {
    toast(
      `Tabletop complete: ${result.data.alert_id} in ${fmtSeconds(result.data.response_time.total_response_time_seconds)}`,
      "success"
    );
    await loadAlerts();
    await selectAlert(result.data.alert_id);
    await loadFleetSummary();
  } else {
    toast("Tabletop exercise failed", "error");
  }
}

// ---------------------------------------------------------------------------
// fleet stats
// ---------------------------------------------------------------------------

async function loadFleetSummary() {
  const result = await api("GET", "/response-time/fleet/summary?limit=10");
  if (!result.ok) return;

  const d = result.data;
  document.getElementById("statAvg").textContent = fmtSeconds(d.average_total_response_time_seconds);
  document.getElementById("statFast").textContent = fmtSeconds(d.fastest_response_time_seconds);
  document.getElementById("statSlow").textContent = fmtSeconds(d.slowest_response_time_seconds);
  document.getElementById("statCount").textContent = d.incidents_analyzed ?? "—";
}

// ---------------------------------------------------------------------------
// wire up
// ---------------------------------------------------------------------------

document.getElementById("refreshBtn").addEventListener("click", () => {
  loadAlerts();
  loadFleetSummary();
  toast("Refreshed");
});

document.getElementById("tabletopBtn").addEventListener("click", runTabletopExercise);

document.getElementById("ingestForm").addEventListener("submit", (e) => {
  e.preventDefault();
  ingestAlert(new FormData(e.target));
});

async function init() {
  await loadHealthAndSafety();
  await loadAlerts();
  await loadFleetSummary();
}

init();
setInterval(() => { loadAlerts(); loadFleetSummary(); }, REFRESH_INTERVAL_MS);