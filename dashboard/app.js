const API_BASE_URL = window.API_BASE_URL || 'http://127.0.0.1:8001';
const WS_URL = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + '127.0.0.1:8001/ws';

function formatTimestamp(value) {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = value;
  }
}

function setList(id, items, emptyText = '—') {
  const container = document.getElementById(id);
  if (!container) return;
  if (!items || items.length === 0) {
    container.innerHTML = `<li>${emptyText}</li>`;
    return;
  }
  container.innerHTML = items.map((item) => `<li>${item}</li>`).join('');
}

async function loadDashboard() {
  try {
    const response = await fetch(`${API_BASE_URL}/reports/dashboard`);
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    const payload = await response.json();
    renderDashboard(payload);
  } catch (error) {
    setText('system-health', 'Offline');
    setList('device-list', ['Backend unavailable. Start the FastAPI service first.']);
    console.error(error);
  }
}

function renderDashboard(payload) {
  const summary = payload?.summary || {};
  const recent = payload?.recent || {};
  const system = payload?.system || {};
  const sync = payload?.sync || {};

  setText('device-count', summary.devices ?? 0);
  setText('alert-count', summary.alerts ?? 0);
  setText('transfer-count', summary.transfers ?? 0);
  setText('sync-pending', sync.pending ?? 0);
  setText('connected-count', summary.devices ?? 0);
  setText('authorized-count', summary.authorized_devices ?? 0);
  setText('blocked-count', summary.blocked_devices ?? 0);
  setText('usb-activity', recent.usb_activity ?? 0);
  setText('file-activity', recent.file_activity ?? 0);
  setText('threat-count', summary.threats ?? 0);
  setText('malware-count', summary.malware ?? 0);
  setText('risk-score', summary.risk_score ?? 0);
  setText('system-health', system.healthy ? 'Healthy' : 'Degraded');
  setText('database-status', system.backend || 'unknown');
  setText('sync-status', sync.status || 'stopped');

  const deviceList = (recent.devices || []).slice(0, 8).map((device) => {
    const name = escapeHtml(device.device_name || device.fingerprint || 'Unknown');
    const status = escapeHtml(device.status || 'unknown');
    const lastSeen = formatTimestamp(device.last_seen);
    return `<strong>${name}</strong> — ${status} <small>${lastSeen}</small>`;
  });
  setList('device-list', deviceList, 'No devices detected yet.');

  const alertList = (recent.alerts || []).slice(0, 8).map((alert) => {
    const severity = escapeHtml(alert.severity || 'info');
    const message = escapeHtml(alert.message || 'No message');
    return `<strong>${severity}</strong> — ${message}`;
  });
  setList('alert-list', alertList, 'No alerts yet.');

  const transferList = (recent.transfers || []).slice(0, 8).map((transfer) => {
    const fileName = escapeHtml(transfer.file_name || 'transfer');
    const decision = escapeHtml(transfer.decision || 'unknown');
    return `${fileName} — ${decision}`;
  });
  setList('transfer-list', transferList, 'No transfers recorded yet.');

  const logList = (recent.logs || []).slice(0, 10).map((entry) => {
    const level = escapeHtml(entry.level || 'INFO');
    const message = escapeHtml(entry.message || 'No message');
    const timestamp = formatTimestamp(entry.timestamp);
    return `<strong>${level}</strong> — ${message} <small>${timestamp}</small>`;
  });
  setList('log-list', logList, 'No logs yet.');

  const malwareList = (recent.malware || []).slice(0, 8).map((entry) => {
    const threat = escapeHtml(entry.threat_name || 'unknown');
    const risk = escapeHtml(entry.risk_score ?? 0);
    return `${threat} — risk ${risk}`;
  });
  setList('malware-list', malwareList, 'No malware detections yet.');

  const policyList = (recent.policies || []).slice(0, 8).map((policy) => {
    const rule = escapeHtml(policy.rule_type || 'policy');
    const reason = escapeHtml(policy.reason || 'No reason');
    return `<strong>${rule}</strong> — ${reason}`;
  });
  setList('policy-list', policyList, 'No policies configured yet.');
}

function connectSocket() {
  const socket = new WebSocket(WS_URL);
  socket.addEventListener('open', () => {
    setText('system-health', 'Live');
  });
  socket.addEventListener('message', (event) => {
    try {
      const message = JSON.parse(event.data);
      if (message?.payload) {
        renderDashboard(message.payload);
      }
    } catch (error) {
      console.error(error);
    }
  });
  socket.addEventListener('close', () => {
    setText('system-health', 'Reconnecting');
    window.setTimeout(connectSocket, 1500);
  });
  window.__usbguardSocket = socket;
}

document.getElementById('policy-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = {
    device_fingerprint: form.fingerprint.value.trim() || null,
    rule_type: form.rule_type.value,
    reason: form.reason.value.trim() || 'Added from dashboard',
  };

  const response = await fetch(`${API_BASE_URL}/policies`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    alert('Unable to add policy');
    return;
  }

  form.reset();
  loadDashboard();
});

document.getElementById('refresh-btn').addEventListener('click', loadDashboard);

loadDashboard();
connectSocket();
