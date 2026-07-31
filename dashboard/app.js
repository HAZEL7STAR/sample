const API_BASE_URL = window.API_BASE_URL || 'http://127.0.0.1:8001';

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

async function loadJson(path) {
  const response = await fetch(`${API_BASE_URL}${path}`);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

async function renderDashboard() {
  try {
    const summary = await loadJson('/reports/summary');
    const devices = await loadJson('/devices');
    const alerts = await loadJson('/alerts');
    const sync = await loadJson('/sync/status');
    const policies = await loadJson('/policies');
    const transfers = await loadJson('/transfers');
    const logs = await loadJson('/logs');

    document.getElementById('device-count').textContent = summary.devices;
    document.getElementById('alert-count').textContent = summary.alerts;
    document.getElementById('transfer-count').textContent = summary.transfers;
    document.getElementById('sync-pending').textContent = sync.pending;

    const deviceList = document.getElementById('device-list');
    deviceList.innerHTML = devices.slice(0, 8).map((device) => `<li><strong>${escapeHtml(device.device_name || device.fingerprint || 'Unknown')}</strong> — ${escapeHtml(device.status || 'unknown')} <small>${formatTimestamp(device.last_seen)}</small></li>`).join('');

    const alertList = document.getElementById('alert-list');
    alertList.innerHTML = alerts.slice(0, 8).map((alert) => `<li><strong>${escapeHtml(alert.severity || 'info')}</strong> — ${escapeHtml(alert.message || 'No message')}</li>`).join('');

    const policyList = document.getElementById('policy-list');
    policyList.innerHTML = policies.slice(0, 8).map((policy) => `<li><strong>${escapeHtml(policy.rule_type || 'policy')}</strong> — ${escapeHtml(policy.reason || 'No reason')} <small>${policy.device_fingerprint || 'all devices'}</small></li>`).join('');

    const transferList = document.getElementById('transfer-list');
    transferList.innerHTML = transfers.slice(0, 8).map((transfer) => `<li>${escapeHtml(transfer.file_name || transfer.path || 'transfer')} — ${escapeHtml(transfer.decision || transfer.direction || 'unknown')} <small>${transfer.blocked ? 'blocked' : 'allowed'}</small></li>`).join('');

    const logList = document.getElementById('log-list');
    logList.innerHTML = logs.slice(0, 10).map((entry) => `<li><strong>${escapeHtml(entry.level || 'INFO')}</strong> — ${escapeHtml(entry.message || 'No message')} <small>${formatTimestamp(entry.timestamp)}</small></li>`).join('');
  } catch (error) {
    document.getElementById('device-list').innerHTML = '<li>Backend unavailable. Start the FastAPI service first.</li>';
    console.error(error);
  }
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
  renderDashboard();
});

document.getElementById('refresh-btn').addEventListener('click', renderDashboard);

renderDashboard();
