const severityColors = { CRITICAL: '#e56855', HIGH: '#f09a68', MEDIUM: '#d09a32', LOW: '#32805e', INFO: '#20777a' };
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[character]));
const formatTime = value => new Date(value).toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });

let summaryRequestInFlight = false;
let notificationsRequestInFlight = false;
let operationsRequestInFlight = false;

function updateLocalTime() {
    const now = new Date();
    const hour = now.getHours();
    document.querySelector('#greeting').textContent = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
    document.querySelector('#live-clock').textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

async function loadSummary() {
    if (summaryRequestInFlight) return;
    summaryRequestInFlight = true;
    try {
        const response = await fetch('/api/summary');
        if (!response.ok) return;
        const data = await response.json();
        document.querySelector('#total-events').textContent = data.today ?? data.total;
        document.querySelector('#open-events').textContent = data.open;
        document.querySelector('#unique-sources').textContent = data.sources;
        document.querySelector('#critical-events').textContent = data.critical;
        document.querySelector('#suspicious-ips').textContent = data.suspicious_ips;
        drawChart(data.counts);
        drawTimeChart(data.hourly);
        renderActivity(data.activity);
        renderEvents(data.events);
        renderOperationsPulse(data);
        loadOperations();
        loadNotifications();
    } finally {
        summaryRequestInFlight = false;
    }
}

async function loadNotifications() {
    if (notificationsRequestInFlight) return;
    notificationsRequestInFlight = true;
    try {
        const response = await fetch('/api/notifications');
        if (!response.ok) return;
        const data = await response.json();
        const count = document.querySelector('#notification-count');
        count.textContent = data.unread;
        count.hidden = !data.unread;
        document.querySelector('#notification-list').innerHTML = data.items.length ? data.items.map(item => `<a class="notification-item ${item.read_at ? 'read' : ''}" href="${escapeHtml(item.link)}" data-notification-id="${item.id}"><span class="severity severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.message)} · ${formatTime(item.created_at)}</small></span></a>`).join('') : '<p class="empty">You are all caught up.</p>';
        document.querySelectorAll('.notification-item').forEach(item => item.addEventListener('click', async () => { await fetch(`/api/notifications/${item.dataset.notificationId}/read`, { method: 'POST', headers: { 'X-CSRF-Token': csrfToken } }); }));
    } finally {
        notificationsRequestInFlight = false;
    }
}

function renderPulseList(targetId, items, labelKey, valueKey) {
    const target = document.querySelector(`#${targetId}`);
    if (!items.length) {
        target.innerHTML = '<p class="empty">No observations yet.</p>';
        return;
    }
    const max = Math.max(...items.map(item => item[valueKey]), 1);
    target.innerHTML = items.map(item => `<div class="pulse-item"><div><strong>${escapeHtml(item[labelKey])}</strong><span>${item[valueKey]} observation${item[valueKey] === 1 ? '' : 's'}</span></div><div class="pulse-meter"><i style="width:${Math.max(10, Math.round(item[valueKey] / max * 100))}%"></i></div></div>`).join('');
}

function renderOperationsPulse(data) {
    renderPulseList('top-sources', data.top_sources, 'source_ip', 'total');
    renderPulseList('top-users', data.top_users, 'user', 'total');
    renderPulseList('rule-counts', data.rule_counts, 'rule_id', 'total');
}

function drawTimeChart(hourly) {
    const chart = document.querySelector('#time-chart');
    const max = Math.max(...hourly.map(item => item.total), 1);
    chart.innerHTML = hourly.map(item => `<span style="height:${Math.max(8, Math.round(item.total / max * 42))}px" title="${escapeHtml(item.hour)}: ${item.total} events"></span>`).join('');
}

function drawChart(counts) {
    const chart = document.querySelector('#severity-chart');
    const max = Math.max(...Object.values(counts), 1);
    chart.innerHTML = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(severity => {
        const count = counts[severity] || 0;
        const height = Math.max(10, Math.round((count / max) * 145));
        return `<div class="bar-group"><span class="bar-count">${count}</span><div class="bar" style="height:${height}px;background:${severityColors[severity]}"></div><span class="bar-label">${severity[0] + severity.slice(1).toLowerCase()}</span></div>`;
    }).join('');
}

function renderEvents(events) {
    const target = document.querySelector('#events-table');
    document.querySelector('#event-count').textContent = `${events.length} event${events.length === 1 ? '' : 's'}`;
    if (!events.length) { target.innerHTML = '<tr><td colspan="5" class="empty">No matching events found.</td></tr>'; return; }
    target.innerHTML = events.map(event => `<tr class="event-row" data-event-id="${event.id}"><td>${escapeHtml(event.event_type)}<span class="event-message">${escapeHtml(event.message)}</span></td><td class="mono">${escapeHtml(event.source_ip)}</td><td><span class="severity severity-${escapeHtml(event.severity)}">${escapeHtml(event.severity)}</span></td><td class="mono">${formatTime(event.timestamp)}</td><td><span class="status ${escapeHtml(event.status)}">${escapeHtml(event.status)}</span></td></tr>`).join('');
    target.querySelectorAll('.event-row').forEach(row => row.addEventListener('click', () => openEvent(events.find(event => String(event.id) === row.dataset.eventId))));
}

function renderActivity(items, targetId = 'activity-list') {
    document.querySelector(`#${targetId}`).innerHTML = items.length ? items.map(item => `<div class="activity-item"><i class="activity-marker"></i><div><strong>${escapeHtml(item.action)}</strong><span>${escapeHtml(item.detail)} · ${formatTime(item.timestamp)}</span></div></div>`).join('') : '<p class="empty">No activity recorded yet.</p>';
}

async function filterEvents() {
    const params = new URLSearchParams({ q: document.querySelector('#event-search').value, severity: document.querySelector('#severity-filter').value });
    const response = await fetch(`/api/events?${params}`);
    renderEvents(await response.json());
}

async function loadOperations() {
    if (operationsRequestInFlight) return;
    operationsRequestInFlight = true;
    try {
        const [incidentsResponse, alertsResponse, rulesResponse] = await Promise.all([fetch('/api/incidents'), fetch('/api/alerts'), fetch('/api/rules')]);
        if (incidentsResponse.ok) renderIncidents(await incidentsResponse.json());
        if (alertsResponse.ok) renderAlerts(await alertsResponse.json());
        if (rulesResponse.ok) renderRules(await rulesResponse.json());
        await Promise.all([
            loadAssets(),
            loadCollectors(),
            loadMetrics(),
            loadUsers(),
            loadIndicators(),
            loadActivityFeed(),
            loadReports(),
            loadNotificationPreferences(),
            loadPlatformSettings()
        ]);
    } finally {
        operationsRequestInFlight = false;
    }
}

function renderIncidents(items) {
    const target = document.querySelector('#incidents-table');
    target.innerHTML = items.length ? items.map(item => `<tr><td><strong>#${item.id}</strong><span class="event-message">${escapeHtml(item.title)}</span></td><td><select class="incident-status" data-incident-id="${item.id}"><option ${item.status === 'OPEN' ? 'selected' : ''}>OPEN</option><option ${item.status === 'INVESTIGATING' ? 'selected' : ''}>INVESTIGATING</option><option ${item.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option><option ${item.status === 'FALSE POSITIVE' ? 'selected' : ''}>FALSE POSITIVE</option></select></td><td class="mono">${formatTime(item.updated_at)}</td><td><button class="row-action" data-incident-id="${item.id}" type="button">Update</button><button class="row-action timeline-action" data-incident-id="${item.id}" type="button">Timeline</button></td></tr>`).join('') : '<tr><td colspan="4" class="empty">No investigations yet.</td></tr>';
    target.querySelectorAll('.row-action:not(.timeline-action)').forEach(button => button.addEventListener('click', () => updateIncident(button.dataset.incidentId)));
    target.querySelectorAll('.timeline-action').forEach(button => button.addEventListener('click', () => loadTimeline(button.dataset.incidentId)));
}

async function loadTimeline(id) {
    const response = await fetch(`/api/incidents/${id}/timeline`);
    if (!response.ok) return;
    const items = await response.json();
    document.querySelector('#incident-timeline').innerHTML = items.length ? items.map(item => `<div class="timeline-item"><strong>${escapeHtml(item.action)}</strong><span>${escapeHtml(item.actor)} · ${formatTime(item.created_at)}</span><p>${escapeHtml(item.detail || '')}</p></div>`).join('') : '<p class="empty">No timeline entries yet.</p>';
}

function renderAlerts(items) {
    document.querySelector('#alert-count').textContent = `${items.length} alert${items.length === 1 ? '' : 's'}`;
    document.querySelector('#alerts-list').innerHTML = items.length ? items.slice(0, 8).map(item => `<button class="alert-item" data-event-id="${item.event_id}" type="button"><span class="severity severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><span><strong>${escapeHtml(item.name || 'Detection alert')}</strong><small>${escapeHtml(item.source_ip)} · ${escapeHtml(item.rule_id || 'manual')} · ${escapeHtml(item.mitre_attack || 'unmapped')}</small></span></button>`).join('') : '<p class="empty">No alerts recorded yet.</p>';
    document.querySelectorAll('.alert-item').forEach(item => item.addEventListener('click', () => inspectEvent(item.dataset.eventId)));
    document.querySelector('#triage-list').innerHTML = items.slice(0, 6).map(item => `<div class="triage-item"><div><strong>${escapeHtml(item.name || 'Detection alert')}</strong><span>${escapeHtml(item.source_ip)} · ${escapeHtml(item.severity)}</span></div><select data-alert-id="${item.id}" class="triage-status"><option ${item.status === 'OPEN' || item.status === 'NEW' ? 'selected' : ''}>NEW</option><option ${item.status === 'ACKNOWLEDGED' ? 'selected' : ''}>ACKNOWLEDGED</option><option ${item.status === 'IN PROGRESS' ? 'selected' : ''}>IN PROGRESS</option><option ${item.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option><option ${item.status === 'FALSE POSITIVE' ? 'selected' : ''}>FALSE POSITIVE</option></select></div>`).join('') || '<p class="empty">No alerts in queue.</p>';
    document.querySelectorAll('.triage-status').forEach(select => select.addEventListener('change', () => updateAlert(select.dataset.alertId, select.value)));
}

async function updateAlert(id, status) {
    await fetch(`/api/alerts/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ status }) });
    loadOperations();
}

async function loadAssets() {
    const response = await fetch('/api/assets');
    if (!response.ok) return;
    const items = await response.json();
    document.querySelector('#assets-table').innerHTML = items.length ? items.map(item => `<tr><td><strong>${escapeHtml(item.name)}</strong><span class="event-message">${escapeHtml(item.asset_type)} · ${escapeHtml(item.operating_system || 'OS unknown')}</span></td><td class="mono">${escapeHtml(item.ip_address)}</td><td><span class="severity severity-${escapeHtml(item.risk_level)}">${item.risk_score}/100</span></td><td>${escapeHtml(item.status)}</td></tr>`).join('') : '<tr><td colspan="4" class="empty">No assets registered.</td></tr>';
}

async function loadActivityFeed() {
    const response = await fetch('/api/activity');
    if (response.ok) renderActivity(await response.json(), 'live-activity');
}

async function loadReports() {
    const response = await fetch('/api/reports/summary');
    if (!response.ok) return;
    const data = await response.json();
    document.querySelector('#report-summary').innerHTML = data.daily.slice(0, 4).map(item => `<div class="report-row"><strong>${escapeHtml(item.day)}</strong><span>${item.events} events · ${item.high_risk || 0} high risk</span></div>`).join('') || '<p class="empty">No report data yet.</p>';
    document.querySelector('#report-techniques').innerHTML = data.techniques.slice(0, 4).map(item => `<div class="report-row"><strong>${escapeHtml(item.technique)}</strong><span>${escapeHtml(item.name)} · ${item.alerts} alerts</span></div>`).join('');
}

async function loadNotificationPreferences() {
    const response = await fetch('/api/notification-preferences');
    if (!response.ok) return;
    const data = await response.json();
    document.querySelector('#notification-preferences [name="minimum_severity"]').value = data.minimum_severity;
    document.querySelector('#notification-preferences [name="browser_enabled"]').checked = Boolean(data.browser_enabled);
}

async function loadPlatformSettings() {
    const response = await fetch('/api/settings');
    if (!response.ok) return;
    const data = await response.json();
    if (data.refresh_seconds) document.querySelector('#platform-settings [name="refresh_seconds"]').value = data.refresh_seconds;
    if (data.retention_days) document.querySelector('#platform-settings [name="retention_days"]').value = data.retention_days;
}

async function loadCollectors() {
    const response = await fetch('/api/collectors');
    if (!response.ok) return;
    const items = await response.json();
    document.querySelector('#collectors-list').innerHTML = items.length ? items.map(item => `<div class="collector-item"><div><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.path)} · ${item.enabled ? 'Enabled' : 'Disabled'}</span></div><button class="row-action" data-collector-id="${item.id}" type="button">Poll</button></div>`).join('') : '<p class="empty">No collectors registered.</p>';
    document.querySelectorAll('[data-collector-id]').forEach(button => button.addEventListener('click', async () => { const { data } = await postJson(`/api/collectors/${button.dataset.collectorId}/poll`, {}); button.textContent = data.error ? 'Error' : `${data.alerts.length} alerts`; loadSummary(); }));
}

async function loadMetrics() {
    const response = await fetch('/api/metrics');
    if (!response.ok) return;
    const data = await response.json();
    document.querySelector('#triage-rate').textContent = `${data.alert_acknowledgement_rate}% acknowledged`;
    document.querySelector('#metric-alerts').textContent = data.alerts;
    document.querySelector('#metric-resolved').textContent = data.resolved_alerts;
    document.querySelector('#metrics-grid').innerHTML = `<div><strong>${data.alert_acknowledgement_rate}%</strong><span>Alert acknowledgement</span></div><div><strong>${data.incident_resolution_rate}%</strong><span>Incident resolution</span></div>`;
}

async function loadUsers() {
    const response = await fetch('/api/users');
    if (!response.ok) return;
    const items = await response.json();
    document.querySelector('#users-list').innerHTML = items.map(item => `<div class="user-item"><strong>${escapeHtml(item.username)}</strong><span>${escapeHtml(item.role)}</span></div>`).join('');
}

function renderRules(items) {
    document.querySelector('#rules-list').innerHTML = items.map(item => `<div class="rule-item"><span><strong>${escapeHtml(item.rule_id)}</strong> ${escapeHtml(item.name)}<small>${escapeHtml(item.mitre_attack)} · ${escapeHtml(item.severity)}</small></span><button class="row-action rule-toggle" data-rule-id="${escapeHtml(item.rule_id)}" data-enabled="${item.enabled ? '1' : '0'}" type="button">${item.enabled ? 'ON' : 'OFF'}</button></div>`).join('');
    document.querySelectorAll('.rule-toggle').forEach(button => button.addEventListener('click', async () => { await fetch('/api/rules', { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ rule_id: button.dataset.ruleId, enabled: button.dataset.enabled !== '1' }) }); loadOperations(); }));
}

let selectedEvent = null;
async function inspectEvent(id) {
    const response = await fetch(`/api/events/${id}`);
    if (!response.ok) return;
    openEvent(await response.json());
}

function openEvent(event) {
    if (!event) return;
    selectedEvent = event;
    document.querySelector('#modal-title').textContent = event.event_type;
    document.querySelector('#modal-content').innerHTML = `<dl class="detail-grid"><dt>Source IP</dt><dd>${escapeHtml(event.source_ip)}</dd><dt>User</dt><dd>${escapeHtml(event.user)}</dd><dt>Severity</dt><dd>${escapeHtml(event.severity)}</dd><dt>Time</dt><dd>${formatTime(event.timestamp)}</dd><dt>Evidence</dt><dd>${escapeHtml(event.message)}</dd><dt>Status</dt><dd>${escapeHtml(event.status)}</dd></dl>`;
    document.querySelector('#event-modal').hidden = false;
}

async function updateIncident(id) {
    const select = document.querySelector(`.incident-status[data-incident-id="${id}"]`);
    await fetch('/api/incidents', { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ id, status: select.value }) });
    loadOperations();
}

document.querySelector('#modal-close').addEventListener('click', () => { document.querySelector('#event-modal').hidden = true; });
document.querySelector('#event-modal').addEventListener('click', event => { if (event.target.id === 'event-modal') event.target.hidden = true; });
document.querySelector('#investigate-button').addEventListener('click', async () => { if (selectedEvent) await postJson('/api/incidents', { event_id: selectedEvent.id, title: selectedEvent.event_type, notes: selectedEvent.message }); document.querySelector('#event-modal').hidden = true; loadOperations(); });
document.querySelector('#resolve-button').addEventListener('click', async () => { if (selectedEvent) await fetch(`/api/events/${selectedEvent.id}/status`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ status: 'Resolved' }) }); document.querySelector('#event-modal').hidden = true; loadSummary(); });
document.querySelectorAll('.nav-link').forEach(link => link.addEventListener('click', () => { document.querySelector(`#${link.dataset.scroll}`).scrollIntoView({ behavior: 'smooth' }); document.querySelectorAll('.nav-link').forEach(item => item.classList.toggle('active', item === link)); }));

document.querySelector('#event-search').addEventListener('input', filterEvents);
document.querySelector('#severity-filter').addEventListener('change', filterEvents);

document.querySelector('#password-input').addEventListener('input', async event => {
    const response = await fetch('/api/password-check', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ password: event.target.value }) });
    const data = await response.json();
    document.querySelector('#strength-label').textContent = data.label;
    document.querySelector('#strength-score').textContent = `${data.score} / 5`;
    document.querySelector('#strength-meter').style.width = `${data.score * 20}%`;
    document.querySelector('#strength-meter').style.background = data.score >= 4 ? '#32805e' : data.score >= 3 ? '#d09a32' : '#e56855';
    Object.entries(data.checks).forEach(([key, valid]) => document.querySelector(`[data-check="${key}"]`).classList.toggle('valid', valid));
});

document.querySelector('#ip-button').addEventListener('click', async () => {
    const target = document.querySelector('#ip-result');
    const response = await fetch('/api/ip-info', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ ip: document.querySelector('#ip-input').value }) });
    const data = await response.json();
    if (!response.ok) { target.textContent = data.error; return; }
    target.innerHTML = `<strong>${data.ip}</strong>${data.version} · ${data.scope}<br>${data.classification} · ${data.observed_events} observed event${data.observed_events === 1 ? '' : 's'}`;
});

async function postJson(url, payload) {
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify(payload) });
    return { response, data: await response.json() };
}

document.querySelector('#log-button').addEventListener('click', async () => {
    const { data } = await postJson('/api/log-analyzer', { text: document.querySelector('#log-input').value });
    document.querySelector('#log-result').textContent = data.error || `${data.lines} lines · ${data.failed_logins} failed logins · ${data.repeated_sources.length} repeated sources detected`;
    loadSummary();
});

document.querySelector('#ids-button').addEventListener('click', async () => {
    const { data } = await postJson('/api/ids-analyze', { text: document.querySelector('#ids-input').value });
    document.querySelector('#ids-result').textContent = data.error || `${data.severity} · ${data.matches.length} rule${data.matches.length === 1 ? '' : 's'} matched`;
});

document.querySelector('#url-button').addEventListener('click', async () => {
    const { data } = await postJson('/api/phishing-check', { url: document.querySelector('#url-input').value });
    document.querySelector('#url-result').textContent = data.error || `${data.verdict} · risk score ${data.score}/100${data.indicators.length ? ` · ${data.indicators.join(', ')}` : ''}`;
});

document.querySelector('#scan-button').addEventListener('click', async () => {
    const { data } = await postJson('/api/network-scan', { ip: document.querySelector('#scan-ip').value, ports: document.querySelector('#scan-ports').value });
    document.querySelector('#scan-result').textContent = data.error || `${data.target} · ${data.open_ports.length ? `open: ${data.open_ports.join(', ')}` : 'no open ports found'}`;
});

document.querySelector('#vuln-button').addEventListener('click', async () => {
    const { data } = await postJson('/api/vulnerability-scan', { ip: document.querySelector('#vuln-ip').value });
    document.querySelector('#vuln-result').textContent = data.error || `${data.scanned_ports} ports checked · ${data.findings.length} potential finding${data.findings.length === 1 ? '' : 's'}`;
});

document.querySelector('#file-button').addEventListener('click', async () => {
    const { data } = await postJson('/api/file-integrity', { path: document.querySelector('#file-input').value });
    document.querySelector('#file-result').textContent = data.error || `${data.path} · ${data.size} bytes · SHA-256 ${data.sha256.slice(0, 18)}...`;
});

let monitorCursor = 0;
let monitorTimer = null;
async function pollMonitor() {
    const { data } = await postJson('/api/monitor-log', { path: document.querySelector('#monitor-file').value, cursor: monitorCursor });
    if (data.error) { document.querySelector('#monitor-result').textContent = data.error; return; }
    monitorCursor = data.cursor;
    document.querySelector('#monitor-result').textContent = `${data.lines.length} new line${data.lines.length === 1 ? '' : 's'} · ${data.alerts.length} alert${data.alerts.length === 1 ? '' : 's'} · cursor ${monitorCursor}`;
    loadSummary();
}
document.querySelector('#monitor-button').addEventListener('click', async event => {
    if (monitorTimer) {
        clearInterval(monitorTimer);
        monitorTimer = null;
        event.target.textContent = 'Poll';
        document.querySelector('#monitor-result').textContent = 'Live monitoring paused.';
        return;
    }
    await pollMonitor();
    if (!document.querySelector('#monitor-result').textContent.includes('only watch') && !document.querySelector('#monitor-result').textContent.includes('does not exist')) {
        monitorTimer = setInterval(pollMonitor, 2000);
        event.target.textContent = 'Stop';
    }
});

document.querySelector('#indicator-button').addEventListener('click', async () => {
    const value = document.querySelector('#indicator-value').value;
    const { data } = await postJson('/api/threat-intel', { value, confidence: Number(document.querySelector('#indicator-confidence').value), indicator_type: value.includes('.') && !value.includes('://') ? 'IP' : 'DOMAIN' });
    document.querySelector('#indicator-result').textContent = data.error || `${data.length} indicators registered locally`;
    loadIndicators();
});

async function loadIndicators() {
    const response = await fetch('/api/threat-intel');
    if (!response.ok) return;
    const items = await response.json();
    document.querySelector('#indicator-list').innerHTML = items.slice(0, 5).map(item => `<div class="indicator-item"><strong>${escapeHtml(item.value)}</strong><span>${escapeHtml(item.status)} · ${item.confidence}% confidence</span></div>`).join('');
}

document.querySelector('#incident-button').addEventListener('click', async () => {
    const { data } = await postJson('/api/incidents', { title: document.querySelector('#incident-title').value });
    document.querySelector('#incident-result').textContent = Array.isArray(data) ? `${data.length} incident${data.length === 1 ? '' : 's'} in the queue` : data.error;
    loadSummary();
});

document.querySelector('#asset-add').addEventListener('click', () => { document.querySelector('#asset-form').hidden = !document.querySelector('#asset-form').hidden; });
document.querySelector('#asset-form').addEventListener('submit', async event => { event.preventDefault(); const payload = Object.fromEntries(new FormData(event.target)); const { data } = await postJson('/api/assets', payload); if (data.error) window.alert(data.error); event.target.reset(); event.target.hidden = true; loadAssets(); });
document.querySelector('#collector-add').addEventListener('click', () => { document.querySelector('#collector-form').hidden = !document.querySelector('#collector-form').hidden; });
document.querySelector('#collector-form').addEventListener('submit', async event => { event.preventDefault(); const payload = Object.fromEntries(new FormData(event.target)); const { data } = await postJson('/api/collectors', payload); if (data.error) window.alert(data.error); event.target.reset(); event.target.hidden = true; loadCollectors(); });
document.querySelector('#user-form').addEventListener('submit', async event => { event.preventDefault(); const payload = Object.fromEntries(new FormData(event.target)); const { data } = await postJson('/api/users', payload); if (data.error) window.alert(data.error); event.target.reset(); loadUsers(); });
document.querySelector('#notification-preferences').addEventListener('submit', async event => { event.preventDefault(); const payload = Object.fromEntries(new FormData(event.target)); payload.browser_enabled = Boolean(payload.browser_enabled); await fetch('/api/notification-preferences', { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify(payload) }); loadNotifications(); });
document.querySelector('#platform-settings').addEventListener('submit', async event => { event.preventDefault(); const payload = Object.fromEntries(new FormData(event.target)); const response = await fetch('/api/settings', { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify(payload) }); const data = await response.json(); if (data.error) window.alert(data.error); });
document.querySelector('#notification-button').addEventListener('click', () => { const panel = document.querySelector('#notification-panel'); panel.hidden = !panel.hidden; loadNotifications(); });
document.querySelector('#notifications-read').addEventListener('click', async () => { await postJson('/api/notifications/read-all', {}); loadNotifications(); });

document.querySelector('#assistant-toggle').addEventListener('click', () => {
    document.querySelector('#assistant-panel').hidden = false;
    document.querySelector('#assistant-input').focus();
});
document.querySelector('#assistant-close').addEventListener('click', () => { document.querySelector('#assistant-panel').hidden = true; });
document.querySelector('#assistant-form').addEventListener('submit', async event => {
    event.preventDefault();
    const input = document.querySelector('#assistant-input');
    const message = input.value.trim();
    if (!message) return;
    const messages = document.querySelector('#assistant-messages');
    messages.insertAdjacentHTML('beforeend', `<div class="user-message">${escapeHtml(message)}</div>`);
    input.value = '';
    const { data } = await postJson('/api/assistant', { message });
    messages.insertAdjacentHTML('beforeend', `<div class="assistant-message">${escapeHtml(data.answer || data.error || 'I could not answer that just now.')}</div>`);
    messages.scrollTop = messages.scrollHeight;
});

loadSummary();
updateLocalTime();
setInterval(updateLocalTime, 1000);
setInterval(loadSummary, 10000);
