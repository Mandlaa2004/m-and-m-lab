const severityColors = { CRITICAL: '#e56855', HIGH: '#f09a68', MEDIUM: '#d09a32', LOW: '#32805e', INFO: '#20777a' };
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[character]));
const formatTime = value => new Date(value).toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
const isAdmin = document.body.dataset.role === 'Admin';

let summaryRequestInFlight = false;
let notificationsRequestInFlight = false;
let operationsRequestInFlight = false;
let selectedIncidentId = null;
let latestAlerts = [];
let latestIncidents = [];

function updateLocalTime() {
    const now = new Date();
    const hour = now.getHours();
    document.querySelector('#greeting').textContent = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
    document.querySelector('#live-clock').textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

async function loadSummary({ refreshOperations = false, refreshNotifications = false } = {}) {
    if (summaryRequestInFlight) return;
    summaryRequestInFlight = true;
    try {
        const response = await fetch('/api/summary');
        if (!response.ok) return;
        const data = await response.json();
        animateCount(document.querySelector('#total-events'), data.today ?? data.total);
        animateCount(document.querySelector('#open-events'), data.open);
        animateCount(document.querySelector('#unique-sources'), data.sources);
        animateCount(document.querySelector('#critical-events'), data.critical);
        animateCount(document.querySelector('#suspicious-ips'), data.suspicious_ips);
        renderRiskGauge(data);
        drawChart(data.counts);
        drawTimeChart(data.hourly);
        renderActivity(data.activity);
        renderEvents(data.events);
        renderOperationsPulse(data);
        renderThreatMap(data.threats);
        renderAttackChart(data.attack_types);
        renderProgress(data.progress);
        renderResponseWorkflow(data.response_stages);
        if (refreshOperations) loadOperations();
        if (refreshNotifications) loadNotifications();
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

function renderThreatMap(threats) {
    const map = document.querySelector('#threat-map');
    const roster = document.querySelector('#threat-roster');
    map.innerHTML = threats.map(threat => {
        const x = Math.max(6, Math.min(94, ((threat.longitude + 180) / 360) * 100));
        const y = Math.max(8, Math.min(88, ((90 - threat.latitude) / 180) * 100));
        return `<button class="threat-point severity-${escapeHtml(threat.severity)}" style="left:${x}%;top:${y}%" title="${escapeHtml(threat.source_ip)} · ${escapeHtml(threat.label)} · ${threat.score}/100" type="button" data-ip="${escapeHtml(threat.source_ip)}"></button>`;
    }).join('') || '<p class="empty">No source telemetry yet.</p>';
    roster.innerHTML = threats.slice(0, 4).map(threat => `<button class="threat-row" type="button" data-ip="${escapeHtml(threat.source_ip)}"><span><strong class="mono">${escapeHtml(threat.source_ip)}</strong><small>${escapeHtml(threat.label)} · ${threat.total} events</small></span><b>${threat.score}</b></button>`).join('') || '<p class="empty">No active IP observations.</p>';
    document.querySelectorAll('[data-ip]').forEach(button => button.addEventListener('click', () => inspectIp(button.dataset.ip)));
}

function renderAttackChart(items) {
    const target = document.querySelector('#attack-chart');
    const max = Math.max(...items.map(item => item.total), 1);
    target.innerHTML = items.map(item => `<div class="attack-row"><span>${escapeHtml(item.event_type)}</span><i><b style="width:${Math.max(8, Math.round(item.total / max * 100))}%"></b></i><strong>${item.total}</strong></div>`).join('') || '<p class="empty">No attack signals yet.</p>';
}

function renderProgress(progress) {
    document.querySelector('#analyst-level').textContent = `LVL ${progress.level}`;
    document.querySelector('#analyst-xp').textContent = `${progress.xp} XP`;
    document.querySelector('#xp-next').textContent = `${progress.next_level_xp - progress.xp} XP to next level`;
    document.querySelector('#xp-progress').style.width = `${Math.min(100, progress.xp / progress.next_level_xp * 100)}%`;
    document.querySelector('#achievement-list').innerHTML = progress.achievements.map(item => `<span class="achievement ${item.earned ? 'earned' : ''}">${item.earned ? '✓' : '○'} ${escapeHtml(item.name)}</span>`).join('');
}

function renderResponseWorkflow(stages) {
    document.querySelector('#response-steps').innerHTML = stages.map((item, index) => `<div class="response-step ${item.total ? 'active' : ''}"><span>${String(index + 1).padStart(2, '0')}</span><strong>${escapeHtml(item.stage)}</strong><b>${item.total}</b></div>`).join('');
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
            loadIndicators(),
            loadActivityFeed(),
            loadReports(),
            loadNotificationPreferences(),
            loadSavedSearches(),
            loadMitreCoverage(),
            loadPlaybooks(),
            loadAuditTrail(),
            loadAnalystActivity()
        ]);
        if (isAdmin) await Promise.all([loadUsers(), loadPlatformSettings(), loadTeams()]);
    } finally {
        operationsRequestInFlight = false;
    }
}

function renderIncidents(items) {
    latestIncidents = items;
    const target = document.querySelector('#incidents-table');
    target.innerHTML = items.length ? items.map(item => `<tr><td><strong>#${item.id}</strong><span class="event-message">${escapeHtml(item.title)}</span></td><td><select class="incident-stage" data-incident-id="${item.id}">${['DETECT', 'INVESTIGATE', 'CONTAIN', 'REMEDIATE', 'RESOLVE'].map(stage => `<option ${item.response_stage === stage ? 'selected' : ''}>${stage}</option>`).join('')}</select></td><td class="mono">${formatTime(item.updated_at)}</td><td><button class="row-action" data-incident-id="${item.id}" type="button">Advance</button><button class="row-action timeline-action" data-incident-id="${item.id}" type="button">Timeline</button></td></tr>`).join('') : '<tr><td colspan="4" class="empty">No investigations yet.</td></tr>';
    target.querySelectorAll('.row-action:not(.timeline-action)').forEach(button => button.addEventListener('click', () => updateIncident(button.dataset.incidentId)));
    target.querySelectorAll('.timeline-action').forEach(button => button.addEventListener('click', () => loadTimeline(button.dataset.incidentId)));
}

async function loadTimeline(id) {
    const response = await fetch(`/api/incidents/${id}/timeline`);
    if (!response.ok) return;
    const items = await response.json();
    document.querySelector('#incident-timeline').innerHTML = items.length ? items.map(item => `<div class="timeline-item"><strong>${escapeHtml(item.action)}</strong><span>${escapeHtml(item.actor)} · ${formatTime(item.created_at)}</span><p>${escapeHtml(item.detail || '')}</p></div>`).join('') : '<p class="empty">No timeline entries yet.</p>';
    selectedIncidentId = id;
    document.querySelector('#evidence-workspace').hidden = false;
    loadEvidence(id);
    renderRelatedAlerts(id);
}

function renderRelatedAlerts(incidentId) {
    const incident = latestIncidents.find(item => String(item.id) === String(incidentId));
    const target = document.querySelector('#incident-related-alerts');
    if (!target) return;
    const related = incident ? latestAlerts.filter(alert => String(alert.event_id) === String(incident.event_id)) : [];
    target.innerHTML = related.length ? related.map(item => `<div class="alert-item static"><span class="severity severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><span><strong>${escapeHtml(item.name || 'Detection alert')}</strong><small>${escapeHtml(item.source_ip)} · ${escapeHtml(item.mitre_attack || 'unmapped')}</small></span></div>`).join('') : '<p class="empty">No linked alerts for this case.</p>';
}

async function loadEvidence(id) {
    const response = await fetch(`/api/incidents/${id}/evidence`);
    if (!response.ok) return;
    const items = await response.json();
    document.querySelector('#evidence-list').innerHTML = items.length ? items.map(item => `<div class="evidence-item"><b>${escapeHtml(item.evidence_type)}</b><span>${escapeHtml(item.content)}</span><small>${escapeHtml(item.created_by)} · ${formatTime(item.created_at)}</small></div>`).join('') : '<p class="empty">No evidence attached to this case.</p>';
}

const ALERT_STAGE_LABELS = { NEW: 'New', OPEN: 'New', ACKNOWLEDGED: 'Investigating', 'IN PROGRESS': 'Contained', RESOLVED: 'Resolved', 'FALSE POSITIVE': 'Resolved' };

function renderAlerts(items) {
    latestAlerts = items;
    document.querySelector('#alert-count').textContent = `${items.length} alert${items.length === 1 ? '' : 's'}`;
    document.querySelector('#alerts-list').innerHTML = items.length ? items.slice(0, 8).map(item => `<div class="alert-item"><button class="alert-open" data-event-id="${item.event_id}" type="button"><span class="severity severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><span><strong>${escapeHtml(item.name || 'Detection alert')}</strong><small>${escapeHtml(item.source_ip)} · ${escapeHtml(item.rule_id || 'manual')} · ${escapeHtml(item.mitre_attack || 'unmapped')}</small></span></button><span class="alert-stage">${escapeHtml(ALERT_STAGE_LABELS[item.status] || item.status)}</span><button class="row-action alert-investigate" data-alert-id="${item.id}" data-event-id="${item.event_id}" type="button">Investigate</button></div>`).join('') : '<p class="empty">No alerts recorded yet.</p>';
    document.querySelectorAll('.alert-open').forEach(item => item.addEventListener('click', () => inspectEvent(item.dataset.eventId)));
    document.querySelectorAll('.alert-investigate').forEach(button => button.addEventListener('click', async () => {
        await fetch(`/api/alerts/${button.dataset.alertId}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ status: 'ACKNOWLEDGED' }) });
        const event = latestAlerts.find(alert => String(alert.id) === button.dataset.alertId);
        if (event) await postJson('/api/incidents', { event_id: Number(button.dataset.eventId), title: event.name || 'Investigation', notes: 'Opened from alert queue.' });
        switchPage('events');
        loadOperations();
    }));
    document.querySelector('#triage-list').innerHTML = items.slice(0, 6).map(item => `<div class="triage-item ${item.overdue ? 'overdue' : ''}"><div><strong>${escapeHtml(item.name || 'Detection alert')}</strong><span>${escapeHtml(item.source_ip)} · ${escapeHtml(item.escalation)} · ${item.overdue ? 'SLA overdue' : `SLA ${item.sla_minutes}m`}</span></div><div class="triage-controls"><input class="alert-assignee" data-alert-id="${item.id}" value="${escapeHtml(item.assignee)}" placeholder="Owner" aria-label="Alert owner"><select data-alert-id="${item.id}" class="triage-status"><option ${item.status === 'OPEN' || item.status === 'NEW' ? 'selected' : ''}>NEW</option><option ${item.status === 'ACKNOWLEDGED' ? 'selected' : ''}>ACKNOWLEDGED</option><option ${item.status === 'IN PROGRESS' ? 'selected' : ''}>IN PROGRESS</option><option ${item.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option></select></div></div>`).join('') || '<p class="empty">No alerts in queue.</p>';
    document.querySelectorAll('.triage-status').forEach(select => select.addEventListener('change', () => updateAlert(select.dataset.alertId, select.value)));
}

async function updateAlert(id, status) {
    const assignee = document.querySelector(`.alert-assignee[data-alert-id="${id}"]`)?.value.trim();
    await fetch(`/api/alerts/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ status, assignee }) });
    loadOperations();
}

async function loadAssets() {
    const response = await fetch('/api/assets');
    if (!response.ok) return;
    const items = await response.json();
    document.querySelector('#assets-table').innerHTML = items.length ? items.map(item => `<tr><td><strong>${escapeHtml(item.name)}</strong><span class="event-message">${escapeHtml(item.asset_type)} · ${item.event_count} linked events · ${escapeHtml(item.risk_trend)}</span></td><td class="mono">${escapeHtml(item.ip_address)}</td><td><span class="severity severity-${escapeHtml(item.risk_level)}">${item.risk_score}/100</span></td><td>${escapeHtml(item.status)}</td><td><input class="asset-team-input" data-asset-id="${item.id}" value="${escapeHtml(item.team || '')}" placeholder="Unassigned" aria-label="Assign team"></td></tr>`).join('') : '<tr><td colspan="5" class="empty">No assets registered.</td></tr>';
    document.querySelectorAll('.asset-team-input').forEach(input => input.addEventListener('change', async () => {
        await fetch(`/api/assets/${input.dataset.assetId}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ team: input.value.trim() }) });
        loadTeams();
    }));
    renderAssetHealth(items);
}

function renderAssetHealth(items) {
    const target = document.querySelector('#asset-health-grid');
    if (!target) return;
    const buckets = { Healthy: 0, 'At risk': 0, Compromised: 0, Offline: 0 };
    items.forEach(item => {
        if (String(item.status).toUpperCase() === 'OFFLINE') buckets.Offline += 1;
        else if (item.risk_level === 'CRITICAL') buckets.Compromised += 1;
        else if (item.risk_level === 'HIGH' || item.risk_level === 'MEDIUM') buckets['At risk'] += 1;
        else buckets.Healthy += 1;
    });
    const tones = { Healthy: 'healthy', 'At risk': 'atrisk', Compromised: 'compromised', Offline: 'offline' };
    target.innerHTML = Object.entries(buckets).map(([label, count]) => `<article class="asset-health-card ${tones[label]}"><strong>${count}</strong><span>${label}</span></article>`).join('');
}

async function loadSavedSearches() {
    const response = await fetch('/api/saved-searches');
    if (!response.ok) return;
    const items = await response.json();
    const target = document.querySelector('#saved-searches');
    target.innerHTML = items.map(item => `<button class="saved-search" data-name="${escapeHtml(item.name)}" data-query="${escapeHtml(item.query)}" data-severity="${escapeHtml(item.severity)}" type="button">${escapeHtml(item.name)}</button>`).join('');
    target.querySelectorAll('.saved-search').forEach(button => button.addEventListener('click', () => {
        document.querySelector('#event-search').value = button.dataset.query;
        document.querySelector('#severity-filter').value = button.dataset.severity;
        filterEvents();
        showSavedSearchLiveView(button.dataset.name, button.dataset.query, button.dataset.severity);
    }));
}

async function showSavedSearchLiveView(name, query, severity) {
    const params = new URLSearchParams({ q: query, severity });
    const response = await fetch(`/api/events?${params}`);
    if (!response.ok) return;
    const items = await response.json();
    document.querySelector('#saved-search-live-title').textContent = `${name} · ${items.length} match${items.length === 1 ? '' : 'es'}`;
    document.querySelector('#saved-search-live-list').innerHTML = items.slice(0, 8).map(item => `<div class="saved-search-live-item"><span class="severity severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><strong>${escapeHtml(item.event_type)}</strong><span class="mono">${escapeHtml(item.source_ip)}</span><small>${formatTime(item.timestamp)}</small></div>`).join('') || '<p class="empty">No matching events.</p>';
    document.querySelector('#saved-search-live').hidden = false;
}

async function loadMitreCoverage() {
    const response = await fetch('/api/mitre-coverage');
    if (!response.ok) return;
    const items = await response.json();
    document.querySelector('#coverage-count').textContent = `${items.filter(item => item.covered).length}/${items.length} covered`;
    document.querySelector('#coverage-matrix').innerHTML = items.map(item => `<button class="coverage-cell ${item.covered ? 'covered' : 'gap'}" data-technique="${escapeHtml(item.technique)}" type="button"><strong>${escapeHtml(item.technique)}</strong><span>${escapeHtml(item.name)}</span><b>${item.covered ? 'Covered' : 'Gap'}</b></button>`).join('');
    document.querySelectorAll('.coverage-cell').forEach(cell => cell.addEventListener('click', () => showTechniqueAlerts(cell.dataset.technique)));
}

function showTechniqueAlerts(technique) {
    const target = document.querySelector('#technique-drilldown');
    if (!target) return;
    const related = latestAlerts.filter(alert => alert.mitre_attack === technique);
    target.hidden = false;
    target.innerHTML = `<p class="eyebrow chart-label">${escapeHtml(technique)} · ${related.length} alert${related.length === 1 ? '' : 's'}</p>` + (related.length ? related.map(item => `<div class="alert-item static"><span class="severity severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><span><strong>${escapeHtml(item.name || 'Detection alert')}</strong><small>${escapeHtml(item.source_ip)}</small></span></div>`).join('') : '<p class="empty">No alerts observed for this technique yet.</p>');
}

async function loadPlaybooks() {
    const response = await fetch('/api/playbooks');
    if (!response.ok) return;
    const items = await response.json();
    const target = document.querySelector('#playbook-list');
    target.innerHTML = items.map(item => `<button class="playbook-button" data-playbook-id="${escapeHtml(item.id)}" type="button"><span>${escapeHtml(item.title)}</span><b>Run</b></button>`).join('');
    target.querySelectorAll('.playbook-button').forEach(button => button.addEventListener('click', async () => {
        const { data } = await postJson('/api/playbooks', { id: button.dataset.playbookId });
        if (data.steps) window.alert(`${data.title}\n\n${data.steps.map((step, index) => `${index + 1}. ${step}`).join('\n')}`);
    }));
}

async function loadActivityFeed() {
    const response = await fetch('/api/activity');
    if (response.ok) renderActivity(await response.json(), 'live-activity');
}

function auditFilterParams() {
    return new URLSearchParams({
        actor: document.querySelector('#audit-actor')?.value || '',
        action: document.querySelector('#audit-action')?.value || ''
    });
}

async function loadAuditTrail() {
    const params = auditFilterParams();
    const response = await fetch(`/api/audit?${params}`);
    if (response.ok) renderActivity(await response.json(), 'audit-list');
    document.querySelector('#audit-export-link').href = `/export/activity.csv?${params}`;
}

async function loadAuditTrail() {
    const actor = document.querySelector('#audit-actor')?.value.trim() || '';
    const action = document.querySelector('#audit-action')?.value.trim() || '';
    const params = new URLSearchParams({ actor, action });
    const response = await fetch(`/api/audit?${params}`);
    if (response.ok) renderActivity(await response.json(), 'audit-list');
    document.querySelector('#audit-export-link').href = `/export/activity.csv?${params}`;
}

async function loadReports() {
    const response = await fetch('/api/reports/summary');
    if (!response.ok) return;
    const data = await response.json();
    document.querySelector('#report-summary').innerHTML = data.daily.slice(0, 4).map(item => `<div class="report-row"><strong>${escapeHtml(item.day)}</strong><span>${item.events} events · ${item.high_risk || 0} high risk</span></div>`).join('') || '<p class="empty">No report data yet.</p>';
    document.querySelector('#report-techniques').innerHTML = data.top_attack_types.slice(0, 4).map(item => `<div class="report-row"><strong>${escapeHtml(item.technique)}</strong><span>${escapeHtml(item.name)} · ${item.alerts} alerts</span></div>`).join('') || '<p class="empty">No attack signal yet.</p>';
    const assetsTarget = document.querySelector('#report-assets');
    if (assetsTarget) assetsTarget.innerHTML = data.most_targeted_assets.slice(0, 4).map(item => `<div class="report-row"><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.ip_address)} · ${item.total} events</span></div>`).join('') || '<p class="empty">No targeted assets yet.</p>';
    const analystsTarget = document.querySelector('#report-analysts');
    if (analystsTarget) analystsTarget.innerHTML = data.analyst_performance.slice(0, 4).map(item => `<div class="report-row"><strong>${escapeHtml(item.assignee)}</strong><span>${item.resolved || 0}/${item.total} resolved</span></div>`).join('') || '<p class="empty">No analyst performance data yet.</p>';
    const responseTarget = document.querySelector('#report-response-time');
    if (responseTarget) responseTarget.textContent = data.avg_response_hours != null ? `Average incident response time: ${data.avg_response_hours}h` : 'Not enough resolved cases to compute response time.';
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
    document.querySelector('#users-list').innerHTML = items.map(item => `<div class="user-item"><strong>${escapeHtml(item.username)}</strong><span>${escapeHtml(item.role)}${item.team ? ` · ${escapeHtml(item.team)}` : ''}${item.totp_enabled ? ' · 2FA' : ''}</span></div>`).join('');
}

async function loadTeams() {
    const response = await fetch('/api/teams');
    if (!response.ok) return;
    const items = await response.json();
    document.querySelector('#teams-list').innerHTML = items.length ? items.map(item => `<div class="user-item"><strong>${escapeHtml(item.name)}</strong><span>${item.asset_count} asset${item.asset_count === 1 ? '' : 's'}</span></div>`).join('') : '<p class="empty">No teams registered yet.</p>';
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
    const select = document.querySelector(`.incident-stage[data-incident-id="${id}"]`);
    await fetch('/api/incidents', { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ id, status: select.value === 'RESOLVE' ? 'RESOLVED' : 'INVESTIGATING', response_stage: select.value }) });
    loadOperations();
}

document.querySelector('#modal-close').addEventListener('click', () => { document.querySelector('#event-modal').hidden = true; });
document.querySelector('#event-modal').addEventListener('click', event => { if (event.target.id === 'event-modal') event.target.hidden = true; });
document.querySelector('#investigate-button').addEventListener('click', async () => { if (selectedEvent) await postJson('/api/incidents', { event_id: selectedEvent.id, title: selectedEvent.event_type, notes: selectedEvent.message }); document.querySelector('#event-modal').hidden = true; loadOperations(); });
document.querySelector('#resolve-button').addEventListener('click', async () => { if (selectedEvent) await fetch(`/api/events/${selectedEvent.id}/status`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ status: 'Resolved' }) }); document.querySelector('#event-modal').hidden = true; loadSummary(); });
document.querySelectorAll('.nav-link[data-page]').forEach(link => link.addEventListener('click', () => switchPage(link.dataset.page)));

const pageTitles = { overview: 'Overview', events: 'Events & Response', assets: 'Assets & Teams', activity: 'Activity & Settings', tools: 'Lab Tools' };

function switchPage(page) {
    if (!pageTitles[page]) return;
    document.querySelectorAll('.page-view').forEach(view => view.classList.toggle('active', view.dataset.page === page));
    document.querySelectorAll('.nav-link[data-page]').forEach(link => link.classList.toggle('active', link.dataset.page === page));
    const title = document.querySelector('#topbar-title');
    if (title) title.textContent = pageTitles[page];
    try { window.localStorage.setItem('mm-active-page', page); } catch (error) { /* storage unavailable */ }
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

try {
    const savedPage = window.localStorage.getItem('mm-active-page');
    if (savedPage && pageTitles[savedPage]) switchPage(savedPage);
} catch (error) { /* storage unavailable */ }

const themeToggleButton = document.querySelector('#theme-toggle');
function applyTheme(theme) {
    document.body.dataset.theme = theme;
    const label = document.querySelector('#theme-toggle-label');
    if (label) label.textContent = theme === 'light' ? 'Light mode' : 'Dark mode';
    if (themeToggleButton) themeToggleButton.setAttribute('aria-pressed', String(theme === 'light'));
}
if (themeToggleButton) {
    let storedTheme = 'dark';
    try { storedTheme = window.localStorage.getItem('mm-theme') || 'dark'; } catch (error) { /* storage unavailable */ }
    applyTheme(storedTheme);
    themeToggleButton.addEventListener('click', () => {
        const nextTheme = document.body.dataset.theme === 'light' ? 'dark' : 'light';
        applyTheme(nextTheme);
        try { window.localStorage.setItem('mm-theme', nextTheme); } catch (error) { /* storage unavailable */ }
    });
}

function animateCount(el, value) {
    const numeric = Number(value);
    if (!el || Number.isNaN(numeric)) { if (el) el.textContent = value; return; }
    const start = Number(el.dataset.countValue || el.textContent) || 0;
    if (start === numeric) { el.textContent = numeric; return; }
    el.dataset.countValue = numeric;
    const startTime = performance.now();
    const duration = 500;
    function step(now) {
        const progress = Math.min(1, (now - startTime) / duration);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(start + (numeric - start) * eased);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

function renderRiskGauge(data) {
    const gauge = document.querySelector('#risk-gauge');
    if (!gauge) return;
    const total = Number(data.today ?? data.total ?? 0) || 0;
    const critical = Number(data.critical ?? 0) || 0;
    const pct = total > 0 ? Math.min(100, Math.round((critical / total) * 100)) : 0;
    const radius = 26;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference * (1 - pct / 100);
    const tone = pct >= 60 ? '#e56855' : pct >= 30 ? '#d09a32' : '#32805e';
    gauge.innerHTML = `<svg viewBox="0 0 64 64"><circle class="gauge-track" cx="32" cy="32" r="${radius}"></circle><circle class="gauge-value" cx="32" cy="32" r="${radius}" stroke="${tone}" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"></circle></svg><div class="gauge-copy"><strong>${pct}%</strong><span>Critical share</span></div>`;
}

function enableDragReorder(gridSelector, cardSelector, storageKey) {
    const grid = document.querySelector(gridSelector);
    if (!grid) return;
    const cards = Array.from(grid.querySelectorAll(cardSelector));
    cards.forEach(card => {
        card.setAttribute('draggable', 'true');
        card.classList.add('draggable-card');
        card.addEventListener('dragstart', () => card.classList.add('dragging'));
        card.addEventListener('dragend', () => {
            card.classList.remove('dragging');
            try {
                window.localStorage.setItem(storageKey, JSON.stringify(Array.from(grid.children).map(child => child.dataset.cardId || '')));
            } catch (error) { /* storage unavailable */ }
        });
    });
    grid.addEventListener('dragover', event => {
        event.preventDefault();
        const dragging = grid.querySelector('.dragging');
        if (!dragging) return;
        const after = Array.from(grid.querySelectorAll(`${cardSelector}:not(.dragging)`)).find(sibling => {
            const box = sibling.getBoundingClientRect();
            return event.clientY <= box.top + box.height / 2;
        });
        if (after) grid.insertBefore(dragging, after); else grid.appendChild(dragging);
    });
    try {
        const savedOrder = JSON.parse(window.localStorage.getItem(storageKey) || 'null');
        if (Array.isArray(savedOrder)) {
            savedOrder.forEach(id => { const card = grid.querySelector(`[data-card-id="${id}"]`); if (card) grid.appendChild(card); });
        }
    } catch (error) { /* storage unavailable */ }
}
document.querySelectorAll('#summary-cards .stat-card').forEach((card, index) => { card.dataset.cardId = card.className.split(' ')[1] || `card-${index}`; });
enableDragReorder('#summary-cards', '.stat-card', 'mm-stat-order');

let searchDebounce = null;
const globalSearchInput = document.querySelector('#global-search-input');
if (globalSearchInput) {
    globalSearchInput.addEventListener('input', () => {
        window.clearTimeout(searchDebounce);
        const query = globalSearchInput.value.trim();
        const resultsBox = document.querySelector('#global-search-results');
        if (query.length < 2) { resultsBox.hidden = true; return; }
        searchDebounce = window.setTimeout(async () => {
            const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
            if (!response.ok) return;
            const { results } = await response.json();
            resultsBox.innerHTML = results.length ? results.map((item, index) => `<button class="search-result" data-index="${index}" data-page="${escapeHtml(item.page)}" type="button"><span class="search-result-type">${escapeHtml(item.type)}</span><span><strong>${escapeHtml(item.label)}</strong><small>${escapeHtml(item.detail)}</small></span></button>`).join('') : '<p class="empty">No matches found.</p>';
            resultsBox.hidden = false;
            resultsBox.querySelectorAll('.search-result').forEach(button => button.addEventListener('click', () => {
                switchPage(button.dataset.page);
                resultsBox.hidden = true;
                globalSearchInput.value = '';
            }));
        }, 220);
    });
    document.addEventListener('click', event => {
        if (!globalSearchInput.contains(event.target) && !document.querySelector('#global-search-results').contains(event.target)) {
            document.querySelector('#global-search-results').hidden = true;
        }
    });
}

document.querySelectorAll('.quick-action-button').forEach(button => button.addEventListener('click', async () => {
    const target = document.querySelector('#quick-action-target').value.trim();
    if (!target) { document.querySelector('#quick-action-result').textContent = 'Enter a target first.'; return; }
    const { data } = await postJson('/api/quick-actions', { action: button.dataset.action, target });
    document.querySelector('#quick-action-result').textContent = data.error || data.message;
    if (!data.error) { document.querySelector('#quick-action-target').value = ''; loadOperations(); }
}));


document.querySelector('#event-search').addEventListener('input', filterEvents);
document.querySelector('#severity-filter').addEventListener('change', filterEvents);
document.querySelector('#save-search').addEventListener('click', () => {
    document.querySelector('#save-search-form').hidden = false;
    document.querySelector('#save-search-form [name="name"]').focus();
});
document.querySelector('#save-search-cancel').addEventListener('click', () => { document.querySelector('#save-search-form').hidden = true; });
document.querySelector('#save-search-form').addEventListener('submit', async event => {
    event.preventDefault();
    const name = new FormData(event.target).get('name');
    if (!name) return;
    const { data } = await postJson('/api/saved-searches', { name, query: document.querySelector('#event-search').value, severity: document.querySelector('#severity-filter').value });
    if (data.error) { window.alert(data.error); return; }
    event.target.reset();
    event.target.hidden = true;
    loadSavedSearches();
});
document.querySelector('#saved-search-live-close').addEventListener('click', () => { document.querySelector('#saved-search-live').hidden = true; });

document.querySelector('#audit-filter-button').addEventListener('click', loadAuditTrail);

document.querySelector('#sign-out-all').addEventListener('click', async () => {
    if (!window.confirm('Sign out of all devices? You will need to log in again.')) return;
    await fetch('/api/account/sessions', { method: 'DELETE', headers: { 'X-CSRF-Token': csrfToken } });
    window.location.href = '/login';
});

const totpSetupButton = document.querySelector('#totp-setup-button');
if (totpSetupButton) {
    totpSetupButton.addEventListener('click', async () => {
        const { data } = await postJson('/api/account/totp/setup', {});
        if (data.error) { window.alert(data.error); return; }
        document.querySelector('#totp-secret').textContent = data.secret;
        document.querySelector('#totp-qr').innerHTML = data.qr_svg || '';
        document.querySelector('#totp-setup-result').hidden = false;
    });
    document.querySelector('#totp-verify-form').addEventListener('submit', async event => {
        event.preventDefault();
        const code = new FormData(event.target).get('code');
        const { data } = await postJson('/api/account/totp/verify', { code });
        if (data.error) { window.alert(data.error); return; }
        document.querySelector('#totp-setup-result').hidden = true;
        document.querySelector('#totp-disable-button').hidden = false;
        window.alert('Two-factor authentication enabled.');
    });
    document.querySelector('#totp-disable-button').addEventListener('click', async () => {
        await postJson('/api/account/totp/disable', {});
        document.querySelector('#totp-disable-button').hidden = true;
    });
}

document.querySelector('#threat-feed-sync-button')?.addEventListener('click', async () => {
    const url = document.querySelector('#threat-feed-sync input[name="url"]').value.trim();
    const { data } = await postJson('/api/threat-intel/sync', url ? { url } : {});
    window.alert(data.error || `${data.added} new indicator${data.added === 1 ? '' : 's'} imported.`);
    loadIndicators();
});

document.querySelector('#team-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    const { data } = await postJson('/api/teams', Object.fromEntries(new FormData(event.target)));
    if (data.error) window.alert(data.error);
    event.target.reset();
    loadTeams();
});

if (window.EventSource) {
    const eventStream = new EventSource('/api/events/stream');
    eventStream.onmessage = () => loadSummary();
}

document.querySelector('#password-input').addEventListener('input', async event => {
    const response = await fetch('/api/password-check', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ password: event.target.value }) });
    const data = await response.json();
    document.querySelector('#strength-label').textContent = data.label;
    document.querySelector('#strength-score').textContent = `${data.score} / 5`;
    document.querySelector('#strength-meter').style.width = `${data.score * 20}%`;
    document.querySelector('#strength-meter').style.background = data.score >= 4 ? '#32805e' : data.score >= 3 ? '#d09a32' : '#e56855';
    Object.entries(data.checks).forEach(([key, valid]) => document.querySelector(`[data-check="${key}"]`).classList.toggle('valid', valid));
});

async function inspectIp(ip) {
    const target = document.querySelector('#ip-result');
    document.querySelector('#ip-input').value = ip;
    const response = await fetch('/api/ip-info', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ ip: document.querySelector('#ip-input').value }) });
    const data = await response.json();
    if (!response.ok) { target.textContent = data.error; return; }
    const providers = data.providers.length ? `<small>External intelligence: ${data.providers.map(item => `${escapeHtml(item.provider)} ${item.available ? 'connected' : 'unavailable'}`).join(' · ')}</small>` : '<small>Offline intelligence mode. Configure provider keys to enrich public IPs.</small>';
    target.innerHTML = `<div class="ip-intel-head"><strong>${escapeHtml(data.ip)}</strong><b>${data.threat_score}/100</b></div><span>${escapeHtml(data.location.label)} · ${escapeHtml(data.classification)}</span><p>${escapeHtml(data.recommendation)}</p>${data.activity.length ? `<small>Recent activity: ${escapeHtml(data.activity[0].event_type)} · ${escapeHtml(data.activity[0].severity)}</small>` : '<small>No local activity history.</small>'}${providers}`;
}
document.querySelector('#ip-button').addEventListener('click', () => inspectIp(document.querySelector('#ip-input').value));

async function postJson(url, payload) {
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify(payload) });
    return { response, data: await response.json() };
}

document.querySelector('#log-button').addEventListener('click', async () => {
    const { data } = await postJson('/api/log-analyzer', { text: document.querySelector('#log-input').value });
    document.querySelector('#log-result').textContent = data.error || `${data.lines} lines · ${data.failed_logins} failed logins · ${data.repeated_sources.length} repeated sources detected`;
    loadSummary({ refreshOperations: true, refreshNotifications: true });
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
    loadSummary({ refreshOperations: true, refreshNotifications: true });
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
    document.querySelector('#indicator-list').innerHTML = items.slice(0, 5).map(item => `<div class="indicator-item"><strong>${escapeHtml(item.value)}</strong><span>${escapeHtml(item.indicator_type)} · ${escapeHtml(item.status)} · source: ${escapeHtml(item.source || 'manual')}</span><div class="pulse-meter"><i style="width:${item.confidence}%"></i></div></div>`).join('');
}

async function loadAnalystActivity() {
    const response = await fetch('/api/analyst-activity');
    if (!response.ok) return;
    const data = await response.json();
    const onlineTarget = document.querySelector('#analyst-online-list');
    const onlineCount = document.querySelector('#analyst-online-count');
    if (onlineCount) onlineCount.textContent = `${data.online.length} online`;
    if (onlineTarget) onlineTarget.innerHTML = data.online.length ? data.online.map(name => `<div class="user-item"><i class="live-dot"></i><strong>${escapeHtml(name)}</strong></div>`).join('') : '<p class="empty">No recent analyst activity.</p>';
    renderPulseList('analyst-assignments', data.assignments, 'assignee', 'open_total');
    const resolvedTarget = document.querySelector('#analyst-resolved');
    if (resolvedTarget) resolvedTarget.innerHTML = data.recent_resolved.length ? data.recent_resolved.map(item => `<div class="activity-item"><i class="activity-marker"></i><div><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.assignee)} · ${formatTime(item.updated_at)}</span></div></div>`).join('') : '<p class="empty">No resolved investigations yet.</p>';
}

document.querySelector('#incident-button').addEventListener('click', async () => {
    const { data } = await postJson('/api/incidents', { title: document.querySelector('#incident-title').value });
    document.querySelector('#incident-result').textContent = Array.isArray(data) ? `${data.length} incident${data.length === 1 ? '' : 's'} in the queue` : data.error;
    loadSummary({ refreshOperations: true });
});

document.querySelector('#evidence-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (!selectedIncidentId) return;
    const { data } = await postJson(`/api/incidents/${selectedIncidentId}/evidence`, Object.fromEntries(new FormData(event.target)));
    if (data.error) window.alert(data.error);
    else { event.target.reset(); loadEvidence(selectedIncidentId); }
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

loadSummary({ refreshOperations: true, refreshNotifications: true });
updateLocalTime();
setInterval(updateLocalTime, 1000);
setInterval(loadSummary, 30000);
setInterval(loadNotifications, 60000);
setInterval(loadOperations, 60000);
