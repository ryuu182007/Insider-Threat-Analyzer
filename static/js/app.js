/**
 * Insider Threat Detection System - Frontend Application
 */

const API = '/api';
let charts = {};
let refreshTimer = null;

const THEME = {
    accent: '#c026d3',
    accentSecondary: '#7c3aed',
    success: '#22d3ee',
    warning: '#fbbf24',
    danger: '#fb7185',
    critical: '#e11d48',
    grid: 'rgba(124, 58, 237, 0.12)',
    tick: '#7c6a9a',
    legend: '#c4b5fd'
};

const VECTOR_ICONS = {
    failed_login: 'key-round',
    login: 'log-in',
    after_hours: 'moon',
    file_access: 'file-lock',
    file_download: 'download',
    bulk_download: 'download-cloud',
    usb_connected: 'usb',
    privilege_escalation: 'arrow-up-circle',
    data_exfiltration: 'upload',
    cross_department: 'building-2'
};

// --- Utility Functions ---

function getRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
}

function getRiskLabel(score) {
    return getRiskLevel(score).toUpperCase();
}

function riskBadge(score) {
    const level = getRiskLevel(score);
    return `<span class="risk-badge ${level}">${getRiskLabel(score)}</span>`;
}

function formatTime(ts) {
    if (!ts) return '--';
    const d = new Date(ts.replace(' ', 'T'));
    if (isNaN(d)) return ts;
    return d.toLocaleString('en-GB', {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}

function formatActivityType(type) {
    return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

async function fetchAPI(endpoint) {
    const res = await fetch(`${API}${endpoint}`);
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
}

function showError(container, msg) {
    if (typeof container === 'string') {
        container = document.getElementById(container);
    }
    if (container) {
        container.innerHTML = `<tr><td colspan="20" class="empty-cell">${msg}</td></tr>`;
    }
}

function refreshIcons() {
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

function getAnalystInitials() {
    const nameEl = document.getElementById('analyst-name');
    if (!nameEl) return 'SA';
    const parts = nameEl.textContent.trim().split(/\s+/);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return nameEl.textContent.trim().slice(0, 2).toUpperCase() || 'SA';
}

function chartDefaults() {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: THEME.legend, font: { size: 11 } } } },
        scales: {
            x: { ticks: { color: THEME.tick, font: { size: 10 } }, grid: { color: THEME.grid } },
            y: { ticks: { color: THEME.tick, font: { size: 10 } }, grid: { color: THEME.grid } }
        }
    };
}

function makeGradient(ctx, h = 180) {
    const g = ctx.createLinearGradient(0, 0, 0, h);
    g.addColorStop(0, THEME.accent);
    g.addColorStop(1, THEME.accentSecondary);
    return g;
}

// --- Navigation ---

function initNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.dataset.page;
            switchPage(page);
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            link.classList.add('active');
        });
    });
}

function switchPage(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const target = document.getElementById(`page-${page}`);
    if (target) target.classList.add('active');

    switch (page) {
        case 'dashboard': loadDashboard(); break;
        case 'users': loadUsers(); break;
        case 'activity': loadActivity(); break;
        case 'incidents': loadIncidents(); break;
        case 'threats': loadThreatAnalysis(); break;
        case 'settings': initSettingsPage(); break;
    }
    refreshIcons();
}

// --- Dashboard ---

async function loadDashboard() {
    try {
        const [stats, threatData, activities] = await Promise.all([
            fetchAPI('/dashboard'),
            fetchAPI('/threat-analysis'),
            fetchAPI('/activity?limit=8')
        ]);

        document.getElementById('stat-total-users').textContent = stats.total_users;
        document.getElementById('stat-active-users').textContent = stats.active_users;
        document.getElementById('stat-suspicious').textContent = stats.suspicious_users;
        document.getElementById('stat-incidents').textContent = stats.open_incidents;
        document.getElementById('system-status').textContent = stats.system_status;
        document.getElementById('avg-risk').textContent = stats.avg_risk_score;
        document.getElementById('high-risk-count').textContent = stats.high_risk_users;
        document.getElementById('critical-count').textContent = stats.critical_incidents;

        const level = stats.threat_level;
        const levelEl = document.getElementById('threat-level');
        levelEl.textContent = level;

        const ring = document.getElementById('risk-ring-fill');
        const pct = Math.min(stats.avg_risk_score / 100, 1);
        const circumference = 326.7;
        ring.style.strokeDashoffset = circumference - (pct * circumference);

        const colors = {
            LOW: THEME.success,
            MEDIUM: THEME.warning,
            HIGH: THEME.danger,
            CRITICAL: THEME.critical
        };
        ring.style.stroke = colors[level] || THEME.accent;

        document.getElementById('posture-risk-score').textContent =
            `${Math.round(stats.avg_risk_score)} / 100`;
        document.getElementById('posture-risk-bar').style.width = `${pct * 100}%`;
        document.getElementById('posture-time').textContent =
            'Updated ' + new Date().toLocaleTimeString();

        document.getElementById('last-updated').textContent =
            'Updated ' + new Date().toLocaleTimeString();

        renderThreatVectors(threatData.activity_by_category);
        renderDashboardAnomalyChart(threatData.threats_timeline);
        renderActivityFeed(activities);

        const scanEl = document.getElementById('settings-last-scan');
        if (scanEl) scanEl.textContent = new Date().toLocaleTimeString();
    } catch (err) {
        console.error('Dashboard load error:', err);
    }
}

function renderThreatVectors(categories) {
    const container = document.getElementById('threat-vectors-list');
    const entries = Object.entries(categories || {});
    if (!entries.length) {
        container.innerHTML = '<div class="empty-cell" style="padding:1rem;">No threat vector data</div>';
        return;
    }

    const max = Math.max(...entries.map(([, v]) => v), 1);
    const top = entries.sort((a, b) => b[1] - a[1]).slice(0, 6);

    container.innerHTML = top.map(([type, count]) => {
        const icon = VECTOR_ICONS[type] || 'activity';
        const pct = Math.round((count / max) * 100);
        return `
            <div class="vector-item">
                <div class="vector-icon"><i data-lucide="${icon}"></i></div>
                <div class="vector-body">
                    <div class="vector-name">${formatActivityType(type)}</div>
                    <div class="vector-bar">
                        <div class="vector-bar-fill" style="width:${pct}%"></div>
                    </div>
                </div>
                <span class="vector-count">${count}</span>
            </div>`;
    }).join('');
    refreshIcons();
}

function renderDashboardAnomalyChart(timeline) {
    const canvas = document.getElementById('chart-dashboard-anomaly');
    if (!canvas) return;

    destroyChart('chart-dashboard-anomaly');
    const ctx = canvas.getContext('2d');
    const labels = (timeline || []).map(t => {
        const d = new Date(t.day);
        return d.toLocaleDateString('en-GB', { weekday: 'short' });
    });
    const data = (timeline || []).map(t => t.count || 0);

    charts['chart-dashboard-anomaly'] = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels.length ? labels : ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [{
                data: data.length ? data : [0, 0, 0, 0, 0, 0, 0],
                backgroundColor: makeGradient(ctx, 150),
                borderRadius: 6,
                borderSkipped: false
            }]
        },
        options: {
            ...chartDefaults(),
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: THEME.tick, font: { size: 10 } }, grid: { display: false } },
                y: { ticks: { color: THEME.tick, font: { size: 10 }, stepSize: 1 }, grid: { color: THEME.grid } }
            }
        }
    });
}

function renderActivityFeed(activities) {
    const container = document.getElementById('activity-feed-list');
    if (!activities.length) {
        container.innerHTML = '<div class="empty-cell" style="padding:1.5rem;">No recent alerts — system stable</div>';
        return;
    }

    container.innerHTML = activities.map(a => {
        const initials = (a.username || '??').slice(0, 2).toUpperCase();
        return `
            <div class="feed-item">
                <div class="feed-icon ${a.status}">${initials}</div>
                <div class="feed-body">
                    <div class="feed-title">${a.username || a.full_name} — ${formatActivityType(a.activity_type)}</div>
                    <div class="feed-meta">${a.ip_address || '--'} · ${a.device || 'Unknown device'}</div>
                </div>
                <div class="feed-right">
                    ${riskBadge(a.risk_score)}
                    <div class="feed-time">${formatTime(a.timestamp)}</div>
                </div>
            </div>`;
    }).join('');
}

function renderActivityRows(tbodyId, activities, colCount) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    if (!activities.length) {
        tbody.innerHTML = `<tr><td colspan="${colCount || 7}" class="empty-cell">No activity records found</td></tr>`;
        return;
    }
    tbody.innerHTML = activities.map(a => {
        const cols = colCount || 7;
        let row = `<tr>`;
        row += `<td>${a.username || a.full_name}</td>`;
        row += `<td>${formatActivityType(a.activity_type)}</td>`;
        if (cols >= 7) {
            row += `<td>${a.ip_address || '--'}</td>`;
            row += `<td>${a.device || '--'}</td>`;
        } else {
            row += `<td>${a.ip_address || '--'}</td>`;
        }
        row += `<td>${riskBadge(a.risk_score)}</td>`;
        if (cols >= 7) {
            row += `<td>${formatTime(a.timestamp)}</td>`;
            row += `<td><span class="status-badge ${a.status}">${a.status}</span></td>`;
        } else {
            row += `<td>${formatTime(a.timestamp)}</td>`;
        }
        row += `</tr>`;
        return row;
    }).join('');
}

// --- Users ---

async function loadUsers() {
    const search = document.getElementById('user-search').value;
    const risk = document.getElementById('user-risk-filter').value;
    let url = '/users?';
    if (search) url += `search=${encodeURIComponent(search)}&`;
    if (risk) url += `risk=${risk}`;

    try {
        const users = await fetchAPI(url);
        const tbody = document.getElementById('users-body');
        if (!users.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No users found</td></tr>';
            return;
        }
        tbody.innerHTML = users.map(u => `
            <tr class="clickable" data-user-id="${u.id}">
                <td>${u.username}</td>
                <td>${u.department}</td>
                <td>${u.role}</td>
                <td>${riskBadge(u.risk_score)} <span style="color:var(--text-muted);font-size:0.75rem;">(${u.risk_score})</span></td>
                <td><span class="status-badge ${u.status}">${u.status}</span></td>
                <td>${formatTime(u.last_activity)}</td>
            </tr>
        `).join('');

        tbody.querySelectorAll('tr.clickable').forEach(row => {
            row.addEventListener('click', () => showUserDetail(row.dataset.userId));
        });
    } catch (err) {
        showError('users-body', 'Failed to load users');
    }
}

async function showUserDetail(userId) {
    try {
        const user = await fetchAPI(`/users/${userId}`);
        document.getElementById('modal-user-name').textContent = user.full_name;

        let html = `
            <div class="detail-grid">
                <div class="detail-item"><span class="detail-label">Username</span><span class="detail-value">${user.username}</span></div>
                <div class="detail-item"><span class="detail-label">Email</span><span class="detail-value">${user.email}</span></div>
                <div class="detail-item"><span class="detail-label">Department</span><span class="detail-value">${user.department}</span></div>
                <div class="detail-item"><span class="detail-label">Role</span><span class="detail-value">${user.role}</span></div>
                <div class="detail-item"><span class="detail-label">Risk Score</span><span class="detail-value">${riskBadge(user.risk_score)} (${user.risk_score})</span></div>
                <div class="detail-item"><span class="detail-label">Status</span><span class="detail-value"><span class="status-badge ${user.status}">${user.status}</span></span></div>
            </div>
            <div class="xp-bar-wrap" style="margin-top:0.75rem;">
                <div class="xp-bar-label"><span>Subject Risk Level</span><strong>${user.risk_score} / 100</strong></div>
                <div class="xp-bar"><div class="xp-bar-fill" style="width:${user.risk_score}%"></div></div>
            </div>
        `;

        if (user.threat_analysis && user.threat_analysis.threats.length) {
            html += `<div class="detail-section"><h4>Detected Threats</h4><ul class="threat-list">`;
            user.threat_analysis.threats.forEach(t => {
                html += `<li><strong>${t.type}</strong> — ${t.description} <span class="risk-badge ${t.severity.toLowerCase()}">${t.severity}</span></li>`;
            });
            html += `</ul></div>`;
        }

        if (user.recent_activities && user.recent_activities.length) {
            html += `<div class="detail-section"><h4>Recent Activity</h4>`;
            html += `<table class="data-table"><thead><tr><th>Activity</th><th>Risk</th><th>Time</th></tr></thead><tbody>`;
            user.recent_activities.slice(0, 8).forEach(a => {
                html += `<tr><td>${formatActivityType(a.activity_type)}</td><td>${riskBadge(a.risk_score)}</td><td>${formatTime(a.timestamp)}</td></tr>`;
            });
            html += `</tbody></table></div>`;
        }

        if (user.incidents && user.incidents.length) {
            html += `<div class="detail-section"><h4>Incident History</h4>`;
            html += `<table class="data-table"><thead><tr><th>Title</th><th>Severity</th><th>Status</th></tr></thead><tbody>`;
            user.incidents.forEach(i => {
                html += `<tr><td>${i.title}</td><td>${riskBadge(i.risk_score)}</td><td><span class="status-badge ${i.status.toLowerCase()}">${i.status}</span></td></tr>`;
            });
            html += `</tbody></table></div>`;
        }

        document.getElementById('user-modal-body').innerHTML = html;
        document.getElementById('user-modal').classList.add('open');
    } catch (err) {
        alert('Failed to load user details');
    }
}

// --- Activity Logs ---

async function loadActivity() {
    const search = document.getElementById('activity-search').value;
    const status = document.getElementById('activity-status-filter').value;
    let url = '/activity?limit=50&';
    if (search) url += `search=${encodeURIComponent(search)}&`;
    if (status) url += `status=${status}`;

    try {
        const activities = await fetchAPI(url);
        renderActivityRows('activity-body', activities, 7);
    } catch (err) {
        showError('activity-body', 'Failed to load activity logs');
    }
}

// --- Incidents ---

async function loadIncidents() {
    const severity = document.getElementById('incident-severity-filter').value;
    const status = document.getElementById('incident-status-filter').value;
    let url = '/incidents?';
    if (severity) url += `severity=${severity}&`;
    if (status) url += `status=${status}`;

    try {
        const incidents = await fetchAPI(url);
        const tbody = document.getElementById('incidents-body');
        if (!incidents.length) {
            tbody.innerHTML = '<tr><td colspan="8" class="empty-cell">No incidents found</td></tr>';
            return;
        }
        tbody.innerHTML = incidents.map(i => `
            <tr>
                <td>#${i.id}</td>
                <td>${i.username}</td>
                <td>${i.incident_type}</td>
                <td>${riskBadge(i.risk_score)}</td>
                <td>${i.risk_score}</td>
                <td>${formatTime(i.detected_at)}</td>
                <td><span class="status-badge ${i.status.toLowerCase()}">${i.status}</span></td>
                <td>
                    <button class="btn btn-primary" onclick="showIncidentDetail(${i.id})">View</button>
                    ${i.status !== 'Resolved' ? `<button class="btn" onclick="updateIncidentStatus(${i.id}, 'Investigating')">Investigate</button>` : ''}
                </td>
            </tr>
        `).join('');
    } catch (err) {
        showError('incidents-body', 'Failed to load incidents');
    }
}

async function showIncidentDetail(id) {
    try {
        const inc = await fetchAPI(`/incidents/${id}`);
        document.getElementById('modal-incident-title').textContent = inc.title;
        document.getElementById('incident-modal-body').innerHTML = `
            <div class="detail-grid">
                <div class="detail-item"><span class="detail-label">Incident ID</span><span class="detail-value">#${inc.id}</span></div>
                <div class="detail-item"><span class="detail-label">User</span><span class="detail-value">${inc.full_name} (${inc.username})</span></div>
                <div class="detail-item"><span class="detail-label">Type</span><span class="detail-value">${inc.incident_type}</span></div>
                <div class="detail-item"><span class="detail-label">Severity</span><span class="detail-value">${riskBadge(inc.risk_score)}</span></div>
                <div class="detail-item"><span class="detail-label">Status</span><span class="detail-value"><span class="status-badge ${inc.status.toLowerCase()}">${inc.status}</span></span></div>
                <div class="detail-item"><span class="detail-label">Detected</span><span class="detail-value">${formatTime(inc.detected_at)}</span></div>
            </div>
            <div class="detail-section">
                <h4>Description</h4>
                <p style="font-size:0.85rem;color:var(--text-secondary);">${inc.description}</p>
            </div>
            ${inc.status !== 'Resolved' ? `
            <div style="margin-top:1rem;display:flex;gap:0.5rem;">
                <button class="btn btn-primary" onclick="updateIncidentStatus(${inc.id}, 'Investigating');document.getElementById('incident-modal').classList.remove('open');">Mark Investigating</button>
                <button class="btn" onclick="updateIncidentStatus(${inc.id}, 'Resolved');document.getElementById('incident-modal').classList.remove('open');">Mark Resolved</button>
            </div>` : ''}
        `;
        document.getElementById('incident-modal').classList.add('open');
    } catch (err) {
        alert('Failed to load incident');
    }
}

async function updateIncidentStatus(id, status) {
    try {
        await fetch(`${API}/incidents/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status })
        });
        loadIncidents();
        loadDashboard();
        appendAuditLog(`Incident #${id} marked as ${status}`);
    } catch (err) {
        alert('Failed to update incident');
    }
}

// --- Threat Analysis ---

async function loadThreatAnalysis() {
    try {
        const data = await fetchAPI('/threat-analysis');

        const tbody = document.getElementById('top-risky-body');
        if (data.top_risky_users.length) {
            tbody.innerHTML = data.top_risky_users.map((u, i) => `
                <tr class="clickable" data-user-id="${u.id}">
                    <td><span style="color:var(--accent);font-family:var(--font-mono);margin-right:0.35rem;">#${i + 1}</span>${u.username}</td>
                    <td>${u.full_name}</td>
                    <td>${u.department}</td>
                    <td>${riskBadge(u.risk_score)} (${u.risk_score})</td>
                </tr>
            `).join('');
            tbody.querySelectorAll('tr.clickable').forEach(row => {
                row.addEventListener('click', () => {
                    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                    document.querySelector('[data-page="users"]').classList.add('active');
                    switchPage('users');
                    showUserDetail(row.dataset.userId);
                });
            });
        }

        renderCharts(data);
    } catch (err) {
        showError('top-risky-body', 'Failed to load threat analysis');
    }
}

function renderCharts(data) {
    const defaults = chartDefaults();

    destroyChart('chart-risk-dist');
    const rd = data.risk_distribution;
    charts['chart-risk-dist'] = new Chart(document.getElementById('chart-risk-dist'), {
        type: 'doughnut',
        data: {
            labels: ['Low', 'Medium', 'High', 'Critical'],
            datasets: [{
                data: [rd.low, rd.medium, rd.high, rd.critical],
                backgroundColor: [THEME.success, THEME.warning, THEME.danger, THEME.critical],
                borderWidth: 0,
                hoverOffset: 6
            }]
        },
        options: {
            ...defaults,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: THEME.legend, font: { size: 11 }, padding: 12 }
                }
            }
        }
    });

    destroyChart('chart-incidents');
    const is = data.incidents_by_severity;
    charts['chart-incidents'] = new Chart(document.getElementById('chart-incidents'), {
        type: 'bar',
        data: {
            labels: Object.keys(is),
            datasets: [{
                data: Object.values(is),
                backgroundColor: [THEME.success, THEME.warning, THEME.danger, THEME.critical],
                borderRadius: 6
            }]
        },
        options: { ...defaults, plugins: { legend: { display: false } } }
    });

    destroyChart('chart-activity');
    const ac = data.activity_by_category;
    const acLabels = Object.keys(ac).map(formatActivityType);
    const actCanvas = document.getElementById('chart-activity');
    const actCtx = actCanvas.getContext('2d');
    charts['chart-activity'] = new Chart(actCanvas, {
        type: 'bar',
        data: {
            labels: acLabels,
            datasets: [{
                data: Object.values(ac),
                backgroundColor: makeGradient(actCtx, 220),
                borderRadius: 6
            }]
        },
        options: {
            ...defaults,
            indexAxis: 'y',
            plugins: { legend: { display: false } }
        }
    });

    destroyChart('chart-timeline');
    const tl = data.threats_timeline;
    const tlCanvas = document.getElementById('chart-timeline');
    const tlCtx = tlCanvas.getContext('2d');
    const lineGrad = tlCtx.createLinearGradient(0, 0, 0, 220);
    lineGrad.addColorStop(0, 'rgba(192, 38, 211, 0.35)');
    lineGrad.addColorStop(1, 'rgba(192, 38, 211, 0)');

    charts['chart-timeline'] = new Chart(tlCanvas, {
        type: 'line',
        data: {
            labels: tl.map(t => t.day),
            datasets: [{
                label: 'Avg Risk Score',
                data: tl.map(t => Math.round(t.avg_risk * 10) / 10),
                borderColor: THEME.accent,
                backgroundColor: lineGrad,
                fill: true,
                tension: 0.35,
                pointRadius: 4,
                pointBackgroundColor: THEME.accent,
                pointBorderColor: '#fff',
                pointBorderWidth: 1
            }]
        },
        options: defaults
    });
}

function destroyChart(id) {
    if (charts[id]) {
        charts[id].destroy();
        delete charts[id];
    }
}

// --- Settings ---

function initSettingsTabs() {
    document.querySelectorAll('.settings-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.settingsTab;
            document.querySelectorAll('.settings-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.settings-pane').forEach(p => p.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById(`settings-${target}`).classList.add('active');
            refreshIcons();
        });
    });
}

function initSettingsSliders() {
    const failedSlider = document.getElementById('setting-failed-threshold');
    const failedVal = document.getElementById('setting-failed-threshold-val');
    if (failedSlider) {
        failedSlider.addEventListener('input', () => {
            failedVal.textContent = failedSlider.value;
        });
    }

    const incSlider = document.getElementById('setting-incident-threshold');
    const incVal = document.getElementById('setting-incident-threshold-val');
    if (incSlider) {
        incSlider.addEventListener('input', () => {
            incVal.textContent = incSlider.value;
        });
    }
}

function loadSettingsFromStorage() {
    try {
        const saved = JSON.parse(localStorage.getItem('itds_settings') || '{}');
        if (saved.failedThreshold) {
            const el = document.getElementById('setting-failed-threshold');
            if (el) { el.value = saved.failedThreshold; document.getElementById('setting-failed-threshold-val').textContent = saved.failedThreshold; }
        }
        if (saved.incidentThreshold) {
            const el = document.getElementById('setting-incident-threshold');
            if (el) { el.value = saved.incidentThreshold; document.getElementById('setting-incident-threshold-val').textContent = saved.incidentThreshold; }
        }
        if (saved.refreshInterval) {
            const el = document.getElementById('setting-refresh-interval');
            if (el) el.value = saved.refreshInterval;
        }
        if (saved.toggles) {
            Object.entries(saved.toggles).forEach(([key, val]) => {
                const input = document.querySelector(`[data-setting="${key}"]`);
                if (input) input.checked = val;
            });
        }
    } catch (_) { /* ignore */ }
}

function saveSettingsToStorage() {
    const toggles = {};
    document.querySelectorAll('[data-setting]').forEach(el => {
        toggles[el.dataset.setting] = el.checked;
    });
    const settings = {
        failedThreshold: document.getElementById('setting-failed-threshold')?.value,
        incidentThreshold: document.getElementById('setting-incident-threshold')?.value,
        refreshInterval: document.getElementById('setting-refresh-interval')?.value,
        toggles
    };
    localStorage.setItem('itds_settings', JSON.stringify(settings));
    appendAuditLog('Detection configuration saved locally');
    setupRefreshTimer();
}

function resetSettingsDefaults() {
    localStorage.removeItem('itds_settings');
    document.getElementById('setting-failed-threshold').value = 3;
    document.getElementById('setting-failed-threshold-val').textContent = '3';
    document.getElementById('setting-incident-threshold').value = 40;
    document.getElementById('setting-incident-threshold-val').textContent = '40';
    document.getElementById('setting-refresh-interval').value = 30;
    document.querySelectorAll('[data-setting]').forEach(el => { el.checked = true; });
    appendAuditLog('Settings reset to defaults');
    setupRefreshTimer();
}

function appendAuditLog(message) {
    const list = document.getElementById('audit-log-list');
    if (!list) return;
    const item = document.createElement('div');
    item.className = 'feed-item';
    item.innerHTML = `
        <div class="feed-icon normal"><i data-lucide="settings"></i></div>
        <div class="feed-body">
            <div class="feed-title">${message}</div>
            <div class="feed-meta">Configuration change</div>
        </div>
        <div class="feed-right">
            <div class="feed-time">${new Date().toLocaleTimeString()}</div>
        </div>`;
    list.prepend(item);
    refreshIcons();
}

function initSettingsPage() {
    document.getElementById('settings-last-scan').textContent = new Date().toLocaleTimeString();
    refreshIcons();
}

function setupRefreshTimer() {
    if (refreshTimer) clearInterval(refreshTimer);
    let interval = 30000;
    try {
        const saved = JSON.parse(localStorage.getItem('itds_settings') || '{}');
        if (saved.refreshInterval) interval = parseInt(saved.refreshInterval, 10) * 1000;
    } catch (_) { /* ignore */ }
    refreshTimer = setInterval(() => {
        const activePage = document.querySelector('.page.active');
        if (activePage && activePage.id === 'page-dashboard') {
            loadDashboard();
        }
    }, interval);
}

// --- Global Search ---

function initGlobalSearch() {
    const input = document.getElementById('global-search');
    if (!input) return;
    let debounce;
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const q = input.value.trim();
            if (!q) return;
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            document.querySelector('[data-page="users"]').classList.add('active');
            switchPage('users');
            document.getElementById('user-search').value = q;
            loadUsers();
        }
    });
    input.addEventListener('input', () => {
        clearTimeout(debounce);
        debounce = setTimeout(() => {
            const q = input.value.trim();
            if (q.length >= 2) {
                document.getElementById('user-search').value = q;
            }
        }, 300);
    });
}

// --- Event Listeners ---

function initFilters() {
    let debounce;
    document.getElementById('user-search').addEventListener('input', () => {
        clearTimeout(debounce);
        debounce = setTimeout(loadUsers, 300);
    });
    document.getElementById('user-risk-filter').addEventListener('change', loadUsers);

    document.getElementById('activity-search').addEventListener('input', () => {
        clearTimeout(debounce);
        debounce = setTimeout(loadActivity, 300);
    });
    document.getElementById('activity-status-filter').addEventListener('change', loadActivity);

    document.getElementById('incident-severity-filter').addEventListener('change', loadIncidents);
    document.getElementById('incident-status-filter').addEventListener('change', loadIncidents);
}

function initModals() {
    document.getElementById('close-user-modal').addEventListener('click', () => {
        document.getElementById('user-modal').classList.remove('open');
    });
    document.getElementById('close-incident-modal').addEventListener('click', () => {
        document.getElementById('incident-modal').classList.remove('open');
    });
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.classList.remove('open');
        });
    });
}

function initSettingsActions() {
    document.getElementById('settings-save-btn')?.addEventListener('click', saveSettingsToStorage);
    document.getElementById('settings-reset-btn')?.addEventListener('click', resetSettingsDefaults);
    document.getElementById('setting-refresh-interval')?.addEventListener('change', () => {
        saveSettingsToStorage();
    });
}

// --- Init ---

document.addEventListener('DOMContentLoaded', () => {
    refreshIcons();
    document.getElementById('analyst-initials').textContent = getAnalystInitials();

    initNavigation();
    initFilters();
    initModals();
    initSettingsTabs();
    initSettingsSliders();
    initSettingsActions();
    initGlobalSearch();
    loadSettingsFromStorage();

    loadDashboard();
    setupRefreshTimer();
});

// Expose for inline onclick handlers
window.showIncidentDetail = showIncidentDetail;
window.updateIncidentStatus = updateIncidentStatus;

// --- Tasks & Members Additions ---

document.addEventListener('DOMContentLoaded', () => {
    // Nav handling for Tasks page
    const navLinks = document.querySelectorAll('.nav-link');
    const pages = document.querySelectorAll('.page');
    
    // We already have a click handler for nav links in app.js, it might handle 'tasks' automatically if it just reads data-page.
    // Let's make sure tasks load when clicked
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            const pageId = e.currentTarget.getAttribute('data-page');
            if (pageId === 'tasks') {
                loadTasks();
            }
        });
    });

    // Modals
    const addMemberModal = document.getElementById('add-member-modal');
    const assignTaskModal = document.getElementById('assign-task-modal');
    
    document.getElementById('add-member-btn')?.addEventListener('click', () => {
        addMemberModal.classList.add('active');
    });
    document.getElementById('close-add-member-modal')?.addEventListener('click', () => {
        addMemberModal.classList.remove('active');
    });
    
    document.getElementById('assign-task-btn')?.addEventListener('click', () => {
        assignTaskModal.classList.add('active');
    });
    document.getElementById('close-assign-task-modal')?.addEventListener('click', () => {
        assignTaskModal.classList.remove('active');
    });

    // Forms
    document.getElementById('add-member-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const data = {
            username: document.getElementById('member-username').value,
            full_name: document.getElementById('member-fullname').value,
            department: document.getElementById('member-department').value,
            role: document.getElementById('member-role').value,
            email: document.getElementById('member-email').value,
            password: document.getElementById('member-password').value
        };
        try {
            const res = await fetch('/api/members', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (res.ok) {
                alert('Member created!');
                addMemberModal.classList.remove('active');
                e.target.reset();
            } else {
                const err = await res.json();
                alert('Error: ' + err.error);
            }
        } catch (err) {
            console.error(err);
        }
    });

    document.getElementById('assign-task-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const data = {
            user_id: parseInt(document.getElementById('task-user-id').value),
            title: document.getElementById('task-title').value,
            description: document.getElementById('task-description').value
        };
        try {
            const res = await fetch('/api/tasks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (res.ok) {
                alert('Task assigned!');
                assignTaskModal.classList.remove('active');
                e.target.reset();
                loadTasks();
            } else {
                const err = await res.json();
                alert('Error: ' + err.error);
            }
        } catch (err) {
            console.error(err);
        }
    });

    async function loadTasks() {
        const tbody = document.getElementById('tasks-body');
        if (!tbody) return;
        try {
            const res = await fetch('/api/tasks');
            const tasks = await res.json();
            tbody.innerHTML = '';
            if(tasks.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No tasks found</td></tr>';
                return;
            }
            tasks.forEach(task => {
                const statusClass = task.status === 'Completed' ? 'status-normal' : 'status-warning';
                tbody.innerHTML += `
                    <tr>
                        <td>${task.id}</td>
                        <td>${task.full_name} (${task.username})</td>
                        <td>${task.title}</td>
                        <td><span class="status-badge ${statusClass}">${task.status}</span></td>
                        <td>${task.created_at}</td>
                    </tr>
                `;
            });
        } catch (err) {
            console.error(err);
            tbody.innerHTML = '<tr><td colspan="5" class="loading-cell">Error loading tasks</td></tr>';
        }
    }
});
