/**
 * ThreatSim - Main Security Operations Console Application Logic
 * Dark Cherry-Red Cybersecurity Platform
 */

const API = '/api';
let charts = {};
let allEmployees = [];
let allScenarios = [];
let selectedScenarioKey = null;
let currentSubTab = 'alerts';
let lastSimulationResult = null;

// Cherry Red Theme Palette for Chart.js
const THEME = {
    accent: '#B5223E',
    cherryMain: '#8F1830',
    cherryHover: '#C92B49',
    success: '#10b981',
    warning: '#f59e0b',
    high: '#f97316',
    danger: '#B5223E',
    grid: 'rgba(50, 21, 28, 0.4)',
    tick: '#A9959A',
    legend: '#D4C3C7'
};

// ==========================================
// UTILITY & API HELPERS
// ==========================================

async function fetchAPI(endpoint, options = {}) {
    const res = await fetch(`${API}${endpoint}`, options);
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
}

function refreshIcons() {
    if (typeof lucide !== 'undefined') lucide.createIcons();
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
    if (!type) return '--';
    return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function getRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
}

function riskBadge(score) {
    const level = getRiskLevel(score);
    return `<span class="risk-badge ${level}">${level.toUpperCase()}</span>`;
}

function statusBadge(status) {
    const s = status || 'normal';
    return `<span class="status-badge ${s}">${s}</span>`;
}

function destroyChart(id) {
    if (charts[id]) {
        charts[id].destroy();
        delete charts[id];
    }
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

// Modal management
function openModal(id) {
    const modal = document.getElementById(id);
    if (modal) {
        modal.classList.add('active');
        modal.classList.add('open');
        refreshIcons();
    }
}

function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) {
        modal.classList.remove('active');
        modal.classList.remove('open');
    }
}

// ==========================================
// NAVIGATION & PAGE ROUTING
// ==========================================

function initNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.dataset.page;
            navigateToPage(page);
        });
    });

    // Mobile nav toggle
    document.getElementById('mobile-toggle')?.addEventListener('click', () => {
        document.getElementById('main-sidebar')?.classList.toggle('open');
    });

    // Theme toggle
    document.getElementById('theme-toggle')?.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', next);
        document.body.className = next === 'light' ? 'light-mode' : '';
    });
}

function navigateToPage(page, subTab = null) {
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));

    const activeLink = document.querySelector(`.nav-link[data-page="${page}"]`);
    const activePage = document.getElementById(`page-${page}`);

    if (activeLink) activeLink.classList.add('active');
    if (activePage) activePage.classList.add('active');

    // Close mobile sidebar if open
    document.getElementById('main-sidebar')?.classList.remove('open');

    switch (page) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'employees':
            loadEmployees();
            break;
        case 'simulator':
            loadSimulator();
            break;
        case 'alerts':
            loadAlertsAndActivity();
            if (subTab) switchAlertSubTab(subTab === 'activity-tab' ? 'activity' : 'alerts');
            break;
        case 'reports':
            loadReports();
            break;
        case 'settings':
            refreshIcons();
            break;
    }

    refreshIcons();
}

// ==========================================
// 1. DASHBOARD
// ==========================================

async function loadDashboard() {
    try {
        const [stats, threatData, activities, recentAlerts] = await Promise.all([
            fetchAPI('/dashboard'),
            fetchAPI('/threat-analysis'),
            fetchAPI('/activity?limit=6'),
            fetchAPI('/incidents')
        ]);

        // 4 KPI Summary Cards
        document.getElementById('stat-total-employees').textContent = stats.total_employees ?? stats.total_users ?? 0;
        document.getElementById('stat-active-alerts').textContent = stats.active_alerts ?? stats.open_incidents ?? 0;
        document.getElementById('stat-high-risk-employees').textContent = stats.high_risk_employees ?? stats.high_risk_users ?? 0;
        document.getElementById('stat-total-simulations').textContent = stats.total_simulations ?? 0;
        
        // System status
        document.getElementById('system-status').textContent = stats.system_status || 'Operational';
        document.getElementById('dashboard-timestamp').textContent = 'Updated ' + new Date().toLocaleTimeString();

        // Security Posture Ring & Bar
        const avgScore = stats.avg_risk_score || 0;
        const threatLevel = stats.threat_level || 'LOW';
        
        document.getElementById('threat-level').textContent = threatLevel;
        document.getElementById('posture-risk-score').textContent = `${Math.round(avgScore)} / 100`;
        document.getElementById('posture-risk-bar').style.width = `${Math.min(avgScore, 100)}%`;

        const ring = document.getElementById('risk-ring-fill');
        if (ring) {
            const pct = Math.min(avgScore / 100, 1);
            const circumference = 326.7;
            ring.style.strokeDashoffset = circumference - (pct * circumference);
            ring.style.stroke = threatLevel === 'CRITICAL' ? THEME.danger : threatLevel === 'HIGH' ? THEME.high : threatLevel === 'MEDIUM' ? THEME.warning : THEME.success;
        }

        // Render Dashboard Charts
        renderDashboardRiskDistChart(threatData.risk_distribution);
        renderDashboardAnomalyChart(threatData.threats_timeline);

        // Render Dashboard Recent Alerts
        renderDashboardRecentAlerts(recentAlerts.slice(0, 5));

        // Render Dashboard Recent Activities
        renderDashboardRecentActivities(activities);

        refreshIcons();
    } catch (err) {
        console.error('Failed to load dashboard:', err);
    }
}

function renderDashboardRiskDistChart(riskDist) {
    const canvas = document.getElementById('chart-dashboard-risk-dist');
    if (!canvas) return;
    destroyChart('chart-dashboard-risk-dist');

    const rd = riskDist || { low: 0, medium: 0, high: 0, critical: 0 };
    charts['chart-dashboard-risk-dist'] = new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['Low (0-29)', 'Medium (30-59)', 'High (60-79)', 'Critical (80+)'],
            datasets: [{
                data: [rd.low, rd.medium, rd.high, rd.critical],
                backgroundColor: [THEME.success, THEME.warning, THEME.high, THEME.danger],
                borderColor: '#160D10',
                borderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: THEME.legend, font: { size: 10 }, boxWidth: 10, padding: 8 }
                }
            }
        }
    });
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

    const grad = ctx.createLinearGradient(0, 0, 0, 160);
    grad.addColorStop(0, THEME.cherryHover);
    grad.addColorStop(1, 'rgba(143, 24, 48, 0.2)');

    charts['chart-dashboard-anomaly'] = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels.length ? labels : ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [{
                label: 'Threat Events',
                data: data.length ? data : [0, 0, 0, 0, 0, 0, 0],
                backgroundColor: grad,
                borderRadius: 4
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

function renderDashboardRecentAlerts(alerts) {
    const tbody = document.getElementById('dashboard-recent-alerts');
    if (!tbody) return;

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-cell">No recent alerts recorded</td></tr>';
        return;
    }

    tbody.innerHTML = alerts.map(a => `
        <tr class="clickable" onclick="showIncidentDetail(${a.id})">
            <td><strong>${a.title}</strong></td>
            <td>${a.full_name || a.username}</td>
            <td><span class="risk-badge ${a.severity.toLowerCase()}">${a.severity}</span></td>
            <td><span class="status-badge ${a.status.toLowerCase()}">${a.status}</span></td>
        </tr>
    `).join('');
}

function renderDashboardRecentActivities(activities) {
    const container = document.getElementById('dashboard-recent-activity');
    if (!container) return;

    if (!activities || activities.length === 0) {
        container.innerHTML = '<div class="empty-cell">No recent activities logged</div>';
        return;
    }

    container.innerHTML = activities.map(a => {
        const initials = (a.username || '??').slice(0, 2).toUpperCase();
        return `
            <div class="feed-item">
                <div class="feed-icon">${initials}</div>
                <div class="feed-body">
                    <div class="feed-title">${a.full_name || a.username} &middot; ${formatActivityType(a.activity_type)}</div>
                    <div class="feed-meta">${a.description} &middot; ${a.ip_address || '10.0.1.x'}</div>
                </div>
                <div class="feed-right">
                    ${riskBadge(a.risk_score)}
                    <div class="feed-time">${formatTime(a.timestamp)}</div>
                </div>
            </div>
        `;
    }).join('');
}

// ==========================================
// 2. EMPLOYEES DIRECTORY
// ==========================================

async function loadEmployees() {
    const search = document.getElementById('employee-search')?.value.trim() || '';
    const department = document.getElementById('employee-department-filter')?.value || '';
    const risk = document.getElementById('employee-risk-filter')?.value || '';
    const status = document.getElementById('employee-status-filter')?.value || '';

    let url = '/users?';
    if (search) url += `search=${encodeURIComponent(search)}&`;
    if (department) url += `department=${encodeURIComponent(department)}&`;
    if (risk) url += `risk=${risk}&`;
    if (status) url += `status=${status}&`;

    try {
        const users = await fetchAPI(url);
        allEmployees = users;
        populateDepartmentFilter(users);

        const tbody = document.getElementById('employees-table-body');
        if (!tbody) return;

        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="empty-cell">No employees match criteria</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(u => {
            const empId = u.emp_id || `EMP-${u.id}`;
            const isActive = u.status === 'active';
            const statusClass = isActive ? 'active' : 'disabled';
            const toggleStatusBtn = isActive
                ? `<button class="btn btn-sm" style="color:var(--text-muted);" title="Disable Account" onclick="event.stopPropagation(); toggleEmployeeStatus(${u.id}, 'disabled')">Disable</button>`
                : `<button class="btn btn-sm btn-primary" title="Enable Account" onclick="event.stopPropagation(); toggleEmployeeStatus(${u.id}, 'active')">Enable</button>`;

            return `
                <tr class="clickable" onclick="showEmployeeDetails(${u.id})">
                    <td>
                        <div style="font-weight: 600; color: var(--text-primary);">${u.full_name}</div>
                        <div style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">${u.username}</div>
                    </td>
                    <td style="font-family: var(--font-mono); font-weight: 500;">${empId}</td>
                    <td>${u.department}</td>
                    <td>${u.role}</td>
                    <td><span class="status-badge ${statusClass}">${u.status}</span></td>
                    <td>${riskBadge(u.risk_score)} <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">(${u.risk_score})</span></td>
                    <td><span style="font-weight: 600; color: ${u.active_alerts > 0 ? 'var(--cherry-hover)' : 'var(--text-muted)'};">${u.active_alerts || 0}</span></td>
                    <td>${u.simulation_count || 0}</td>
                    <td>
                        <div style="display: flex; gap: 6px;" onclick="event.stopPropagation()">
                            <button class="btn btn-sm" onclick="showEmployeeDetails(${u.id})">View</button>
                            <button class="btn btn-sm" onclick="openEditEmployeeModal(${u.id})">Edit</button>
                            ${toggleStatusBtn}
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        refreshIcons();
    } catch (err) {
        console.error('Failed to load employees:', err);
    }
}

function populateDepartmentFilter(users) {
    const select = document.getElementById('employee-department-filter');
    if (!select || select.options.length > 1) return;

    const depts = Array.from(new Set(users.map(u => u.department).filter(Boolean))).sort();
    depts.forEach(d => {
        const opt = document.createElement('option');
        opt.value = d;
        opt.textContent = d;
        select.appendChild(opt);
    });
}

async function toggleEmployeeStatus(userId, newStatus) {
    try {
        await fetchAPI(`/employees/${userId}/status`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus })
        });
        loadEmployees();
        loadDashboard();
    } catch (err) {
        alert('Failed to update employee status: ' + err.message);
    }
}

async function showEmployeeDetails(userId) {
    try {
        const u = await fetchAPI(`/users/${userId}`);
        document.getElementById('modal-emp-name').textContent = `${u.full_name} (${u.emp_id || 'EMP-' + u.id})`;

        const container = document.getElementById('employee-detail-modal-body');
        
        let html = `
            <div class="detail-grid">
                <div class="detail-item"><span class="detail-label">Full Name</span><span class="detail-value">${u.full_name}</span></div>
                <div class="detail-item"><span class="detail-label">Employee ID</span><span class="detail-value">${u.emp_id || 'EMP-' + u.id}</span></div>
                <div class="detail-item"><span class="detail-label">Username</span><span class="detail-value">${u.username}</span></div>
                <div class="detail-item"><span class="detail-label">Department</span><span class="detail-value">${u.department}</span></div>
                <div class="detail-item"><span class="detail-label">Role</span><span class="detail-value">${u.role}</span></div>
                <div class="detail-item"><span class="detail-label">Account Status</span><span class="detail-value"><span class="status-badge ${u.status}">${u.status}</span></span></div>
                <div class="detail-item"><span class="detail-label">Corporate Email</span><span class="detail-value">${u.email}</span></div>
                <div class="detail-item"><span class="detail-label">Current Risk Score</span><span class="detail-value">${riskBadge(u.risk_score)} (${u.risk_score} / 100)</span></div>
            </div>

            <div style="display: flex; gap: 10px; margin-bottom: 20px;">
                <button class="btn btn-primary" onclick="closeModal('employee-detail-modal'); launchSimulationForEmployee(${u.id});">
                    <i data-lucide="crosshair"></i> Run Threat Simulation on ${u.full_name}
                </button>
                <button class="btn" onclick="openEditEmployeeModal(${u.id})">
                    <i data-lucide="edit"></i> Edit Record
                </button>
            </div>
        `;

        // Active Alerts section
        if (u.incidents && u.incidents.length > 0) {
            html += `
                <div style="margin-top: 18px;">
                    <h4 style="font-size: 0.9rem; color: var(--text-primary); margin-bottom: 8px;">Security Alerts &amp; Incidents (${u.incidents.length})</h4>
                    <table class="data-table">
                        <thead><tr><th>Alert</th><th>Threat Vector</th><th>Severity</th><th>Status</th><th>Detected</th></tr></thead>
                        <tbody>
                            ${u.incidents.map(i => `
                                <tr>
                                    <td><strong>${i.title}</strong></td>
                                    <td>${i.incident_type}</td>
                                    <td><span class="risk-badge ${i.severity.toLowerCase()}">${i.severity}</span></td>
                                    <td><span class="status-badge ${i.status.toLowerCase()}">${i.status}</span></td>
                                    <td>${formatTime(i.detected_at)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }

        // Simulation History
        if (u.simulations && u.simulations.length > 0) {
            html += `
                <div style="margin-top: 18px;">
                    <h4 style="font-size: 0.9rem; color: var(--text-primary); margin-bottom: 8px;">Simulation Execution History (${u.simulations.length})</h4>
                    <table class="data-table">
                        <thead><tr><th>Scenario</th><th>Risk Score</th><th>Level</th><th>Alert Created</th><th>Executed</th></tr></thead>
                        <tbody>
                            ${u.simulations.map(s => `
                                <tr>
                                    <td><strong>${s.scenario_name}</strong></td>
                                    <td>${s.risk_score}</td>
                                    <td><span class="risk-badge ${s.risk_level.toLowerCase()}">${s.risk_level}</span></td>
                                    <td>${s.alert_created ? '<span class="status-badge active">Yes</span>' : '<span class="status-badge normal">Log Only</span>'}</td>
                                    <td>${formatTime(s.created_at)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }

        // Recent Activity
        if (u.recent_activities && u.recent_activities.length > 0) {
            html += `
                <div style="margin-top: 18px;">
                    <h4 style="font-size: 0.9rem; color: var(--text-primary); margin-bottom: 8px;">Recent Activity Logs (Last ${u.recent_activities.length})</h4>
                    <table class="data-table">
                        <thead><tr><th>Activity</th><th>Description</th><th>IP Address</th><th>Risk</th><th>Time</th></tr></thead>
                        <tbody>
                            ${u.recent_activities.slice(0, 8).map(a => `
                                <tr>
                                    <td><strong>${formatActivityType(a.activity_type)}</strong></td>
                                    <td>${a.description}</td>
                                    <td>${a.ip_address || '--'}</td>
                                    <td>${riskBadge(a.risk_score)}</td>
                                    <td>${formatTime(a.timestamp)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }

        container.innerHTML = html;
        openModal('employee-detail-modal');
        refreshIcons();
    } catch (err) {
        alert('Failed to load employee details: ' + err.message);
    }
}

function openEditEmployeeModal(userId) {
    const u = allEmployees.find(e => e.id === userId);
    if (!u) return;

    document.getElementById('edit-emp-user-id').value = u.id;
    document.getElementById('edit-emp-fullname').value = u.full_name;
    document.getElementById('edit-emp-id').value = u.emp_id || `EMP-${u.id}`;
    document.getElementById('edit-emp-department').value = u.department;
    document.getElementById('edit-emp-role').value = u.role;
    document.getElementById('edit-emp-status').value = u.status;
    document.getElementById('edit-emp-password').value = '';

    openModal('edit-employee-modal');
}

// ==========================================
// 3. THREAT SIMULATOR (CORE FEATURE)
// ==========================================

async function loadSimulator() {
    try {
        const [scenarios, users] = await Promise.all([
            fetchAPI('/scenarios'),
            fetchAPI('/users')
        ]);

        allScenarios = scenarios;
        allEmployees = users;

        // Populate Target Employee Dropdown
        const targetSelect = document.getElementById('sim-target-employee');
        if (targetSelect) {
            targetSelect.innerHTML = '<option value="">Select target employee…</option>' +
                users.map(u => `
                    <option value="${u.id}">${u.full_name} (${u.emp_id || 'EMP-' + u.id}) — ${u.department} [Risk: ${u.risk_score}]</option>
                `).join('');
        }

        // Render Scenarios Grid (7 required scenarios)
        const grid = document.getElementById('sim-scenarios-grid');
        if (grid) {
            grid.innerHTML = scenarios.map((s, idx) => {
                const isSelected = selectedScenarioKey === s.key || (idx === 0 && !selectedScenarioKey);
                if (isSelected) selectedScenarioKey = s.key;

                return `
                    <div class="scenario-card ${isSelected ? 'selected' : ''}" data-scenario-key="${s.key}" onclick="selectScenario('${s.key}')">
                        <div class="scenario-card-header">
                            <span class="scenario-card-title">${s.name}</span>
                            <span class="risk-badge ${s.severity.toLowerCase()}">${s.severity}</span>
                        </div>
                        <div style="font-size: 0.72rem; color: var(--cherry-hover); font-weight: 500;">${s.threat_vector}</div>
                        <div class="scenario-card-desc">${s.description}</div>
                    </div>
                `;
            }).join('');
        }

        refreshIcons();
    } catch (err) {
        console.error('Failed to load simulator:', err);
    }
}

function selectScenario(key) {
    selectedScenarioKey = key;
    document.querySelectorAll('.scenario-card').forEach(c => {
        c.classList.toggle('selected', c.dataset.scenarioKey === key);
    });
}

function launchSimulationForEmployee(userId) {
    navigateToPage('simulator');
    setTimeout(() => {
        const select = document.getElementById('sim-target-employee');
        if (select) {
            select.value = userId;
            triggerEmployeeMetaUpdate(userId);
        }
    }, 200);
}

function triggerEmployeeMetaUpdate(userId) {
    const u = allEmployees.find(e => e.id == userId);
    const metaEl = document.getElementById('sim-employee-meta');
    if (!metaEl) return;

    if (u) {
        metaEl.style.display = 'block';
        metaEl.innerHTML = `Subject: <strong>${u.full_name}</strong> &middot; Current Risk: <strong>${u.risk_score}/100</strong> &middot; Status: <strong>${u.status}</strong>`;
    } else {
        metaEl.style.display = 'none';
    }
}

async function runSimulation() {
    const userId = document.getElementById('sim-target-employee')?.value;
    if (!userId) {
        alert('Please select an employee subject first.');
        return;
    }

    if (!selectedScenarioKey) {
        alert('Please select a threat scenario to simulate.');
        return;
    }

    const autoAlert = document.getElementById('sim-auto-alert-toggle')?.checked ?? true;
    const btn = document.getElementById('run-simulation-btn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i data-lucide="loader-2"></i> Analyzing threat telemetry…';
        refreshIcons();
    }

    try {
        const result = await fetchAPI('/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: parseInt(userId),
                scenario_key: selectedScenarioKey,
                create_alert: autoAlert
            })
        });

        lastSimulationResult = result;
        displaySimulationResult(result);
    } catch (err) {
        alert('Simulation failed: ' + err.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i data-lucide="play"></i> Execute Threat Simulation';
            refreshIcons();
        }
    }
}

function displaySimulationResult(res) {
    document.getElementById('simulation-empty-state').style.display = 'none';
    const activeResults = document.getElementById('simulation-active-results');
    activeResults.style.display = 'block';

    document.getElementById('sim-result-scenario-name').textContent = res.scenario_name;
    document.getElementById('sim-result-vector').textContent = res.threat_vector;
    
    const badge = document.getElementById('sim-result-badge');
    badge.textContent = res.risk_level;
    badge.className = `risk-badge ${res.risk_level.toLowerCase()}`;

    document.getElementById('sim-result-score').textContent = res.risk_score;
    document.getElementById('sim-result-employee-display').textContent = `${res.employee_name} (${res.employee_id})`;

    const noteEl = document.getElementById('sim-result-status-note');
    if (res.alert_created && res.alert_id) {
        noteEl.innerHTML = `<i data-lucide="check-circle" style="width: 14px; height: 14px; display: inline-block; vertical-align: -2px;"></i> Security Alert #${res.alert_id} created and dispatched to Alerts &amp; Activity console`;
        noteEl.style.color = 'var(--risk-low)';
    } else {
        noteEl.innerHTML = '<i data-lucide="info" style="width: 14px; height: 14px; display: inline-block; vertical-align: -2px;"></i> Telemetry logged into Activity Stream without alert escalation';
        noteEl.style.color = 'var(--text-muted)';
    }

    // Indicators list
    const indicatorsList = document.getElementById('sim-result-indicators');
    indicatorsList.innerHTML = (res.indicators || []).map(ind => `
        <li><i data-lucide="alert-octagon" style="width: 14px; height: 14px; color: var(--cherry-hover); flex-shrink: 0; margin-top: 2px;"></i> ${ind}</li>
    `).join('');

    document.getElementById('sim-result-recommendation').textContent = res.recommended_action;

    // View in alerts button handler
    const viewAlertBtn = document.getElementById('sim-view-in-alerts-btn');
    if (viewAlertBtn) {
        viewAlertBtn.onclick = () => {
            navigateToPage('alerts');
            if (res.alert_id) {
                setTimeout(() => showIncidentDetail(res.alert_id), 300);
            }
        };
    }

    refreshIcons();
}

function resetSimulator() {
    document.getElementById('simulation-active-results').style.display = 'none';
    document.getElementById('simulation-empty-state').style.display = 'block';
    selectedScenarioKey = 'normal_behaviour';
    selectScenario('normal_behaviour');
}

// ==========================================
// 4. ALERTS & ACTIVITY (MERGED MODULE)
// ==========================================

function switchAlertSubTab(tab) {
    currentSubTab = tab;
    document.getElementById('tab-alerts-btn')?.classList.toggle('active', tab === 'alerts');
    document.getElementById('tab-activity-btn')?.classList.toggle('active', tab === 'activity');

    document.getElementById('subtab-alerts').style.display = tab === 'alerts' ? 'block' : 'none';
    document.getElementById('subtab-activity').style.display = tab === 'activity' ? 'block' : 'none';

    if (tab === 'alerts') loadAlertsList();
    if (tab === 'activity') loadActivityStream();
}

async function loadAlertsAndActivity() {
    if (currentSubTab === 'alerts') await loadAlertsList();
    else await loadActivityStream();
}

async function loadAlertsList() {
    const search = document.getElementById('alerts-search')?.value.trim() || '';
    const severity = document.getElementById('alerts-severity-filter')?.value || '';
    const status = document.getElementById('alerts-status-filter')?.value || '';

    let url = '/incidents?';
    if (severity) url += `severity=${severity}&`;
    if (status) url += `status=${status}&`;

    try {
        const incidents = await fetchAPI(url);
        
        // Update count badge
        const countBadge = document.getElementById('alerts-tab-count');
        if (countBadge) countBadge.textContent = incidents.length;

        const tbody = document.getElementById('alerts-table-body');
        if (!tbody) return;

        let filtered = incidents;
        if (search) {
            const q = search.toLowerCase();
            filtered = incidents.filter(i => 
                (i.title && i.title.toLowerCase().includes(q)) ||
                (i.username && i.username.toLowerCase().includes(q)) ||
                (i.full_name && i.full_name.toLowerCase().includes(q)) ||
                (i.incident_type && i.incident_type.toLowerCase().includes(q))
            );
        }

        if (filtered.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="empty-cell">No security alerts match filters</td></tr>';
            return;
        }

        tbody.innerHTML = filtered.map(i => `
            <tr class="clickable" onclick="showIncidentDetail(${i.id})">
                <td style="font-family: var(--font-mono);">#${i.id}</td>
                <td><strong>${i.title}</strong></td>
                <td>${i.full_name || i.username}</td>
                <td>${i.incident_type}</td>
                <td><span class="risk-badge ${i.severity.toLowerCase()}">${i.severity}</span></td>
                <td>${i.risk_score}</td>
                <td>${formatTime(i.detected_at)}</td>
                <td><span class="status-badge ${i.status.toLowerCase()}">${i.status}</span></td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); showIncidentDetail(${i.id})">
                        Investigate
                    </button>
                </td>
            </tr>
        `).join('');

        refreshIcons();
    } catch (err) {
        console.error('Failed to load alerts list:', err);
    }
}

async function loadActivityStream() {
    const search = document.getElementById('activity-search')?.value.trim() || '';
    const status = document.getElementById('activity-status-filter')?.value || '';

    let url = '/activity?limit=50&';
    if (search) url += `search=${encodeURIComponent(search)}&`;
    if (status) url += `status=${status}&`;

    try {
        const acts = await fetchAPI(url);
        const tbody = document.getElementById('activity-table-body');
        if (!tbody) return;

        if (acts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="empty-cell">No activity records logged</td></tr>';
            return;
        }

        tbody.innerHTML = acts.map(a => `
            <tr>
                <td><strong>${a.full_name || a.username}</strong></td>
                <td>${formatActivityType(a.activity_type)}</td>
                <td>${a.description}</td>
                <td style="font-family: var(--font-mono); font-size: 0.8rem;">${a.ip_address || '--'}</td>
                <td>${a.device || 'Workstation'}</td>
                <td>${riskBadge(a.risk_score)}</td>
                <td>${formatTime(a.timestamp)}</td>
                <td><span class="status-badge ${a.status}">${a.status}</span></td>
            </tr>
        `).join('');

        refreshIcons();
    } catch (err) {
        console.error('Failed to load activity stream:', err);
    }
}

// Alert Investigation & Embedded Actions (Absorbs Tasks!)
async function showIncidentDetail(alertId) {
    try {
        const inc = await fetchAPI(`/incidents/${alertId}`);
        document.getElementById('modal-alert-title').textContent = `Alert #${inc.id} — ${inc.title}`;

        const container = document.getElementById('alert-detail-modal-body');
        container.innerHTML = `
            <div class="detail-grid">
                <div class="detail-item"><span class="detail-label">Alert ID</span><span class="detail-value">#${inc.id}</span></div>
                <div class="detail-item"><span class="detail-label">Subject</span><span class="detail-value">${inc.full_name} (${inc.username})</span></div>
                <div class="detail-item"><span class="detail-label">Department</span><span class="detail-value">${inc.department || '--'}</span></div>
                <div class="detail-item"><span class="detail-label">Threat Vector</span><span class="detail-value">${inc.incident_type}</span></div>
                <div class="detail-item"><span class="detail-label">Calculated Risk</span><span class="detail-value">${riskBadge(inc.risk_score)} (${inc.risk_score})</span></div>
                <div class="detail-item"><span class="detail-label">Current Status</span><span class="detail-value"><span class="status-badge ${inc.status.toLowerCase()}">${inc.status}</span></span></div>
            </div>

            <div style="margin-bottom: 18px; padding: 14px; background: var(--bg-input); border-radius: var(--radius-sm); border: 1px solid var(--border-color);">
                <h4 style="font-size: 0.82rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Incident Evidence &amp; Description</h4>
                <p style="font-size: 0.86rem; color: var(--text-primary); line-height: 1.5;">${inc.description}</p>
            </div>

            <!-- EMBEDDED TASK ACTIONS (Replacing standalone tasks) -->
            <div style="border-top: 1px solid var(--border-color); padding-top: 16px;">
                <h4 style="font-size: 0.88rem; color: var(--text-primary); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                    <i data-lucide="check-square" style="width: 16px; height: 16px; color: var(--cherry-accent);"></i>
                    Embedded Containment &amp; Investigation Actions
                </h4>
                
                <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px;">
                    <button class="btn btn-sm" onclick="triggerAlertAction(${inc.id}, 'review_activity')">
                        <i data-lucide="scroll-text"></i> Review Employee Activity
                    </button>
                    <button class="btn btn-sm" onclick="triggerAlertAction(${inc.id}, 'verify_usb')">
                        <i data-lucide="usb"></i> Verify USB Device
                    </button>
                    <button class="btn btn-sm" onclick="triggerAlertAction(${inc.id}, 'check_files')">
                        <i data-lucide="file-search"></i> Check Accessed Files
                    </button>
                    <button class="btn btn-sm" style="color: var(--risk-med);" onclick="triggerAlertAction(${inc.id}, 'mark_reviewed')">
                        <i data-lucide="eye"></i> Mark as Reviewed
                    </button>
                    <button class="btn btn-sm btn-primary" onclick="triggerAlertAction(${inc.id}, 'resolve_alert')">
                        <i data-lucide="check-circle"></i> Resolve Alert
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="triggerAlertAction(${inc.id}, 'quarantine')">
                        <i data-lucide="lock"></i> Quarantine Account
                    </button>
                </div>

                <div id="alert-action-output-box" style="display: none; padding: 14px; background: var(--bg-input); border-radius: var(--radius-sm); border: 1px solid var(--border-highlight);">
                    <!-- Dynamic action output -->
                </div>
            </div>
        `;

        openModal('alert-detail-modal');
        refreshIcons();
    } catch (err) {
        alert('Failed to load incident detail: ' + err.message);
    }
}

async function triggerAlertAction(alertId, actionType) {
    const box = document.getElementById('alert-action-output-box');
    if (!box) return;

    box.style.display = 'block';
    box.innerHTML = '<div class="loading-cell" style="padding: 1rem;">Executing operational action…</div>';

    try {
        const res = await fetchAPI(`/alerts/${alertId}/action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: actionType })
        });

        let content = `<div style="font-weight: 600; color: var(--cherry-hover); margin-bottom: 8px;">${res.message || 'Action executed successfully.'}</div>`;

        if (res.activities && res.activities.length) {
            content += `
                <table class="data-table" style="margin-top: 8px;">
                    <thead><tr><th>Activity</th><th>Description</th><th>Risk</th><th>Time</th></tr></thead>
                    <tbody>
                        ${res.activities.slice(0, 6).map(a => `
                            <tr>
                                <td>${formatActivityType(a.activity_type)}</td>
                                <td>${a.description}</td>
                                <td>${riskBadge(a.risk_score)}</td>
                                <td>${formatTime(a.timestamp)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }

        if (res.accessed_files && res.accessed_files.length) {
            content += `
                <table class="data-table" style="margin-top: 8px;">
                    <thead><tr><th>Event</th><th>Resource Description</th><th>Time</th></tr></thead>
                    <tbody>
                        ${res.accessed_files.map(f => `
                            <tr>
                                <td>${formatActivityType(f.activity_type)}</td>
                                <td>${f.description}</td>
                                <td>${formatTime(f.timestamp)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }

        box.innerHTML = content;
        loadAlertsList();
        loadDashboard();
        refreshIcons();
    } catch (err) {
        box.innerHTML = `<div style="color: var(--risk-crit);">Action failed: ${err.message}</div>`;
    }
}

// ==========================================
// 5. REPORTS
// ==========================================

async function loadReports() {
    try {
        const summary = await fetchAPI('/reports/summary');

        document.getElementById('report-total-employees').textContent = summary.total_employees;
        document.getElementById('report-total-simulations').textContent = summary.total_simulations;
        document.getElementById('report-total-alerts').textContent = summary.total_alerts;

        const critCount = (summary.events_by_severity?.CRITICAL || 0) + (summary.events_by_severity?.HIGH || 0);
        document.getElementById('report-critical-events').textContent = critCount;

        // Most simulated scenario
        document.getElementById('report-most-sim-name').textContent = summary.most_simulated_scenario?.scenario_name || 'None';
        document.getElementById('report-most-sim-count').textContent = summary.most_simulated_scenario?.count || 0;

        // Breakdown list
        const breakdownList = document.getElementById('report-simulations-breakdown-list');
        if (breakdownList && summary.simulations_breakdown) {
            breakdownList.innerHTML = summary.simulations_breakdown.map(b => `
                <div style="display: flex; justify-content: space-between; font-size: 0.8rem; padding: 4px 8px; background: var(--bg-card); border-radius: 4px;">
                    <span>${b.scenario_name}</span>
                    <strong style="color: var(--cherry-hover); font-family: var(--font-mono);">${b.count}</strong>
                </div>
            `).join('');
        }

        // Render Report Risk Chart
        renderReportsRiskChart(summary.risk_distribution);

        // Highest-Risk Employees ranking table
        const tbody = document.getElementById('report-top-risky-body');
        if (tbody && summary.highest_risk_employees) {
            tbody.innerHTML = summary.highest_risk_employees.map((e, idx) => `
                <tr>
                    <td style="font-family: var(--font-mono); font-weight: 700; color: var(--cherry-hover);">#${idx + 1}</td>
                    <td><strong>${e.full_name}</strong> <span style="font-size: 0.75rem; color: var(--text-muted);">(${e.username})</span></td>
                    <td style="font-family: var(--font-mono);">${e.emp_id || 'EMP-' + e.id}</td>
                    <td>${e.department}</td>
                    <td>${e.role}</td>
                    <td>${riskBadge(e.risk_score)} (${e.risk_score})</td>
                    <td><span class="status-badge ${e.status}">${e.status}</span></td>
                </tr>
            `).join('');
        }

        refreshIcons();
    } catch (err) {
        console.error('Failed to load reports:', err);
    }
}

function renderReportsRiskChart(riskDist) {
    const canvas = document.getElementById('chart-reports-risk-dist');
    if (!canvas) return;
    destroyChart('chart-reports-risk-dist');

    const rd = riskDist || { low: 0, medium: 0, high: 0, critical: 0 };
    charts['chart-reports-risk-dist'] = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: ['Low (0-29)', 'Medium (30-59)', 'High (60-79)', 'Critical (80+)'],
            datasets: [{
                label: 'Employee Distribution',
                data: [rd.low, rd.medium, rd.high, rd.critical],
                backgroundColor: [THEME.success, THEME.warning, THEME.high, THEME.danger],
                borderRadius: 6
            }]
        },
        options: {
            ...chartDefaults(),
            plugins: { legend: { display: false } }
        }
    });
}

async function generateExecutiveReport() {
    try {
        const [summary, stats] = await Promise.all([
            fetchAPI('/reports/summary'),
            fetchAPI('/dashboard')
        ]);

        const container = document.getElementById('report-preview-modal-body');
        container.innerHTML = `
            <div style="padding: 10px; font-family: var(--font-sans);">
                <div style="border-bottom: 2px solid var(--border-cherry); padding-bottom: 12px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: flex-end;">
                    <div>
                        <h2 style="font-size: 1.4rem; color: var(--cherry-hover); margin-bottom: 2px;">ThreatSim Insider Threat Executive Report</h2>
                        <span style="font-size: 0.8rem; color: var(--text-muted);">Confidential &middot; Security Operations Center Briefing</span>
                    </div>
                    <div style="font-size: 0.78rem; color: var(--text-muted); text-align: right; font-family: var(--font-mono);">
                        Generated: ${new Date().toLocaleString()}<br>
                        Status: <strong>${stats.system_status}</strong>
                    </div>
                </div>

                <div class="summary-cards" style="margin-bottom: 20px;">
                    <div class="stat-card" style="padding: 12px;">
                        <div class="stat-body">
                            <span class="stat-label">Monitored Staff</span>
                            <span class="stat-value" style="font-size: 1.3rem;">${summary.total_employees}</span>
                        </div>
                    </div>
                    <div class="stat-card" style="padding: 12px;">
                        <div class="stat-body">
                            <span class="stat-label">Total Alerts</span>
                            <span class="stat-value danger" style="font-size: 1.3rem;">${summary.total_alerts}</span>
                        </div>
                    </div>
                    <div class="stat-card" style="padding: 12px;">
                        <div class="stat-body">
                            <span class="stat-label">Simulations</span>
                            <span class="stat-value" style="font-size: 1.3rem;">${summary.total_simulations}</span>
                        </div>
                    </div>
                    <div class="stat-card" style="padding: 12px;">
                        <div class="stat-body">
                            <span class="stat-label">Global Risk</span>
                            <span class="stat-value warning" style="font-size: 1.3rem;">${stats.avg_risk_score} / 100</span>
                        </div>
                    </div>
                </div>

                <div style="margin-bottom: 18px;">
                    <h4 style="font-size: 0.92rem; color: var(--text-primary); margin-bottom: 8px;">Top Identified Risk Subjects</h4>
                    <table class="data-table">
                        <thead><tr><th>Rank</th><th>Employee</th><th>ID</th><th>Department</th><th>Risk</th></tr></thead>
                        <tbody>
                            ${summary.highest_risk_employees.slice(0, 5).map((e, idx) => `
                                <tr>
                                    <td>#${idx + 1}</td>
                                    <td><strong>${e.full_name}</strong></td>
                                    <td>${e.emp_id}</td>
                                    <td>${e.department}</td>
                                    <td>${riskBadge(e.risk_score)} (${e.risk_score})</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>

                <div style="display: flex; gap: 10px; margin-top: 24px;">
                    <button class="btn btn-primary" onclick="window.print()">
                        <i data-lucide="printer"></i> Print / Save PDF
                    </button>
                    <button class="btn" onclick="closeModal('report-preview-modal')">Close</button>
                </div>
            </div>
        `;

        openModal('report-preview-modal');
        refreshIcons();
    } catch (err) {
        alert('Failed to generate report: ' + err.message);
    }
}

// ==========================================
// FORM SUBMISSIONS & EVENT LISTENERS
// ==========================================

function initForms() {
    // Add Employee Form
    document.getElementById('add-employee-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            full_name: document.getElementById('add-emp-fullname').value.trim(),
            emp_id: document.getElementById('add-emp-id').value.trim(),
            department: document.getElementById('add-emp-department').value.trim(),
            role: document.getElementById('add-emp-role').value.trim(),
            username: document.getElementById('add-emp-username').value.trim(),
            password: document.getElementById('add-emp-password').value.trim(),
            is_admin: document.getElementById('add-emp-account-role').value === 'ADMIN' ? 1 : 0,
            status: document.getElementById('add-emp-status').value
        };

        try {
            await fetchAPI('/employees', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            alert('Employee account successfully created.');
            closeModal('add-employee-modal');
            e.target.reset();
            loadEmployees();
            loadDashboard();
        } catch (err) {
            alert('Failed to create employee: ' + err.message);
        }
    });

    // Edit Employee Form
    document.getElementById('edit-employee-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const userId = document.getElementById('edit-emp-user-id').value;
        const payload = {
            full_name: document.getElementById('edit-emp-fullname').value.trim(),
            emp_id: document.getElementById('edit-emp-id').value.trim(),
            department: document.getElementById('edit-emp-department').value.trim(),
            role: document.getElementById('edit-emp-role').value.trim(),
            status: document.getElementById('edit-emp-status').value
        };

        const newPass = document.getElementById('edit-emp-password').value.trim();
        if (newPass) payload.password = newPass;

        try {
            await fetchAPI(`/employees/${userId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            alert('Employee record successfully updated.');
            closeModal('edit-employee-modal');
            loadEmployees();
            loadDashboard();
        } catch (err) {
            alert('Failed to update employee: ' + err.message);
        }
    });

    // Open Add Employee Modal Button
    document.getElementById('open-add-employee-btn')?.addEventListener('click', () => {
        openModal('add-employee-modal');
    });

    // Simulation Trigger
    document.getElementById('run-simulation-btn')?.addEventListener('click', runSimulation);

    // Target employee select change
    document.getElementById('sim-target-employee')?.addEventListener('change', (e) => {
        triggerEmployeeMetaUpdate(e.target.value);
    });

    // Generate Report Button
    document.getElementById('generate-report-modal-btn')?.addEventListener('click', generateExecutiveReport);

    // Filters Debounce
    let debounceTimer;
    const bindFilter = (id, fn) => {
        document.getElementById(id)?.addEventListener('input', () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(fn, 300);
        });
        document.getElementById(id)?.addEventListener('change', fn);
    };

    bindFilter('employee-search', loadEmployees);
    bindFilter('employee-department-filter', loadEmployees);
    bindFilter('employee-risk-filter', loadEmployees);
    bindFilter('employee-status-filter', loadEmployees);

    bindFilter('alerts-search', loadAlertsList);
    bindFilter('alerts-severity-filter', loadAlertsList);
    bindFilter('alerts-status-filter', loadAlertsList);

    bindFilter('activity-search', loadActivityStream);
    bindFilter('activity-status-filter', loadActivityStream);

    // Global Search
    document.getElementById('global-search')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const q = e.target.value.trim();
            if (!q) return;
            navigateToPage('employees');
            const empSearch = document.getElementById('employee-search');
            if (empSearch) {
                empSearch.value = q;
                loadEmployees();
            }
        }
    });
}

// Modal Backdrop clicks
document.querySelectorAll('.modal').forEach(m => {
    m.addEventListener('click', (e) => {
        if (e.target === m) closeModal(m.id);
    });
});

// ==========================================
// BOOTSTRAP APPLICATION
// ==========================================

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initForms();
    loadDashboard();
    refreshIcons();
});

// Global bindings for inline event triggers
window.navigateToPage = navigateToPage;
window.switchAlertSubTab = switchAlertSubTab;
window.showEmployeeDetails = showEmployeeDetails;
window.openEditEmployeeModal = openEditEmployeeModal;
window.toggleEmployeeStatus = toggleEmployeeStatus;
window.showIncidentDetail = showIncidentDetail;
window.triggerAlertAction = triggerAlertAction;
window.selectScenario = selectScenario;
window.runSimulation = runSimulation;
window.resetSimulator = resetSimulator;
window.launchSimulationForEmployee = launchSimulationForEmployee;
window.closeModal = closeModal;
window.generateExecutiveReport = generateExecutiveReport;
