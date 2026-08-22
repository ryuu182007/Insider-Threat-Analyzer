"""Data access layer for the Insider Threat Detection System."""

from backend.utils.db import get_db, dict_from_row
from backend.services.threat_detector import get_risk_level, analyze_user_activities


def get_dashboard_stats():
    conn = get_db()
    try:
        total_users = conn.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']
        active_users = conn.execute(
            "SELECT COUNT(*) as c FROM users WHERE status = 'active'"
        ).fetchone()['c']
        suspicious_users = conn.execute(
            'SELECT COUNT(*) as c FROM users WHERE risk_score >= 30'
        ).fetchone()['c']
        open_incidents = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE status IN ('Open', 'Investigating')"
        ).fetchone()['c']

        avg_risk = conn.execute(
            'SELECT AVG(risk_score) as avg FROM users'
        ).fetchone()['avg'] or 0

        critical_incidents = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE severity = 'CRITICAL' AND status != 'Resolved'"
        ).fetchone()['c']

        high_risk_users = conn.execute(
            'SELECT COUNT(*) as c FROM users WHERE risk_score >= 60'
        ).fetchone()['c']

        # Determine overall threat level
        if avg_risk >= 60 or critical_incidents >= 2:
            threat_level = 'CRITICAL'
        elif avg_risk >= 40 or suspicious_users >= 5:
            threat_level = 'HIGH'
        elif avg_risk >= 25 or suspicious_users >= 2:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'

        return {
            'total_users': total_users,
            'active_users': active_users,
            'suspicious_users': suspicious_users,
            'open_incidents': open_incidents,
            'avg_risk_score': round(avg_risk, 1),
            'critical_incidents': critical_incidents,
            'high_risk_users': high_risk_users,
            'threat_level': threat_level,
            'system_status': 'Operational'
        }
    finally:
        conn.close()


def get_all_users(search=None, risk_filter=None):
    conn = get_db()
    try:
        query = 'SELECT * FROM users WHERE 1=1'
        params = []

        if search:
            query += ' AND (username LIKE ? OR full_name LIKE ? OR department LIKE ?)'
            term = f'%{search}%'
            params.extend([term, term, term])

        if risk_filter:
            if risk_filter == 'low':
                query += ' AND risk_score < 30'
            elif risk_filter == 'medium':
                query += ' AND risk_score >= 30 AND risk_score < 60'
            elif risk_filter == 'high':
                query += ' AND risk_score >= 60 AND risk_score < 80'
            elif risk_filter == 'critical':
                query += ' AND risk_score >= 80'

        query += ' ORDER BY risk_score DESC'
        rows = conn.execute(query, params).fetchall()
        return [dict_from_row(r) for r in rows]
    finally:
        conn.close()


def get_user_by_id(user_id):
    conn = get_db()
    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            return None

        user_dict = dict_from_row(user)

        activities = conn.execute(
            'SELECT * FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20',
            (user_id,)
        ).fetchall()
        user_dict['recent_activities'] = [dict_from_row(a) for a in activities]

        incidents = conn.execute(
            'SELECT * FROM incidents WHERE user_id = ? ORDER BY detected_at DESC',
            (user_id,)
        ).fetchall()
        user_dict['incidents'] = [dict_from_row(i) for i in incidents]

        analysis = analyze_user_activities(user_dict['recent_activities'])
        user_dict['threat_analysis'] = analysis

        return user_dict
    finally:
        conn.close()


def get_activity_logs(search=None, status_filter=None, limit=50):
    conn = get_db()
    try:
        query = '''
            SELECT al.*, u.username, u.full_name
            FROM activity_logs al
            JOIN users u ON al.user_id = u.id
            WHERE 1=1
        '''
        params = []

        if search:
            query += ' AND (u.username LIKE ? OR al.description LIKE ? OR al.activity_type LIKE ?)'
            term = f'%{search}%'
            params.extend([term, term, term])

        if status_filter:
            query += ' AND al.status = ?'
            params.append(status_filter)

        query += ' ORDER BY al.timestamp DESC LIMIT ?'
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict_from_row(r) for r in rows]
    finally:
        conn.close()


def get_incidents(severity_filter=None, status_filter=None, type_filter=None):
    conn = get_db()
    try:
        query = '''
            SELECT i.*, u.username, u.full_name
            FROM incidents i
            JOIN users u ON i.user_id = u.id
            WHERE 1=1
        '''
        params = []

        if severity_filter:
            query += ' AND i.severity = ?'
            params.append(severity_filter.upper())

        if status_filter:
            query += ' AND i.status = ?'
            params.append(status_filter)

        if type_filter:
            query += ' AND i.incident_type LIKE ?'
            params.append(f'%{type_filter}%')

        query += ' ORDER BY i.detected_at DESC'
        rows = conn.execute(query, params).fetchall()
        return [dict_from_row(r) for r in rows]
    finally:
        conn.close()


def get_incident_by_id(incident_id):
    conn = get_db()
    try:
        row = conn.execute('''
            SELECT i.*, u.username, u.full_name, u.department, u.email
            FROM incidents i
            JOIN users u ON i.user_id = u.id
            WHERE i.id = ?
        ''', (incident_id,)).fetchone()
        return dict_from_row(row)
    finally:
        conn.close()


def create_incident(data):
    conn = get_db()
    try:
        required = ['user_id', 'title', 'description', 'severity', 'incident_type']
        for field in required:
            if field not in data or not data[field]:
                return None, f'Missing required field: {field}'

        valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if data['severity'].upper() not in valid_severities:
            return None, 'Invalid severity level'

        cursor = conn.execute('''
            INSERT INTO incidents (user_id, title, description, severity, risk_score,
                                   incident_type, status, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ''', (
            data['user_id'],
            data['title'],
            data['description'],
            data['severity'].upper(),
            data.get('risk_score', 50),
            data['incident_type'],
            data.get('status', 'Open')
        ))
        conn.commit()
        return cursor.lastrowid, None
    finally:
        conn.close()


def update_incident(incident_id, data):
    conn = get_db()
    try:
        existing = conn.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,)).fetchone()
        if not existing:
            return False, 'Incident not found'

        allowed_fields = ['title', 'description', 'severity', 'status', 'risk_score', 'incident_type']
        updates = []
        params = []

        for field in allowed_fields:
            if field in data:
                if field == 'severity' and data[field].upper() not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                    return False, 'Invalid severity'
                if field == 'status' and data[field] not in ['Open', 'Investigating', 'Resolved']:
                    return False, 'Invalid status'
                updates.append(f'{field} = ?')
                params.append(data[field].upper() if field == 'severity' else data[field])

        if data.get('status') == 'Resolved':
            updates.append('resolved_at = datetime("now")')

        if not updates:
            return False, 'No valid fields to update'

        params.append(incident_id)
        conn.execute(f'UPDATE incidents SET {", ".join(updates)} WHERE id = ?', params)
        conn.commit()
        return True, None
    finally:
        conn.close()


def get_threat_analysis():
    conn = get_db()
    try:
        # Risk distribution
        risk_dist = {
            'low': conn.execute('SELECT COUNT(*) as c FROM users WHERE risk_score < 30').fetchone()['c'],
            'medium': conn.execute('SELECT COUNT(*) as c FROM users WHERE risk_score >= 30 AND risk_score < 60').fetchone()['c'],
            'high': conn.execute('SELECT COUNT(*) as c FROM users WHERE risk_score >= 60 AND risk_score < 80').fetchone()['c'],
            'critical': conn.execute('SELECT COUNT(*) as c FROM users WHERE risk_score >= 80').fetchone()['c'],
        }

        # Incidents by severity
        inc_severity = conn.execute('''
            SELECT severity, COUNT(*) as count FROM incidents
            GROUP BY severity
        ''').fetchall()
        incidents_by_severity = {r['severity']: r['count'] for r in inc_severity}

        # Activity by category (last 7 days)
        activity_cats = conn.execute('''
            SELECT activity_type, COUNT(*) as count FROM activity_logs
            GROUP BY activity_type ORDER BY count DESC LIMIT 10
        ''').fetchall()
        activity_by_category = {r['activity_type']: r['count'] for r in activity_cats}

        # Top risky users
        top_risky = conn.execute('''
            SELECT id, username, full_name, department, risk_score
            FROM users ORDER BY risk_score DESC LIMIT 5
        ''').fetchall()

        # Threats over time (activity risk by day, last 7 days)
        threats_timeline = conn.execute('''
            SELECT DATE(timestamp) as day, AVG(risk_score) as avg_risk, COUNT(*) as count
            FROM activity_logs
            WHERE timestamp >= datetime('now', '-7 days')
            GROUP BY DATE(timestamp)
            ORDER BY day
        ''').fetchall()

        return {
            'risk_distribution': risk_dist,
            'incidents_by_severity': incidents_by_severity,
            'activity_by_category': activity_by_category,
            'top_risky_users': [dict_from_row(r) for r in top_risky],
            'threats_timeline': [dict_from_row(r) for r in threats_timeline]
        }
    finally:
        conn.close()

def verify_login(username, password):
    conn = get_db()
    try:
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        return dict_from_row(user)
    finally:
        conn.close()

def create_member(data):
    conn = get_db()
    try:
        required = ['username', 'full_name', 'department', 'role', 'email', 'password']
        for field in required:
            if field not in data or not data[field]:
                return None, f'Missing required field: {field}'
        
        cursor = conn.execute('''
            INSERT INTO users (username, full_name, department, role, email, password, is_admin)
            VALUES (?, ?, ?, ?, ?, ?, 0)
        ''', (
            data['username'],
            data['full_name'],
            data['department'],
            data['role'],
            data['email'],
            data['password']
        ))
        conn.commit()
        return cursor.lastrowid, None
    except sqlite3.IntegrityError:
        return None, 'Username already exists'
    finally:
        conn.close()

def get_all_tasks():
    conn = get_db()
    try:
        rows = conn.execute('''
            SELECT t.*, u.username, u.full_name 
            FROM tasks t
            JOIN users u ON t.user_id = u.id
            ORDER BY t.created_at DESC
        ''').fetchall()
        return [dict_from_row(r) for r in rows]
    finally:
        conn.close()

def get_tasks_for_user(username):
    conn = get_db()
    try:
        rows = conn.execute('''
            SELECT t.* 
            FROM tasks t
            JOIN users u ON t.user_id = u.id
            WHERE u.username = ?
            ORDER BY t.created_at DESC
        ''', (username,)).fetchall()
        return [dict_from_row(r) for r in rows]
    finally:
        conn.close()

def create_task(data):
    conn = get_db()
    try:
        required = ['user_id', 'title']
        for field in required:
            if field not in data or not data[field]:
                return None, f'Missing required field: {field}'
                
        cursor = conn.execute('''
            INSERT INTO tasks (user_id, title, description, status)
            VALUES (?, ?, ?, 'Pending')
        ''', (
            data['user_id'],
            data['title'],
            data.get('description', '')
        ))
        conn.commit()
        return cursor.lastrowid, None
    finally:
        conn.close()

def update_task_status(task_id, status):
    conn = get_db()
    try:
        conn.execute('UPDATE tasks SET status = ? WHERE id = ?', (status, task_id))
        conn.commit()
        return True, None
    finally:
        conn.close()
