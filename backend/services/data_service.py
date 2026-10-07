"""Data access layer for the Insider Threat Detection System (ThreatSim)."""

import sqlite3
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from backend import config
from backend.utils.db import get_db, dict_from_row
from backend.services.threat_detector import get_risk_level, analyze_user_activities


def get_dashboard_stats():
    conn = get_db()
    try:
        total_users = conn.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']
        total_employees = conn.execute('SELECT COUNT(*) as c FROM users WHERE is_admin = 0').fetchone()['c']
        active_users = conn.execute(
            "SELECT COUNT(*) as c FROM users WHERE status = 'active'"
        ).fetchone()['c']
        suspicious_users = conn.execute(
            'SELECT COUNT(*) as c FROM users WHERE risk_score >= 30'
        ).fetchone()['c']
        open_incidents = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE status IN ('Open', 'New', 'Investigating')"
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

        high_risk_employees = conn.execute(
            'SELECT COUNT(*) as c FROM users WHERE risk_score >= 60 AND is_admin = 0'
        ).fetchone()['c']

        total_simulations = 0
        try:
            total_simulations = conn.execute('SELECT COUNT(*) as c FROM simulations').fetchone()['c']
        except Exception:
            pass

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
            'total_employees': total_employees,
            'active_users': active_users,
            'suspicious_users': suspicious_users,
            'open_incidents': open_incidents,
            'active_alerts': open_incidents,
            'avg_risk_score': round(float(avg_risk), 1),
            'critical_incidents': critical_incidents,
            'high_risk_users': high_risk_users,
            'high_risk_employees': high_risk_employees,
            'total_simulations': total_simulations,
            'threat_level': threat_level,
            'system_status': 'Operational'
        }
    finally:
        conn.close()


def get_all_users(search=None, risk_filter=None, department_filter=None, status_filter=None):
    conn = get_db()
    try:
        query = '''
            SELECT u.*,
                   (SELECT COUNT(*) FROM incidents WHERE user_id = u.id AND status != 'Resolved') as active_alerts,
                   (SELECT COUNT(*) FROM simulations WHERE user_id = u.id) as simulation_count
            FROM users u WHERE u.is_admin = 0
        '''
        params = []

        if search:
            query += ' AND (u.username LIKE ? OR u.full_name LIKE ? OR u.department LIKE ? OR u.role LIKE ? OR u.emp_id LIKE ?)'
            term = f'%{search}%'
            params.extend([term, term, term, term, term])

        if risk_filter:
            if risk_filter == 'low':
                query += ' AND u.risk_score < 30'
            elif risk_filter == 'medium':
                query += ' AND u.risk_score >= 30 AND u.risk_score < 60'
            elif risk_filter == 'high':
                query += ' AND u.risk_score >= 60 AND u.risk_score < 80'
            elif risk_filter == 'critical':
                query += ' AND u.risk_score >= 80'

        if department_filter:
            query += ' AND LOWER(u.department) = LOWER(?)'
            params.append(department_filter.strip())

        if status_filter:
            query += ' AND LOWER(u.status) = LOWER(?)'
            params.append(status_filter.strip())

        query += ' ORDER BY u.risk_score DESC'
        rows = conn.execute(query, params).fetchall()
        result = [dict_from_row(r) for r in rows]
        for r in result:
            r.pop('password', None)   # never expose password hashes
        return result
    finally:
        conn.close()


def get_departments():
    conn = get_db()
    try:
        rows = conn.execute(
            'SELECT DISTINCT department FROM users WHERE department IS NOT NULL AND department != "" ORDER BY department ASC'
        ).fetchall()
        return [r['department'] for r in rows]
    finally:
        conn.close()


def get_user_by_id(user_id):
    conn = get_db()
    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            return None

        user_dict = dict_from_row(user)
        user_dict.pop('password', None)   # never expose password hashes

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

        try:
            simulations = conn.execute(
                'SELECT * FROM simulations WHERE user_id = ? ORDER BY created_at DESC LIMIT 15',
                (user_id,)
            ).fetchall()
            user_dict['simulations'] = [dict_from_row(s) for s in simulations]
        except Exception:
            user_dict['simulations'] = []

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
                if field == 'status' and data[field] not in ['New', 'Open', 'Investigating', 'Resolved']:
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
            SELECT id, emp_id, username, full_name, department, risk_score
            FROM users ORDER BY risk_score DESC LIMIT 5
        ''').fetchall()

        # Threats over time (activity risk by day, last 7 days)
        threats_timeline = conn.execute('''
            SELECT DATE(CAST(timestamp AS TIMESTAMPTZ)) as day,
                   AVG(risk_score) as avg_risk,
                   COUNT(*) as count
            FROM activity_logs
            WHERE CAST(timestamp AS TIMESTAMPTZ) >= (CURRENT_TIMESTAMP - INTERVAL '7 days')
            GROUP BY DATE(CAST(timestamp AS TIMESTAMPTZ))
            ORDER BY day
        ''').fetchall()

        if not threats_timeline:
            # Fallback to the latest 7 active days so the tracker is always live and on
            threats_timeline = conn.execute('''
                SELECT day, avg_risk, count FROM (
                    SELECT DATE(CAST(timestamp AS TIMESTAMPTZ)) as day,
                           AVG(risk_score) as avg_risk,
                           COUNT(*) as count
                    FROM activity_logs
                    GROUP BY DATE(CAST(timestamp AS TIMESTAMPTZ))
                    ORDER BY day DESC
                    LIMIT 7
                ) ORDER BY day ASC
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


def log_logout(user_id):
    conn = get_db()
    try:
        conn.execute('''
            INSERT INTO activity_logs (user_id, activity_type, description, ip_address, device, timestamp, risk_score, status)
            VALUES (?, 'logout', 'User signed out of security portal', '127.0.0.1', 'Web Terminal', datetime('now'), 0, 'normal')
        ''', (user_id,))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def reset_password(identity, new_password):
    """Reset password for an existing user by username or email with minimum 8 characters."""
    conn = get_db()
    try:
        user = conn.execute(
            'SELECT * FROM users WHERE is_admin = 0 AND (LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?))',
            (identity.strip(), identity.strip())
        ).fetchone()
        if not user:
            return False, 'No account found with that username or email address.'

        if len(new_password) < 8:
            return False, 'Password must be at least 8 characters long.'

        hashed = generate_password_hash(new_password)
        conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, user['id']))
        conn.commit()
        return True, f"Password successfully updated for user '{user['username']}'."
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def get_daily_subject_tracker(department=None):
    """Get daily threat tracker metrics for subjects / department."""
    conn = get_db()
    try:
        where_dept = ""
        params = []
        if department and department.strip() and department.lower() != 'all':
            where_dept = " AND LOWER(u.department) = LOWER(?)"
            params.append(department.strip())

        total_subjects = conn.execute(f"SELECT COUNT(*) as c FROM users u WHERE 1=1 {where_dept}", params).fetchone()['c']
        avg_risk = conn.execute(f"SELECT AVG(risk_score) as avg FROM users u WHERE 1=1 {where_dept}", params).fetchone()['avg'] or 0
        high_risk = conn.execute(f"SELECT COUNT(*) as c FROM users u WHERE risk_score >= 60 {where_dept}", params).fetchone()['c']

        log_query = f"""
            SELECT COUNT(*) as c FROM activity_logs a
            JOIN users u ON a.user_id = u.id
            WHERE a.status IN ('suspicious', 'critical') {where_dept}
        """
        daily_anomalies = conn.execute(log_query, params).fetchone()['c']

        return {
            'total_subjects': total_subjects,
            'avg_risk': round(float(avg_risk), 1),
            'high_risk': high_risk,
            'daily_anomalies': daily_anomalies,
            'tracker_status': 'ACTIVE',
            'department': department or 'All'
        }
    finally:
        conn.close()


def create_employee(data):
    """Create a new EMPLOYEE account (always non-admin; the admin is a fixed built-in account)."""
    conn = get_db()
    try:
        for field in ['full_name', 'department', 'role', 'username', 'password']:
            if not data.get(field) or not str(data[field]).strip():
                return None, f"Field '{field}' is required."
        if len(data['password']) < 8:
            return None, 'Password must be at least 8 characters long.'

        username = data['username'].strip()
        if username.lower() == config.ADMIN_USERNAME.lower():
            return None, 'That username is reserved.'
        if conn.execute('SELECT id FROM users WHERE LOWER(username) = LOWER(?)', (username,)).fetchone():
            return None, f"Username '{username}' already exists."

        emp_id = str(data.get('emp_id') or '').strip()
        if not emp_id:
            max_id = conn.execute('SELECT MAX(id) as m FROM users').fetchone()['m'] or 0
            emp_id = f"EMP-{1001 + max_id}"
        if conn.execute('SELECT id FROM users WHERE emp_id = ?', (emp_id,)).fetchone():
            return None, f"Employee ID '{emp_id}' is already assigned."

        email = str(data.get('email') or '').strip() or f"{username.lower()}@corp.local"
        status = 'disabled' if str(data.get('status', 'active')).lower() in ('disabled', 'inactive') else 'active'

        cursor = conn.execute('''
            INSERT INTO users (emp_id, username, full_name, department, role, email, password, status, risk_score, last_activity, is_admin)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, datetime('now'), 0)
        ''', (emp_id, username, data['full_name'].strip(), data['department'].strip(),
              data['role'].strip(), email, generate_password_hash(data['password']), status))
        user_id = cursor.lastrowid
        conn.execute('''
            INSERT INTO activity_logs (user_id, activity_type, description, ip_address, device, timestamp, risk_score, status)
            VALUES (?, 'profile_created', 'Employee account created by administrator', '127.0.0.1', 'Admin Console', datetime('now'), 0, 'normal')
        ''', (user_id,))
        conn.commit()
        return user_id, None
    except Exception as e:
        return None, str(e)
    finally:
        conn.close()


def delete_employee(user_id):
    """Permanently remove an employee and everything that belongs to them; ends their live sessions."""
    conn = get_db()
    try:
        user = conn.execute('SELECT id FROM users WHERE id = ? AND is_admin = 0', (user_id,)).fetchone()
        if not user:
            return False, 'Employee not found.'
        for table in ('activity_logs', 'incidents', 'simulations', 'tasks'):
            conn.execute(f'DELETE FROM {table} WHERE user_id = ?', (user_id,))
        conn.execute('DELETE FROM auth_sessions WHERE user_id = ?', (user_id,))
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def update_employee(user_id, data):
    """Update employee details and optionally update password."""
    conn = get_db()
    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            return False, 'Employee not found.'

        allowed_fields = ['full_name', 'department', 'role', 'email', 'status', 'emp_id']
        updates = []
        params = []

        new_emp_id = str(data.get('emp_id') or '').strip()
        if new_emp_id:
            clash = conn.execute('SELECT id FROM users WHERE emp_id = ? AND id != ?', (new_emp_id, user_id)).fetchone()
            if clash:
                return False, f"Employee ID '{new_emp_id}' is already assigned to another employee."

        for field in allowed_fields:
            if field in data and data[field] is not None and str(data[field]).strip() != '':
                updates.append(f"{field} = ?")
                params.append(str(data[field]).strip())

        if data.get('password'):
            if len(data['password']) < 8:
                return False, 'Password must be at least 8 characters long.'
            updates.append("password = ?")
            params.append(generate_password_hash(data['password']))

        if not updates:
            return False, 'No valid fields provided to update.'

        params.append(user_id)
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)

        conn.execute('''
            INSERT INTO activity_logs (user_id, activity_type, description, ip_address, device, timestamp, risk_score, status)
            VALUES (?, 'profile_update', 'Employee record updated by administrator', '127.0.0.1', 'Admin Console', datetime('now'), 0, 'normal')
        ''', (user_id,))

        conn.commit()
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def set_employee_status(user_id, new_status):
    """Enable or disable an employee account."""
    conn = get_db()
    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            return False, 'Employee not found.'

        status = 'active' if str(new_status).lower() in ('active', 'enable', 'enabled') else 'disabled'
        conn.execute('UPDATE users SET status = ? WHERE id = ?', (status, user_id))

        desc = f"Account status set to {status.upper()} by administrator"
        conn.execute('''
            INSERT INTO activity_logs (user_id, activity_type, description, ip_address, device, timestamp, risk_score, status)
            VALUES (?, 'status_change', ?, '127.0.0.1', 'Admin Console', datetime('now'), 0, 'normal')
        ''', (user_id, desc))

        conn.commit()
        return True, status
    finally:
        conn.close()


def run_simulation(user_id, scenario_key, create_alert=True):
    """
    Execute a threat simulation scenario for an employee.
    Calculates risk score, logs simulated activities, records simulation,
    and optionally generates a security alert/incident.
    """
    conn = get_db()
    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            return None, 'Employee not found.'

        emp_dict = dict_from_row(user)
        from backend.services.threat_detector import simulate_threat
        result = simulate_threat(scenario_key, emp_dict)

        # 1. Log the simulated activities into activity_logs
        for act in result['activities']:
            conn.execute('''
                INSERT INTO activity_logs (user_id, activity_type, description, ip_address, device, timestamp, risk_score, status)
                VALUES (?, ?, ?, '10.0.4.88', 'Simulated Endpoint', datetime('now'), ?, ?)
            ''', (user_id, act['type'], f"[SIMULATION] {act['desc']}", act['risk'], act['status']))

        alert_id = None
        alert_created_flag = 0

        # 2. If create_alert or significant risk
        if create_alert:
            alert_data = result['alert_data']
            cursor = conn.execute('''
                INSERT INTO incidents (user_id, title, description, severity, risk_score, incident_type, status, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, 'New', datetime('now'))
            ''', (
                user_id,
                alert_data['title'],
                alert_data['description'],
                alert_data['severity'],
                alert_data['risk_score'],
                alert_data['incident_type']
            ))
            alert_id = cursor.lastrowid
            alert_created_flag = 1

            # Update employee's risk score
            new_risk = max(emp_dict['risk_score'], result['risk_score']) if result['risk_score'] > 20 else result['risk_score']
            conn.execute("UPDATE users SET risk_score = ?, last_activity = datetime('now') WHERE id = ?", (new_risk, user_id))

        # 3. Insert into simulations table
        sim_cursor = conn.execute('''
            INSERT INTO simulations (user_id, scenario_type, scenario_name, risk_score, risk_level, indicators, alert_created, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ''', (
            user_id,
            result['scenario_key'],
            result['scenario_name'],
            result['risk_score'],
            result['risk_level'],
            json.dumps(result['indicators']),
            alert_created_flag
        ))
        sim_id = sim_cursor.lastrowid

        conn.commit()

        result['simulation_id'] = sim_id
        result['alert_id'] = alert_id
        result['alert_created'] = bool(alert_created_flag)
        result['employee_name'] = emp_dict['full_name']
        result['employee_id'] = emp_dict.get('emp_id') or f"EMP-{user_id}"

        return result, None
    except Exception as e:
        return None, str(e)
    finally:
        conn.close()


def get_simulations(user_id=None, limit=50):
    """Retrieve simulation history with joined employee data."""
    conn = get_db()
    try:
        query = '''
            SELECT s.*, u.full_name, u.username, u.emp_id, u.department, u.role
            FROM simulations s
            JOIN users u ON s.user_id = u.id
            WHERE 1=1
        '''
        params = []
        if user_id:
            query += ' AND s.user_id = ?'
            params.append(user_id)

        query += ' ORDER BY s.created_at DESC LIMIT ?'
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            d = dict_from_row(r)
            if d.get('indicators') and isinstance(d['indicators'], str):
                try:
                    d['indicators'] = json.loads(d['indicators'])
                except Exception:
                    d['indicators'] = [d['indicators']]
            results.append(d)
        return results
    finally:
        conn.close()


def get_reports_summary():
    """Consolidated metrics for Reports view."""
    conn = get_db()
    try:
        total_employees = conn.execute('SELECT COUNT(*) as c FROM users WHERE is_admin = 0').fetchone()['c']
        total_simulations = conn.execute('SELECT COUNT(*) as c FROM simulations').fetchone()['c']
        total_alerts = conn.execute('SELECT COUNT(*) as c FROM incidents').fetchone()['c']

        # Event counts by severity
        sev_counts = conn.execute('''
            SELECT severity, COUNT(*) as c FROM incidents GROUP BY severity
        ''').fetchall()
        severity_map = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        for r in sev_counts:
            severity_map[r['severity'].upper()] = r['c']

        # Most simulated scenario
        most_sim_row = conn.execute('''
            SELECT scenario_name, COUNT(*) as count FROM simulations
            GROUP BY scenario_name ORDER BY count DESC LIMIT 1
        ''').fetchone()
        most_simulated = dict_from_row(most_sim_row) if most_sim_row else {'scenario_name': 'None', 'count': 0}

        # Highest risk employees
        high_risk_emps = conn.execute('''
            SELECT id, emp_id, username, full_name, department, role, risk_score, status
            FROM users WHERE is_admin = 0 ORDER BY risk_score DESC LIMIT 6
        ''').fetchall()

        # Risk distribution
        risk_dist = {
            'low': conn.execute('SELECT COUNT(*) as c FROM users WHERE risk_score < 30 AND is_admin = 0').fetchone()['c'],
            'medium': conn.execute('SELECT COUNT(*) as c FROM users WHERE risk_score >= 30 AND risk_score < 60 AND is_admin = 0').fetchone()['c'],
            'high': conn.execute('SELECT COUNT(*) as c FROM users WHERE risk_score >= 60 AND risk_score < 80 AND is_admin = 0').fetchone()['c'],
            'critical': conn.execute('SELECT COUNT(*) as c FROM users WHERE risk_score >= 80 AND is_admin = 0').fetchone()['c'],
        }

        # Simulations breakdown by scenario
        sims_by_scenario = conn.execute('''
            SELECT scenario_name, COUNT(*) as count FROM simulations GROUP BY scenario_name ORDER BY count DESC
        ''').fetchall()

        return {
            'total_employees': total_employees,
            'total_simulations': total_simulations,
            'total_alerts': total_alerts,
            'events_by_severity': severity_map,
            'most_simulated_scenario': most_simulated,
            'highest_risk_employees': [dict_from_row(r) for r in high_risk_emps],
            'risk_distribution': risk_dist,
            'simulations_breakdown': [dict_from_row(r) for r in sims_by_scenario]
        }
    finally:
        conn.close()


def execute_alert_action(alert_id, action_type, context=None):
    """
    Execute an operational action inside an alert (absorbing Tasks functionality).
    Actions: review_activity, verify_usb, check_files, mark_reviewed, resolve_alert, quarantine
    """
    conn = get_db()
    try:
        incident = conn.execute('SELECT * FROM incidents WHERE id = ?', (alert_id,)).fetchone()
        if not incident:
            return None, 'Alert not found.'

        inc_dict = dict_from_row(incident)
        user_id = inc_dict['user_id']

        response_data = {'action': action_type, 'alert_id': alert_id}

        if action_type == 'review_activity':
            activities = conn.execute('''
                SELECT * FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20
            ''', (user_id,)).fetchall()
            response_data['activities'] = [dict_from_row(a) for a in activities]
            response_data['message'] = f"Retrieved {len(activities)} recent logs for {inc_dict['title']}."

        elif action_type == 'verify_usb':
            usb_logs = conn.execute('''
                SELECT * FROM activity_logs WHERE user_id = ? AND activity_type LIKE '%usb%' ORDER BY timestamp DESC LIMIT 5
            ''', (user_id,)).fetchall()
            device_info = "Device Serial #USB-8849-SANDISK (64GB Flash Storage)" if usb_logs else "No active unauthorized USB device detected in registry."
            response_data['usb_verified'] = True
            response_data['device_info'] = device_info
            response_data['message'] = f"USB Verification complete: {device_info}"
            conn.execute("UPDATE incidents SET status = 'Investigating' WHERE id = ? AND status = 'New'", (alert_id,))
            conn.commit()

        elif action_type == 'check_files':
            file_logs = conn.execute('''
                SELECT * FROM activity_logs 
                WHERE user_id = ? AND (activity_type LIKE '%file%' OR activity_type LIKE '%exfiltration%')
                ORDER BY timestamp DESC LIMIT 15
            ''', (user_id,)).fetchall()
            response_data['accessed_files'] = [dict_from_row(f) for f in file_logs]
            response_data['message'] = f"Audited {len(file_logs)} file access events."
            conn.execute("UPDATE incidents SET status = 'Investigating' WHERE id = ? AND status = 'New'", (alert_id,))
            conn.commit()

        elif action_type == 'mark_reviewed':
            conn.execute("UPDATE incidents SET status = 'Investigating' WHERE id = ?", (alert_id,))
            conn.commit()
            response_data['status'] = 'Investigating'
            response_data['message'] = "Alert status updated to 'Investigating'."

        elif action_type == 'resolve_alert':
            conn.execute("UPDATE incidents SET status = 'Resolved', resolved_at = datetime('now') WHERE id = ?", (alert_id,))
            conn.commit()
            response_data['status'] = 'Resolved'
            response_data['message'] = "Alert successfully resolved and closed."

        elif action_type == 'quarantine':
            conn.execute("UPDATE users SET status = 'disabled' WHERE id = ?", (user_id,))
            conn.execute("UPDATE incidents SET status = 'Investigating' WHERE id = ?", (alert_id,))
            conn.execute('''
                INSERT INTO activity_logs (user_id, activity_type, description, ip_address, device, timestamp, risk_score, status)
                VALUES (?, 'quarantine_enforced', 'Account quarantined due to security alert', '127.0.0.1', 'SOC Console', datetime('now'), 80, 'critical')
            ''', (user_id,))
            conn.commit()
            response_data['message'] = "Employee account quarantined and network credentials disabled."

        else:
            return None, f"Unknown alert action: {action_type}"

        return response_data, None
    finally:
        conn.close()


def get_employee_dashboard_data(user_id):
    """Scoped strictly to current logged-in employee."""
    conn = get_db()
    try:
        user = conn.execute('SELECT id, emp_id, username, full_name, department, role, email, status, risk_score, last_activity FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            return None

        emp_dict = dict_from_row(user)
        active_alerts_count = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE user_id = ? AND status != 'Resolved'", (user_id,)
        ).fetchone()['c']

        total_activities_count = conn.execute(
            "SELECT COUNT(*) as c FROM activity_logs WHERE user_id = ?", (user_id,)
        ).fetchone()['c']

        recent_alerts = conn.execute('''
            SELECT * FROM incidents WHERE user_id = ? ORDER BY detected_at DESC LIMIT 5
        ''', (user_id,)).fetchall()

        recent_activity = conn.execute('''
            SELECT * FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10
        ''', (user_id,)).fetchall()

        return {
            'profile': emp_dict,
            'active_alerts_count': active_alerts_count,
            'total_activities_count': total_activities_count,
            'risk_score': emp_dict['risk_score'],
            'risk_level': get_risk_level(emp_dict['risk_score']),
            'recent_alerts': [dict_from_row(r) for r in recent_alerts],
            'recent_activity': [dict_from_row(r) for r in recent_activity]
        }
    finally:
        conn.close()


def get_employee_activities(user_id, limit=50):
    """Scoped strictly to current employee's activity logs."""
    conn = get_db()
    try:
        rows = conn.execute('''
            SELECT * FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?
        ''', (user_id, limit)).fetchall()
        return [dict_from_row(r) for r in rows]
    finally:
        conn.close()


def get_employee_alerts(user_id):
    """Scoped strictly to current employee's alerts/incidents."""
    conn = get_db()
    try:
        rows = conn.execute('''
            SELECT * FROM incidents WHERE user_id = ? ORDER BY detected_at DESC
        ''', (user_id,)).fetchall()
        return [dict_from_row(r) for r in rows]
    finally:
        conn.close()


# --- Backward compatibility methods ---
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

