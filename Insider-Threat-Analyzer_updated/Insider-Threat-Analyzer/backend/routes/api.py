"""Flask API routes for the ThreatSim Cybersecurity System with strict RBAC enforcement."""

from functools import wraps
from flask import Blueprint, jsonify, request, g
from backend import config
from backend.services import data_service
from backend.services import threat_detector
from backend.services import auth_service

api_bp = Blueprint('api', __name__)


def _token_from_request():
    """Each browser tab sends its own token, so sessions never overlap."""
    header = request.headers.get('Authorization', '')
    if header.lower().startswith('bearer '):
        return header[7:].strip()
    return request.headers.get('X-Session-Token', '').strip() or None


def _authenticate():
    identity = auth_service.resolve_session(_token_from_request())
    g.auth = identity
    return identity


def _unauthorized():
    return jsonify({'error': 'Session expired or not signed in. Please sign in again.', 'code': 'UNAUTHORIZED'}), 401


def login_required(f):
    """Any signed-in user (admin or employee)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not _authenticate():
            return _unauthorized()
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        identity = _authenticate()
        if not identity:
            return _unauthorized()
        if identity['role'] != config.ROLE_ADMIN:
            return jsonify({'error': 'Access Denied: Administrator role required.', 'code': 'FORBIDDEN'}), 403
        return f(*args, **kwargs)
    return decorated_function


def employee_required(f):
    """Employee-only. Every query is scoped to g.auth['user_id'] (this request's own user)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        identity = _authenticate()
        if not identity:
            return _unauthorized()
        if identity['role'] != config.ROLE_EMPLOYEE:
            return jsonify({'error': 'Access Denied: Employee account required.', 'code': 'FORBIDDEN'}), 403
        return f(*args, **kwargs)
    return decorated_function


@api_bp.after_request
def _no_cache(resp):
    # Never let a browser/back-button serve another user's data from cache.
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Vary'] = 'Authorization'
    return resp


# ==========================================
# AUTHENTICATION (separate Admin / Employee sign-in)
# ==========================================

def public_identity(identity):
    """The six separated profile fields (never includes the password)."""
    return {
        'role_type': identity['role'],              # 'admin' | 'employee' (portal)
        'name': identity['full_name'],
        'id': identity['emp_id'],
        'username': identity['username'],
        'department': identity['department'],
        'role': identity['job_role'],               # job title
        'user_id': identity['user_id'],
    }


@api_bp.route('/auth/login', methods=['POST'])
def auth_login():
    data = request.get_json(silent=True) or {}
    portal = str(data.get('portal', '')).lower()
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))

    if portal not in (config.ROLE_ADMIN, config.ROLE_EMPLOYEE):
        return jsonify({'error': 'Please choose Employee or Admin sign-in.'}), 400
    if not username or not password:
        return jsonify({'error': 'Please enter both your username and password.'}), 400

    if portal == config.ROLE_ADMIN:
        if not auth_service.check_admin_credentials(username, password):
            return jsonify({'error': 'Invalid admin credentials.'}), 401
        token = auth_service.create_session(config.ROLE_ADMIN, config.ADMIN_USERNAME)
        redirect_to = '/'
    else:
        user, err = auth_service.check_employee_credentials(username, password)
        if err == 'disabled':
            return jsonify({'error': 'This account has been disabled by a security administrator.'}), 403
        if not user:
            return jsonify({'error': 'Invalid employee credentials. Please verify your username and password.'}), 401
        token = auth_service.create_session(config.ROLE_EMPLOYEE, user['username'], user['id'])
        redirect_to = '/member'

    identity = auth_service.resolve_session(token)
    return jsonify({'token': token, 'redirect': redirect_to, 'user': public_identity(identity)})


@api_bp.route('/auth/me')
@login_required
def auth_me():
    return jsonify(public_identity(g.auth))


@api_bp.route('/auth/logout', methods=['POST'])
def auth_logout():
    token = _token_from_request()
    identity = auth_service.resolve_session(token)
    if identity and identity['role'] == config.ROLE_EMPLOYEE:
        data_service.log_logout(identity['user_id'])
    auth_service.delete_session(token)
    return jsonify({'success': True})


# ==========================================
# ADMIN DASHBOARD & CORE ENDPOINTS
# ==========================================

@api_bp.route('/dashboard')
@admin_required
def dashboard():
    try:
        stats = data_service.get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/users')
@admin_required
def users():
    try:
        search = request.args.get('search', '')
        risk = request.args.get('risk', '')
        department = request.args.get('department', '')
        status = request.args.get('status', '')
        result = data_service.get_all_users(
            search=search if search else None,
            risk_filter=risk if risk else None,
            department_filter=department if department else None,
            status_filter=status if status else None
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/departments')
@admin_required
def departments():
    try:
        depts = data_service.get_departments()
        return jsonify(depts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/users/<int:user_id>')
@admin_required
def user_detail(user_id):
    try:
        user = data_service.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'Employee record not found'}), 404
        return jsonify(user)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# EMPLOYEE CRUD (ADMIN ONLY)
# ==========================================

@api_bp.route('/employees', methods=['POST'])
@admin_required
def create_employee():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request payload required'}), 400
        user_id, error = data_service.create_employee(data)
        if error:
            return jsonify({'error': error}), 400
        created = data_service.get_user_by_id(user_id)
        return jsonify({'message': 'Employee created successfully', 'employee': created}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/employees/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_employee(user_id):
    try:
        ok, error = data_service.delete_employee(user_id)
        if not ok:
            return jsonify({'error': error}), 404 if error == 'Employee not found.' else 400
        return jsonify({'message': 'Employee removed successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/employees/<int:user_id>', methods=['PUT'])
@admin_required
def update_employee(user_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request payload required'}), 400

        success, error = data_service.update_employee(user_id, data)
        if not success:
            return jsonify({'error': error}), 400

        updated = data_service.get_user_by_id(user_id)
        return jsonify({'message': 'Employee updated successfully', 'employee': updated})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/employees/<int:user_id>/status', methods=['PUT'])
@admin_required
def set_employee_status(user_id):
    try:
        data = request.get_json() or {}
        new_status = data.get('status', 'active')
        success, final_status = data_service.set_employee_status(user_id, new_status)
        if not success:
            return jsonify({'error': 'Failed to update employee status'}), 400
        return jsonify({'message': f'Employee status changed to {final_status}', 'status': final_status})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# THREAT SIMULATOR ENDPOINTS
# ==========================================

@api_bp.route('/scenarios')
@admin_required
def get_scenarios():
    """Return all available threat simulation scenarios."""
    try:
        scenarios = threat_detector.get_simulation_scenarios()
        return jsonify(scenarios)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/simulate', methods=['POST'])
@admin_required
def simulate():
    """Run a threat simulation on an employee."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request payload required'}), 400

        user_id = data.get('user_id')
        scenario_key = data.get('scenario_key')
        create_alert = data.get('create_alert', True)

        if not user_id or not scenario_key:
            return jsonify({'error': 'Both user_id and scenario_key are required'}), 400

        result, error = data_service.run_simulation(user_id, scenario_key, create_alert=create_alert)
        if error:
            return jsonify({'error': error}), 400

        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/simulations')
@admin_required
def list_simulations():
    """List simulation history."""
    try:
        user_id = request.args.get('user_id', type=int)
        limit = request.args.get('limit', 50, type=int)
        results = data_service.get_simulations(user_id=user_id, limit=min(limit, 100))
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# ALERTS & INCIDENTS & ACTIONS
# ==========================================

@api_bp.route('/incidents')
@admin_required
def incidents():
    try:
        severity = request.args.get('severity', '')
        status = request.args.get('status', '')
        inc_type = request.args.get('type', '')
        result = data_service.get_incidents(
            severity_filter=severity if severity else None,
            status_filter=status if status else None,
            type_filter=inc_type if inc_type else None
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/incidents/<int:incident_id>')
@admin_required
def incident_detail(incident_id):
    try:
        incident = data_service.get_incident_by_id(incident_id)
        if not incident:
            return jsonify({'error': 'Incident not found'}), 404
        return jsonify(incident)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/incidents', methods=['POST'])
@admin_required
def create_incident():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400

        incident_id, error = data_service.create_incident(data)
        if error:
            return jsonify({'error': error}), 400

        incident = data_service.get_incident_by_id(incident_id)
        return jsonify(incident), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/incidents/<int:incident_id>', methods=['PUT'])
@admin_required
def update_incident(incident_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400

        success, error = data_service.update_incident(incident_id, data)
        if not success:
            return jsonify({'error': error}), 400

        incident = data_service.get_incident_by_id(incident_id)
        return jsonify(incident)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/alerts/<int:alert_id>/action', methods=['POST'])
@admin_required
def alert_action(alert_id):
    """
    Execute task actions inside alerts:
    review_activity, verify_usb, check_files, mark_reviewed, resolve_alert, quarantine
    """
    try:
        data = request.get_json() or {}
        action_type = data.get('action')
        if not action_type:
            return jsonify({'error': 'Action type required'}), 400

        result, error = data_service.execute_alert_action(alert_id, action_type, context=data)
        if error:
            return jsonify({'error': error}), 400

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# ACTIVITY LOGS & THREAT ANALYSIS & REPORTS
# ==========================================

@api_bp.route('/activity')
@admin_required
def activity():
    try:
        search = request.args.get('search', '')
        status = request.args.get('status', '')
        limit = request.args.get('limit', 50, type=int)
        result = data_service.get_activity_logs(
            search=search if search else None,
            status_filter=status if status else None,
            limit=min(limit, 200)
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/reports/summary')
@admin_required
def reports_summary():
    try:
        summary = data_service.get_reports_summary()
        return jsonify(summary)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/threat-analysis')
@admin_required
def threat_analysis():
    try:
        result = data_service.get_threat_analysis()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/tracker/daily')
@admin_required
def daily_tracker():
    try:
        department = request.args.get('department', '')
        tracker_data = data_service.get_daily_subject_tracker(department=department)
        return jsonify(tracker_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# SCOPED EMPLOYEE PORTAL ENDPOINTS (RBAC)
# Employees can ONLY see their own data!
# ==========================================

@api_bp.route('/employee/dashboard')
@employee_required
def employee_dashboard():
    try:
        user_id = g.auth['user_id']
        data = data_service.get_employee_dashboard_data(user_id)
        if not data:
            return jsonify({'error': 'Employee profile not found'}), 404
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/employee/profile')
@employee_required
def employee_profile():
    try:
        user_id = g.auth['user_id']
        user = data_service.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify(user)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/employee/activity')
@employee_required
def employee_activity():
    try:
        user_id = g.auth['user_id']
        limit = request.args.get('limit', 50, type=int)
        acts = data_service.get_employee_activities(user_id, limit=min(limit, 100))
        return jsonify(acts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/employee/alerts')
@employee_required
def employee_alerts():
    try:
        user_id = g.auth['user_id']
        alerts = data_service.get_employee_alerts(user_id)
        return jsonify(alerts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# AUTH / PASSWORD RESET / COMPATIBILITY
# ==========================================

@api_bp.route('/auth/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400

        identity = data.get('identity', '').strip()
        new_password = data.get('new_password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()

        if not identity or not new_password:
            return jsonify({'error': 'Username/Email and new password are required'}), 400

        if new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400

        success, message = data_service.reset_password(identity, new_password)
        if not success:
            return jsonify({'error': message}), 400

        return jsonify({'message': message, 'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Backward compatibility
@api_bp.route('/members', methods=['POST'])
@admin_required
def add_member():
    return create_employee()


@api_bp.route('/tasks', methods=['GET', 'POST'])
@admin_required
def manage_tasks():
    try:
        if request.method == 'GET':
            tasks = data_service.get_all_tasks()
            return jsonify(tasks)
        elif request.method == 'POST':
            data = request.get_json()
            task_id, error = data_service.create_task(data)
            if error:
                return jsonify({'error': error}), 400
            return jsonify({'message': 'Task created', 'id': task_id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/tasks/me', methods=['GET'])
@employee_required
def get_my_tasks():
    try:
        tasks = data_service.get_tasks_for_user(g.auth['username'])
        return jsonify(tasks)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/tasks/<int:task_id>', methods=['PUT'])
@admin_required
def update_task(task_id):
    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'error': 'Status required'}), 400
        success, error = data_service.update_task_status(task_id, data['status'])
        if not success:
            return jsonify({'error': error}), 400
        return jsonify({'message': 'Task updated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
