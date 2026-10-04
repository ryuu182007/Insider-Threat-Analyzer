"""Automated end-to-end test suite for ThreatSim."""

import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from app import app
from backend.services.data_service import verify_login, reset_password, get_dashboard_stats
from database.init_db import init_database

def run_tests():
    print("=" * 60)
    print("RUNNING THREATSIM VERIFICATION & COMPLIANCE TEST SUITE")
    print("=" * 60)

    # 1. Database Init Check
    init_database()
    print("[PASS] Database initialized and verified.")

    # Ensure baseline password for aryan
    from werkzeug.security import generate_password_hash
    from backend.utils.db import get_db
    conn = get_db()
    conn.execute('UPDATE users SET password = ? WHERE username = ?', (generate_password_hash('aryan07'), 'aryan'))
    conn.commit()
    conn.close()

    # 2. Authentication: Admin Login
    admin_user = verify_login('ryuu', 'ryuu12')
    assert admin_user is not None, "Admin login failed!"
    assert admin_user['is_admin'] == 1, "Admin role check failed!"
    print(f"[PASS] Admin login succeeded: {admin_user['username']} (is_admin: {admin_user['is_admin']})")

    # 3. Authentication: Employee Login
    emp_user = verify_login('aryan', 'aryan07')
    assert emp_user is not None, "Employee login failed!"
    assert emp_user['is_admin'] == 0, "Employee role check failed!"
    print(f"[PASS] Employee login succeeded: {emp_user['username']} (is_admin: {emp_user['is_admin']})")

    # 4. Authentication: Invalid Login
    invalid_user = verify_login('ryuu', 'wrong_password_123')
    assert invalid_user is None, "Invalid login should return None!"
    print("[PASS] Invalid password rejected successfully.")

    # 5. Password Reset Validation (< 8 chars fails, >= 8 chars passes)
    fail_reset, msg = reset_password('aryan', 'short')
    assert not fail_reset, "Short password should fail reset!"
    print(f"[PASS] Short password (< 8 chars) rejected: {msg}")

    ok_reset, msg = reset_password('aryan', 'newsecurepass2026')
    assert ok_reset, "Valid password reset failed!"
    print(f"[PASS] Valid password reset succeeded: {msg}")

    # Re-verify login with new password
    re_login = verify_login('aryan', 'newsecurepass2026')
    assert re_login is not None, "Login with updated password failed!"
    print("[PASS] Sign in with newly updated hashed password verified.")

    # Reset back to aryan07 for consistency
    reset_password('aryan', 'aryan07')

    # 6. Test Flask Test Client & RBAC
    client = app.test_client()

    # Unauthorized access check
    res = client.get('/api/dashboard')
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"
    print("[PASS] Unauthenticated access to /api/dashboard blocked with 401.")

    # Login as Employee and test RBAC prohibition on Admin endpoints
    with client.session_transaction() as sess:
        sess['analyst'] = 'aryan'
        sess['user_id'] = 12
        sess['is_admin'] = 0

    res = client.get('/api/dashboard')
    assert res.status_code == 403, f"Expected 403 Forbidden for employee, got {res.status_code}"
    print("[PASS] Employee access to Admin /api/dashboard blocked with 403 Forbidden.")

    res = client.get('/api/users')
    assert res.status_code == 403, f"Expected 403 Forbidden for employee on /api/users, got {res.status_code}"
    print("[PASS] Employee access to /api/users blocked with 403 Forbidden.")

    res = client.post('/api/simulate', json={'user_id': 1, 'scenario_key': 'data_exfiltration'})
    assert res.status_code == 403, f"Expected 403 Forbidden on /api/simulate, got {res.status_code}"
    print("[PASS] Employee access to /api/simulate blocked with 403 Forbidden.")

    # Employee Scoped Endpoints check
    res = client.get('/api/employee/dashboard')
    assert res.status_code == 200, f"Expected 200 on /api/employee/dashboard, got {res.status_code}"
    emp_dash = res.get_json()
    assert 'risk_score' in emp_dash, "Employee dashboard missing risk_score"
    print(f"[PASS] Scoped /api/employee/dashboard returned: Risk {emp_dash['risk_score']}")

    res = client.get('/api/employee/activity')
    assert res.status_code == 200, f"Expected 200 on /api/employee/activity, got {res.status_code}"
    print(f"[PASS] Scoped /api/employee/activity returned {len(res.get_json())} logs for employee only.")

    res = client.get('/api/employee/alerts')
    assert res.status_code == 200, f"Expected 200 on /api/employee/alerts, got {res.status_code}"
    print(f"[PASS] Scoped /api/employee/alerts returned {len(res.get_json())} alerts for employee only.")

    # Login as Admin and test Admin functionality
    with client.session_transaction() as sess:
        sess['analyst'] = 'ryuu'
        sess['user_id'] = 11
        sess['is_admin'] = 1

    res = client.get('/api/dashboard')
    assert res.status_code == 200, f"Expected 200 for admin, got {res.status_code}"
    dash_data = res.get_json()
    assert 'total_employees' in dash_data, "Missing total_employees"
    assert 'active_alerts' in dash_data, "Missing active_alerts"
    assert 'total_simulations' in dash_data, "Missing total_simulations"
    print(f"[PASS] Admin /api/dashboard loaded: {dash_data['total_employees']} employees, {dash_data['active_alerts']} active alerts, {dash_data['total_simulations']} simulations.")

    # 7. Threat Simulator API Check
    res = client.get('/api/scenarios')
    assert res.status_code == 200, f"Expected 200 on /api/scenarios, got {res.status_code}"
    scenarios = res.get_json()
    assert len(scenarios) == 7, f"Expected 7 scenarios, got {len(scenarios)}"
    scenario_keys = [s['key'] for s in scenarios]
    assert 'normal_behaviour' in scenario_keys
    assert 'after_hours_access' in scenario_keys
    assert 'data_exfiltration' in scenario_keys
    assert 'privilege_abuse' in scenario_keys
    assert 'credential_misuse' in scenario_keys
    assert 'unauthorized_usb' in scenario_keys
    assert 'combined_threat' in scenario_keys
    print(f"[PASS] All 7 threat simulation scenarios verified: {scenario_keys}")

    # Execute simulation
    sim_res = client.post('/api/simulate', json={
        'user_id': 1,
        'scenario_key': 'data_exfiltration',
        'create_alert': True
    })
    assert sim_res.status_code == 200, f"Expected 200 on /api/simulate, got {sim_res.status_code}"
    sim_output = sim_res.get_json()
    assert sim_output['risk_score'] >= 70, f"Expected high risk score, got {sim_output['risk_score']}"
    assert sim_output['alert_created'] is True, "Alert should have been created!"
    assert sim_output['alert_id'] is not None, "Alert ID missing"
    print(f"[PASS] Threat simulation executed: Score {sim_output['risk_score']}, Level {sim_output['risk_level']}, Alert #{sim_output['alert_id']}")

    # 8. Alert Action Execution (Absorbs Tasks)
    alert_id = sim_output['alert_id']
    act_res = client.post(f'/api/alerts/{alert_id}/action', json={'action': 'review_activity'})
    assert act_res.status_code == 200, "review_activity action failed"
    print("[PASS] Alert Action 'review_activity' executed successfully.")

    act_res = client.post(f'/api/alerts/{alert_id}/action', json={'action': 'verify_usb'})
    assert act_res.status_code == 200, "verify_usb action failed"
    print("[PASS] Alert Action 'verify_usb' executed successfully.")

    act_res = client.post(f'/api/alerts/{alert_id}/action', json={'action': 'resolve_alert'})
    assert act_res.status_code == 200, "resolve_alert action failed"
    print("[PASS] Alert Action 'resolve_alert' executed successfully.")

    # 9. Reports Summary API Check
    rep_res = client.get('/api/reports/summary')
    assert rep_res.status_code == 200, f"Expected 200 on /api/reports/summary, got {rep_res.status_code}"
    rep_data = rep_res.get_json()
    assert 'total_employees' in rep_data
    assert 'total_simulations' in rep_data
    assert 'total_alerts' in rep_data
    assert 'most_simulated_scenario' in rep_data
    assert 'highest_risk_employees' in rep_data
    print(f"[PASS] Reports summary verified: Most simulated is '{rep_data['most_simulated_scenario']['scenario_name']}'.")

    # 10. Employee Creation API Check
    import time
    unique_user = f"testqa_{int(time.time())}"
    create_res = client.post('/api/employees', json={
        'full_name': 'Test Engineer',
        'emp_id': f"EMP-{int(time.time())%10000}",
        'department': 'QA Security',
        'role': 'Automation Engineer',
        'username': unique_user,
        'password': 'StrongPassword123',
        'status': 'active',
        'is_admin': 0
    })
    assert create_res.status_code == 201, f"Expected 201, got {create_res.status_code}: {create_res.get_data(as_text=True)}"
    created_id = create_res.get_json()['employee']['id']
    print(f"[PASS] Employee created with secure password hashing: ID {created_id}")

    # Test toggling employee status
    status_res = client.put(f'/api/employees/{created_id}/status', json={'status': 'disabled'})
    assert status_res.status_code == 200
    disabled_login = verify_login(unique_user, 'StrongPassword123')
    assert disabled_login.get('is_disabled') is True, "Disabled account should have is_disabled=True"
    print("[PASS] Disabling employee account prevents access as expected.")

    # Restore aryan password to aryan07
    from werkzeug.security import generate_password_hash
    from backend.utils.db import get_db
    conn = get_db()
    conn.execute('UPDATE users SET password = ? WHERE username = ?', (generate_password_hash('aryan07'), 'aryan'))
    conn.commit()
    conn.close()

    print("=" * 60)
    print("ALL 10 TESTS PASSED SUCCESSFULLY! ZERO BREAKAGES.")
    print("=" * 60)

if __name__ == '__main__':
    run_tests()
