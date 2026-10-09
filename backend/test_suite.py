"""Authentication / session / isolation tests.  Run:  python -m backend.test_suite

Runs against a throw-away copy of the database, so real data is never touched.
"""

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash
from backend.utils import db as dbmod

_tmpdir = tempfile.mkdtemp()
_tmpdb = os.path.join(_tmpdir, 'test.db')
shutil.copy(dbmod.DB_PATH, _tmpdb)
dbmod.DB_PATH = _tmpdb            # every get_db() call now uses the copy
dbmod._initialized = True

from database import migrate
migrate.DB_PATH = _tmpdb
from app import app                # noqa: E402
from backend.services import auth_service  # noqa: E402


def _add_employee(username, emp_id, name, dept, role, password):
    # Employee creation is disabled in the app, so tests insert rows directly.
    conn = sqlite3.connect(_tmpdb)
    conn.execute(
        "INSERT INTO users (emp_id, username, full_name, department, role, email, status, risk_score, password, is_admin) "
        "VALUES (?,?,?,?,?,?,'active',0,?,0)",
        (emp_id, username, name, dept, role, f'{username}@corp.local', generate_password_hash(password)))
    conn.commit()
    conn.close()


def H(token):
    return {'Authorization': 'Bearer ' + token}


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        migrate.run_migration()
        auth_service.init_session_table()
        _add_employee('emp_one', 'E-1', 'Employee One', 'Finance', 'Analyst', 'Password-One1')
        _add_employee('emp_two', 'E-2', 'Employee Two', 'HR', 'Manager', 'Password-Two2')
        cls.c = app.test_client()   # ONE cookie jar: simulates several tabs of one browser

    def login(self, portal, user, pw):
        r = self.c.post('/api/auth/login', json={'portal': portal, 'username': user, 'password': pw})
        return r.status_code, r.get_json()

    def test_01_no_demo_accounts_left(self):
        conn = sqlite3.connect(_tmpdb)
        names = {r[0] for r in conn.execute('SELECT username FROM users')}
        conn.close()
        for gone in ('rkumar', 'ppatel', 'ryuu', 'testqa_emp'):
            self.assertNotIn(gone, names)

    def test_02_admin_fixed_credentials(self):
        self.assertEqual(self.login('admin', 'Ryuu', 'Ryuu12')[0], 200)
        self.assertEqual(self.login('admin', 'ryuu', 'Ryuu12')[0], 401)      # case-sensitive
        self.assertEqual(self.login('admin', 'Ryuu', 'wrong')[0], 401)
        self.assertEqual(self.login('employee', 'Ryuu', 'Ryuu12')[0], 401)   # not valid in employee section

    def test_03_employee_cannot_use_admin_section(self):
        self.assertEqual(self.login('admin', 'emp_one', 'Password-One1')[0], 401)

    def test_04_two_sessions_do_not_overlap(self):
        _, a = self.login('employee', 'emp_one', 'Password-One1')
        _, b = self.login('employee', 'emp_two', 'Password-Two2')
        me_a = self.c.get('/api/auth/me', headers=H(a['token'])).get_json()
        me_b = self.c.get('/api/auth/me', headers=H(b['token'])).get_json()
        self.assertEqual(me_a['username'], 'emp_one')
        self.assertEqual(me_b['username'], 'emp_two')
        for key in ('name', 'id', 'username', 'department', 'role'):
            self.assertIn(key, me_a)
        self.assertNotIn('password', me_a)
        # "refresh" = same token again
        self.assertEqual(self.c.get('/api/auth/me', headers=H(a['token'])).get_json()['username'], 'emp_one')

    def test_05_role_fences(self):
        _, a = self.login('employee', 'emp_one', 'Password-One1')
        _, adm = self.login('admin', 'Ryuu', 'Ryuu12')
        self.assertEqual(self.c.get('/api/users', headers=H(a['token'])).status_code, 403)
        self.assertEqual(self.c.get('/api/employee/dashboard', headers=H(adm['token'])).status_code, 403)
        self.assertEqual(self.c.get('/api/users').status_code, 401)

    def test_06_admin_can_add_and_remove_employees(self):
        _, adm = self.login('admin', 'Ryuu', 'Ryuu12')
        h = H(adm['token'])
        new = {'full_name': 'New Hire', 'department': 'Ops', 'role': 'Clerk', 'username': 'newhire',
               'password': 'Newhire-123', 'emp_id': 'E-99', 'is_admin': 1}
        r = self.c.post('/api/employees', json=new, headers=h)
        self.assertEqual(r.status_code, 201)
        uid = r.get_json()['employee']['id']
        self.assertEqual(r.get_json()['employee']['is_admin'], 0)           # can never create an admin
        self.assertEqual(self.c.post('/api/employees', json=new, headers=h).status_code, 400)   # duplicate
        self.assertEqual(self.c.post('/api/employees', json=dict(new, username='ryuu', emp_id='E-98'), headers=h).status_code, 400)
        code, tok = self.login('employee', 'newhire', 'Newhire-123')
        self.assertEqual(code, 200)
        self.assertEqual(self.c.delete(f'/api/employees/{uid}', headers=h).status_code, 200)
        self.assertEqual(self.c.get('/api/auth/me', headers=H(tok['token'])).status_code, 401)  # live session ended
        self.assertEqual(self.login('employee', 'newhire', 'Newhire-123')[0], 401)
        self.assertEqual(self.c.delete(f'/api/employees/{uid}', headers=h).status_code, 404)
        # an employee cannot add/remove
        _, e = self.login('employee', 'emp_one', 'Password-One1')
        self.assertEqual(self.c.post('/api/employees', json=new, headers=H(e['token'])).status_code, 403)

    def test_07_no_password_in_admin_listing(self):
        _, adm = self.login('admin', 'Ryuu', 'Ryuu12')
        users = self.c.get('/api/users', headers=H(adm['token'])).get_json()
        self.assertTrue(users)
        self.assertFalse(any('password' in u for u in users))

    def test_08_logout_and_disable_are_per_session(self):
        _, a = self.login('employee', 'emp_one', 'Password-One1')
        _, b = self.login('employee', 'emp_two', 'Password-Two2')
        self.c.post('/api/auth/logout', headers=H(a['token']))
        self.assertEqual(self.c.get('/api/auth/me', headers=H(a['token'])).status_code, 401)
        self.assertEqual(self.c.get('/api/auth/me', headers=H(b['token'])).status_code, 200)
        _, adm = self.login('admin', 'Ryuu', 'Ryuu12')
        uid = b['user']['user_id']
        self.c.put(f'/api/employees/{uid}/status', json={'status': 'disabled'}, headers=H(adm['token']))
        self.assertEqual(self.c.get('/api/auth/me', headers=H(b['token'])).status_code, 401)

    def register(self, data):
        return self.c.post('/api/auth/register', json=data)

    def test_09_employee_self_signup_success(self):
        auth_service.reset_signup_rate_limits()
        reg_data = {
            'full_name': 'Alex Mercer',
            'emp_id': 'EMP-777',
            'username': 'alex_m',
            'department': 'SecOps',
            'role': 'Incident Handler',
            'password': 'Password-Alex777',
            'confirm_password': 'Password-Alex777'
        }
        res = self.register(reg_data)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data.get('username'), 'alex_m')
        self.assertIn('message', data)
        self.assertNotIn('token', data)  # Do NOT auto-login

    def test_10_signup_duplicate_username(self):
        dup = {
            'full_name': 'Another Alex',
            'emp_id': 'EMP-888',
            'username': 'ALEX_M',  # case-insensitive duplicate check
            'department': 'IT',
            'role': 'Support',
            'password': 'Password-Alex777',
            'confirm_password': 'Password-Alex777'
        }
        res = self.register(dup)
        self.assertEqual(res.status_code, 400)

    def test_11_signup_duplicate_employee_id(self):
        dup = {
            'full_name': 'Duplicate ID Person',
            'emp_id': 'EMP-777',
            'username': 'unique_user_id1',
            'department': 'IT',
            'role': 'Support',
            'password': 'Password-12345',
            'confirm_password': 'Password-12345'
        }
        res = self.register(dup)
        self.assertEqual(res.status_code, 400)
        # Case-insensitive employee ID check
        dup['emp_id'] = 'emp-777'
        dup['username'] = 'unique_user_id2'
        res = self.register(dup)
        self.assertEqual(res.status_code, 400)

    def test_12_signup_reserved_username_ryuu(self):
        for reserved in ('Ryuu', 'ryuu', 'RYUU', 'rYuu'):
            res = self.register({
                'full_name': 'Fake Admin',
                'emp_id': f'EMP-RSV-{reserved}',
                'username': reserved,
                'department': 'IT',
                'role': 'Support',
                'password': 'Password-12345',
                'confirm_password': 'Password-12345'
            })
            self.assertEqual(res.status_code, 400)
            self.assertIn('reserved', res.get_json().get('error', '').lower())

    def test_13_signup_password_validation(self):
        base = {
            'full_name': 'Pass Test',
            'emp_id': 'EMP-PW',
            'username': 'pw_tester',
            'department': 'QA',
            'role': 'Tester',
        }
        # Short password (< 8 chars)
        res_short = self.register(dict(base, password='Short1!', confirm_password='Short1!'))
        self.assertEqual(res_short.status_code, 400)
        self.assertIn('8 characters', res_short.get_json().get('error', ''))

        # Password mismatch
        res_mismatch = self.register(dict(base, password='Password-Valid1', confirm_password='Password-Mismatch2'))
        self.assertEqual(res_mismatch.status_code, 400)
        self.assertIn('match', res_mismatch.get_json().get('error', '').lower())

    def test_14_signup_username_and_fields_validation(self):
        base = {
            'full_name': 'User Test',
            'emp_id': 'EMP-USR',
            'department': 'QA',
            'role': 'Tester',
            'password': 'Password-Valid1',
            'confirm_password': 'Password-Valid1'
        }
        # Too short (< 3 chars)
        self.assertEqual(self.register(dict(base, username='ab')).status_code, 400)
        # Invalid characters (spaces, symbols)
        self.assertEqual(self.register(dict(base, username='bad user!')).status_code, 400)
        # Missing required field
        self.assertEqual(self.register(dict(base, username='valid_user', full_name='')).status_code, 400)

    def test_15_signup_attempt_as_admin_ignored(self):
        auth_service.reset_signup_rate_limits()
        admin_attempt = {
            'full_name': 'Sneaky Employee',
            'emp_id': 'EMP-ADM-ATTEMPT',
            'username': 'sneaky_emp',
            'department': 'Security',
            'role': 'Admin',
            'is_admin': 1,
            'password': 'Password-Sneaky1',
            'confirm_password': 'Password-Sneaky1'
        }
        res = self.register(admin_attempt)
        self.assertEqual(res.status_code, 201)
        # Verify in database: is_admin MUST be 0
        conn = sqlite3.connect(_tmpdb)
        row = conn.execute("SELECT is_admin, password FROM users WHERE username = 'sneaky_emp'").fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 0)
        self.assertTrue(row[1].startswith(('scrypt:', 'pbkdf2:')))  # password hashed, never plain text
        # Cannot log in via admin portal
        self.assertEqual(self.login('admin', 'sneaky_emp', 'Password-Sneaky1')[0], 401)

    def test_16_new_account_login_from_employee_tab(self):
        # alex_m from test_09 can log in via Employee tab
        code, login_data = self.login('employee', 'alex_m', 'Password-Alex777')
        self.assertEqual(code, 200)
        self.assertIn('token', login_data)
        self.assertEqual(login_data['redirect'], '/member')
        # Token works for /api/auth/me
        me = self.c.get('/api/auth/me', headers=H(login_data['token'])).get_json()
        self.assertEqual(me['username'], 'alex_m')
        self.assertEqual(me['name'], 'Alex Mercer')
        self.assertEqual(me['id'], 'EMP-777')
        self.assertEqual(me['role_type'], 'employee')
        # Cannot log in via Admin tab
        self.assertEqual(self.login('admin', 'alex_m', 'Password-Alex777')[0], 401)

    def test_17_new_account_in_admin_employee_list(self):
        _, adm = self.login('admin', 'Ryuu', 'Ryuu12')
        users_res = self.c.get('/api/users', headers=H(adm['token']))
        self.assertEqual(users_res.status_code, 200)
        users = users_res.get_json()
        usernames = [u['username'] for u in users]
        self.assertIn('alex_m', usernames)
        # Admin can edit or disable or remove the new employee
        alex_row = next(u for u in users if u['username'] == 'alex_m')
        alex_id = alex_row['id']
        up_res = self.c.put(f'/api/employees/{alex_id}', json={'department': 'SOC Alpha'}, headers=H(adm['token']))
        self.assertEqual(up_res.status_code, 200)
        dis_res = self.c.put(f'/api/employees/{alex_id}/status', json={'status': 'disabled'}, headers=H(adm['token']))
        self.assertEqual(dis_res.status_code, 200)
        # Disabled user cannot log in
        self.assertEqual(self.login('employee', 'alex_m', 'Password-Alex777')[0], 403)

    def test_18_rate_limiting_abuse_protection(self):
        auth_service.reset_signup_rate_limits()
        for i in range(5):
            r = self.register({
                'full_name': f'Spam User {i}',
                'emp_id': f'EMP-SPAM-{i}',
                'username': f'spam_user_{i}',
                'department': 'Testing',
                'role': 'Bot',
                'password': 'Password-Spam123',
                'confirm_password': 'Password-Spam123'
            })
            self.assertEqual(r.status_code, 201)
        r_blocked = self.register({
            'full_name': 'Spam User 6',
            'emp_id': 'EMP-SPAM-6',
            'username': 'spam_user_6',
            'department': 'Testing',
            'role': 'Bot',
            'password': 'Password-Spam123',
            'confirm_password': 'Password-Spam123'
        })
        self.assertEqual(r_blocked.status_code, 429)
        self.assertIn('Too many sign-up attempts', r_blocked.get_json().get('error', ''))
        auth_service.reset_signup_rate_limits()


if __name__ == '__main__':
    try:
        unittest.main(verbosity=2, exit=False)
    finally:
        shutil.rmtree(_tmpdir, ignore_errors=True)
