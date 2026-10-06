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


if __name__ == '__main__':
    try:
        unittest.main(verbosity=2, exit=False)
    finally:
        shutil.rmtree(_tmpdir, ignore_errors=True)
