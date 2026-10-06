"""Create or repair the employee logins aryan and swara.

Run from the project folder:   python restore_employees.py
Safe to run more than once: it resets their password and re-enables the account.
"""
import sqlite3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from werkzeug.security import generate_password_hash
from database.init_db import init_database
from backend.utils.db import DB_PATH

ACCOUNTS = [
    # username, password, emp_id, full name, department, role
    ('aryan', 'aryan07', 'EMP-1012', 'Aryan', 'Engineering', 'Member'),
    ('swara', 'swara123', 'EMP-1013', 'Swara', 'HR', 'Member'),
]

init_database()
conn = sqlite3.connect(DB_PATH)
for username, pw, emp_id, name, dept, role in ACCOUNTS:
    row = conn.execute('SELECT id FROM users WHERE LOWER(username) = ?', (username,)).fetchone()
    h = generate_password_hash(pw)
    if row:
        conn.execute("UPDATE users SET password=?, status='active', is_admin=0 WHERE id=?", (h, row[0]))
        print(f'Repaired  {username}')
    else:
        conn.execute(
            "INSERT INTO users (emp_id, username, full_name, department, role, email, status, risk_score, password, is_admin) "
            "VALUES (?,?,?,?,?,?,'active',0,?,0)",
            (emp_id, username, name, dept, role, f'{username}@corp.local', h))
        print(f'Created   {username}')
conn.commit()
print('\nDatabase:', DB_PATH)
print('Logins ->  aryan / aryan07     swara / swara123   (Employee tab)')
