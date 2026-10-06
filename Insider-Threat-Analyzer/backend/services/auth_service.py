"""Server-side session management.

Why not Flask's cookie session?
  A cookie is shared by every tab of the same browser, so logging in as a
  second user in another tab silently overwrote the first user's session.

How this works instead:
  * Every login creates a random, unguessable token stored in the
    `auth_sessions` table (one row per login).
  * The browser keeps that token in `sessionStorage`, which is private to a
    single tab, and sends it as `Authorization: Bearer <token>` on every API
    call.
  * Each request therefore resolves its own identity, so any number of tabs or
    browsers (Chrome, Edge, ...) can be logged in as different people at once
    without overlap. A page refresh keeps the token, so the session survives.
"""

import hmac
import secrets
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from backend import config
from backend.utils.db import get_db, dict_from_row

_FMT = '%Y-%m-%d %H:%M:%S'


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def init_session_table():
    conn = get_db()
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                user_id INTEGER,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        ''')
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Credential checks
# ---------------------------------------------------------------------------

def check_admin_credentials(username, password):
    """Constant-time, case-sensitive check against the fixed admin account."""
    ok_user = hmac.compare_digest(str(username).encode(), config.ADMIN_USERNAME.encode())
    ok_pass = hmac.compare_digest(str(password).encode(), config.ADMIN_PASSWORD.encode())
    return ok_user and ok_pass


def check_employee_credentials(username, password):
    """Return (employee_row_dict, error). Never matches an admin row."""
    conn = get_db()
    try:
        row = conn.execute(
            'SELECT * FROM users WHERE LOWER(username) = LOWER(?) AND is_admin = 0',
            (username.strip(),)
        ).fetchone()
        if not row:
            return None, 'invalid'
        user = dict_from_row(row)
        stored = user.get('password')
        if not stored:
            return None, 'invalid'

        if stored.startswith(('scrypt:', 'pbkdf2:')):
            valid = check_password_hash(stored, password)
        else:
            # legacy plaintext value: compare, then upgrade to a hash
            valid = hmac.compare_digest(stored.encode(), password.encode())
            if valid:
                conn.execute('UPDATE users SET password = ? WHERE id = ?',
                             (generate_password_hash(password), user['id']))
                conn.commit()
        if not valid:
            return None, 'invalid'

        if user.get('status') in ('disabled', 'inactive'):
            return None, 'disabled'

        try:
            conn.execute('''
                INSERT INTO activity_logs (user_id, activity_type, description, ip_address, device, timestamp, risk_score, status)
                VALUES (?, 'login', 'User authenticated to security portal', '127.0.0.1', 'Web Terminal', datetime('now'), 0, 'normal')
            ''', (user['id'],))
            conn.execute("UPDATE users SET last_activity = datetime('now') WHERE id = ?", (user['id'],))
            conn.commit()
        except Exception:
            pass
        return user, None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------

def create_session(kind, username, user_id=None):
    token = secrets.token_urlsafe(32)
    now = _now().strftime(_FMT)
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO auth_sessions (token, kind, user_id, username, created_at, last_seen) VALUES (?,?,?,?,?,?)',
            (token, kind, user_id, username, now, now))
        conn.commit()
    finally:
        conn.close()
    purge_expired()
    return token


def delete_session(token):
    if not token:
        return
    conn = get_db()
    try:
        conn.execute('DELETE FROM auth_sessions WHERE token = ?', (token,))
        conn.commit()
    finally:
        conn.close()


def purge_expired():
    now = _now()
    idle_cut = (now - timedelta(seconds=config.SESSION_IDLE_TIMEOUT)).strftime(_FMT)
    life_cut = (now - timedelta(seconds=config.SESSION_MAX_LIFETIME)).strftime(_FMT)
    conn = get_db()
    try:
        conn.execute('DELETE FROM auth_sessions WHERE last_seen < ? OR created_at < ?', (idle_cut, life_cut))
        conn.commit()
    finally:
        conn.close()


def resolve_session(token):
    """Validate a token and return the *live* identity for this request.

    Employee identity is re-read from the database on every call, so a
    disabled or deleted employee loses access immediately and profile edits
    show up in real time. Returns None when the token is missing/invalid.
    """
    if not token:
        return None
    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM auth_sessions WHERE token = ?', (token,)).fetchone()
        if not row:
            return None
        sess = dict_from_row(row)
        now = _now()
        try:
            last_seen = datetime.strptime(sess['last_seen'], _FMT)
            created = datetime.strptime(sess['created_at'], _FMT)
        except ValueError:
            conn.execute('DELETE FROM auth_sessions WHERE token = ?', (token,))
            conn.commit()
            return None
        if (now - last_seen).total_seconds() > config.SESSION_IDLE_TIMEOUT or \
           (now - created).total_seconds() > config.SESSION_MAX_LIFETIME:
            conn.execute('DELETE FROM auth_sessions WHERE token = ?', (token,))
            conn.commit()
            return None

        if sess['kind'] == config.ROLE_ADMIN:
            identity = {
                'role': config.ROLE_ADMIN,
                'is_admin': True,
                'user_id': None,
                'username': config.ADMIN_USERNAME,
                'full_name': config.ADMIN_DISPLAY_NAME,
                'emp_id': None,
                'department': 'Administration',
                'job_role': 'Administrator',
            }
        else:
            u = conn.execute(
                'SELECT id, emp_id, username, full_name, department, role, status FROM users WHERE id = ? AND is_admin = 0',
                (sess['user_id'],)).fetchone()
            if not u or u['status'] in ('disabled', 'inactive'):
                conn.execute('DELETE FROM auth_sessions WHERE token = ?', (token,))
                conn.commit()
                return None
            identity = {
                'role': config.ROLE_EMPLOYEE,
                'is_admin': False,
                'user_id': u['id'],
                'username': u['username'],
                'full_name': u['full_name'],
                'emp_id': u['emp_id'] or f"EMP-{u['id']}",
                'department': u['department'],
                'job_role': u['role'],
            }

        # sliding expiry (only write if it has moved by 30s+ to limit DB churn)
        if (now - last_seen).total_seconds() > 30:
            conn.execute('UPDATE auth_sessions SET last_seen = ? WHERE token = ?', (now.strftime(_FMT), token))
            conn.commit()
        identity['token'] = token
        return identity
    finally:
        conn.close()
