"""Authentication and session management.

Local development uses the original SQLite-backed server-side sessions.
Vercel/serverless uses signed, stateless bearer tokens because /tmp storage is
per-instance and cannot reliably hold a session between separate invocations.
Employee status is still re-read from SQLite on every request, so disabled or
deleted employees lose access even with a previously issued token.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from backend import config
from backend.utils.db import get_db, dict_from_row

_FMT = '%Y-%m-%d %H:%M:%S'
_IS_VERCEL = os.environ.get('VERCEL') == '1'


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _session_secret():
    """Return a stable signing secret for serverless tokens.

    Prefer THREATSIM_SESSION_SECRET in Vercel. For a zero-configuration demo,
    fall back to a value derived from the admin password so the secret remains
    stable across invocations without putting another required setting in the
    deployment.
    """
    explicit = os.environ.get('THREATSIM_SESSION_SECRET')
    if explicit:
        return explicit.encode('utf-8')
    return ('threatsim-session-v1|' + config.ADMIN_PASSWORD).encode('utf-8')


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def _create_serverless_token(kind, username, user_id=None):
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        'v': 1,
        'role': kind,
        'username': username,
        'user_id': user_id,
        'iat': now,
        'exp': now + config.SESSION_MAX_LIFETIME,
        'jti': secrets.token_urlsafe(12),
    }
    raw = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    body = _b64e(raw)
    sig = hmac.new(_session_secret(), body.encode('ascii'), hashlib.sha256).digest()
    return 'v1.' + body + '.' + _b64e(sig)


def _read_serverless_token(token):
    try:
        prefix, body, signature = token.split('.', 2)
        if prefix != 'v1':
            return None
        expected = hmac.new(_session_secret(), body.encode('ascii'), hashlib.sha256).digest()
        supplied = _b64d(signature)
        if not hmac.compare_digest(expected, supplied):
            return None
        payload = json.loads(_b64d(body).decode('utf-8'))
        now = int(datetime.now(timezone.utc).timestamp())
        if payload.get('v') != 1 or int(payload.get('exp', 0)) <= now:
            return None
        if payload.get('role') not in (config.ROLE_ADMIN, config.ROLE_EMPLOYEE):
            return None
        return payload
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeError):
        return None


def init_session_table():
    # A serverless token does not need a database session row. Keeping this a
    # no-op on Vercel also avoids pretending that ephemeral SQLite is a
    # persistent session store.
    if _IS_VERCEL:
        return
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
    if _IS_VERCEL:
        return _create_serverless_token(kind, username, user_id)

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
    if _IS_VERCEL:
        # Stateless bearer tokens are invalidated client-side on logout. An
        # employee deletion/disable is also checked on every resolve_session.
        return
    conn = get_db()
    try:
        conn.execute('DELETE FROM auth_sessions WHERE token = ?', (token,))
        conn.commit()
    finally:
        conn.close()


def purge_expired():
    if _IS_VERCEL:
        return
    now = _now()
    idle_cut = (now - timedelta(seconds=config.SESSION_IDLE_TIMEOUT)).strftime(_FMT)
    life_cut = (now - timedelta(seconds=config.SESSION_MAX_LIFETIME)).strftime(_FMT)
    conn = get_db()
    try:
        conn.execute('DELETE FROM auth_sessions WHERE last_seen < ? OR created_at < ?', (idle_cut, life_cut))
        conn.commit()
    finally:
        conn.close()


def _identity_from_employee(conn, user_id):
    u = conn.execute(
        'SELECT id, emp_id, username, full_name, department, role, status FROM users WHERE id = ? AND is_admin = 0',
        (user_id,)).fetchone()
    if not u or u['status'] in ('disabled', 'inactive'):
        return None
    return {
        'role': config.ROLE_EMPLOYEE,
        'is_admin': False,
        'user_id': u['id'],
        'username': u['username'],
        'full_name': u['full_name'],
        'emp_id': u['emp_id'] or f"EMP-{u['id']}",
        'department': u['department'],
        'job_role': u['role'],
    }


def resolve_session(token):
    """Validate a token and return the live identity for this request."""
    if not token:
        return None

    if _IS_VERCEL:
        payload = _read_serverless_token(token)
        if not payload:
            return None
        conn = get_db()
        try:
            if payload['role'] == config.ROLE_ADMIN:
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
                identity = _identity_from_employee(conn, payload.get('user_id'))
                if identity is None:
                    return None
            identity['token'] = token
            return identity
        finally:
            conn.close()

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
            identity = _identity_from_employee(conn, sess['user_id'])
            if identity is None:
                conn.execute('DELETE FROM auth_sessions WHERE token = ?', (token,))
                conn.commit()
                return None

        if (now - last_seen).total_seconds() > 30:
            conn.execute('UPDATE auth_sessions SET last_seen = ? WHERE token = ?', (now.strftime(_FMT), token))
            conn.commit()
        identity['token'] = token
        return identity
    finally:
        conn.close()
