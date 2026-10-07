"""Database migration.

* Ensures emp_id exists and is back-filled.
* Ensures the simulations / auth_sessions tables exist.
* One-time purge of every demo, fake and tester account (and their data).
* Enforces unique Username and Employee ID.

NOTE: this module never inserts sample users or sample data.
"""

import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'database', 'insider_threat.db')

PURGE_FLAG = 'demo_accounts_purged_v1'

# Accounts that shipped with the project as demo data, plus the old DB-based admin
# (the admin is now a fixed built-in account that does not live in this table).
DEMO_USERNAMES = {
    'rkumar', 'ppatel', 'asharma', 'ssingh', 'nreddy', 'mmishra', 'agupta',
    'rdas', 'vjain', 'kjoshi', 'aryan', 'swara', 'ryuu',
}
TEST_PREFIXES = ('testqa', 'test_', 'tester')


def _is_fake(row):
    uname = (row['username'] or '').lower()
    return (
        uname in DEMO_USERNAMES
        or uname.startswith(TEST_PREFIXES)
        or row['is_admin'] == 1
        or not row['password']          # no password = cannot be a real login
    )


def purge_demo_accounts(conn):
    """Remove demo/fake/tester employees and everything that belongs to them. Runs once."""
    conn.execute('CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT)')
    if conn.execute('SELECT 1 FROM schema_meta WHERE key = ?', (PURGE_FLAG,)).fetchone():
        return 0

    conn.row_factory = sqlite3.Row
    users = conn.execute('SELECT id, username, password, is_admin FROM users').fetchall()
    doomed = [u['id'] for u in users if _is_fake(u)]

    for uid in doomed:
        for table in ('activity_logs', 'incidents', 'simulations', 'tasks'):
            conn.execute(f'DELETE FROM {table} WHERE user_id = ?', (uid,))
        conn.execute('DELETE FROM users WHERE id = ?', (uid,))

    # Orphans (rows whose user no longer exists)
    for table in ('activity_logs', 'incidents', 'simulations', 'tasks'):
        conn.execute(f'DELETE FROM {table} WHERE user_id NOT IN (SELECT id FROM users)')

    try:
        conn.execute('DELETE FROM auth_sessions WHERE user_id IS NOT NULL AND user_id NOT IN (SELECT id FROM users)')
    except sqlite3.OperationalError:
        pass

    conn.execute('INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)', (PURGE_FLAG, str(len(doomed))))
    conn.row_factory = None
    print(f'Removed {len(doomed)} demo/fake/tester accounts.')
    return len(doomed)


def run_migration():
    if not os.path.exists(DB_PATH):
        print('Database not found, skipping migration.')
        return

    conn = sqlite3.connect(DB_PATH, timeout=15)
    cur = conn.cursor()

    cur.execute('PRAGMA table_info(users)')
    cols = [r[1] for r in cur.fetchall()]
    if 'emp_id' not in cols:
        cur.execute('ALTER TABLE users ADD COLUMN emp_id TEXT')
        print('Added emp_id column to users table.')

    cur.execute("SELECT id FROM users WHERE emp_id IS NULL OR emp_id = ''")
    rows = cur.fetchall()
    for (uid,) in rows:
        cur.execute('UPDATE users SET emp_id = ? WHERE id = ?', (f'EMP-{1000 + uid}', uid))
    if rows:
        print(f'Updated {len(rows)} users with emp_id.')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS simulations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scenario_type TEXT NOT NULL,
            scenario_name TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            indicators TEXT,
            alert_created INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS auth_sessions (
            token TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            user_id INTEGER,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    ''')

    purge_demo_accounts(conn)

    # Strict separation: each employee has a unique Username and a unique ID.
    for stmt in (
        'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_ci ON users(LOWER(username))',
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_emp_id ON users(emp_id) WHERE emp_id IS NOT NULL AND emp_id != ''",
    ):
        try:
            cur.execute(stmt)
        except sqlite3.IntegrityError as e:
            print('Could not add unique index (duplicate data exists):', e)

    conn.commit()
    conn.close()
    print('Migration finished successfully.')


if __name__ == '__main__':
    run_migration()
