"""SQLite connection helper with Vercel/serverless-safe database handling.

Locally the application keeps using database/insider_threat.db.
On Vercel, the deployed source tree is not a persistent writable filesystem,
so the bundled seed database is copied once per warm serverless instance to
/tmp and all reads/writes use that writable copy.

IMPORTANT: /tmp is ephemeral. This makes the demo/application work on Vercel,
but database changes are not a permanent production datastore. For a
multi-instance production deployment, move persistent data to PostgreSQL or
another hosted database.
"""

import os
import shutil
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOURCE_DB_PATH = os.path.join(BASE_DIR, 'database', 'insider_threat.db')

# Vercel sets VERCEL=1. The Lambda variable is included as a fallback for
# other serverless deployments.
_IS_SERVERLESS = (
    os.environ.get('VERCEL') == '1'
    or bool(os.environ.get('AWS_LAMBDA_FUNCTION_VERSION'))
)

if _IS_SERVERLESS:
    DB_PATH = os.path.join('/tmp', 'insider_threat.db')
else:
    DB_PATH = SOURCE_DB_PATH

_initialized = False


def _ensure_database():
    """Ensure DB_PATH exists and is writable before sqlite3.connect()."""
    global _initialized
    if _initialized and os.path.exists(DB_PATH):
        return

    if _IS_SERVERLESS:
        os.makedirs('/tmp', exist_ok=True)
        if not os.path.exists(DB_PATH):
            # The repository contains the working employee database. Copy it
            # to Vercel's writable temporary filesystem for this instance.
            if os.path.exists(SOURCE_DB_PATH):
                shutil.copy2(SOURCE_DB_PATH, DB_PATH)
            else:
                # Fallback for a deployment where the database file was not
                # committed: create the schema in /tmp.
                from database.init_db import create_tables
                conn = sqlite3.connect(DB_PATH)
                try:
                    create_tables(conn)
                    conn.commit()
                finally:
                    conn.close()
    else:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    _initialized = True


def get_db():
    """Return a database connection with row factory enabled.

    A generous busy timeout plus WAL mode lets several users (several tabs /
    browsers) read and write at the same time without "database is locked"
    errors. WAL is safe here because the serverless copy is in /tmp.
    """
    _ensure_database()
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    try:
        conn.execute('PRAGMA journal_mode = WAL')
    except sqlite3.DatabaseError:
        pass
    return conn


def dict_from_row(row):
    """Convert a sqlite3.Row to a dictionary."""
    if row is None:
        return None
    return dict(row)
