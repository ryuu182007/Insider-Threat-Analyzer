import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(BASE_DIR, 'database', 'insider_threat.db')


def get_db():
    """Return a database connection with row factory enabled.

    A generous busy timeout plus WAL mode lets several users (several tabs /
    browsers) read and write at the same time without "database is locked"
    errors.
    """
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
