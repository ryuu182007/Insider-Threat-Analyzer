"""One-time migration: copy the existing SQLite database into Supabase Postgres.

Usage on a machine that has the project and dependencies installed:
    set SUPABASE_DB_URL=postgresql://...
    python database/migrate_sqlite_to_supabase.py

The script copies users and application data. Run it against a new/empty
Supabase project or review the target tables before running it again.
"""
import os
import sqlite3
import sys

if not (os.environ.get("SUPABASE_DB_URL") or os.environ.get("DATABASE_URL")):
    raise SystemExit("Set SUPABASE_DB_URL to your Supabase Postgres connection string first.")

# Importing get_db initializes the Postgres schema when the env var is present.
from backend.utils.db import get_db

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQLITE_PATH = os.path.join(BASE_DIR, "database", "insider_threat.db")
TABLES = ["users", "activity_logs", "incidents", "simulations", "tasks", "auth_sessions", "schema_meta"]


def main():
    src = sqlite3.connect(SQLITE_PATH)
    src.row_factory = sqlite3.Row
    dst = get_db()
    try:
        # Child tables first when clearing, parent first when inserting.
        for table in reversed(TABLES):
            dst.execute(f'DELETE FROM {table}')
        dst.commit()

        for table in TABLES:
            rows = src.execute(f'SELECT * FROM "{table}"').fetchall()
            if not rows:
                continue
            columns = [d[1] for d in src.execute(f'PRAGMA table_info("{table}")').fetchall()]
            placeholders = ','.join(['?'] * len(columns))
            for row in rows:
                dst.execute(
                    f'INSERT INTO {table} ({", ".join(columns)}) VALUES ({placeholders})',
                    tuple(row[c] for c in columns)
                )
        dst.commit()

        # Align identity sequences with the imported IDs.
        for table in ["users", "activity_logs", "incidents", "simulations", "tasks"]:
            row = dst.execute(f'SELECT MAX(id) AS m FROM {table}').fetchone()
            max_id = row['m'] if row else None
            if max_id:
                dst.execute(
                    "SELECT setval(pg_get_serial_sequence(%s, 'id'), %s, true)",
                    (table, max_id)
                )
        dst.commit()
        print("Migration complete.")
    finally:
        src.close()
        dst.close()


if __name__ == '__main__':
    main()
