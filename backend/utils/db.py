"""SQLite database connection helper for local and Vercel deployments.

Vercel's deployed application directory is not writable.  SQLite needs a
writable directory for journal/WAL files, so on Vercel we copy the committed
seed database to /tmp and use that copy for the lifetime of the serverless
instance.

This keeps the existing SQLite-based application working without changing the
rest of the code.  /tmp is ephemeral, so this is appropriate for a demo but
is not a permanent production database.
"""

import os
import shutil
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOURCE_DB_PATH = os.path.join(BASE_DIR, "database", "insider_threat.db")

# Do not rely only on VERCEL=1: the fallback below also works if the runtime
# environment does not expose that variable during a particular invocation.
_RUNTIME_TMP = os.path.join("/tmp", "threatsim-insider-threat.db")
_IS_VERCEL = os.environ.get("VERCEL") == "1"

# Public name kept for compatibility with the rest of the project/tests.
DB_PATH = _RUNTIME_TMP if _IS_VERCEL else SOURCE_DB_PATH

_initialized = False


def _source_is_readable():
    return os.path.isfile(SOURCE_DB_PATH) and os.access(SOURCE_DB_PATH, os.R_OK)


def _prepare_runtime_database():
    """Select a writable SQLite path and create/copy the DB if necessary."""
    global DB_PATH, _initialized

    if _initialized and os.path.isfile(DB_PATH):
        return

    # Vercel/serverless: always use /tmp.  It is the writable filesystem area.
    if _IS_VERCEL:
        DB_PATH = _RUNTIME_TMP
    else:
        # Local development keeps the repository DB.  If the application is
        # unexpectedly running from a read-only deployment directory, fall
        # back to /tmp instead of crashing.
        try:
            os.makedirs(os.path.dirname(SOURCE_DB_PATH), exist_ok=True)
            test_path = SOURCE_DB_PATH + ".write-test"
            with open(test_path, "ab"):
                pass
            os.remove(test_path)
            DB_PATH = SOURCE_DB_PATH
        except (OSError, PermissionError):
            DB_PATH = _RUNTIME_TMP

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    if not os.path.exists(DB_PATH):
        if _source_is_readable() and os.path.abspath(SOURCE_DB_PATH) != os.path.abspath(DB_PATH):
            shutil.copyfile(SOURCE_DB_PATH, DB_PATH)
        elif os.path.abspath(SOURCE_DB_PATH) == os.path.abspath(DB_PATH):
            # Let sqlite create the file; schema initialization is handled by
            # database.init_db when running the app locally.
            pass
        else:
            # If a deployment omitted the binary seed database, create the
            # schema in the writable runtime location.
            from database.init_db import create_tables
            conn = sqlite3.connect(DB_PATH)
            try:
                create_tables(conn)
                conn.commit()
            finally:
                conn.close()

    # Verify that SQLite can actually open the selected file before marking it
    # ready.  This catches bad paths/permissions early.
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.close()
    _initialized = True


def get_db():
    """Return a SQLite connection with row access enabled."""
    _prepare_runtime_database()
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.execute("PRAGMA journal_mode = WAL")
    except sqlite3.DatabaseError:
        # WAL is an optimization, not a requirement for the application.
        pass
    return conn


def dict_from_row(row):
    """Convert a sqlite3.Row to a dictionary."""
    if row is None:
        return None
    return dict(row)
