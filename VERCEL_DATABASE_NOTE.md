# Vercel database note

The application uses SQLite. On Vercel, `backend/utils/db.py` copies the bundled
`database/insider_threat.db` into `/tmp/insider_threat.db` and uses that writable
copy for the lifetime of a serverless instance. This fixes the `sqlite3.OperationalError:
unable to open database file` error caused by trying to write to the deployed source tree.

The `/tmp` database is ephemeral and is not a permanent production database. For a
multi-instance production deployment, migrate persistent data to a hosted PostgreSQL
(or other server database) service.
