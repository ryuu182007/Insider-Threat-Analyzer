# Vercel SQLite fix

`backend/utils/db.py` detects Vercel and copies the committed
`database/insider_threat.db` to `/tmp/threatsim-insider-threat.db`, because the
Vercel deployment directory is not writable by SQLite.

The rest of the application continues to use the same `get_db()` function.
This preserves the existing employee accounts in the bundled database.

Important: `/tmp` is temporary serverless storage. Data written after deploy
is not a permanent production datastore. For a real multi-instance deployment,
move the database to PostgreSQL or another hosted database.
